#!/usr/bin/env python3
"""
bsc_pairwatch.py - COMPLETE-COVERAGE catch-up scanner for GitHub Actions (the free "full daemon on GitHub").
WHY: the GeckoTerminal-sourced monitor MISSES on-chain pairs (JL/BFB/PHX were invisible to it). This reads
the SAME on-chain PairCreated events the WS daemon does - just POLLED (catch-up) instead of streamed. Every
run: last_block (from actions/cache) -> scan PairCreated in 50-block getLogs chunks to head -> run the
pair-burn-sync bytecode detector (sync/skim + EIP-1967/1167 proxy resolution) on each new token -> notify.
Robust to cron delays: a late run just scans a bigger range and catches up (no permanent gap, unlike a daemon).
Loses only the real-time/mempool t=0 tier (irrelevant for slow drains: JL 4.4h window, PHX 13.5 DAYS).
env: TELEGRAM_BOT_TOKEN+TELEGRAM_CHAT_ID (or DISCORD_WEBHOOK/NTFY_TOPIC); PW_HOME (state dir); MIN_LIQ_USD.
"""
import json, os, sys, time, urllib.request, urllib.parse
try:
    from eth_utils import keccak
    PAIRCREATED = "0x" + keccak(text="PairCreated(address,address,address,uint256)").hex()
except Exception:
    PAIRCREATED = "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9"

HOME = os.environ.get("PW_HOME") or os.path.dirname(os.path.abspath(__file__))
os.makedirs(HOME, exist_ok=True)
STATE = os.path.join(HOME, "pairwatch_state.json")
ALERTS = os.path.join(HOME, "pairwatch_alerts.json")
MIN_LIQ_USD = float(os.environ.get("MIN_LIQ_USD") or 1000)
MAX_CATCHUP = int(os.environ.get("PW_MAX_CATCHUP") or 500000)
# ^ blocks of backlog one run will accept before JUMPING AHEAD AND PERMANENTLY DROPPING the rest. This is the
# only place the scanner knowingly loses coverage, so the number has to be honest about BSC's real block rate.
# WAS 20000, chosen when BSC made a block every ~3s => ~16h of chain (a sane outage cap). BSC now blocks every
# ~0.45s (~8,000/hour), so 20000 silently became just 2.5 HOURS — shorter than GitHub's own cron throttling
# (observed 1-3h gaps between */10 runs). Combined with the old CHUNK=50 (which couldn't keep pace), the scanner
# ran chronically behind, blew this cap routinely, and dropped fresh pairs FOREVER. WAS 200000 (~25h): too low
# once the SECOND bug (unbounded analysis, below) froze last_block — the scanner sat >25h behind and DROPPED every
# run. 500000 = ~62h of chain; combined with the block-tracked analysis commit below the scanner now self-heals a
# backlog over a few runs, so this cap only ever fires on a truly catastrophic (>2.5-day) outage.
CHUNK = 2000        # drpc's getLogs cap. WHY THIS MATTERS: BSC now produces a block every ~0.45s (~8,000/hour),
                    # ~6.7x faster than the ~3s this was designed against. At the old CHUNK=50 (sized for the
                    # WORST node, 1rpc/publicnode) each call covered just 23 SECONDS of chain -> 160 calls/hour,
                    # and GitHub throttles the */10 cron to real gaps of 1-3h => 320-479 sequential calls per run.
                    # get_paircreated stops at the first failed chunk, so one rate-limit hiccup leaves it behind,
                    # which makes the next range bigger -> a lag death-spiral, and fresh pairs are never reached.
                    # drpc serves 2000 blocks/call (~15 min of chain) = 40x throughput; SUB_CHUNK is the fallback
                    # for the 50-cap nodes so a drpc outage degrades instead of failing.
SUB_CHUNK = 50                                                 # 1rpc/publicnode getLogs cap (fallback only)
SCAN_BUDGET_S = int(os.environ.get("PW_SCAN_BUDGET_S") or 300)  # the SCAN (getLogs) gets up to 5 min of the run.
RUN_BUDGET_S  = int(os.environ.get("PW_RUN_BUDGET_S")  or 1020) # TOTAL run budget (scan + ANALYSIS), 17 min; the
                                                               # 20-min workflow timeout leaves ~3 min for state
                                                               # save + notify. Bigger budget = more pairs analyzed
                                                               # per run = the ~25h backlog clears in fewer runs
                                                               # (analysis throughput is now the binding constraint).
                                                               # WHY TWO BUDGETS (the freeze bug):
                                                               # the old code time-boxed ONLY the scan, then ran an
                                                               # UNBOUNDED per-pair bytecode analysis (~3s/pair). A
                                                               # 200k backlog = ~1,500 pairs = >80 min of analysis,
                                                               # so every run was KILLED by the 15-min timeout BEFORE
                                                               # the state save (`last_block = ...`) was ever reached
                                                               # -> last_block froze -> the backlog grew each run and
                                                               # the DROP alert fired forever. Now the analysis loop
                                                               # is ALSO deadline-bounded (RUN_BUDGET_S) and commits
                                                               # last_block at a clean BLOCK boundary of the pairs it
                                                               # actually finished, so every run saves progress and
                                                               # the backlog is worked off across runs.

# UniV2-style factories (all share the PairCreated topic + data layout)
FACTORIES = [
    "0xca143ce32fe78f1f7019d7d551a6402fc5350c73",  # PancakeSwap V2
    "0x858e3312ed3a876947ea49d572a7c42de08af7ee",  # Biswap
    "0x0841bd0b734e4f5853f0dd8d7ea041c241fb0da6",  # ApeSwap
    "0x3cd1c46068daea5ebb0d3f55f6915b10648062b8",  # MDEX
    "0x01bf7c66c6bd861915cdaae475042d3c4bae16a7",  # BakerySwap
]
WBNB = "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"
# Base/quote tokens a fresh pair can be funded in. base_liq_usd reads how much of THESE the pair holds -> USD.
# WHY THIS LIST MATTERS (measured 2026-07-17): with only USDT/USDC/BUSD/WBNB, a burn-sync token paired against
# any OTHER base read $0 liquidity -> looked UNFUNDED -> NEVER alerted (a $2,637 pool scored $0). Fresh BSC
# tokens increasingly quote in FDUSD/USD1 (new stables) and CAKE/ETH/BTCB. All are 18-decimals on BSC.
BASES = [("0x55d398326f99059ff775485246999027b3197955", 1.0),   # USDT  (stable)
         ("0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d", 1.0),   # USDC  (stable)
         ("0xe9e7cea3dedca5984780bafc599bd69add087d56", 1.0),   # BUSD  (stable)
         ("0xc5f0f7b66764f6ec8c8dff7ba683102295e16409", 1.0),   # FDUSD (stable, newer)
         ("0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d", 1.0),   # USD1  (stable, newer)
         (WBNB, None),                                          # None => live BNB price
         ("0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82", "L"),   # CAKE  ("L" => live price lookup)
         ("0x2170ed0880ac9a755fd29b2688956bd959f933f8", "L"),   # ETH
         ("0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c", "L")]   # BTCB
BASE_SET = {a for a, _ in BASES}
_LIVE_PX = {}          # addr -> USD, fetched once per process for the "L" bases (CAKE/ETH/BTCB)

def _base_price(tok, price, bnb):
    """USD price for a base token: fixed for stables, live BNB for WBNB, live lookup (cached) for CAKE/ETH/BTCB.
    Unknown/failed lookup -> 0.0 (NEVER fabricate a price; that would invent liquidity that isn't there)."""
    if price is None:
        return bnb
    if price != "L":
        return price
    if tok not in _LIVE_PX:
        try:
            r = json.loads(urllib.request.urlopen(
                "https://api.geckoterminal.com/api/v2/simple/networks/bsc/token_price/" + tok, timeout=10).read())
            _LIVE_PX[tok] = float(list(r["data"]["attributes"]["token_prices"].values())[0])
        except Exception:
            _LIVE_PX[tok] = 0.0        # couldn't price -> don't count this base (fail safe, not fail loud)
    return _LIVE_PX[tok]

# getLogs-capable nodes (50-block chunks); general RPC nodes for getCode/eth_call (no range limit)
# WIDE-RANGE getLogs nodes first, then the 50-cap fallbacks. WHY A POOL, NOT ONE (measured 2026-07-21): the scan
# needs a 2000-block getLogs; if NO wide node serves it the scan degrades to 50-block sub-chunks (~250 blocks/15s),
# which can't keep pace with BSC's ~8,000 blocks/h across GitHub's 1-3h cron gaps -> the scanner falls behind. drpc
# was the ONLY wide node we had and it's FLAKY (observed fully DOWN mid-fix). So we now carry FOUR independent wide
# providers (each tested 3/3 reliable, serving 2000-50k block ranges): bloXroute, OnFinality, 48.club x2, plus drpc.
# A single wide node serving = full throughput; all four must fail simultaneously before we ever crawl. nodies
# (200-block) then the 50-cap nodes are the deep fallbacks. Order = most-reliable-first.
LOG_RPCS = ["https://bsc.rpc.blxrbdn.com", "https://bnb.api.onfinality.io/public", "https://0.48.club",
            "https://rpc-bsc.48.club", "https://bsc.drpc.org", "https://bsc-pokt.nodies.app",
            "https://1rpc.io/bnb", "https://bsc-rpc.publicnode.com"]
GEN_RPCS = ["https://bsc-rpc.publicnode.com", "https://bsc-dataseed.bnbchain.org",
            "https://bsc-dataseed1.defibit.io", "https://1rpc.io/bnb"]
if os.environ.get("ALCHEMY_KEY"):
    GEN_RPCS.insert(0, "https://bnb-mainnet.g.alchemy.com/v2/" + os.environ["ALCHEMY_KEY"])

_MANIP = ("fff6cae9", "bc25cf77")            # sync() + skim()
_BURN = ("42966c68", "9dc29fac", "89afcb44", "b1faeac6", "6b2fb3a3")
_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

def _rpc(urls, method, params, tries=2):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for _ in range(tries):
        for u in urls:
            try:
                req = urllib.request.Request(u, payload, {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
                r = json.loads(urllib.request.urlopen(req, timeout=15).read())
                if "result" in r:
                    return r["result"]
            except Exception:
                continue
        time.sleep(0.4)
    return None

def head_block():
    r = _rpc(GEN_RPCS, "eth_blockNumber", [])
    return int(r, 16) if r else None

KNOWN_FACTORIES = {f.lower() for f in FACTORIES}   # trusted -> no validation needed
_VALIDATED_FACT = set()      # unknown factories proven real this process (pair.factory() points back)
_REJECTED_FACT = set()       # spoofers (fake PairCreated emitters) -> cheap skip after one check

def _pair_factory(pair):
    """factory() on a pair. A REAL UniV2 pair returns the factory that created it; a spoofed 'pair' (random
    contract that merely emitted a PairCreated log) does not -> lets us safely scan ALL PairCreated instead of a
    hardcoded allowlist, without a DoS surface. None on failure."""
    r = _rpc(GEN_RPCS, "eth_call", [{"to": pair, "data": "0xc45a0155"}, "latest"])   # factory()
    try:
        return ("0x" + r[-40:]).lower() if r and int(r, 16) != 0 else None
    except Exception:
        return None

def get_paircreated(frm, to, deadline=None):
    """PairCreated logs across ALL V2 factories in [frm,to] via CHUNK-block getLogs. Returns ([(blk,t0,t1,pair)], scanned).
    GAP-1 FIX: no factory allowlist. We scan EVERY PairCreated event (auto-covers present+future V2 DEXes, not just
    5 hardcoded factories), and validate an UNKNOWN emitter ONCE via pair.factory()==emitter (cached) so spoofed
    events can't DoS us. Known factories are fast-pathed (no validation call).

    `deadline` (unix ts) time-boxes the SCAN: on hitting it we return the blocks scanned SO FAR, the caller commits
    that as last_block, and the next run resumes there. This alone is NOT enough: state is only saved at the END of
    a run, and the per-pair ANALYSIS that runs AFTER the scan (~3s/pair) is the real cost — a 200k backlog is ~1,500
    pairs = >80 min of analysis vs a 15-min timeout, so the run was KILLED before the save and last_block FROZE (the
    backlog then grew every run and the DROP alert fired forever). The scan deadline here caps the scan; main() caps
    the analysis with a SECOND deadline and commits at a clean block boundary. Both together = the scanner self-heals.
    """
    out = []
    b = frm
    while b <= to:
        if deadline and time.time() > deadline:
            print(f"  deadline hit at block {b}; committing through {b-1}, next run resumes there", flush=True)
            return out, b - 1              # partial progress COMMITTED -> no gap, no deadlock
        e = min(b + CHUNK - 1, to)
        logs = _rpc(LOG_RPCS, "eth_getLogs",
                    [{"fromBlock": hex(b), "toBlock": hex(e), "topics": [PAIRCREATED]}])
        if logs is None and CHUNK > SUB_CHUNK:
            # the wide chunk failed (drpc down / range rejected) -> re-try the SAME range in 50-block sub-chunks
            # so the capped nodes can still serve it. Degrade, don't stall.
            logs = []
            sb = b
            while sb <= e:
                if deadline and time.time() > deadline:
                    # the deadline must be checked HERE too: when drpc is down we grind 40 sub-chunks per outer
                    # chunk, and checking only between 2000-block chunks let one stuck chunk blow the whole run
                    # budget -> overshoot the 15-min timeout -> commit nothing -> deadlock (the exact failure the
                    # budget exists to stop). Commit what the sub-loop scanned and resume next run.
                    print(f"  deadline hit mid-sub-chunk at {sb}; committing through {sb-1}", flush=True)
                    return out, sb - 1
                se = min(sb + SUB_CHUNK - 1, e)
                part = _rpc(LOG_RPCS, "eth_getLogs",
                            [{"fromBlock": hex(sb), "toBlock": hex(se), "topics": [PAIRCREATED]}])
                if part is None:
                    print(f"  getLogs FAILED at {sb}-{se}; committing through {sb-1}, re-scan next run", flush=True)
                    return out, sb - 1      # commit only fully-scanned blocks
                logs.extend(part)
                sb = se + 1
        if logs is None:                    # ALL nodes failed this chunk (None != empty []). DON'T advance past it:
            print(f"  getLogs FAILED at {b}-{e}; committing through {b-1}, re-scan next run", flush=True)
            return out, b - 1               # commit only fully-scanned blocks -> failed range re-scanned next run
        for lg in logs:
            if deadline and time.time() > deadline:
                # per-LOG deadline check: the _pair_factory() spoof-validation below is an RPC call, and a spam range
                # emitting PairCreated from many DISTINCT fake factories could grind this loop past the budget (the
                # between-chunk checks above wouldn't catch it). Commit through the last FULLY-scanned chunk (b-1);
                # this chunk re-scans next run and seen-dedup skips anything already analyzed. Now the scan budget
                # TRULY bounds all scan work, not just the getLogs calls.
                print(f"  deadline hit mid-chunk log-processing at block {b}; committing through {b-1}", flush=True)
                return out, b - 1
            tp = lg.get("topics") or []
            data = lg.get("data") or ""
            if len(tp) >= 3 and len(data) >= 66:
                t0 = "0x" + tp[1][-40:]; t1 = "0x" + tp[2][-40:]; pair = ("0x" + data[2:66][-40:]).lower()
                emitter = (lg.get("address") or "").lower()
                if emitter in KNOWN_FACTORIES or emitter in _VALIDATED_FACT:
                    pass                                     # trusted factory
                elif emitter in _REJECTED_FACT:
                    continue                                 # known spoofer -> cheap skip
                elif _pair_factory(pair) == emitter:         # NEW factory: validate once (pair points back)
                    _VALIDATED_FACT.add(emitter)
                    print(f"  [new factory validated: {emitter}]", flush=True)
                else:
                    _REJECTED_FACT.add(emitter); continue    # spoofed PairCreated -> reject + cache
                blk = int(lg.get("blockNumber") or "0x0", 16)   # needed so the ANALYSIS loop can commit progress
                out.append((blk, t0.lower(), t1.lower(), pair)) # at a clean block boundary (see main())
        b = e + 1
    return out, to

def getcode(a):
    r = _rpc(GEN_RPCS, "eth_getCode", [a, "latest"])
    return (r or "").lower()

def _impl_code(token):
    r = _rpc(GEN_RPCS, "eth_getStorageAt", [token, _IMPL, "latest"])
    if r and int(r, 16) != 0:
        return getcode("0x" + r[-40:])
    b = _rpc(GEN_RPCS, "eth_getStorageAt", [token, _BEACON, "latest"])
    if b and int(b, 16) != 0:
        impl = _rpc(GEN_RPCS, "eth_call", [{"to": "0x" + b[-40:], "data": "0x5c60da1b"}, "latest"])
        if impl and int(impl, 16) != 0:
            return getcode("0x" + impl[-40:])
    return ""

def _clone_impl(code):
    m = "363d3d373d3d3d363d73"; i = code.find(m)
    if i != -1 and len(code) >= i + len(m) + 40:
        impl = "0x" + code[i + len(m):i + len(m) + 40]
        try:
            if int(impl, 16) != 0:
                return impl
        except Exception:
            pass
    return None

def _get_source(token):
    """Etherscan verified source: non-empty str = verified w/ source, '' = unverified, None = couldn't check."""
    key = os.environ.get("ETHERSCAN_API_KEY")
    if not key:
        return None
    try:
        u = "https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getsourcecode&address=%s&apikey=%s" % (token, key)
        r = json.loads(urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"}), timeout=15).read())
        res = r.get("result")
        if isinstance(res, list) and res:
            return res[0].get("SourceCode") or ""
    except Exception:
        pass
    return None

def _burn_from_pair(src):
    low = src.lower().replace(" ", "")
    return any(k in low for k in ("_burn(pair", "_burn(uniswap", "_burn(pancake", "_burn(targetpool", "_burn(_pair",
                                  "_burn(lppair", "_burn(pool", "balances[pair]-=", "_balances[pair]-=", "balanceof[pair]"))

def sync_burn_flag(token):
    own = getcode(token)
    if own == "":                        # RPC failure — a real deployed token ALWAYS has code. Don't false-clear:
        return "INCONCLUSIVE"            # caller re-checks next run instead of marking it 'seen' forever
    code = own + _impl_code(token)
    ci = _clone_impl(own)
    if ci:
        code += getcode(ci)
    if not any(s in code for s in _MANIP):
        return None
    if any(s in code for s in _BURN):
        return "PAIR-BURN-SYNC:SYNC/SKIM+BURN(HIGH)"            # bytecode has BOTH sync/skim AND a burn selector -> HIGH
    # sync/skim WITHOUT a known burn selector: hidden-burn drain (PHX) OR a LEGIT sync-caller (the $91.8M FP).
    # Disambiguate via VERIFIED source: burn-from-pair present -> real drain; verified but ABSENT -> legit, drop.
    src = _get_source(token)
    if src:                                                     # verified source available -> trust it
        return "PAIR-BURN-SYNC:SRC-BURN-FROM-PAIR(HIGH)" if _burn_from_pair(src) else None
    return "PAIR-BURN-SYNC:UNVERIFIED-SYNC/SKIM(HIGH)"          # unverified / no key -> keep HIGH (PHX+JL hidden-burn class)

def pick_token(t0, t1):
    if t1 in BASE_SET and t0 not in BASE_SET:
        return t0
    if t0 in BASE_SET and t1 not in BASE_SET:
        return t1
    return None

def _bnb():
    try:
        r = json.loads(urllib.request.urlopen("https://api.geckoterminal.com/api/v2/simple/networks/bsc/token_price/" + WBNB, timeout=10).read())
        return float(list(r["data"]["attributes"]["token_prices"].values())[0])
    except Exception:
        return 600.0

def base_liq_usd(pair, bnb):
    best = 0.0
    for tok, price in BASES:
        r = _rpc(GEN_RPCS, "eth_call", [{"to": tok, "data": "0x70a08231" + pair[2:].rjust(64, "0")}, "latest"])
        bal = int(r, 16) if r and r != "0x" else 0
        usd = bal / 1e18 * _base_price(tok, price, bnb)      # stable=$1, WBNB=live BNB, CAKE/ETH/BTCB=live lookup
        if usd > best:
            best = usd
    return best

def notify(text):
    tok, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if tok and chat:
        try:
            d = urllib.parse.urlencode({"chat_id": chat, "text": text, "disable_web_page_preview": "true"}).encode()
            urllib.request.urlopen(urllib.request.Request("https://api.telegram.org/bot%s/sendMessage" % tok, d), timeout=15)
        except Exception:
            pass
    wh = os.environ.get("DISCORD_WEBHOOK")
    if wh:
        try:
            urllib.request.urlopen(urllib.request.Request(wh, json.dumps({"content": text}).encode(), {"Content-Type": "application/json"}), timeout=15)
        except Exception:
            pass
    topic = os.environ.get("NTFY_TOPIC")
    if topic:
        try:
            urllib.request.urlopen(urllib.request.Request("https://ntfy.sh/" + topic, text.encode("utf-8"), {"Title": "BSC pairwatch"}), timeout=15)
        except Exception:
            pass

def main():
    _t0 = time.time()          # run start -> the scan deadline (_t0 + RUN_BUDGET_S) time-boxes this pass
    st = {}
    if os.path.exists(STATE):
        try:
            st = json.load(open(STATE))
        except Exception:
            st = {}
    alerts = json.load(open(ALERTS)) if os.path.exists(ALERTS) else []
    seen = st.get("seen", [])                              # ordered list (newest last) so pruning keeps recent
    seen_set = set(seen)
    pending = st.get("pending", {})                        # token -> [pair, flag, first_ts]: burn-sync but not yet
    PENDING_TTL = 6 * 3600                                 # funded -> re-checked EVERY run (the create-then-fund fix)
    head = head_block()
    if not head:
        print("no head - all RPCs down this pass", flush=True); return
    last = st.get("last_block") or (head - 300)          # first run: last ~5 min
    if head - last > MAX_CATCHUP:                          # long outage: cap the backlog
        dropped = head - last - MAX_CATCHUP
        print(f"backlog {head-last} > cap {MAX_CATCHUP}; jumping ahead (DROPPING {dropped} blocks)", flush=True)
        # A dropped range is a COVERAGE HOLE — tokens in it are never scanned. FCOW was missed exactly this way,
        # silently, while every run reported success. If we ever drop, SAY SO.
        notify("BSC pairwatch COVERAGE GAP\n"
               "backlog %d blocks > cap %d -> DROPPED %d blocks (~%.1f h of chain).\n"
               "Pairs created in that range were NEVER scanned. Scanner is falling behind."
               % (head - last, MAX_CATCHUP, dropped, dropped * 0.45 / 3600))
        last = head - MAX_CATCHUP
    frm = last + 1
    if frm > head:                                         # no new blocks (or stale head): skip scan but STILL
        pairs, scanned = [], last                          # re-check pending below (it's TIME-based, not block-based)
    else:
        pairs, scanned = get_paircreated(frm, head, deadline=_t0 + SCAN_BUDGET_S)  # `scanned` may be < head if a
                                                           # chunk failed OR the SCAN budget expired (both commit
                                                           # only fully-scanned blocks -> resume, never a gap)
    print(f"scan {frm}..{scanned} -> {len(pairs)} PairCreated", flush=True)
    bnb = _bnb()
    fired = 0

    def _mark(tok):
        seen_set.add(tok); seen.append(tok)
    def _fire(tok, pair, flag, usd):
        nonlocal fired
        fired += 1
        rec = {"token": tok, "pair": pair, "flag": flag, "liq_usd": round(usd), "t": time.strftime("%Y-%m-%d %H:%M")}
        alerts.append(rec)
        print("*** ALERT", rec, flush=True)
        notify("BSC pairwatch ALERT (pair-burn-sync)\n%s  liq ~$%d\n%s\nhttps://bscscan.com/token/%s"
               % (flag, round(usd), tok, tok))

    # 1) NEW pairs from this scan. BUDGET-BOUNDED: the per-pair bytecode analysis is ~3s and a big backlog is
    # thousands of pairs (>80 min), which used to overrun the workflow timeout and KILL the run before the state
    # save -> last_block froze forever. We now stop at RUN_BUDGET_S and commit last_block at a CLEAN BLOCK BOUNDARY:
    # `analyzed_through` = the highest block whose pairs were ALL analyzed. Pairs are sorted by block, so on a
    # mid-pass stop everything before the current pair's block is done; that block..scanned is re-scanned next run
    # (cheap — pairs are sparse, and any already-seen token is skipped). Every run now SAVES progress and resumes.
    pairs.sort(key=lambda r: r[0])
    analysis_deadline = _t0 + RUN_BUDGET_S
    analyzed_through = scanned                              # default: finished every pair -> commit the full scan
    for i, (blk, t0, t1, pair) in enumerate(pairs):
        if time.time() > analysis_deadline:
            analyzed_through = blk - 1                      # blk..scanned not fully analyzed -> re-scan next run
            print(f"  analysis budget hit at pair {i}/{len(pairs)} (block {blk}); committing through {blk-1}", flush=True)
            break
        token = pick_token(t0, t1)
        if not token or token in seen_set or token in pending:
            continue
        flag = sync_burn_flag(token)
        if flag == "INCONCLUSIVE":
            pending[token] = [pair, "?", time.time()]      # code unreadable (RPC blip) -> re-run detector next run, DON'T clear
        elif not flag:
            _mark(token)                                   # not burn-sync (bytecode immutable) -> never re-check
        else:
            usd = base_liq_usd(pair, bnb)
            if usd >= MIN_LIQ_USD:
                _fire(token, pair, flag, usd); _mark(token)
            else:
                pending[token] = [pair, flag, time.time()] # burn-sync but UNFUNDED -> re-check (create-then-fund)

    # 2) RE-CHECK pending: flag "?" = code was unreadable (re-run detector); a real flag = unfunded (re-check liq).
    # Also budget-bounded: pending can hold many burn-sync-but-unfunded tokens and each re-check is an RPC round;
    # left unbounded it could re-open the timeout hole. Anything not reached stays pending (TTL governs expiry).
    for token in list(pending.keys()):
        if time.time() > analysis_deadline:
            print(f"  analysis budget hit during pending re-check; {len(pending)} left for next run", flush=True)
            break
        pair, flag, ts = pending[token]
        if time.time() - ts > PENDING_TTL:
            del pending[token]; _mark(token); continue
        if flag == "?":
            flag = sync_burn_flag(token)
            if flag == "INCONCLUSIVE":
                continue                                   # still can't read -> keep pending
            if not flag:
                del pending[token]; _mark(token); continue # resolved: not burn-sync
            pending[token][1] = flag                        # now known burn-sync -> fall through to liq check
        usd = base_liq_usd(pair, bnb)
        if usd >= MIN_LIQ_USD:
            _fire(token, pair, flag, usd); del pending[token]; _mark(token)

    # commit only blocks whose pairs were fully ANALYZED (<= scanned); a failed chunk OR a budget-truncated analysis
    # re-scans next run. INVARIANT: last_block is MONOTONIC — never below where this run started (`last`). Correct
    # operation always gives analyzed_through in [last, scanned]; the max() is a guard so a single malformed
    # blockNumber from some future RPC can never rewind last_block and trigger a catastrophic re-scan from genesis.
    st["last_block"] = max(analyzed_through, last)
    st["seen"] = seen[-20000:]                             # ordered -> keeps the most recent
    st["pending"] = pending
    json.dump(st, open(STATE, "w"))
    json.dump(alerts, open(ALERTS, "w"), indent=1)
    print(f"done: scanned {scanned}/{head}, {len(pairs)} pairs, {len(pending)} pending, {fired} alert(s)", flush=True)
    if os.environ.get("SELFTEST", "").strip().lower() in ("1", "true", "yes"):
        notify("BSC pairwatch SELF-TEST - catch-up scanner alive on GitHub Actions.")

if __name__ == "__main__":
    main()
