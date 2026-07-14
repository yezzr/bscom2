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
MAX_CATCHUP = int(os.environ.get("PW_MAX_CATCHUP") or 20000)   # cap a huge backlog (long outage) so one run can't run forever
CHUNK = 50                                                     # 1rpc/publicnode getLogs cap

# UniV2-style factories (all share the PairCreated topic + data layout)
FACTORIES = [
    "0xca143ce32fe78f1f7019d7d551a6402fc5350c73",  # PancakeSwap V2
    "0x858e3312ed3a876947ea49d572a7c42de08af7ee",  # Biswap
    "0x0841bd0b734e4f5853f0dd8d7ea041c241fb0da6",  # ApeSwap
    "0x3cd1c46068daea5ebb0d3f55f6915b10648062b8",  # MDEX
    "0x01bf7c66c6bd861915cdaae475042d3c4bae16a7",  # BakerySwap
]
WBNB = "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"
BASES = [("0x55d398326f99059ff775485246999027b3197955", 1.0),   # USDT
         ("0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d", 1.0),   # USDC
         ("0xe9e7cea3dedca5984780bafc599bd69add087d56", 1.0),   # BUSD
         (WBNB, None)]                                          # None => BNB price
BASE_SET = {a for a, _ in BASES}

# getLogs-capable nodes (50-block chunks); general RPC nodes for getCode/eth_call (no range limit)
LOG_RPCS = ["https://1rpc.io/bnb", "https://bsc-rpc.publicnode.com", "https://bsc.drpc.org"]
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

def get_paircreated(frm, to):
    """PairCreated logs across all V2 factories in [frm,to] via 50-block chunks. Returns [(token0,token1,pair)]."""
    out = []
    b = frm
    while b <= to:
        e = min(b + CHUNK - 1, to)
        logs = _rpc(LOG_RPCS, "eth_getLogs",
                    [{"fromBlock": hex(b), "toBlock": hex(e), "address": FACTORIES, "topics": [PAIRCREATED]}])
        if logs is None:                    # ALL nodes failed this chunk (None != empty []). DON'T advance past it:
            print(f"  getLogs FAILED at {b}-{e}; committing through {b-1}, re-scan next run", flush=True)
            return out, b - 1               # commit only fully-scanned blocks -> failed range re-scanned next run
        for lg in logs:
            tp = lg.get("topics") or []
            data = lg.get("data") or ""
            if len(tp) >= 3 and len(data) >= 66:
                t0 = "0x" + tp[1][-40:]; t1 = "0x" + tp[2][-40:]; pair = "0x" + data[2:66][-40:]
                out.append((t0.lower(), t1.lower(), pair.lower()))
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
        usd = bal / 1e18 * (bnb if price is None else price)
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
        print(f"backlog {head-last} > cap {MAX_CATCHUP}; jumping ahead (accepting one gap)", flush=True)
        last = head - MAX_CATCHUP
    frm = last + 1
    if frm > head:                                         # no new blocks (or stale head): skip scan but STILL
        pairs, scanned = [], last                          # re-check pending below (it's TIME-based, not block-based)
    else:
        pairs, scanned = get_paircreated(frm, head)        # `scanned` may be < head if a chunk's getLogs failed
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

    # 1) NEW pairs from this scan
    for t0, t1, pair in pairs:
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
    for token in list(pending.keys()):
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

    st["last_block"] = scanned                             # commit ONLY fully-scanned blocks; a failed chunk re-scans next run
    st["seen"] = seen[-20000:]                             # ordered -> keeps the most recent
    st["pending"] = pending
    json.dump(st, open(STATE, "w"))
    json.dump(alerts, open(ALERTS, "w"), indent=1)
    print(f"done: scanned {scanned}/{head}, {len(pairs)} pairs, {len(pending)} pending, {fired} alert(s)", flush=True)
    if os.environ.get("SELFTEST", "").strip().lower() in ("1", "true", "yes"):
        notify("BSC pairwatch SELF-TEST - catch-up scanner alive on GitHub Actions.")

if __name__ == "__main__":
    main()
