#!/usr/bin/env python3
"""
taxtoken_profitsim.py — the mechanic-AGNOSTIC forward monitor for the BSC reflection/tax/
DividendDistributor family (ATM force-dump, DTXT fee-skip, $SHIP JIT-dividend, + every future
variant). We stopped chasing mechanics with static detectors (D1/D7/...) — one template spawns
unlimited mechanics and static matchers always lag the last exploit. This does what the ATTACKER
does: fork BSC, become a holder, fire the permissionless side-effect, claim, round-trip out, and
check "did I end richer at frozen price?" (test/TaxTokenProfitSim.t.sol). Catches the family by
PROFIT, not by shape. WHITE-HAT / DISCLOSURE-ONLY: catch + warn before the attacker. ~0 EV (no
bounty on these) — this is a safety monitor; the same profit-sim technique is what we run on REAL
bountied targets (dreUSD AtomicProfit). Run on a TIGHT cadence — the exploitable window is hours.
"""
import json, os, sys, time, subprocess, urllib.request, urllib.parse, re

ESK = os.environ.get('ETHERSCAN_API_KEY') or ""
BSC_RPC = os.environ.get('BSC_RPC_URL') or ""
FORGE = os.path.expanduser("~/.foundry/bin/forge.exe")
PROJECT = os.path.join(os.path.dirname(__file__), "atomic_confirm")
ALERTS = "D:/CLAUDE/taxtoken_profitsim_alerts.json"
MIN_LIQ = 2000        # only sim tokens with real liquidity worth draining
MAX_SIM = 25          # cap forge runs per cycle (each fork is RPC-heavy)
BUY_WBNB = "200000000000000000"   # 0.2 WBNB probe size

# Pre-filter = the TAX-TOKEN SUPERSET, not the dividend mechanic. We previously gated the
# mechanic-AGNOSTIC sim behind dividend-specific words (dropping 58/63 funded tokens) — a
# contradiction that blinded us to any variant not using those exact words. Now we admit ANY
# token that takes a fee / has a transfer side-effect (the family's true superset); the SIM is
# the verdict, and MAX_SIM + liquidity-ranking bound the cost. Unverified source -> still sim.
FAMILY_MARKERS = ("dividend", "swapback", "shouldswapback", "distributedividend", "process(",
                  "reflection", "_taxfee", "dividenddistributor", "setshare", "swapandliquify",
                  "fee", "tax", "marketingwallet", "liquidityfee", "selltax", "buytax", "inswap",
                  "swapandsend", "swapenabled", "_takefee", "totalfees", "swapthreshold",
                  "_isexcludedfromfee", "numtokenssellto", "_reflectfee", "rewardtoken")

def jget(u, hdr=None):
    try: return json.loads(urllib.request.urlopen(urllib.request.Request(u, headers=hdr or {"User-Agent":"Mozilla/5.0"}), timeout=40).read().decode())
    except Exception: return {}

def fresh_bsc_pools(pages=6):
    """token -> (pair/pool address, liquidity usd)"""
    out = {}
    for path in ("new_pools", "trending_pools"):
        for pg in range(1, pages + 1):
            d = jget(f"https://api.geckoterminal.com/api/v2/networks/bsc/{path}?page={pg}")
            for p in (d.get("data") or []):
                attr = p.get("attributes", {}) or {}
                pool = attr.get("address", "")
                liq = float(attr.get("reserve_in_usd") or 0)
                bt = (((p.get("relationships", {}) or {}).get("base_token", {}) or {}).get("data") or {}).get("id", "")
                if bt.startswith("bsc_") and pool:
                    a = bt.split("_")[1].lower()
                    if a not in out or liq > out[a][1]: out[a] = (pool, liq)
            if not d.get("data"): break
            time.sleep(0.6)
    return out

def source(addr):
    r = jget("https://api.etherscan.io/v2/api?" + urllib.parse.urlencode(
        {"chainid":56,"module":"contract","action":"getsourcecode","address":addr,"apikey":ESK}))
    x = (r.get("result") or [{}])[0]
    return (x.get("ContractName",""), (x.get("SourceCode","") or "").lower())

def looks_family(src_lower):
    return sum(1 for m in FAMILY_MARKERS if m in src_lower) >= 2

def _bsc_call(to, data):
    body = json.dumps({"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":to,"data":data},"latest"]}).encode()
    try:
        r = json.loads(urllib.request.urlopen(urllib.request.Request(BSC_RPC, body, {"Content-Type":"application/json"}), timeout=20).read())
        return r.get("result","") or ""
    except Exception: return ""
def _u(hexstr):
    try: return int(hexstr, 16) if hexstr and hexstr != "0x" else 0
    except Exception: return 0
def has_reserve(token):
    """The exploitability PRECONDITION: does the contract currently HOLD an accumulated reserve worth
    draining? Tax/dividend tokens collect fees as their own balance (pending swapBack); a legit token
    (ARK etc.) holds ~0 of itself. balanceOf(token,token) >= 0.1% of supply == there's a reserve to take.
    This is mechanic-agnostic and directly targets 'is there money on the table right now'."""
    self_bal = _u(_bsc_call(token, "0x70a08231" + token[2:].lower().rjust(64, "0")))   # balanceOf(token,token)
    supply   = _u(_bsc_call(token, "0x18160ddd"))                                        # totalSupply()
    if self_bal == 0: return False
    if supply == 0:   return self_bal > 0
    return self_bal * 1000 >= supply        # >= 0.1% of supply sitting in the contract

import re
WBNB_L = "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"
_SKIP_ADDR = {WBNB_L, "0x10ed43c718714eb63d5aa57b78b54704e256024e",      # WBNB, Pcake router
              "0x0000000000000000000000000000000000000000",
              "0x000000000000000000000000000000000000dead",
              "0x55d398326f99059ff775485246999027b3197955",              # USDT (common paired, not reward)
              "0xe9e7cea3dedca5984780bafc599bd69add087d56"}              # BUSD
def _kk4(sig):
    from Crypto.Hash import keccak as ck
    h = ck.new(digest_bits=256); h.update(sig.encode()); return "0x" + h.hexdigest()[:8]
def _call_addr(to, sig):
    """call a no-arg getter returning an address; works on UNVERIFIED bytecode too. None if revert/zero."""
    r = _bsc_call(to, _kk4(sig))
    if r and len(r) >= 66:
        a = "0x" + r[-40:].lower()
        if int(a, 16) != 0: return a
    return None
# getters the family exposes for its dividend/reward token (on the token AND on its distributor)
_RWD_GETTERS = ("RWRD()","rewardToken()","_rewardToken()","dividendToken()","reward()")
_DIST_GETTERS = ("distributor()","dividendDistributor()","_distributor()","dividendTracker()")

def reward_tokens(token_addr, pair, src_lower):
    """THE KEYSTONE: find the dividend/reward token so the sim can liquidate JIT-dividend profit
    ($SHIP class pays in a TOKEN, not BNB -> invisible without this). Two sources, merged:
      (a) on-chain GETTERS on the token + its distributor — works even for UNVERIFIED contracts
          (where source-literal scanning returns nothing, the old blind spot);
      (b) every address literal in the verified source (constructor-constant reward tokens).
    Shotgun-safe: the sim only sells tokens the attacker actually holds, so extra candidates are
    free (0-balance -> skipped)."""
    skip = set(_SKIP_ADDR); skip.add(token_addr.lower())
    if pair: skip.add(pair.lower())
    found = []
    def _add(a):
        if a and a not in skip and a not in found and len(a) == 42: found.append(a)
    # (a) on-chain getters — the verification-independent path that closes the unverified blind spot
    for g in _RWD_GETTERS: _add(_call_addr(token_addr, g))
    for dg in _DIST_GETTERS:
        d = _call_addr(token_addr, dg)
        if d:
            for g in _RWD_GETTERS + ("token()",): _add(_call_addr(d, g))
    # (b) verified-source address literals (boundary-aware: never a 40-hex slice of a 256-bit mask)
    if src_lower:
        for a in re.findall(r"(?<![a-f0-9])0x[a-f0-9]{40}(?![a-f0-9])", src_lower):
            body = a[2:]
            if body.count("f") >= 30 or body.count("0") >= 34: continue
            _add(a)
    return found[:10]   # cap to bound sim cost

BNB_USD = 600          # rough frozen numeraire for sizing the buy ladder to pool depth
def buy_sizes_for(liq_usd):
    """Liquidity-scaled buy ladder (plain-integer wei, comma-sep) — these drains are size-dependent,
    so we sweep fractions of the WBNB-side reserve. Capped to sane bounds."""
    wbnb_reserve = (liq_usd / 2.0) / BNB_USD          # WBNB tokens on the WBNB side
    fracs = [0.03, 0.10, 0.25, 0.60]
    sizes, seen = [], set()
    for f in fracs:
        w = max(0.03, min(50.0, wbnb_reserve * f))    # >=0.03 WBNB, <=50 WBNB
        wei = int(w * 1e18)
        if wei not in seen: seen.add(wei); sizes.append(wei)
    return ",".join(str(s) for s in sizes)

def _fetch_src(addr):
    """fetch verified source for a BSC token (Etherscan V2 free, multi-file aware)."""
    u = 'https://api.etherscan.io/v2/api?' + urllib.parse.urlencode(
        {'chainid': 56, 'module': 'contract', 'action': 'getsourcecode', 'address': addr, 'apikey': ESK})
    for _ in range(3):
        try:
            res = json.loads(urllib.request.urlopen(
                urllib.request.Request(u, headers={'User-Agent': 'M'}), timeout=20).read()).get('result')
            if isinstance(res, list) and res:
                s = res[0].get('SourceCode') or ''
                if s.startswith('{'):
                    j = json.loads(s[1:-1]) if s.startswith('{{') else json.loads(s)
                    srcs = j.get('sources', j)
                    s = '\n'.join(v.get('content', '') for v in srcs.values()) if isinstance(srcs, dict) else s
                return s
        except Exception:
            time.sleep(0.5)
    return ''

def detect_buy_gate(src):
    """Detect a BUY-side restriction (whitelist/allowlist/trading-flag on the buy path).
    A gated token cannot be permissionlessly BOUGHT, so an 'untradable' sim result is a
    BUY-GATE, not a clean/honeypot -> it must be routed to STATIC review, never silently cleared
    (the AIDC miss: AIDC gates buys to a whitelist, so the sim correctly couldn't trade it, but
    'untradable' read as a benign skip). Returns (gated:bool, reason:str)."""
    if not src:
        return (False, '')
    s = src
    # 1) require message explicitly about buying being restricted
    m = re.search(r'require\([^;]*?,\s*"([^"]*\b(?:can\s+buy|allowed?\s+to\s+buy|buy\s+(?:is\s+)?(?:not|disabled|restricted)|whitelist[^"]*buy|only[^"]*buy)[^"]*)"', s, re.I)
    if m:
        return (True, 'buy-gate require: "%s"' % m.group(1)[:70])
    # 2) whitelist/allowlist check guarding the from==pair (buy) branch
    for bm in re.finditer(r'(isFromPair|from\s*==\s*\w*[pP]air|_from\s*==\s*\w*[pP]air)', s):
        win = s[bm.start():bm.start() + 400]
        if re.search(r'require\([^;]*(whitelist|allowlist|isWhitelist|_isExcluded|authorized|canTrade|isAllowed)\b', win, re.I) and 'buy' in win.lower():
            return (True, 'whitelist gate on from==pair (buy) branch')
    # 3) trading-enabled flag, owner-gated (buys blocked until enabled)
    if re.search(r'require\([^;]*\b(tradingEnabled|tradingActive|tradingOpen|swapEnabled)\b[^;]*,\s*"[^"]*(trad|not open|not enabled|not started)', s, re.I):
        return (True, 'trading-enabled gate (buys blocked until owner enables)')
    return (False, '')

def sim(token, pair, liq_usd, reward_list=None, fork_block=None, rpc=None):
    """run the multi-size x MULTI-TRIGGER fork profit-sim; returns (verdict, profit_wei, best_buy_wei, raw_tail).
    fork_block: pin a historical block (for validating against a drained token at its pre-exploit state).
    rpc: override the BSC RPC endpoint (rotate free endpoints to dodge 429 rate-limits)."""
    env = dict(os.environ)
    env.update({"TOKEN": token, "PAIR": pair, "BSC_RPC": rpc or BSC_RPC,
                "REWARD_TOKENS": ",".join(reward_list or []),   # family pays dividends in a token, not BNB
                "PATH": os.path.dirname(FORGE) + os.pathsep + env.get("PATH", "")})
    if fork_block:
        env["FORK_BLOCK"] = str(fork_block)
    try:
        p = subprocess.run([FORGE, "test", "--match-path", "test/TaxTokenProfitSim.t.sol", "-vv"],
                           cwd=PROJECT, env=env, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return ("timeout", 0, 0, "")
    out = p.stdout + p.stderr
    profit, bsize = 0, 0
    for ln in out.splitlines():
        if "ATOMIC_PROFIT_wei" in ln:
            try: profit = int(ln.split(":")[-1].strip())
            except Exception: pass
        if "at_buy_size_wei" in ln:
            try: bsize = int(ln.split(":")[-1].strip())
            except Exception: pass
    if "ATOMIC_PROFIT:" in out:    return ("EXPLOITABLE", profit, bsize, out[-500:])
    if "UNTRADABLE" in out:
        # NOT a clean skip — disambiguate a BUY-GATE (whitelist/trading-flag) from a true honeypot.
        # A buy-gated token cannot be permissionlessly bought, so the dynamic sim is structurally
        # blind; it must be routed to STATIC review (run pair_burn_sync / arsenal), never cleared.
        gated, reason = detect_buy_gate(_fetch_src(token))
        if gated:                  return ("BUY-GATED", 0, 0, "needs static review: " + reason)
        return ("untradable", 0, 0, "")
    if "CLEAN:" in out:            return ("clean", 0, 0, "")
    return ("inconclusive", 0, 0, out[-300:])

def main():
    if not os.path.exists(FORGE):
        print(f"!! forge not found at {FORGE} — install/locate foundry first"); sys.exit(1)
    pools = fresh_bsc_pools()
    funded = {a: v for a, v in pools.items() if v[1] >= MIN_LIQ}
    print(f"# {time.strftime('%Y-%m-%d %H:%M')} | {len(pools)} fresh BSC pooled tokens, {len(funded)} with liq>=${MIN_LIQ}", flush=True)

    # pre-filter to the family (cheap) — keeps unverified (could be the exploitable ones) + family-marked source
    cands = []
    skipped_noreserve = 0
    for a, (pair, liq) in sorted(funded.items(), key=lambda x: -x[1][1]):
        nm, sc = source(a)
        if not sc:
            why = "unverified"                                  # can't inspect -> sim it (could be the exploitable one)
        elif looks_family(sc) and has_reserve(a):
            why = "family+reserve"                              # tax/dividend token currently holding a drainable reserve
        else:
            if sc and looks_family(sc): skipped_noreserve += 1  # family-shaped but no reserve on the table right now
            time.sleep(0.15); continue
        cands.append((a, pair, liq, nm or "?", why, reward_tokens(a, pair, sc)))
        time.sleep(0.2)
    cands = cands[:MAX_SIM]
    print(f"# {len(cands)} candidates to PROFIT-SIM (cap {MAX_SIM}); "
          f"{skipped_noreserve} family-shaped skipped (no reserve to drain now)\n", flush=True)

    alerts = []
    for a, pair, liq, nm, why, rtoks in cands:
        verdict, profit, bsize, tail = sim(a, pair, liq, rtoks)
        mark = "🚨" if verdict == "EXPLOITABLE" else "  "
        extra = f"  profit={profit/1e18:.4f} BNB @ buy {bsize/1e18:.2f} WBNB" if profit else ""
        print(f"{mark} {a} [{nm[:18]}] liq=${liq:,.0f} ({why}) -> {verdict}{extra}", flush=True)
        if verdict == "EXPLOITABLE":
            alerts.append({"addr": a, "pair": pair, "name": nm, "liq_usd": round(liq),
                           "profit_bnb": round(profit/1e18, 5), "best_buy_wbnb": round(bsize/1e18, 4),
                           "ts": int(time.time()), "tail": tail})

    prev = []
    if os.path.exists(ALERTS):
        try: prev = json.load(open(ALERTS))
        except Exception: pass
    seen = {x["addr"] for x in prev}
    new = [x for x in alerts if x["addr"] not in seen]
    json.dump(prev + new, open(ALERTS, "w"), indent=1)
    print(f"\n# {len(alerts)} EXPLOITABLE ({len(new)} NEW) -> {ALERTS}", flush=True)
    if not alerts:
        print("# clean window - no live atomically-profitable tax token right now (the honest base rate).", flush=True)
    else:
        print("# WHITE-HAT: warn the holders / report. Confirm the shrunk sequence before any disclosure.", flush=True)

if __name__ == "__main__":
    main()
