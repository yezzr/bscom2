#!/usr/bin/env python3
"""
sync_token_watch.py -- CONTINUOUS reserve-cliff monitor for the sync/skim-carrying token family
(the FH/CCC "burn-from-pair + sync" class, and any price-manip drain of a watched pool).

WHY THIS EXISTS (the FH/CCC miss, Aug 2026): bsc_pairwatch analyzes each token exactly ONCE, at its
PairCreated moment, and only above a liq floor. So a token seeded thin, dropped in a scan-lag, or
INCONCLUSIVE on an RPC blip -- then drained 7 days later -- is never seen. FH ($20k) and CCC ($117k)
both carried the sync() selector and would have flagged HIGH *if scanned*, but were never handed to
the detector. This lane fixes that: it WATCHES each sync/skim-carrying token CONTINUOUSLY and fires
on the reserve CLIFF at drain time, however long after launch. Pure public RPC (getLogs/getCode/
balanceOf) -- no Dune, no archive -- so it also backstops pool_drain_watch when Dune is down or a
drain syncs fewer times than that lane's threshold.

EACH RUN:
  1) DISCOVER  new PairCreated in [last_block, head]; add pairs whose non-base token carries
     sync()/skim() -> watchlist entry, baseline = current base reserve (USD).
  2) RE-CHECK  every watchlisted pair: read base reserve, track PEAK; if it has cliffed
     >= FRACTION below peak AND peak >= MIN_POOL_USD -> DRAIN alert (once), mark drained.
  3) PRUNE     entries older than MAX_AGE_DAYS whose pool stayed trivial (never worth watching).

Env (NO secrets in file): TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, SW_MIN_POOL_USD (default 15000),
  SW_FRACTION (0.35), SW_MAX_AGE_DAYS (30), SW_RANGE_BLOCKS (12000 ~= 90 min), SW_RPC (comma list).
State: sync_watchlist.json next to this file (commit it back in CI for persistence).
Modes:  (default) discover+recheck   |   --selftest (offline logic test, no network)
"""
import os, sys, json, time, urllib.request

HERE      = os.path.dirname(os.path.abspath(__file__))
STATE     = os.environ.get("SW_STATE") or os.path.join(HERE, "sync_watchlist.json")
# PRIMARY discovery: pairwatch appends sync/skim carriers here. In CI point SW_SEED at the restored
# pairwatch cache (pwstate/sync_watchlist_seed.jsonl); locally the default shared dir just works.
SEED      = os.environ.get("SW_SEED") or os.path.join(HERE, "sync_watchlist_seed.jsonl")
TG_TOKEN  = os.environ.get("TELEGRAM_BOT_TOKEN")
TG_CHAT   = os.environ.get("TELEGRAM_CHAT_ID")
MIN_POOL  = float(os.environ.get("SW_MIN_POOL_USD", "15000"))   # only alert on pools that were worth draining
FRACTION  = float(os.environ.get("SW_FRACTION", "0.35"))        # cliff = lost >= this fraction of the PEAK reserve
MAX_AGE   = int(os.environ.get("SW_MAX_AGE_DAYS", "30"))
RANGE_BLK = int(os.environ.get("SW_RANGE_BLOCKS", "12000"))     # discovery lookback if no saved last_block
RPCS      = [u for u in (os.environ.get("SW_RPC") or "").split(",") if u] or [
    "https://bsc-dataseed.bnbchain.org", "https://bsc-rpc.publicnode.com",
    "https://bsc.drpc.org", "https://bsc-dataseed1.defibit.io"]

SYNC_SEL, SKIM_SEL = "fff6cae9", "bc25cf77"
PAIRCREATED = "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9"
FACTORIES = None  # no allowlist -- we accept any PairCreated, then gate by the token's own bytecode
BASES = {  # base token -> (symbol, usd price). ALL verified 18-decimal on BSC (reserve read divides by 1e18).
  "0x55d398326f99059ff775485246999027b3197955": ("USDT", 1.0),
  "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": ("WBNB", 900.0),
  "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": ("USDC", 1.0),
  "0xe9e7cea3dedca5984780bafc599bd69add087d56": ("BUSD", 1.0),
  "0x2170ed0880ac9a755fd29b2688956bd959f933f8": ("ETH", 3000.0),
  "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c": ("BTCB", 95000.0),
  "0x0782b6d8c4551b9760e74c0545a9bcd90bdc41e5": ("lisUSD", 1.0),  # Lista USD (FOX-class quote)
  "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409": ("FDUSD", 1.0),
  "0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3": ("DAI", 1.0),
  "0x14016e85a25aeb13065688cafb43044c2ef86784": ("TUSD", 1.0),
  "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d": ("USD1", 1.0),
  "0x90c97f71e18723b0cf0dfa30ee176ab653e89f40": ("FRAX", 1.0),
}

# ---- RPC (round-robin, fault-tolerant) ---------------------------------------------------------
_ri = [0]
def rpc(method, params, _rpcs=None):
    nodes = _rpcs or RPCS
    b = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for _ in range(len(nodes) * 2):
        u = nodes[_ri[0] % len(nodes)]; _ri[0] += 1
        try:
            r = json.loads(urllib.request.urlopen(urllib.request.Request(
                u, b, {"Content-Type": "application/json", "User-Agent": "M"}), timeout=12).read())
            if r.get("result") is not None: return r["result"]
        except Exception: continue
    return None

def head_block():
    r = rpc("eth_blockNumber", []); return int(r, 16) if r else None

def get_code(addr):
    r = rpc("eth_getCode", [addr, "latest"]); return r or ""

def token_of_pair(pair, sel):  # 0x0dfe1681 token0 / 0xd21220a7 token1
    r = rpc("eth_call", [{"to": pair, "data": sel}, "latest"])
    return ("0x" + r[-40:]).lower() if r and len(r) >= 42 else None

def sym(addr):
    r = rpc("eth_call", [{"to": addr, "data": "0x95d89b41"}, "latest"])
    if not r or len(r) < 130: return addr[:10]
    try: return bytes.fromhex(r[130:130+int(r[66:130],16)*2]).decode("utf8", "replace")
    except Exception: return addr[:10]

def base_reserve_usd(pair, base):
    """USD value of the BASE token held by the pair right now (pure balanceOf, no archive)."""
    r = rpc("eth_call", [{"to": base, "data": "0x70a08231" + pair[2:].rjust(64, "0")}, "latest"])
    if not r or r == "0x": return None
    return int(r, 16) / 1e18 * BASES[base][1]

# ---- pure, testable cliff logic --------------------------------------------------------------
def evaluate(entry, current_usd):
    """Update peak; decide DRAIN vs OK. Returns (verdict, entry). Pure -- unit-tested offline.
       DRAIN when the pool that once held >= MIN_POOL has now lost >= FRACTION of its PEAK."""
    peak = max(entry.get("peak_usd", 0.0), current_usd)
    entry["peak_usd"] = peak
    entry["last_usd"] = current_usd
    if entry.get("drained"):                      # already alerted -> stay quiet
        return "OK", entry
    if peak >= MIN_POOL and current_usd <= peak * (1.0 - FRACTION):
        entry["drained"] = True
        entry["loss_usd"] = peak - current_usd
        return "DRAIN", entry
    return "OK", entry

# ---- state -----------------------------------------------------------------------------------
def load():
    if os.path.exists(STATE):
        try: return json.load(open(STATE))
        except Exception: pass
    return {"last_block": 0, "watch": {}}     # watch: pair(lower) -> entry

def save(st): json.dump(st, open(STATE, "w"), indent=0)

def tg(msg):
    if not (TG_TOKEN and TG_CHAT):
        print("[no telegram -> stdout]\n" + msg); return
    import urllib.parse
    data = urllib.parse.urlencode({"chat_id": TG_CHAT, "text": msg, "parse_mode": "HTML",
                                   "disable_web_page_preview": "true"}).encode()
    try: urllib.request.urlopen(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage", data=data, timeout=15)
    except Exception as e: print("TG send failed:", e); print(msg)

# ---- discovery: PRIMARY = seed file from pairwatch (reuses its working drpc-backed discovery) ----
def ingest_seed(st):
    """Idempotent: read pairwatch's appended sync/skim carriers, add any pair we're not already watching.
       Reuses pairwatch's discovery (which fights the getLogs wall with a drpc pool) instead of duplicating it,
       AND fixes pairwatch's one-shot flaw -- once here, the pair is re-checked forever, past PENDING_TTL."""
    if not os.path.exists(SEED): return 0
    try: lines = open(SEED).read().splitlines()
    except Exception: return 0
    added = 0
    for ln in lines[-8000:]:                 # bound work; dedup is by st['watch'] so re-reading is harmless
        try: rec = json.loads(ln)
        except Exception: continue
        pair = (rec.get("pair") or "").lower(); tok = (rec.get("token") or "").lower()
        if not pair or pair in st["watch"]: continue
        t0 = token_of_pair(pair, "0x0dfe1681"); t1 = token_of_pair(pair, "0xd21220a7")
        base = t0 if t0 in BASES else (t1 if t1 in BASES else None)
        if not base: continue
        res = base_reserve_usd(pair, base) or 0.0
        st["watch"][pair] = {"token": tok, "base": base, "sym": sym(tok) if tok else pair[:10],
                             "peak_usd": res, "last_usd": res, "added": int(time.time()),
                             "sync_only": True, "flag": rec.get("flag"), "drained": False}
        added += 1
    return added

# ---- discovery: OPTIONAL supplement, only if a getLogs-capable node is provided (free nodes cap PairCreated) ----
def discover(st, head):
    frm = st["last_block"] + 1 if st["last_block"] else max(1, head - RANGE_BLK)
    added = 0; b = frm
    while b <= head:
        e = min(b + 2000, head)   # drpc getLogs cap
        logs = rpc("eth_getLogs", [{"fromBlock": hex(b), "toBlock": hex(e), "topics": [PAIRCREATED]}],
                   _rpcs=[os.environ["SW_LOG_RPC"]])
        if logs is None:
            print(f"  getLogs {b}-{e} failed; committing through {b-1}", flush=True)
            st["last_block"] = b - 1; return added
        for lg in logs:
            # PairCreated(token0 indexed, token1 indexed, pair, ...) -> pair is first word of data
            data = lg.get("data", "0x")
            if len(data) < 66: continue
            pair = ("0x" + data[2:66][-40:]).lower()
            if pair in st["watch"]: continue
            t0 = token_of_pair(pair, "0x0dfe1681"); t1 = token_of_pair(pair, "0xd21220a7")
            if not t0 or not t1: continue
            base = t0 if t0 in BASES else (t1 if t1 in BASES else None)
            if not base: continue
            other = t1 if base == t0 else t0
            code = get_code(other)
            if not code or not (SYNC_SEL in code or SKIM_SEL in code):
                continue                                   # not the sync/skim family -> ignore
            has_burn_sel = any(s in code for s in ("42966c68","9dc29fac","89afcb44","b1faeac6","6b2fb3a3"))
            res = base_reserve_usd(pair, base) or 0.0
            st["watch"][pair] = {"token": other, "base": base, "sym": sym(other),
                                 "peak_usd": res, "last_usd": res, "added": int(time.time()),
                                 "sync_only": not has_burn_sel, "drained": False}
            added += 1
        b = e + 1
    st["last_block"] = head
    return added

def recheck(st):
    now = int(time.time()); drained = 0; dropped = 0
    for pair, e in list(st["watch"].items()):
        cur = base_reserve_usd(pair, e["base"])
        if cur is None: continue                            # RPC blip -> leave untouched, retry next run
        verdict, e = evaluate(e, cur)
        if verdict == "DRAIN":
            drained += 1
            bs = BASES[e["base"]][0]
            tag = "sync-only (pairwatch-blind)" if e.get("sync_only") else "sync+burn"
            tg(f"🚨 <b>WATCHLIST DRAIN</b> ~${int(e['loss_usd']):,} {bs} "
               f"({int(100*(1-e['last_usd']/max(e['peak_usd'],1)))}% of peak)\n"
               f"token: <b>{e['sym']}</b>  [{tag}]\n"
               f"pool: <code>{pair}</code>  (${int(e['peak_usd']):,} peak → ${int(e['last_usd']):,})\n"
               f"token: https://bscscan.com/token/{e['token']}\n"
               f"(reserve-cliff on a continuously-watched sync/skim token)")
        # prune long-dead trivial entries
        if (now - e.get("added", now) > MAX_AGE * 86400) and e.get("peak_usd", 0) < MIN_POOL and not e.get("drained"):
            del st["watch"][pair]; dropped += 1
    return drained, dropped

def main():
    if "--selftest" in sys.argv: return selftest()
    st = load()
    seeded = ingest_seed(st)                       # PRIMARY: pairwatch's carriers (reliable)
    added = 0
    if os.environ.get("SW_LOG_RPC"):               # OPTIONAL: own getLogs discovery, only with a capable node
        head = head_block()
        if head: added = discover(st, head)
    drained, dropped = recheck(st)                 # the reliable half: balanceOf cliff on every watched pool
    save(st)
    print(f"sync_token_watch: watching {len(st['watch'])} pools | +{seeded} seeded +{added} scanned | "
          f"{drained} DRAINS | pruned {dropped}")

# ---- offline self-test (no network) ---------------------------------------------------------
def selftest():
    ok = True
    # 1) a pool that grows to $40k then loses 50% -> DRAIN
    e = {"peak_usd": 0, "drained": False}
    for r in (5000, 20000, 40000):        # growth: no alert
        v, e = evaluate(e, r); ok &= (v == "OK")
    v, e = evaluate(e, 18000)             # 40k -> 18k = -55% >= 35% -> DRAIN
    ok &= (v == "DRAIN"); print("  grow-then-cliff:", v, "peak", e["peak_usd"], "loss", e.get("loss_usd"))
    # 2) never alert twice
    v, e = evaluate(e, 100); ok &= (v == "OK"); print("  no-double-alert:", v)
    # 3) a thin pool ($8k) that empties -> NO alert (below MIN_POOL, not worth it)
    e2 = {"peak_usd": 0, "drained": False}
    v, e2 = evaluate(e2, 8000); v, e2 = evaluate(e2, 100)
    ok &= (v == "OK"); print("  thin-pool-ignored:", v, "(peak", e2["peak_usd"], "< MIN_POOL", MIN_POOL, ")")
    # 4) a normal -10% dip -> NO alert
    e3 = {"peak_usd": 0, "drained": False}
    v, e3 = evaluate(e3, 50000); v, e3 = evaluate(e3, 45000)
    ok &= (v == "OK"); print("  normal-dip-ok:", v)
    print("SELFTEST:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
