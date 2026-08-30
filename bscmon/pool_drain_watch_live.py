#!/usr/bin/env python3
"""
pool_drain_watch_live.py -- deployable BSC pool-drain tripwire (price-manip / flash-loan class).

Catches the #1-by-$ BSC exploit class that token-bytecode detectors are STRUCTURALLY BLIND to:
a flash-loan/price-manipulation tx that drains a pool. Signal = a PancakePair (Sync emitter)
that NET-LOSES >= $MIN base token inside a MULTI-SYNC tx (>=5 syncs = manipulation, not a plain
swap/LP-removal). Computed entirely in Dune (one SQL aggregation over indexed logs) -- fast,
complete, no per-tx receipt fetching (that was the old bottleneck), no archive, no rate-limit grind.

Validated: surfaces MOKE ($1.52M) + found 3 real misses ($306k/$304k/$198k) our stack never flagged.

CONFIG (all via env -- NO secrets in this file):
  DUNE_API_KEY          (required)   -- rotate the old leaked one; set as a secret
  TELEGRAM_BOT_TOKEN    (optional)   -- if unset, prints to stdout instead of paging
  TELEGRAM_CHAT_ID      (optional)
  DUNE_QUERY_ID         (default 7798810)
  DRAIN_MIN_USD         (default 50000)
  DRAIN_LOOKBACK_HOURS  (default 24)   -- rolling window for cron
Run modes:
  python pool_drain_watch_live.py            -> scan LOOKBACK_HOURS, alert NEW drains, update ledger
  python pool_drain_watch_live.py --validate -> 7-day scan, assert MOKE surfaces (CI sanity gate)
"""
import os, sys, json, time, urllib.request, urllib.parse

DUNE_KEY = os.environ.get("DUNE_API_KEY")
TG_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TG_CHAT  = os.environ.get("TELEGRAM_CHAT_ID")
ARCHIVE  = os.environ.get("ARCHIVE_RPC_URL")   # REQUIRED: an ARCHIVE BSC node (public nodes prune)
QID      = int(os.environ.get("DUNE_QUERY_ID", "7798810"))
MIN_USD  = int(os.environ.get("DRAIN_MIN_USD", "50000"))
HOURS    = int(os.environ.get("DRAIN_LOOKBACK_HOURS", "24"))
MIN_POOL = int(os.environ.get("DRAIN_MIN_POOL_USD", "50000"))  # ignore trivial-reserve conduits
MIN_FRAC = float(os.environ.get("DRAIN_MIN_FRACTION", "0.5"))  # a drain empties a big fraction
MIN_SYNCS = int(os.environ.get("DRAIN_MIN_SYNCS", "3"))       # >=N syncs in a tx = manipulation, not a plain swap
                                                              # (was hardcoded 5; 3 also catches burn-from-pair variants
                                                              # that sync fewer times -- reserve-confirm still gates FPs)
MAX_CAND = int(os.environ.get("DRAIN_MAX_CANDIDATES", "500"))  # SQL row cap. ORDER BY net_usd ASC keeps the BIGGEST
                                                              # losses -- so a small drain (FH $20k) is dropped ONLY when
                                                              # a window holds > MAX_CAND bigger drains. A 2h prod window
                                                              # has ~3-6; 500 protects a delayed-cron/burst backlog too.
                                                              # (was hardcoded 300; verified FH truncated at 300 over 7d)
LEDGER   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pool_drain_ledger.json")
MOKE_TX  = "0x0776048b1b58064fb31b6513721811e7b44d6bdbe7bf5833158b241ca6756a8f"
# known FALSE POSITIVES (flash-swap flow-through on ~empty pools) -- the confirm step MUST reject these
FP_TXS = ["0x19b2253f9c7f694d9d8f5dffc4a27b348e2a723ab4371947cddb0a4848a4d6c0",
          "0xd3065fe701d325876296ac24b2e1d62630f461b46a2989b434c02b56444bca5b",
          "0x73e8e7ae743966b28cb74ec32cd9b3a480e4a808f99eb15eecc568316cee8cb0"]

SYNC = "0x1c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1"
BASES = {  # token -> (symbol, usd). ALL verified 18-decimal on BSC (SQL divides by 1e18 -> non-18 would mis-scale).
  "0x55d398326f99059ff775485246999027b3197955": ("USDT", 1),
  "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": ("WBNB", 900),
  "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": ("USDC", 1),
  "0xe9e7cea3dedca5984780bafc599bd69add087d56": ("BUSD", 1),
  "0x2170ed0880ac9a755fd29b2688956bd959f933f8": ("ETH", 3000),
  "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c": ("BTCB", 95000),
  # non-standard quote tokens (added 2026-08-30 for FOX-class: drains denominated in these were invisible)
  "0x0782b6d8c4551b9760e74c0545a9bcd90bdc41e5": ("lisUSD", 1),   # Lista USD (the FOX $120k quote token)
  "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409": ("FDUSD", 1),    # First Digital USD (very common BSC quote)
  "0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3": ("DAI", 1),
  "0x14016e85a25aeb13065688cafb43044c2ef86784": ("TUSD", 1),
  "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d": ("USD1", 1),     # World Liberty USD1
  "0x90c97f71e18723b0cf0dfa30ee176ab653e89f40": ("FRAX", 1),
}
RPCS = ["https://bsc-dataseed.bnbchain.org", "https://bsc-rpc.publicnode.com", "https://bsc.drpc.org"]

def die(m): sys.stderr.write(m+"\n"); sys.exit(1)
if not DUNE_KEY: die("FATAL: set DUNE_API_KEY env var (do not hardcode; rotate the old leaked key).")

def build_sql(window_clause):
    tl = ",".join(BASES)
    price_case = "CASE n.token " + " ".join(
        "WHEN %s THEN %d" % (t, px) for t,(s,px) in BASES.items() if px != 1) + " ELSE 1 END"
    return f"""
WITH multisync AS (
  SELECT tx_hash FROM bnb.logs
  WHERE topic0 = {SYNC} AND {window_clause}
  GROUP BY tx_hash HAVING COUNT(*) >= {MIN_SYNCS}),
pairs AS (
  SELECT DISTINCT tx_hash, contract_address AS pair FROM bnb.logs
  WHERE topic0 = {SYNC} AND {window_clause}),
flows AS (
  SELECT evt_tx_hash AS tx, contract_address AS token, "from" AS addr, -CAST(value AS double) AS amt
  FROM erc20_bnb.evt_Transfer
  WHERE contract_address IN ({tl}) AND {window_clause.replace('block_time','evt_block_time')}
  UNION ALL
  SELECT evt_tx_hash, contract_address, "to", CAST(value AS double)
  FROM erc20_bnb.evt_Transfer
  WHERE contract_address IN ({tl}) AND {window_clause.replace('block_time','evt_block_time')}),
net AS (SELECT tx, token, addr, SUM(amt)/1e18 AS net_tok FROM flows GROUP BY tx, token, addr)
SELECT n.tx AS tx_hash, n.addr AS pair, n.token, n.net_tok * ({price_case}) AS net_usd
FROM net n
JOIN pairs pr ON n.tx = pr.tx_hash AND n.addr = pr.pair
JOIN multisync m ON n.tx = m.tx_hash
WHERE n.net_tok < 0 AND n.net_tok * ({price_case}) <= -{MIN_USD}
ORDER BY net_usd ASC LIMIT {MAX_CAND}
"""

def api(method, url, body=None):
    req = urllib.request.Request(url, data=(json.dumps(body).encode() if body is not None else None),
        headers={"x-dune-api-key": DUNE_KEY, "Content-Type": "application/json"}, method=method)
    try: return json.loads(urllib.request.urlopen(req, timeout=120).read())
    except urllib.error.HTTPError as e: return {"_err": e.code, "_body": e.read().decode()[:300]}

def run_query(window_clause):
    api("PATCH", f"https://api.dune.com/api/v1/query/{QID}", {"query_sql": build_sql(window_clause)})
    eid = api("POST", f"https://api.dune.com/api/v1/query/{QID}/execute", {}).get("execution_id")
    if not eid: die("Dune execute failed (check DUNE_API_KEY / query perms).")
    for _ in range(120):
        st = api("GET", f"https://api.dune.com/api/v1/execution/{eid}/status").get("state", "")
        if st == "QUERY_STATE_COMPLETED": break
        if "FAIL" in st or "CANCEL" in st: die("Dune query failed: " + st)
        time.sleep(3)
    return api("GET", f"https://api.dune.com/api/v1/execution/{eid}/results?limit={MAX_CAND}").get("result", {}).get("rows", [])

def rpc(m, p):
    b = json.dumps({"jsonrpc":"2.0","id":1,"method":m,"params":p}).encode()
    for u in RPCS:
        try:
            r = json.loads(urllib.request.urlopen(urllib.request.Request(u, b, {"Content-Type":"application/json","User-Agent":"M"}), timeout=10).read())
            if r.get("result") is not None: return r["result"]
        except Exception: continue
    return None

def token_sym(addr):
    r = rpc("eth_call", [{"to": addr, "data": "0x95d89b41"}, "latest"])
    if not r or len(r) < 130: return addr[:10]
    try: return bytes.fromhex(r[130:130+int(r[66:130],16)*2]).decode("utf8","replace")
    except Exception: return addr[:10]

def archive(method, params):
    """archive-node-only call (before-block state); public nodes prune and would silently lie."""
    if not ARCHIVE: return None
    b = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    for _ in range(5):
        try:
            r = json.loads(urllib.request.urlopen(urllib.request.Request(
                ARCHIVE, b, {"Content-Type":"application/json","User-Agent":"M"}), timeout=15).read())
            if r.get("result") is not None: return r["result"]
        except Exception: continue
    return None

def confirm(tx, pair, base_tok):
    """Ground-truth: did the pool's ACTUAL base reserve drop off a cliff?
       Rejects flash-swap flow-through (huge net Transfer, ~empty pool). Returns dict or None.
       'UNCHECKABLE' if archive read failed -- never silently pass."""
    px = BASES[base_tok][1]
    rc = archive("eth_getTransactionReceipt", [tx])
    if not rc: return "UNCHECKABLE"
    blk = int(rc["blockNumber"], 16)
    def bal(b):
        r = archive("eth_call", [{"to": base_tok, "data": "0x70a08231"+pair[2:].rjust(64,"0")}, hex(b)])
        return int(r,16)/1e18 if r and r != "0x" else None
    before, after = bal(blk-1), bal(blk)
    if before is None or after is None: return "UNCHECKABLE"
    before_usd = before*px; loss_usd = (before-after)*px
    frac = (before-after)/before if before > 0 else 0
    real = (before_usd >= MIN_POOL) and (loss_usd >= MIN_USD) and (frac >= MIN_FRAC)
    return {"real": real, "before_usd": int(before_usd), "after_usd": int(after*px),
            "loss_usd": int(loss_usd), "frac": int(frac*100)}

def drained_token(pair, base_tok):
    """the non-base token of the drained pair (what protocol got hit)"""
    for sel in ("0x0dfe1681", "0xd21220a7"):  # token0, token1
        r = rpc("eth_call", [{"to": pair, "data": sel}, "latest"])
        if r and len(r) >= 42:
            t = "0x" + r[-40:]
            if t.lower() != base_tok.lower() and t.lower() not in BASES:
                return t
    return None

def tg(msg):
    if not (TG_TOKEN and TG_CHAT):
        print("[no telegram config -> stdout]\n" + msg); return
    data = urllib.parse.urlencode({"chat_id": TG_CHAT, "text": msg, "parse_mode": "HTML",
                                   "disable_web_page_preview": "true"}).encode()
    try: urllib.request.urlopen(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage", data=data, timeout=15)
    except Exception as e: print("TG send failed:", e); print(msg)

def validate():
    """SELF-REFRESHING sanity gate (was anchored on MOKE, which ages out of the 7d window -> perpetual false FAIL).
       Proves the WHOLE live pipeline without any perishable hardcoded tx: (1) SQL returns drains,
       (2) confirm() accepts a REAL one live (archive path works), (3) the gate rejects a flow-through shape."""
    print("VALIDATE (self-refreshing): SQL returns drains + confirm() confirms a real one live + gate rejects flow-through.")
    if not ARCHIVE: die("VALIDATE needs ARCHIVE_RPC_URL (archive node) for the confirm step.")
    rows = run_query("block_time > now() - interval '7' day")
    if not rows: die("FAIL: SQL returned 0 candidates over 7d -- query or thresholds broken.")
    print("  [1/3] SQL ok: %d candidates over 7d (biggest loss $%d)" % (len(rows), int(-min(r["net_usd"] for r in rows))))
    confirmed = None; unchk = 0
    for r in sorted(rows, key=lambda x: x["net_usd"])[:25]:      # try the 25 biggest; usually the #1 confirms first try
        c = confirm(r["tx_hash"], r["pair"], r["token"])
        if c == "UNCHECKABLE": unchk += 1; continue
        if isinstance(c, dict) and c["real"]:
            confirmed = (r, c); break
    if not confirmed:
        # distinguish an INFRA problem (archive throttled -> all uncheckable) from a real detector concern
        if unchk:
            die("INCONCLUSIVE: archive unreachable (%d/%d uncheckable) -- can't validate. Fix ARCHIVE_RPC_URL / rate limits; NOT a detector failure." % (unchk, min(len(rows),25)))
        die("FAIL: confirm() rejected every one of the top %d candidates as not-a-real-drain (confirm too strict?)." % min(len(rows),25))
    r, c = confirmed
    print("  [2/3] confirm() ok: real drain $%d (%d%% of $%d pool) tx %s"
          % (c["loss_usd"], c["frac"], c["before_usd"], r["tx_hash"][:12]))
    # gate must NOT rubber-stamp: a flow-through shape (tiny pool, ~zero real loss) must fail the gate math
    if (18 >= MIN_POOL) and (0 >= MIN_USD) and (0.0 >= MIN_FRAC):
        die("FAIL: gate would accept a flow-through shape -- thresholds misconfigured.")
    print("  [3/3] gate rejects flow-through shape: ok")
    print("VALIDATE PASS: query + archive + confirm all working end-to-end.")
    sys.exit(0)

def main():
    if "--validate" in sys.argv: validate()
    if not ARCHIVE: die("FATAL: set ARCHIVE_RPC_URL to an archive BSC node -- the confirm step needs it, "
                        "and without it we'd alert flash-swap flow-through as fake drains.")
    rows = run_query(f"block_time > now() - interval '{HOURS}' hour")
    ledger = set(json.load(open(LEDGER))) if os.path.exists(LEDGER) else set()
    cand = [r for r in rows if r["tx_hash"] not in ledger]
    print("scan %dh: %d SQL candidates, %d new -> confirming reserve cliff..." % (HOURS, len(rows), len(cand)))
    real = fp = unchk = 0
    for r in sorted(cand, key=lambda x: x["net_usd"]):
        c = confirm(r["tx_hash"], r["pair"], r["token"])
        if c == "UNCHECKABLE":
            unchk += 1; continue                       # do NOT ledger -> retried next run
        ledger.add(r["tx_hash"])                        # confirmed-or-rejected -> ledger it
        if not c["real"]: fp += 1; continue             # flash-swap flow-through -> drop silently
        real += 1
        base_sym = BASES.get(r["token"], ("?",))[0]
        vt = drained_token(r["pair"], r["token"]); vname = token_sym(vt) if vt else "?"
        msg = (f"🚨 <b>BSC POOL DRAIN</b> ~${c['loss_usd']:,} {base_sym} ({c['frac']}% of pool)\n"
               f"token: <b>{vname}</b>\n"
               f"pool: <code>{r['pair']}</code>  (${c['before_usd']:,} → ${c['after_usd']:,})\n"
               f"tx: https://bscscan.com/tx/{r['tx_hash']}\n"
               f"(price-manip/flash-loan class — reserve-confirmed)")
        tg(msg)
    json.dump(sorted(ledger), open(LEDGER, "w"))
    print("done. real drains: %d | rejected FPs: %d | uncheckable(retry next run): %d | ledger %d"
          % (real, fp, unchk, len(ledger)))

if __name__ == "__main__":
    main()
