#!/usr/bin/env python3
"""
pool_drain_watch.py — the EFFECT-BASED drain watcher (the RWT gap).

WHY: every other detector here is a PATTERN matcher on the TOKEN (pair-burn-sync bytecode, honeypot source, etc.).
That whole approach is blind to the #1 BSC exploit class by dollars: economic / PRICE-MANIPULATION drains, where
a flash-loan skews a pool and an attacker exploits a price-dependent function in a SEPARATE (often unverified,
proxied) staking/reward/LP contract. The token is innocent; there is no token-code tell. RWT ($118K, 2026-07-19)
was exactly this — our arsenal flagged NOTHING, and the vulnerable contract was an unverified proxy.

THE FIX: don't try to understand arbitrary protocol logic — watch the EFFECT. Snapshot the base-asset reserve
(USDT/WBNB/BUSD/USDC) of funded pools each pass; if a pool loses a large fraction in one interval, alert. This is
mechanism-agnostic (catches price-manip AND pair-burn-sync AND classes we've never seen) and age-agnostic
(catches ESTABLISHED tokens, which the fresh-deploy monitors never watch — RWT was 4 days old).

HONEST LIMITS baked in:
 - POST-HOC, not pre-drain. Price-manip exploits are atomic (one tx, no setup) -> there is no pre-signal to catch.
   This detects the drop within one poll cycle (minutes) so you can warn holders/others and respond fast.
 - It only sees pools it WATCHES -> we watch every pool above a liquidity floor that we can source.
 - A big legit LP removal / owner rug also looks like a drop -> this is a REVIEW/WARN signal with the %/$ so you
   triage, not a proven exploit. A 99.9% single-interval drop (RWT) is a very strong signal; tune DROP_PCT.

Deploy like the others: GitHub Actions cron + actions/cache state + Telegram. Free.
"""
import json, os, time, urllib.request

HOME = os.environ.get("PDW_HOME") or os.path.dirname(os.path.abspath(__file__))
os.makedirs(HOME, exist_ok=True)
STATE = os.path.join(HOME, "pool_drain_state.json")
ALERTS = os.path.join(HOME, "pool_drain_alerts.json")

MIN_WATCH_USD = float(os.environ.get("PDW_MIN_WATCH_USD") or 20000)   # only watch pools worth draining
DROP_PCT      = float(os.environ.get("PDW_DROP_PCT") or 40)           # alert if base reserve falls this % in 1 interval
MAX_WATCH     = int(os.environ.get("PDW_MAX_WATCH") or 4000)          # cap the watchlist (state size / RPC budget)

RPCS = [os.environ.get("BSC_RPC") or "https://bsc-dataseed.bnbchain.org",
        "https://bsc-rpc.publicnode.com", "https://bsc.drpc.org", "https://1rpc.io/bnb"]

# base assets a pool holds -> (usd_per_token, decimals). A drain shows up as the BASE side leaving the pool.
BASES = {
    "0x55d398326f99059ff775485246999027b3197955": (1.0, 18),   # USDT
    "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": (1.0, 18),   # USDC
    "0xe9e7cea3dedca5984780bafc599bd69add087d56": (1.0, 18),   # BUSD
    "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": (None, 18),  # WBNB (None -> live BNB price)
}
_BNB = [600.0]

def notify(text):
    tok, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if tok and chat:
        try:
            data = urllib.parse.urlencode({"chat_id": chat, "text": text, "disable_web_page_preview": "true"}).encode()
            urllib.request.urlopen(urllib.request.Request("https://api.telegram.org/bot%s/sendMessage" % tok, data), timeout=15)
        except Exception:
            pass
    wh = os.environ.get("DISCORD_WEBHOOK")
    if wh:
        try:
            urllib.request.urlopen(urllib.request.Request(wh, json.dumps({"content": text}).encode(),
                                   {"Content-Type": "application/json"}), timeout=15)
        except Exception:
            pass

import urllib.parse  # noqa: E402 (used by notify)

def jget(url):
    for _ in range(3):
        try:
            return json.loads(urllib.request.urlopen(urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}), timeout=25).read())
        except Exception:
            time.sleep(0.6)
    return {}

def _rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for u in RPCS:
        try:
            r = json.loads(urllib.request.urlopen(urllib.request.Request(
                u, body, {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}), timeout=15).read())
            if "result" in r and r["result"] is not None:
                return r["result"]
        except Exception:
            continue
    return None

# --- DRAIN-TX IDENTIFICATION -----------------------------------------------------------------------------------
# An alert saying "pool X lost 90%" still leaves you hunting the tx by hand — the slow step. On a drop we scan the
# BASE token's Transfer-OUT-of-the-pool logs across the interval and return the LARGEST one: that is the drain tx,
# and its recipient is the attacker's contract/EOA. That single tx is what `cast run` needs to NAME the bug and what
# a Dune bytecode/selector dedupe needs to find siblings. VALIDATED against ground truth: on FCOW's pool it returns
# exactly 0x78a6463e...c601 at block 110,415,810 (the drain we independently fork-replayed) + attacker 0x772744c4.
# NOTE the returned amount is GROSS flow (a flash-loan drain moves borrow+repay through the pool), not net victim loss.
_LOG_RPCS = ["https://bsc.rpc.blxrbdn.com", "https://bnb.api.onfinality.io/public", "https://0.48.club",
             "https://rpc-bsc.48.club", "https://bsc.drpc.org"]   # the 4 measured wide-getLogs providers + drpc
_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
_TX_CHUNK = 2000                 # wide-getLogs cap on the reliable nodes
_TX_MAX_SPAN = 30000             # never scan more than this on one alert (bounds a post-outage catch-up)

def _find_drain_tx(pool, base, frm, to):
    """Largest BASE outflow from `pool` in [frm,to] -> (tx, attacker, amount_raw, block) or None. Best-effort:
    any RPC failure just yields None so the alert still fires (never let enrichment block the warning)."""
    if not base or frm is None or to is None or to < frm:
        return None
    frm = max(frm, to - _TX_MAX_SPAN)
    topic_pool = "0x" + "0" * 24 + pool[2:].lower()
    best = None
    b = frm
    while b <= to:
        e = min(b + _TX_CHUNK - 1, to)
        logs = None
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getLogs",
                           "params": [{"address": base, "topics": [_TRANSFER_TOPIC, topic_pool],
                                       "fromBlock": hex(b), "toBlock": hex(e)}]}).encode()
        for u in _LOG_RPCS:
            try:
                r = json.loads(urllib.request.urlopen(urllib.request.Request(
                    u, body, {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}), timeout=20).read())
                if r.get("result") is not None:
                    logs = r["result"]
                    break
            except Exception:
                continue
        for lg in (logs or []):
            try:
                v = int(lg["data"], 16)
            except Exception:
                continue
            if best is None or v > best[2]:
                best = (lg["transactionHash"], "0x" + lg["topics"][2][-40:], v, int(lg["blockNumber"], 16))
        b = e + 1
    return best

def bnb_usd():
    d = jget("https://api.coingecko.com/api/v3/simple/price?ids=binancecoin&vs_currencies=usd")
    try:
        _BNB[0] = float(d["binancecoin"]["usd"])
    except Exception:
        pass
    return _BNB[0]

import urllib.parse as _up  # noqa
from eth_utils import keccak as _kk
_PAIRCREATED = "0x" + _kk(text="PairCreated(address,address,address,uint256)").hex()
_ENUM_CHUNK = 2000                                  # drpc getLogs cap
def _base_topic(b):
    return "0x" + "0" * 24 + b[2:].lower()

def enumerate_new_base_pairs(frm, to, deadline=None):
    """ON-CHAIN enumeration: every PairCreated where a BASE asset (USDT/WBNB/BUSD/USDC) is token0 OR token1, in
    [frm,to]. Removes the GeckoTerminal dependency — going forward EVERY base-paired pool is watched (the whole
    drainable universe), no API rate-limit, no subgraph. Returns ({pair: base}, scanned_through); commits only
    fully-scanned blocks so a failure/deadline just re-scans. Carries the BASE so snapshotting is 1 RPC/pool."""
    out = {}
    b = frm
    while b <= to:
        if deadline and time.time() > deadline:
            return out, b - 1
        e = min(b + _ENUM_CHUNK - 1, to)
        for base in BASES:
            bt = _base_topic(base)
            for topics in ([_PAIRCREATED, bt], [_PAIRCREATED, None, bt]):   # base as token0, then token1
                logs = _rpc("eth_getLogs", [{"fromBlock": hex(b), "toBlock": hex(e), "topics": topics}])
                if logs is None:
                    return out, b - 1        # a base/half failed -> re-scan this chunk next run (never skip)
                for lg in logs:
                    d = lg.get("data") or ""
                    if len(d) >= 66:
                        out["0x" + d[2:66][-40:]] = base
        b = e + 1
    return out, to

def base_reserve_usd(pool, base=None):
    """USD value of the BASE side held by `pool`. If `base` known (from enumeration) -> 1 RPC; else probe all
    (GT-sourced pools). None = unreadable (never treated as 'drained' -> no false alert)."""
    bases = [base] if base and base in BASES else list(BASES)
    best = None
    for b in bases:
        px, dec = BASES[b]
        d = "0x70a08231" + "0" * 24 + pool[2:].lower()
        r = _rpc("eth_call", [{"to": b, "data": d}, "latest"])
        if r is None:
            continue
        try:
            bal = int(r, 16)
        except Exception:
            continue
        usd = bal / 10 ** dec * (px if px is not None else _BNB[0])
        if usd > (best or 0):
            best = usd
    return best

def source_pools():
    """token(lower)->pool watchlist. THREE feeds, because coverage IS the detector for this class:
      - new_pools    : fresh launches (median ~$2k) — the fresh-deploy overlap.
      - trending_pools: hot pools.
      - pools?sort=h24_volume_usd_desc: ESTABLISHED high-TVL pools (median ~$1.2M). THIS is the one that fixes the
        RWT gap — new_pools does NOT carry a 4-day-old $158k pool, so without this feed the watcher has no
        baseline for an established-token drain and MISSES it (the exact failure this class is about).
    Union'd with the PERSISTED watchlist in main(), so any pool that has EVER appeared in a feed stays watched
    and baselined. An active project like RWT appears in trending/top-volume during its life -> gets a baseline."""
    out = {}
    feeds = [("new_pools", ""), ("trending_pools", ""), ("pools", "&sort=h24_volume_usd_desc")]
    for path, extra in feeds:
        for pg in range(1, 11):     # GT caps ~10 pages/endpoint
            d = jget("https://api.geckoterminal.com/api/v2/networks/bsc/%s?page=%d%s" % (path, pg, extra))
            rows = d.get("data") or []
            for p in rows:
                attr = p.get("attributes", {}) or {}
                pool = (attr.get("address") or "").lower()
                liq = float(attr.get("reserve_in_usd") or 0)
                nm = attr.get("name", "") or ""
                if pool and liq >= MIN_WATCH_USD:
                    out[pool] = nm
            if not rows:
                break
            time.sleep(2.5)          # GT rate-limit (learned the hard way: 0.6s = silent 429 truncation)
    return out

RUN_BUDGET_S = int(os.environ.get("PDW_RUN_BUDGET_S") or 600)     # cap a run under the 15-min job
BACKFILL_STEP = int(os.environ.get("PDW_BACKFILL_STEP") or 60000) # blocks of history to seed per run (~7.5h)

def head_block():
    r = _rpc("eth_blockNumber", [])
    return int(r, 16) if r else None

def main():
    t0 = time.time()
    st = json.load(open(STATE)) if os.path.exists(STATE) else {}
    last = st.get("reserves", {})            # pool -> last base_usd
    names = st.get("names", {})
    poolbase = st.get("poolbase", {})        # pool -> base token (so snapshot is 1 RPC)
    alerts = json.load(open(ALERTS)) if os.path.exists(ALERTS) else []
    bnb_usd()
    head = head_block()
    if not head:
        print("no head - all RPCs down", flush=True); return
    enum_fwd = st.get("enum_fwd") or (head - 5)     # forward frontier (new pools) — first run: from ~now
    enum_back = st.get("enum_back") or head         # backfill frontier (existing pools), walks DOWN
    # block window covered by THIS interval — the range a detected drain must have happened in, so _find_drain_tx
    # knows where to look. First run: a short lookback (no prior snapshot means no drop can fire anyway).
    last_head = st.get("last_head") or (head - 2000)

    # (1) FORWARD: every base-paired pool created since last run — comprehensive going forward, NO GeckoTerminal.
    fwd, fscan = enumerate_new_base_pairs(enum_fwd + 1, head, deadline=t0 + RUN_BUDGET_S * 0.4)
    # (2) BACKFILL: walk history downward to seed EXISTING pools (RWT was 4 days old) — bounded per run, resumes.
    back = {}
    if enum_back > 0 and time.time() < t0 + RUN_BUDGET_S * 0.6:
        bfrm = max(0, enum_back - BACKFILL_STEP)
        back, bscan = enumerate_new_base_pairs(bfrm, enum_back - 1, deadline=t0 + RUN_BUDGET_S * 0.6)
        enum_back = bscan if bscan >= bfrm else enum_back   # commit only fully-scanned; else retry same next run
    # (3) GT feeds — supplementary immediate high-TVL seed (best-effort; on-chain enum is the backbone).
    try:
        gt = source_pools()
    except Exception:
        gt = {}
    for p, nm in gt.items():
        names.setdefault(p, nm)

    # merge newly-discovered base pairs (with known base) into the watchlist, keeping only funded ones
    for p, b in {**fwd, **back}.items():
        poolbase.setdefault(p, b)
    # candidate set = persisted watchlist + newly enumerated + GT
    watch = list(dict.fromkeys(list(last.keys()) + list(poolbase.keys()) + list(gt.keys())))

    new_reserves = {}
    checked = fired = 0
    for pool in watch:
        if time.time() > t0 + RUN_BUDGET_S:      # never overrun the job; unscanned pools keep their last value
            new_reserves[pool] = last.get(pool)
            continue
        cur = base_reserve_usd(pool, poolbase.get(pool))
        if cur is None:
            new_reserves[pool] = last.get(pool)  # unreadable -> keep last, never read as a drop
            continue
        # prune pools that never had meaningful liquidity (bounds state/RPC)
        if cur < MIN_WATCH_USD and not last.get(pool):
            continue
        checked += 1
        prev = last.get(pool)
        new_reserves[pool] = cur
        if prev and prev >= MIN_WATCH_USD and cur < prev * (1 - DROP_PCT / 100):
            drop = (prev - cur) / prev * 100
            fired += 1
            rec = {"pool": pool, "name": names.get(pool, "?"), "before": round(prev), "after": round(cur),
                   "drop_pct": round(drop, 1), "ts": time.strftime("%Y-%m-%d %H:%M")}
            # enrich with the actual drain tx + attacker so the alert is IMMEDIATELY actionable (cast run -> name the
            # bug -> dedupe siblings). Best-effort: if it can't be resolved the alert still goes out.
            hit = _find_drain_tx(pool, poolbase.get(pool), last_head, head)
            tail = ""
            if hit:
                rec["tx"], rec["attacker"], rec["drain_block"] = hit[0], hit[1], hit[3]
                tail = ("\nDRAIN TX: %s\nattacker: %s  (block %d)\n"
                        "-> cast run %s   |   dedupe siblings of the VICTIM contract on Dune"
                        % (hit[0], hit[1], hit[3], hit[0]))
            alerts.append(rec)
            notify("BSC POOL-DRAIN ALERT (effect-based)\n%s\npool base reserve $%s -> $%s  (-%.1f%% in ~1 interval)\n"
                   "possible drain/exploit (mechanism-agnostic) OR large LP removal - INVESTIGATE\n"
                   "https://bscscan.com/address/%s%s"
                   % (rec["name"], f"{rec['before']:,}", f"{rec['after']:,}", drop, pool, tail))
            print("*** POOL-DRAIN", pool, rec, flush=True)

    # cap state size (keep the funded ones)
    if len(new_reserves) > MAX_WATCH:
        new_reserves = dict(sorted(new_reserves.items(), key=lambda kv: -(kv[1] or 0))[:MAX_WATCH])
    keep = set(new_reserves)
    st = {"reserves": new_reserves, "enum_fwd": fscan, "enum_back": enum_back, "last_head": head,
          "poolbase": {p: poolbase[p] for p in poolbase if p in keep},
          "names": {p: names[p] for p in names if p in keep}}
    json.dump(st, open(STATE, "w"))
    json.dump(alerts[-500:], open(ALERTS, "w"))
    print("%s | fwd+%d back+%d gt+%d | watched %d checked %d | back_to %d | drain-alerts %d (total %d)"
          % (time.strftime("%H:%M:%S"), len(fwd), len(back), len(gt), len(watch), checked, enum_back, fired, len(alerts)), flush=True)
    if os.environ.get("SELFTEST", "").strip().lower() in ("1", "true", "yes"):
        notify("pool_drain_watch SELF-TEST alive — on-chain base-pair enumeration + %d watched, alerts on >%d%% base-reserve drop." % (len(watch), int(DROP_PCT)))

if __name__ == "__main__":
    main()
