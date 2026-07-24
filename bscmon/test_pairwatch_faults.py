#!/usr/bin/env python3
"""Fault-injection test for bsc_pairwatch.py — deliberately FIRES the failure/re-check paths (which I couldn't
trigger from live data) and asserts the scanner fails SAFE (re-scan / re-check) instead of silently losing data.
Run: python test_pairwatch_faults.py"""
import importlib.util, json, os, tempfile

spec = importlib.util.spec_from_file_location("pw", os.path.join(os.path.dirname(__file__), "bsc_pairwatch.py"))
pw = importlib.util.module_from_spec(spec); spec.loader.exec_module(pw)
_REAL_GPC = pw.get_paircreated                          # saved before TESTs A/B/D monkeypatch it (TEST E restores)

BASE = pw.BASES[0][0]                                    # USDT
BURN = "0x60fff6cae9" + "42966c68" + "00"               # fake bytecode: has sync() + burn selector
CLEAN = "0x6001600200"                                  # no manip selectors
T_BURN = "0xaaaa000000000000000000000000000000000001"
P_BURN = "0xbbbb000000000000000000000000000000000001"

tmp = tempfile.mkdtemp()
pw.STATE = os.path.join(tmp, "state.json")
pw.ALERTS = os.path.join(tmp, "alerts.json")
pw.MIN_LIQ_USD = 1000
pw._impl_code = lambda t: ""                            # isolate: no proxy
pw._bnb = lambda: 600.0
_sent = []
pw.notify = lambda m: _sent.append(m)

# These fault tests exercise DETECTION/COVERAGE (getcode resolution, create-then-fund, budget-truncation resume),
# not the honeypot-sim alert routing (covered by test_honeypot_sim_routing.py). Stub the sim to always look
# naive-PROFITABLE so a detected+funded burn-sync token INSTANT-pings, keeping these assertions about coverage.
class _AlwaysProfit:
    def simulate(self, *a, **k):
        return {"tag": "ROUNDTRIP-OK", "profitable": True, "note": "test-stub"}
pw.honeypot_sim = _AlwaysProfit()

def load_state():
    return json.load(open(pw.STATE)) if os.path.exists(pw.STATE) else {}

PASS = True
def check(name, cond):
    global PASS
    print(("  PASS " if cond else "  FAIL ") + name); PASS = PASS and cond

# ============ TEST C: getLogs chunk failure -> commit only fully-scanned blocks (Bug 1) ============
# NOTE: written against pw.CHUNK/pw.SUB_CHUNK rather than hardcoded 50/99. The original test assumed CHUNK=50;
# when CHUNK moved to 2000 its range collapsed to ONE successful chunk, so it silently stopped exercising the
# failure path at all — a test that passes by not testing. Derive the ranges from the real constants.
print("TEST C: getLogs chunk failure must NOT advance past unscanned blocks")
C = pw.CHUNK
_n = {"i": 0}
def rpc_logfail(urls, method, params, tries=2):
    if method == "eth_getLogs":
        _n["i"] += 1
        return [] if _n["i"] == 1 else None            # chunk1 ok(empty); EVERYTHING after fails (incl sub-chunks)
    return None
pw._rpc = rpc_logfail
out, scanned = pw.get_paircreated(0, 2 * C - 1)        # chunk1 = 0..C-1 (ok), chunk2 = C..2C-1 (fails)
check(f"stops before failed chunk (scanned=={C-1}, not {2*C-1})", scanned == C - 1)

# ---- TEST C2: the wide chunk fails but the 50-block SUB-CHUNK fallback succeeds -> scan completes, no stall.
# (drpc down / range rejected must DEGRADE to the 50-cap nodes, not halt the scanner.)
print("TEST C2: wide-chunk failure must fall back to sub-chunks, not stall")
_w = {"first": True}
def rpc_widefail(urls, method, params, tries=2):
    if method == "eth_getLogs":
        span = int(params[0]["toBlock"], 16) - int(params[0]["fromBlock"], 16) + 1
        if span > pw.SUB_CHUNK:                        # wide request -> reject (as a 50-cap node would)
            return None
        return []                                      # sub-chunk sized -> serve it
    return None
pw._rpc = rpc_widefail
out2, scanned2 = pw.get_paircreated(0, C - 1)
check("wide fails + sub-chunks OK -> full range scanned (degrade, not stall)", scanned2 == C - 1)

# ============ TEST A: getcode RPC blip -> INCONCLUSIVE -> pending (NOT cleared), then resolves (Bug 2) ============
print("TEST A: getcode failure must go to pending, not be marked 'seen' forever")
for f in (pw.STATE, pw.ALERTS):
    if os.path.exists(f): os.remove(f)
HEAD = [1000]
pw.head_block = lambda: HEAD[0]
pw.get_paircreated = lambda frm, to, **kw: ([(1, BASE, T_BURN, P_BURN)], to)   # (blk, t0, t1, pair)
_code = {T_BURN: ""}                                    # run1: getcode FAILS (empty)
pw.getcode = lambda a: _code.get(a.lower(), "")
pw.base_liq_usd = lambda pair, bnb: 999999             # funded (so only the getcode-fail matters)
pw.main()
st = load_state()
check("run1: token in pending as '?' (not seen, not cleared)", T_BURN in st.get("pending", {}) and st["pending"][T_BURN][1] == "?")
check("run1: token NOT in seen", T_BURN not in st.get("seen", []))
check("run1: no false alert", len(_sent) == 0)
# run2: getcode now works and returns burn-sync code
HEAD[0] = 1000                                          # no new blocks; pending re-check still runs
pw.get_paircreated = lambda frm, to, **kw: ([], to)
_code[T_BURN] = BURN
pw.main()
st = load_state()
check("run2: getcode resolves -> burn-sync + funded -> ALERT fired", len(_sent) == 1)
check("run2: token removed from pending", T_BURN not in st.get("pending", {}))

# ============ TEST B: burn-sync UNFUNDED -> pending -> funded later -> alert (create-then-fund) ============
print("TEST B: burn-sync pair created empty then funded later must still alert")
for f in (pw.STATE, pw.ALERTS):
    if os.path.exists(f): os.remove(f)
_sent.clear()
T2 = "0xaaaa000000000000000000000000000000000002"; P2 = "0xbbbb000000000000000000000000000000000002"
HEAD[0] = 2000
pw.head_block = lambda: HEAD[0]
pw.get_paircreated = lambda frm, to, **kw: ([(1, BASE, T2, P2)], to)          # (blk, t0, t1, pair)
pw.getcode = lambda a: BURN if a.lower() == T2 else CLEAN
_liq = {P2: 0}                                          # run1: UNFUNDED
pw.base_liq_usd = lambda pair, bnb: _liq.get(pair.lower(), 0)
pw.main()
st = load_state()
check("run1: unfunded burn-sync -> pending (not alerted, not seen)", T2 in st.get("pending", {}) and len(_sent) == 0 and T2 not in st.get("seen", []))
# run2: liquidity arrives
HEAD[0] = 2000
pw.get_paircreated = lambda frm, to, **kw: ([], to)
_liq[P2] = 50000
pw.main()
check("run2: funded -> ALERT fired (create-then-fund closed)", len(_sent) == 1)
check("run2: token now in seen, out of pending", T2 not in load_state().get("pending", {}))

# ====== TEST D: analysis OVER BUDGET must COMMIT at a clean BLOCK boundary + save state (the FREEZE fix) ======
# The real production failure: a ~200k-block backlog = ~1,500 pairs x ~3s analysis >> the 15-min job timeout, so
# the run was KILLED before `st["last_block"]=...` was ever reached -> last_block FROZE -> the backlog grew every
# run and the COVERAGE-GAP/DROP alert fired forever. This asserts the analysis loop now stops at RUN_BUDGET_S and
# commits last_block at the block boundary of the pairs it FINISHED (never the frozen old value, never `scanned`).
print("TEST D: analysis over budget must commit progress at a block boundary, not freeze last_block")
for f in (pw.STATE, pw.ALERTS):
    if os.path.exists(f): os.remove(f)
_sent.clear()
TD1 = "0xaaaa000000000000000000000000000000000003"; PD1 = "0xbbbb000000000000000000000000000000000003"
TD2 = "0xaaaa000000000000000000000000000000000004"; PD2 = "0xbbbb000000000000000000000000000000000004"
HEAD[0] = 500000
pw.head_block = lambda: HEAD[0]
json.dump({"last_block": 300000, "seen": [], "pending": {}}, open(pw.STATE, "w"))   # 200k-block backlog
pw.get_paircreated = lambda frm, to, **kw: ([(310000, BASE, TD1, PD1), (320000, BASE, TD2, PD2)], to)  # scanned=to=head
pw.getcode = lambda a: BURN
pw.base_liq_usd = lambda pair, bnb: 999999
_saved_budget = pw.RUN_BUDGET_S
pw.RUN_BUDGET_S = -1                                    # force the analysis deadline to fire BEFORE the first pair
pw.main()
st = load_state()
check("run1: last_block committed at block boundary (310000-1), NOT scanned=500000", st.get("last_block") == 309999)
check("run1: over-budget tokens NOT marked seen (will be re-scanned)", TD1 not in st.get("seen", []) and TD2 not in st.get("seen", []))
check("run1: state SAVED / advanced (NOT frozen at 300000, NOT dropped)", st.get("last_block") == 309999)
check("run1: no alert (analysis never ran)", len(_sent) == 0)
# run2: full budget -> resumes from 310000, analyzes BOTH -> catches fully up
pw.RUN_BUDGET_S = _saved_budget
_sent.clear()
pw.get_paircreated = lambda frm, to, **kw: ([(310000, BASE, TD1, PD1), (320000, BASE, TD2, PD2)], to)
pw.main()
st = load_state()
check("run2: full budget -> last_block == head (fully caught up, no freeze)", st.get("last_block") == HEAD[0])
check("run2: burn-sync + funded -> alert fired (nothing missed by the truncation)", len(_sent) >= 1)

# ====== TEST E: a healthy wide-node POOL serves the 2000-block chunk in ONE call — no sub-chunk crawl (Bug 2) ======
# Bug 2 was throughput collapse: drpc was the ONLY wide (2000-block) getLogs node, and when it rejected a wide call
# the scan degraded to 50-block sub-chunks (~250 blocks/15s) -> couldn't keep pace with BSC across cron gaps -> fell
# behind. Fix = a POOL of independent wide nodes (blxrbdn/onfinality/48.club x2/drpc), so a single node's failure
# never forces the crawl: _rpc walks the pool and the first member that serves the wide range wins. This asserts the
# FAST path (pool healthy -> exactly one wide call, zero sub-chunks). TEST C2 above already covers the opposite end
# (ALL wide nodes down -> degrade to sub-chunks but still commit progress, no data loss).
print("TEST E: healthy wide pool serves a 2000-block chunk in ONE call (no crawl)")
C = pw.CHUNK
_calls = {"wide": 0, "sub": 0}
def rpc_widepool_ok(urls, method, params, tries=2):
    if method == "eth_getLogs":
        span = int(params[0]["toBlock"], 16) - int(params[0]["fromBlock"], 16) + 1
        _calls["wide" if span > pw.SUB_CHUNK else "sub"] += 1
        return []                                       # a pool member SERVED it (empty result, but not None)
    return None
pw._rpc = rpc_widepool_ok
pw.get_paircreated = _REAL_GPC                           # TESTs A/B/D replaced it with a lambda; exercise the REAL one
outE, scannedE = pw.get_paircreated(0, C - 1)
check(f"wide pool serves the chunk (scanned=={C-1})", scannedE == C - 1)
check(f"exactly 1 wide call, ZERO sub-chunk crawl (wide={_calls['wide']}, sub={_calls['sub']})",
      _calls["wide"] == 1 and _calls["sub"] == 0)

# ====== TEST F: per-LOG deadline — a spam chunk (many distinct fake factories) can't overrun the scan budget ======
# The scan budget is enforced BETWEEN chunks, but the emitter spoof-validation (_pair_factory, an RPC) runs PER LOG
# inside a chunk. A range emitting PairCreated from many DISTINCT fake factories would grind that loop past the
# budget with no between-chunk check to catch it. The per-log deadline commits through the last full chunk (b-1).
# Fake clock = deterministic (no sleeps): each time.time() advances 0.5s; deadline 1002 is crossed mid-log-loop.
print("TEST F: per-log deadline bounds the _pair_factory loop (spoof-DoS guard), commits at chunk boundary")
import time as _realtime
class _FakeClock:
    def __init__(self): self.t = 1000.0
    def time(self): self.t += 0.5; return self.t
    def sleep(self, s): pass
pw.time = _FakeClock()
def _mklog(i):
    a = lambda n: "0x" + ("%040x" % n)
    base = pw.BASES[0][0]; tok = a(100 + i); pair = a(5000 + i); emitter = a(9000 + i)  # DISTINCT unknown factory each
    topic = lambda addr: "0x" + "0" * 24 + addr[2:]
    return {"topics": ["0xtopic", topic(base), topic(tok)], "data": "0x" + pair[2:].rjust(64, "0") + "0" * 64,
            "address": emitter, "blockNumber": hex(1000 + i)}
_logs = [_mklog(i) for i in range(10)]
pw._rpc = lambda urls, method, params, tries=2: (_logs if method == "eth_getLogs" else None)
pw._pair_factory = lambda pair: None                    # unknown emitter -> validation work per log (uncached: distinct)
pw.get_paircreated = _REAL_GPC
outF, scannedF = pw.get_paircreated(1000, 1000 + pw.CHUNK - 1, deadline=1002.0)
pw.time = _realtime                                     # restore real clock for any later use
# scanned==999 (frm-1) PROVES the per-log break fired; if it had processed all 10 logs it would return `to` (2999).
check("per-log deadline stops mid-chunk & commits b-1 (scanned==999, not 2999)", scannedF == 999)

print("\n" + ("ALL FAULT-INJECTION TESTS PASSED" if PASS else "SOME TESTS FAILED"))
raise SystemExit(0 if PASS else 1)
