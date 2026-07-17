#!/usr/bin/env python3
"""Fault-injection test for bsc_pairwatch.py — deliberately FIRES the failure/re-check paths (which I couldn't
trigger from live data) and asserts the scanner fails SAFE (re-scan / re-check) instead of silently losing data.
Run: python test_pairwatch_faults.py"""
import importlib.util, json, os, tempfile

spec = importlib.util.spec_from_file_location("pw", os.path.join(os.path.dirname(__file__), "bsc_pairwatch.py"))
pw = importlib.util.module_from_spec(spec); spec.loader.exec_module(pw)

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
pw.get_paircreated = lambda frm, to, **kw: ([(BASE, T_BURN, P_BURN)], to)
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
pw.get_paircreated = lambda frm, to, **kw: ([(BASE, T2, P2)], to)
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

print("\n" + ("ALL FAULT-INJECTION TESTS PASSED" if PASS else "SOME TESTS FAILED"))
raise SystemExit(0 if PASS else 1)
