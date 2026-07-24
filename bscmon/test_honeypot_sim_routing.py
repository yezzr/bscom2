"""Routing test for the honeypot-sim calibration in bsc_pairwatch:
  - a naive-PROFITABLE sim  -> INSTANT ping (+ recorded in alerts.json)
  - anything else (honeypot-shaped / tradeable-lossy / unsimmable) -> NO instant ping, batched to `suspects`
  - once per calendar day the accumulated suspects go out as ONE digest, then clear
The safety property under test: a non-profitable burn-sync HIGH is never dropped and never instant-pings — it
waits in the daily digest (because a real gated drain is cheaply indistinguishable from a honeypot)."""
import json, os, tempfile, time
import bsc_pairwatch as pw

tmp = tempfile.mkdtemp()
pw.STATE = os.path.join(tmp, "state.json")
pw.ALERTS = os.path.join(tmp, "alerts.json")
pw.MIN_LIQ_USD = 1000
pw._impl_code = lambda t: ""
pw._bnb = lambda: 600.0
pw.head_block = lambda: 1000
pw.getcode = lambda a: "sync"                                   # non-empty so sync_burn_flag isn't INCONCLUSIVE
pw.sync_burn_flag = lambda t: "PAIR-BURN-SYNC:SRC-BURN-FROM-PAIR(HIGH)"
pw.base_liq_usd = lambda pair, bnb: 50000                       # funded

_sent = []
pw.notify = lambda m: _sent.append(m)

USDT = pw.BASES[0][0]
TOKP = "0x00000000000000000000000000000000000000a1"              # "profitable" token
TOKS = "0x00000000000000000000000000000000000000b2"              # "suspect" token
PAIR = "0x00000000000000000000000000000000000000ee"


class FakeSim:
    """profitable -> ROUNDTRIP-OK evaluated; not-profitable -> TRADEABLE-LOSSY evaluated; None -> SIM-ERROR (could
    not evaluate) so we can assert an inconclusive sim keeps the loud ping instead of being suppressed."""
    def __init__(self, mode):
        self.mode = mode                       # True=profitable, False=evaluated-lossy, None=inconclusive
    def simulate(self, token, pair, **k):
        if self.mode is True:
            return {"tag": "ROUNDTRIP-OK", "back_pct": 140.0, "profitable": True, "evaluated": True, "note": "+40%"}
        if self.mode is False:
            return {"tag": "TRADEABLE-LOSSY", "back_pct": 74.0, "profitable": False, "evaluated": True, "note": "74% back"}
        return {"tag": "SIM-ERROR", "back_pct": None, "profitable": False, "evaluated": False, "note": "inconclusive"}


def _state():
    return json.load(open(pw.STATE)) if os.path.exists(pw.STATE) else {}


def _fresh():
    for f in (pw.STATE, pw.ALERTS):
        if os.path.exists(f):
            os.remove(f)
    _sent.clear()


# ---- CASE A: profitable sim -> instant ping + alerts.json entry, no suspect ----------------------------------
_fresh()
pw.honeypot_sim = FakeSim(True)
pw.get_paircreated = lambda frm, to, **kw: ([(1, USDT, TOKP, PAIR)], to)
pw.main()
alerts = json.load(open(pw.ALERTS)) if os.path.exists(pw.ALERTS) else []
st = _state()
assert any("PROFITABLE" in m for m in _sent), "A: profitable sim must INSTANT-ping"
assert len(alerts) == 1, "A: profitable alert must be recorded in alerts.json"
assert not st.get("suspects"), "A: profitable must NOT go to the suspect digest"
print("CASE A ok: profitable -> instant ping, recorded, no suspect")

# ---- CASE B: non-profitable EVALUATED sim -> NO instant ping, one suspect queued for the digest --------------
_fresh()
pw.honeypot_sim = FakeSim(False)
pw.get_paircreated = lambda frm, to, **kw: ([(1, USDT, TOKS, PAIR)], to)
pw.main()
st = _state()
assert not _sent, "B: non-profitable must NOT instant-ping (got: %r)" % _sent
assert len(st.get("suspects", [])) == 1, "B: non-profitable must be queued as a suspect"
assert st["suspects"][0]["sim"] == "TRADEABLE-LOSSY"
print("CASE B ok: non-profitable -> no ping, 1 suspect queued")

# ---- CASE C: a new calendar day with queued suspects -> ONE digest goes out, suspects clear ------------------
# seed state: one suspect, hb_date = yesterday; no new pairs this run
st = _state()
st["hb_date"] = "2000-01-01"
json.dump(st, open(pw.STATE, "w"))
_sent.clear()
pw.get_paircreated = lambda frm, to, **kw: ([], to)
pw.main()
st = _state()
assert any("daily burn-sync digest" in m for m in _sent), "C: a new day with suspects must emit ONE digest"
assert st.get("suspects") == [], "C: suspects must clear after the digest"
assert st.get("hb_date") == time.strftime("%Y-%m-%d"), "C: hb_date advances to today"
print("CASE C ok: daily digest emitted once, suspects cleared, hb_date advanced")

# ---- CASE D: quiet day (no suspects) -> NO digest ping at all ------------------------------------------------
_fresh()
st = {"hb_date": "2000-01-01", "last_block": 950, "seen": [], "pending": {}, "suspects": []}
json.dump(st, open(pw.STATE, "w"))
pw.get_paircreated = lambda frm, to, **kw: ([], to)
pw.main()
assert not _sent, "D: quiet day must stay silent (got: %r)" % _sent
print("CASE D ok: quiet day -> silent")

# ---- CASE E: INCONCLUSIVE sim (couldn't evaluate) -> keep the LOUD instant ping, NOT the digest ---------------
# the getcode-fail discipline: never suppress a HIGH we couldn't actually check (unsimmable base / RPC failure).
_fresh()
pw.honeypot_sim = FakeSim(None)
pw.get_paircreated = lambda frm, to, **kw: ([(1, USDT, "0x00000000000000000000000000000000000000c3", PAIR)], to)
pw.main()
st = _state()
alerts = json.load(open(pw.ALERTS)) if os.path.exists(pw.ALERTS) else []
assert any("sim n/a" in m for m in _sent), "E: inconclusive sim must still INSTANT-ping (kept loud)"
assert len(alerts) == 1, "E: inconclusive HIGH must be recorded as an alert, not silently digested"
assert not st.get("suspects"), "E: inconclusive must NOT be demoted to the suspect digest"
print("CASE E ok: inconclusive sim -> kept loud (ping), not suppressed")

print("\nALL ROUTING TESTS PASS")
