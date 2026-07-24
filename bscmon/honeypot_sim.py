"""honeypot_sim.py - forge-accurate buy->sell round-trip simulation via a SINGLE eth_call with state override.

WHY THIS EXISTS: the pair-burn-sync bytecode detector fires HIGH on any token with sync/skim + a burn selector.
Across 5+ live alerts (RWX/TKN/BNC/XINGHUO/AICAT/PEPGEM) that HIGH was almost always a HONEYPOT or benign
deflation, never a permissionless LP drain we could act on. This runs the actual buy->sell that a real
attacker/user would, so the alert can be CALIBRATED instead of blindly loud.

CRITICAL LIMIT (fork-proven 2026-07-24, do not forget): a gated HONEYPOT (PEPGEM) and a REAL gated DRAIN
(FCOW $61k, AIDC $120k) return the IDENTICAL sim signature (BUY-REVERTED) - the real drainers acquire tokens via
an alt/whitelist path and drain with a crafted flash-loan attack this sim does NOT reproduce. So a non-profitable
/reverting sim is NOT proof of safety and MUST NOT auto-clear a HIGH. The ONLY strong POSITIVE signal is a
naive-PROFITABLE round-trip (rare) -> that one is worth an instant ping. Everything else = SUSPECT (route to the
daily digest, never a silent drop). This is exactly why the monitor keeps digesting, not dropping, these.

HOW: eth_call with a 3rd 'state override' param (Alchemy/geth) injects a tiny tester contract at a scratch
address + funds it with the base asset (balance-slot override), then calls run() which does
router.swap(base->token) then router.swap(token->base) and reports what happened. No forge, no on-chain funding,
no key beyond a normal archive RPC. Stdlib-only (no web3/keccak at runtime): the two storage-slot keys are
precomputed constants for the FIXED tester address, and base balance-slots are a small measured table.
"""
import json, urllib.request, urllib.error

# tester runtime bytecode: HoneypotTester.run(base,tok,router,cap) -> (code,bought,back); buy then sell, never reverts.
# code: 0=roundtrip ok, 1=buy reverted, 2=buy gave 0, 3=sell reverted, 4=<50% back, 5=approve reverted.
_TESTER_CODE = "0x608060405234801561000f575f5ffd5b5060043610610029575f3560e01c806324499bae1461002d575b5f5ffd5b61004061003b36600461046e565b610063565b6040805160ff909416845260208401929092529082015260600160405180910390f35b60405163095ea7b360e01b81526001600160a01b0383811660048301525f1960248301525f91829182919088169063095ea7b3906044016020604051808303815f875af19250505080156100d4575060408051601f3d908101601f191682019092526100d1918101906104b6565b60015b6100e65750600591505f905080610449565b506040805160028082526060820183525f9260208301908036833701905050905087815f8151811061011a5761011a6104dc565b60200260200101906001600160a01b031690816001600160a01b031681525050868160018151811061014e5761014e6104dc565b6001600160a01b0392831660209182029290920101528616635c11d795865f843061017b4261012c6104f0565b6040518663ffffffff1660e01b815260040161019b959493929190610515565b5f604051808303815f87803b1580156101b2575f5ffd5b505af19250505080156101c3575060015b6101d75760015f5f93509350935050610449565b6040516370a0823160e01b81523060048201526001600160a01b038816906370a0823190602401602060405180830381865afa158015610219573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061023d9190610585565b9250825f036102565760025f5f93509350935050610449565b60405163095ea7b360e01b81526001600160a01b0387811660048301525f19602483015288169063095ea7b3906044016020604051808303815f875af19250505080156102c0575060408051601f3d908101601f191682019092526102bd918101906104b6565b60015b6102d15750600592505f9050610449565b506040805160028082526060820183525f9260208301908036833701905050905087815f81518110610305576103056104dc565b60200260200101906001600160a01b031690816001600160a01b0316815250508881600181518110610339576103396104dc565b6001600160a01b0392831660209182029290920101528716635c11d795855f84306103664261012c6104f0565b6040518663ffffffff1660e01b8152600401610386959493929190610515565b5f604051808303815f87803b15801561039d575f5ffd5b505af19250505080156103ae575060015b6103c15750600393505f91506104499050565b6040516370a0823160e01b81523060048201526001600160a01b038a16906370a0823190602401602060405180830381865afa158015610403573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906104279190610585565b925061043460028761059c565b831015610442576004610444565b5f5b945050505b9450945094915050565b80356001600160a01b0381168114610469575f5ffd5b919050565b5f5f5f5f60808587031215610481575f5ffd5b61048a85610453565b935061049860208601610453565b92506104a660408601610453565b9396929550929360600135925050565b5f602082840312156104c6575f5ffd5b815180151581146104d5575f5ffd5b9392505050565b634e487b7160e01b5f52603260045260245ffd5b8082018082111561050f57634e487b7160e01b5f52601160045260245ffd5b92915050565b5f60a0820187835286602084015260a0604084015280865180835260c0850191506020880192505f5b818110156105655783516001600160a01b031683526020938401939092019160010161053e565b50506001600160a01b039590951660608401525050608001529392505050565b5f60208284031215610595575f5ffd5b5051919050565b5f826105b657634e487b7160e01b5f52601260045260245ffd5b50049056fea264697066735822122039fd5a7b02c7eecb891e28ad6cd117f215f54f8d0cdc0914214558e911a8f70b64736f6c634300081e0033"
_TESTER = "0x00000000000000000000000000000000beef0001"
_ROUTER = "0x10ed43c718714eb63d5aa57b78b54704e256024e"     # PancakeSwap V2 router
_RUN_SEL = "0x24499bae"                                    # run(address,address,address,uint256)

# base asset -> (precomputed keccak(pad32(_TESTER).pad32(balanceSlot)) storage key, probe capital in base units).
# Measured on-chain 2026-07-24: USDT/USDC/BUSD balances live at mapping slot 1, WBNB at slot 3. CAP must be a small,
# realistic trade (~$100) sized PER BASE: a flat 100e18 is $100 in a stable but ~$60,000 in WBNB - a pool-wrecking
# trade that would misclassify every fresh WBNB-paired token as honeypot-shaped (and could hide a real profit under
# slippage). Stables -> 100e18 ($100); WBNB -> 0.15e18 (~$90 at ~$600/BNB, fine across $300-$1200).
_SLOT1_KEY = "0x5e29a24b80d96d0fef704ca3f9778f89379f1a911a313d2781c205ded1d86939"
_SLOT3_KEY = "0x63acad40b798a968ccb67b7b316f7cc8e148d3c32f72412161603d835111cfc6"
_CAP_STABLE = 100 * 10**18
_CAP_WBNB = 15 * 10**16
BASES = {
    "0x55d398326f99059ff775485246999027b3197955": (_SLOT1_KEY, _CAP_STABLE),  # USDT
    "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": (_SLOT1_KEY, _CAP_STABLE),  # USDC
    "0xe9e7cea3dedca5984780bafc599bd69add087d56": (_SLOT1_KEY, _CAP_STABLE),  # BUSD
    "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": (_SLOT3_KEY, _CAP_WBNB),    # WBNB
}
# eth_call STATE OVERRIDE (the 3rd param) needs an archive node that supports it — Alchemy does, reliably. Read the
# key from the ALCHEMY_KEY SECRET (NEVER hardcode it: this repo is public). Public fallbacks may not honor the
# override; if none does, simulate() returns SIM-ERROR -> evaluated=False -> the caller KEEPS THE LOUD PING (safe).
import os as _os
_AK = _os.environ.get("ALCHEMY_KEY")
_SIM_RPCS = ([("https://bnb-mainnet.g.alchemy.com/v2/" + _AK)] if _AK else []) + \
            ["https://bsc.drpc.org", "https://bsc-rpc.publicnode.com"]

_CODE_NAMES = {0: "ROUNDTRIP-OK", 1: "BUY-REVERTED", 2: "BUY-ZERO",
               3: "SELL-REVERTED", 4: "LOW-RETURN", 5: "APPROVE-REVERTED"}


def _ea(a):
    return a[2:].lower().rjust(64, "0")


def _eu(x):
    return hex(int(x))[2:].rjust(64, "0")


def _token_sides(pair, rpc):
    """(token0, token1) of the pair, lowercased, via eth_call. None on failure."""
    out = []
    for sel in ("0x0dfe1681", "0xd21220a7"):     # token0() / token1()
        try:
            payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_call",
                                  "params": [{"to": pair, "data": sel}, "latest"]}).encode()
            req = urllib.request.Request(rpc, payload, {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
            r = json.loads(urllib.request.urlopen(req, timeout=12).read()).get("result")
            if not r or len(r) < 42:
                return None
            out.append("0x" + r[-40:].lower())
        except Exception:
            return None
    return tuple(out)


def _eth_call_override(rpc, tx, override, timeout=25):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_call",
                          "params": [tx, "latest", override]}).encode()
    req = urllib.request.Request(rpc, payload, {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
    try:
        return json.loads(urllib.request.urlopen(req, timeout=timeout).read())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read())
        except Exception:
            return {"error": {"message": "http%s" % e.code}}
    except Exception as e:
        return {"error": {"message": str(e)[:50], "net": 1}}


def simulate(token, pair, cap_units=None):
    """Run the buy->sell round-trip. Returns a dict {'tag','back_pct','profitable','evaluated','note'}.

    `evaluated` is the key routing field: True only when the tester CONTRACT actually ran and returned a code (so
    the verdict is trustworthy). False when the sim could NOT run (pair sides unreadable, unknown base, or every RPC
    errored). A caller must DEMOTE a burn-sync HIGH to the digest ONLY when evaluated AND not profitable — an
    UN-evaluated result must keep the loud ping (never suppress a HIGH you couldn't actually check; same discipline
    as the getcode-fail false-negative). `profitable` (naive round-trip > 101%) is the ONLY signal safe to escalate
    on; a real gated drain has the same reverting signature as a honeypot, so 'not profitable' is SUSPECT, not clean.
    cap_units defaults to a per-base ~$100 probe (see BASES) - do NOT pass a flat value across bases."""
    token = token.lower()
    pair = pair.lower()
    sides = None
    for rpc in _SIM_RPCS:
        sides = _token_sides(pair, rpc)
        if sides:
            break
    if not sides:
        return {"tag": "SIM-ERROR", "back_pct": None, "profitable": False, "evaluated": False, "note": "pair sides unreadable"}
    base = sides[0] if sides[1] == token else (sides[1] if sides[0] == token else None)
    if base is None or base not in BASES:
        return {"tag": "NO-BASE", "back_pct": None, "profitable": False, "evaluated": False,
                "note": "pair not against a simmable base (USDT/USDC/BUSD/WBNB) - sim n/a, kept loud"}
    key, base_cap = BASES[base]
    cap = int(cap_units) if cap_units else base_cap
    data = _RUN_SEL + _ea(base) + _ea(token) + _ea(_ROUTER) + _eu(cap)
    tx = {"from": _TESTER, "to": _TESTER, "data": data}
    override = {_TESTER: {"code": _TESTER_CODE}, base: {"stateDiff": {key: "0x" + _eu(cap)}}}
    last = None
    for rpc in _SIM_RPCS:
        r = _eth_call_override(rpc, tx, override)
        res = r.get("result")
        if res and len(res) >= 2 + 192:
            body = res[2:]
            code = int(body[0:64], 16)
            back = int(body[128:192], 16)
            back_pct = back / cap * 100.0
            tag = _CODE_NAMES.get(code, "code%d" % code)
            profitable = (code == 0 and back_pct > 101.0)
            if code == 0 and not profitable:
                tag = "TRADEABLE-LOSSY"
            notes = {
                "ROUNDTRIP-OK": ">> NAIVE-PROFITABLE round-trip +%.1f%% - RARE, act" % (back_pct - 100),
                "TRADEABLE-LOSSY": "tradeable but round-trip returns %.0f%% (tax/deflation, not a naive drain)" % back_pct,
                "BUY-REVERTED": "buy gated/reverts (honeypot OR gated-drain like FCOW/AIDC - indistinguishable)",
                "BUY-ZERO": "buy yields 0 tokens (confiscating honeypot)",
                "SELL-REVERTED": "sell blocked (honeypot OR crafted-attack drain like FCOW - verify by replay)",
                "LOW-RETURN": "round-trip returns %.0f%% (heavy trap)" % back_pct,
                "APPROVE-REVERTED": "approve reverts (broken/hostile token)",
            }
            return {"tag": tag, "back_pct": back_pct, "profitable": profitable, "evaluated": True, "note": notes.get(tag, tag)}
        err = (r.get("error") or {})
        if err.get("net"):
            last = "neterr"
            continue                                  # network error -> try next node
        last = (err.get("message") or "revert")[:60]
    # every node errored (or reverted at the top level without our return data) -> INDETERMINATE, not evaluated ->
    # the caller must keep the loud ping (never suppress a HIGH we couldn't actually run).
    return {"tag": "SIM-ERROR", "back_pct": None, "profitable": False, "evaluated": False, "note": "sim inconclusive (%s)" % last}
