#!/usr/bin/env python3
"""
double_settle_detector.py - detect the DIP-class "missing-return double-settlement" bug in a fee-token
_transfer override (BSC drain, ~$111k, 2026-06-17, tx 0x1c093958...).

ROOT CAUSE CLASS: an overridden `_transfer`/`_tokenTransfer` settles the SAME (from,to,amount) leg twice
because a conditional branch calls the transfer primitive with the recipient == the function's `to`
WITHOUT a `return`, and an UNCONDITIONAL terminal call to `to` of the same `amount` runs afterward. Any
transfer that takes that branch moves 2*amount. Permissionlessly triggerable via Pair.skim(router) when
the branch key is `to == router` (DIP), draining the pool's real reserve.

WHY STATIC + PRECISE (low FP): a BENIGN fee token's conditional branch transfers to `feeAddress` (a
DIFFERENT recipient) and reduces `amount`, then the terminal call sends the reduced amount to `to` ONCE.
The bug is specifically a branch whose primitive recipient == the terminal recipient (`to`) with no return.

Usage:
  python double_settle_detector.py <addr> [<addr> ...] [--chain 56]
  python double_settle_detector.py --selftest          # validates on DIP (fires) + control (clean)
Returns per addr: EXPLOITABLE / CLEAN / NO-OVERRIDE / UNVERIFIED, with the offending lines.
"""
import sys, re, json, urllib.request, urllib.parse, time

ESK = ""  # Etherscan V2 (all chains)
DIP = "0x6c60bf5db0670ae94489d3dde2c60f271625db50"   # known TRUE positive
AIC = "0x524c72268e2053bb356ecb4c1364b5bb74644405"   # sibling (control unless also a clone)

def _get(u):
    return json.loads(urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent":"M"}), timeout=40).read())

def fetch_source(addr, chain=56):
    u = "https://api.etherscan.io/v2/api?" + urllib.parse.urlencode(
        {"chainid":chain,"module":"contract","action":"getsourcecode","address":addr,"apikey":ESK})
    r = _get(u).get("result")
    if not r: return None, None
    res = r[0]
    src = res.get("SourceCode") or ""
    if not src: return None, res.get("ContractName")
    if src.startswith("{"):                       # standard-json multi-file
        s = src[1:-1] if src.startswith("{{") else src
        try:
            j = json.loads(s)
            src = "\n".join(c.get("content","") for c in j.get("sources",{}).values())
        except Exception: pass
    return src, res.get("ContractName")

def _balanced_body(src, start_idx):
    """given index at the function's first '{', return the body up to the matching '}'."""
    depth = 0
    for i in range(start_idx, len(src)):
        if src[i] == "{": depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0: return src[start_idx:i+1]
    return src[start_idx:]

# a call to the settlement primitive, capturing the 2nd (recipient) and 3rd (amount) args
CALL = re.compile(r"(?:super\.)?(?:_transfer|_tokenTransfer|_basicTransfer)\s*\(\s*([^,]+?)\s*,\s*([^,]+?)\s*,\s*([^,)]+?)\s*\)")

def analyze_transfer_override(src):
    """find _transfer/_tokenTransfer override(s); return findings list."""
    findings = []
    for m in re.finditer(r"function\s+(_transfer|_tokenTransfer)\s*\(([^)]*)\)[^{]*\boverride\b[^{]*\{", src):
        # recipient param name = 2nd param of the override signature (from, TO, amount)
        params = [p.strip().split()[-1] for p in m.group(2).split(",") if p.strip()]
        to_param = params[1] if len(params) >= 2 else "to"
        amt_param = params[2] if len(params) >= 3 else "amount"
        brace = src.index("{", m.end()-1)
        body = _balanced_body(src, brace)
        calls = list(CALL.finditer(body))
        if not calls: continue
        # TERMINAL unconditional call: the LAST primitive call sending to `to_param`
        terminal = None
        for c in reversed(calls):
            if c.group(2).strip() == to_param:
                terminal = c; break
        if terminal is None: continue
        term_pos = terminal.start()
        # is the terminal at depth-0 (unconditional)? compute brace depth at term_pos within body
        depth = body.count("{",0,term_pos) - body.count("}",0,term_pos)
        terminal_unconditional = (depth <= 1)  # 1 = inside the function body only
        if not terminal_unconditional: continue
        # BRANCH bug: an EARLIER primitive call to the SAME recipient (`to_param`) sitting INSIDE a
        # conditional (depth>1) whose enclosing branch has NO `return` before reaching the terminal.
        for c in calls:
            if c.start() >= term_pos: continue
            if c.group(2).strip() != to_param: continue          # must target the same `to`
            cdepth = body.count("{",0,c.start()) - body.count("}",0,c.start())
            if cdepth <= 1: continue                              # this is itself unconditional (not the branch bug)
            # between this branch-call and the terminal, is there a `return`? if so, no fallthrough.
            between = body[c.start():term_pos]
            # crude: a `return` that is reachable (any return token in the branch before its close)
            # find the branch's own closing brace
            d = 0; close = c.start()
            for i in range(c.start(), term_pos):
                if body[i]=="{": d+=1
                elif body[i]=="}":
                    d-=1
                    if d < 0: close=i; break
            branch_seg = body[c.start():close]
            if re.search(r"\breturn\b", branch_seg): continue     # branch returns -> no double settle
            findings.append({
                "fn": m.group(1),
                "branch_call": c.group(0).strip(),
                "terminal_call": terminal.group(0).strip(),
                "to_param": to_param, "amount_param": amt_param,
            })
    return findings

def scan(addr, chain=56):
    src, name = fetch_source(addr, chain)
    if src is None:
        return {"addr":addr, "name":name, "verdict":"UNVERIFIED"}
    if not re.search(r"function\s+(_transfer|_tokenTransfer)\s*\([^)]*\)[^{]*\boverride\b", src):
        return {"addr":addr, "name":name, "verdict":"NO-OVERRIDE"}
    f = analyze_transfer_override(src)
    return {"addr":addr, "name":name, "verdict":"EXPLOITABLE" if f else "CLEAN", "findings":f}

def selftest():
    print("# SELFTEST: DIP must EXPLOITABLE, AIC is the control")
    for a,label in [(DIP,"DIP (true positive)"), (AIC,"AIC (control)")]:
        r = scan(a); time.sleep(0.3)
        print(f"\n  {label}: {r['name']} -> {r['verdict']}")
        for x in r.get("findings",[]):
            print(f"     fn {x['fn']}: branch `{x['branch_call']}` (no return) + terminal `{x['terminal_call']}`")
    print("\n# DIP should be EXPLOITABLE. If AIC is also EXPLOITABLE it is a live clone of the same template.")

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] == "--selftest":
        selftest(); sys.exit(0)
    chain = 56
    if "--chain" in args:
        i = args.index("--chain"); chain = int(args[i+1]); args = args[:i]+args[i+2:]
    for a in args:
        r = scan(a, chain); time.sleep(0.25)
        print(f"{r['addr']}  {r.get('name')}  -> {r['verdict']}")
        for x in r.get("findings",[]):
            print(f"   {x['fn']}: branch `{x['branch_call']}` (no return) + terminal `{x['terminal_call']}`")
