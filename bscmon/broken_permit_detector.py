#!/usr/bin/env python3
# BROKEN-PERMIT / FORGEABLE-APPROVAL detector (Lixir class, Ethereum 2026-06-25, ~$12.3K + LIX).
# Two independently-fatal flaws, both statically detectable:
#   A) permit() recovers a signer but checks `recovered != address(0)` instead of `recovered == owner`
#      -> ANY well-formed dummy signature forges an approval (no real owner signature needed).
#   B) allowance keyed by SPENDER ONLY: `mapping(address=>uint256) _allowance` instead of
#      `mapping(address=>mapping(address=>uint256))` -> a single global allowance per spender,
#      no owner-scoped isolation; setting it lets the spender pull ANY holder's balance.
# Either alone is critical; together = drain all holders via withdrawFrom/transferFrom.
import re, sys

def _permit_body(src):
    m=re.search(r'function\s+permit\s*\([^)]*\)[^\{]*\{', src)
    if not m: return None
    i=m.end()-1; d=0; j=i
    while j<len(src):
        if src[j]=='{': d+=1
        elif src[j]=='}':
            d-=1
            if d==0: break
        j+=1
    return src[i:j+1]

def detect(src):
    finds=[]
    body=_permit_body(src)
    if body:
        # find the OWNER parameter name from the permit signature (first address param)
        owner='owner'
        sigm=re.search(r'function\s+permit\s*\(([^)]*)\)', src)
        if sigm:
            pm=re.search(r'address\s+(\w+)', sigm.group(1))
            if pm: owner=pm.group(1)
        has_rec = re.search(r'(ecrecover|recover)\s*\(', body)
        checks_nonzero = re.search(r'!=\s*address\s*\(\s*0\s*\)', body)
        # is the recovered signer bound to the owner param (any naming, == or !=, either order)?
        binds_owner = re.search(r'==\s*'+re.escape(owner)+r'\b', body) or re.search(r'\b'+re.escape(owner)+r'\s*==', body) \
                   or re.search(r'!=\s*'+re.escape(owner)+r'\b', body) or re.search(r'\b'+re.escape(owner)+r'\s*!=', body)
        # also accept OZ-style _hashTypedDataV4/_useNonce delegation (the check lives in the library)
        oz = re.search(r'(_hashTypedDataV4|_useNonce|ERC20Permit|EIP712)', src)
        if has_rec and not binds_owner and not oz:
            why='permit() recovers a signer but never compares it to the owner param `%s`'%owner
            if checks_nonzero: why+=' (only checks != address(0)) -> ANY dummy signature forges an approval'
            finds.append(('CRITICAL','FORGEABLE-PERMIT',why))
    # B) spender-only allowance mapping
    # good: mapping(address => mapping(address => uint256)) ... allowance
    nested = re.search(r'mapping\s*\(\s*address\s*=>\s*mapping\s*\(\s*address\s*=>\s*uint\d*\s*\)\s*\)\s*(?:public|private|internal|external|\s)*_?[Aa]llowance', src)
    single = re.search(r'mapping\s*\(\s*address\s*=>\s*uint\d*\s*\)\s*(?:public|private|internal|external|\s)*_?[Aa]llowances?\b', src)
    if single and not nested:
        finds.append(('CRITICAL','SPENDER-GLOBAL-ALLOWANCE',
            'allowance is keyed by SPENDER only (mapping(address=>uint256)), not (owner,spender) -> no per-owner isolation; one approval drains any holder'))
    return finds

if __name__=='__main__':
    src=open(sys.argv[1],encoding='utf-8',errors='ignore').read()
    finds=detect(src)
    print('=== broken-permit detector ===')
    for sv,tag,why in finds: print('  [%s] %s -- %s'%(sv,tag,why))
    print('VERDICT:', 'VULNERABLE (forgeable approvals)' if finds else 'no broken-permit pattern')
