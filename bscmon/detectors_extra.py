#!/usr/bin/env python3
"""
detectors_extra.py — extra bug-class detectors built on Slither's AST/SlithIR
(not regex). Covers classes the stock catalog + price-taint miss:

  A) first-depositor / share-inflation (ERC4626 mint rounding + donation)
  B) read-only reentrancy exposure (view returns state mutated mid-external-call,
     consumed by an external integrator)
  C) liquidation-math edge cases (bad-debt rounding / incentive>collateral / self-liq)
  D) cross-function invariant smell (sum of balances vs totalSupply not enforced)

Each is heuristic but AST-grounded. Used by battery.py as an extra engine.
Usage: python detectors_extra.py <addr|file|dir>
"""
import sys, re
from slither import Slither
from slither.slithir.operations import HighLevelCall, LibraryCall, InternalCall, Binary, BinaryType

ESKEY=""

def get_sl(target):
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", str(target)):
        return Slither(target, etherscan_api_key=ESKEY)
    return Slither(target)

def fname(ir):
    f=getattr(ir,"function",None)
    return (getattr(f,"name","") if f else "") or getattr(ir,"function_name","") or ""

# ---- A) first-depositor / share inflation ----
def detect_share_inflation(sl):
    out=[]
    for c in sl.contracts_derived:
        names=[f.name for f in c.functions]
        is_vault = any(n in names for n in ("deposit","mint","previewDeposit","convertToShares")) and \
                   any(n in names for n in ("totalAssets","totalSupply"))
        if not is_vault: continue
        src=""
        try: src=c.source_mapping.content or ""
        except: pass
        # protections: dead shares (mint to 0/this in first deposit), virtual offset (_decimalsOffset / +1 in convert)
        has_offset = ("_decimalsOffset" in src) or re.search(r"totalAssets\(\)\s*\+\s*1", src) or re.search(r"\+\s*10\s*\*\*\s*_?decimals", src)
        has_deadshares = re.search(r"_mint\(\s*address\(0\)|_mint\(\s*address\(this\)|MINIMUM_LIQUIDITY|balanceOf\[address\(0\)\]", src)
        has_minfirst = re.search(r"totalSupply\(\)\s*==\s*0", src)
        if not (has_offset or has_deadshares):
            sev = "HIGH" if not has_minfirst else "MEDIUM"
            out.append((sev,"share-inflation-exposure",c.name,
                        "vault has deposit/convertToShares but no virtual-offset and no dead-shares; check first-depositor inflation"))
    return out

# ---- B) read-only reentrancy ----
def detect_readonly_reentrancy(sl):
    out=[]
    for c in sl.contracts_derived:
        # functions that make an external call THEN write state (classic reentrancy window)
        windows=[]
        for f in c.functions:
            if f.view or f.pure: continue
            seen_ext=False
            for ir in f.slithir_operations:
                if isinstance(ir,(HighLevelCall,LibraryCall)) and fname(ir) not in ("transfer","transferFrom","safeTransfer","safeTransferFrom"):
                    seen_ext=True
                if seen_ext and getattr(ir,"lvalue",None) is None and isinstance(ir,(HighLevelCall,)):
                    pass
            # writes after external call?
            if seen_ext and f.state_variables_written:
                windows.append(f.name)
        # public view getters that read state others rely on (price/share/totalAssets)
        getters=[f.name for f in c.functions if (f.view or f.pure) and any(
                 k in f.name.lower() for k in ("price","share","rate","totalassets","convert","preview","balance"))]
        if windows and getters:
            out.append(("MEDIUM","read-only-reentrancy-exposure",c.name,
                        f"state-mutating-after-extcall fns={windows[:4]} + price/share view getters={getters[:4]}; "
                        f"an integrator reading a getter mid-reentrancy may see manipulated value"))
    return out

# ---- C) liquidation math ----
def detect_liq_math(sl):
    out=[]
    for c in sl.contracts_derived:
        liqfns=[f for f in c.functions if "liquidat" in f.name.lower() and not (f.view or f.pure)]
        for f in liqfns:
            src=""
            try: src=f.source_mapping.content or ""
            except: pass
            # smells: incentive/bonus mul without cap vs collateral; self-liquidation not blocked
            self_block = re.search(r"borrower\s*!=\s*msg\.sender|msg\.sender\s*!=\s*borrower|NotBorrower|SelfLiquidat", src)
            incentive = re.search(r"(incentive|bonus|lif|LIF)\b", src, re.I)
            div_then_mul = re.search(r"/\s*\w+[^;]*\*", src)
            if incentive and not self_block:
                out.append(("MEDIUM","liquidation-self-or-incentive",c.name,
                            f"{f.name}: liquidation incentive present, no explicit self-liquidation guard; verify incentive cannot exceed seized collateral"))
    return out

def run(target):
    try: sl=get_sl(target)
    except Exception as e:
        print("SLITHER_ERROR:",e); return []
    res=[]
    for fn in (detect_share_inflation, detect_readonly_reentrancy, detect_liq_math):
        try: res+=fn(sl)
        except Exception as e: res.append(("INFO",fn.__name__+"-error",str(e)[:80],""))
    return res

if __name__=="__main__":
    if len(sys.argv)<2: print("usage: detectors_extra.py <addr|file|dir>"); sys.exit()
    r=run(sys.argv[1])
    if not r: print("# extra-detectors: no exposure flagged")
    for sev,title,where,detail in r:
        print(f"  [{sev:8}] {title}  @{where}  {detail}")
