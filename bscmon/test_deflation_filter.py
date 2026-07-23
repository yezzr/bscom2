#!/usr/bin/env python3
"""Regression test for the DEFLATION-FAMILY downgrade (the SYNC/SKIM+BURN FP filter).
Fork-proven 2026-07 across 5 live tokens: every SYNC/SKIM+BURN / SRC-BURN-FROM-PAIR alert was NOT a permissionless
LP drain. The verified daily-gated burn-to-dead family (RWX/TKN/BNC) is provably not a profitable drain and must
DIGEST, not HIGH-ping. Honeypots (no daily gate), real drains (caller-credit/unbounded), and UNVERIFIED tokens must
stay HIGH. This pins that behavior so a future edit can't silently re-inflate the noise OR drop a real drain.
Run: python test_deflation_filter.py"""
import importlib.util, os

spec = importlib.util.spec_from_file_location("fm", os.path.join(os.path.dirname(__file__), "bsc_forward_monitor.py"))
fm = importlib.util.module_from_spec(spec); spec.loader.exec_module(fm)

PASS = True
def check(name, cond):
    global PASS
    print(("  PASS " if cond else "  FAIL ") + name); PASS = PASS and cond

# --- _deflation_family(src): the cheap static discriminator ---
# DEFLATION family: reduces the pair balance + once-per-day gate + dead/zero destination, caller not paid -> downgrade.
DEFLATION  = "if(roundCutted[getDay()])return; _balances[pancakePair]-=a; _balances[address(0)]+=a; pair.sync();"   # RWX .sub()/-= style
DEFLATION2 = "require(!dayExecuted[dayIndex]); super._transfer(lpPair,address(this),a); _burn(address(this),a); pair.sync();"  # TKN super._transfer style
# HONEYPOT / team-extraction: reduces pair + burns to dead but NO daily gate (XINGHUO-shape) -> stays HIGH.
HONEYPOT = "function forceFollow()public{ super._transfer(uniswapV2Pair,address(0xdead),a); pair.sync(); }"
# REAL DRAIN, direct credit: reduces pair AND credits msg.sender directly, no gate -> must NOT downgrade.
DRAIN = "function atk()external{ _burn(pair,balanceOf(pair)); _balances[msg.sender]+=x; pair.sync(); }"
# REAL DRAIN, SWAP payout (the residual we just closed): coincidental daily+dead strings + reduces pair, but the
# drain pays the caller via pair.swap(...,msg.sender,...) -> must NOT downgrade (caught by the swap-to-caller bail).
DRAIN_SWAP = "if(getDay()>last){_balances[address(0)]+=1;} function d()external{_balances[pancakePair]-=x; IPair(p).swap(out,0,msg.sender,z);}"
# COINCIDENTAL strings, NO pair reduction: has getDay()+address(0) but the token never touches the pair balance ->
# must NOT downgrade (caught by the pair-reduction requirement), even with no caller payout.
NO_PAIR = "if(getDay()>last){_balances[address(0)]+=1;} function claim()external{IERC20(u).transfer(treasury,x);}"
# NORMAL token: the standard transfer entry (the false-match that bit v1) alongside a real deflation body -> downgrade.
STD_TRANSFER = "function transfer(address r,uint256 a)public returns(bool){_transfer(msg.sender,r,a);return true;}"

check("deflation RWX-style (.sub/-= pair, daily, dead) -> downgrade",   fm._deflation_family(DEFLATION) is True)
check("deflation TKN-style (super._transfer pair, daily, dead) -> down",fm._deflation_family(DEFLATION2) is True)
check("honeypot (reduces pair+dead, NO daily gate) -> NOT downgraded",  fm._deflation_family(HONEYPOT) is False)
check("real drain, direct balance credit -> NOT downgraded",           fm._deflation_family(DRAIN) is False)
check("real drain, SWAP-to-caller payout -> NOT downgraded (residual)", fm._deflation_family(DRAIN_SWAP) is False)
check("coincidental strings, NO pair reduction -> NOT downgraded",      fm._deflation_family(NO_PAIR) is False)
check("standard transfer entry doesn't false-block a real deflation",  fm._deflation_family(DEFLATION + STD_TRANSFER) is True)
check("no source (unverified) -> NOT downgraded (stays HIGH path)",     fm._deflation_family(None) is False)

# --- routing: DIGEST flag must NOT ping; HIGH flags must ping ---
check("DEFLATION-FAMILY(DIGEST) is NOT pushworthy",   fm.is_pushworthy(['PAIR-BURN-SYNC:DEFLATION-FAMILY(DIGEST)']) is False)
check("SRC-BURN-FROM-PAIR(HIGH) IS pushworthy",       fm.is_pushworthy(['PAIR-BURN-SYNC:SRC-BURN-FROM-PAIR(HIGH)']) is True)
check("SYNC/SKIM+BURN(HIGH) IS pushworthy",           fm.is_pushworthy(['PAIR-BURN-SYNC:SYNC/SKIM+BURN(HIGH)']) is True)
check("UNVERIFIED-SYNC/SKIM(HIGH) IS pushworthy",     fm.is_pushworthy(['PAIR-BURN-SYNC:UNVERIFIED-SYNC/SKIM(HIGH)']) is True)

print("\n" + ("ALL DEFLATION-FILTER TESTS PASSED" if PASS else "SOME TESTS FAILED"))
raise SystemExit(0 if PASS else 1)
