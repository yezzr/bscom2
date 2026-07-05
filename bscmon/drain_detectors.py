#!/usr/bin/env python3
"""
drain_detectors.py — extended BSC scam-token DRAIN catalog (D9..D22 + H7..H13), mined from the real
incident corpus (DeFiHackLabs + SlowMist/BlockSec/PeckShield writeups + GoPlus/RPHunter taxonomies).

Design principle (the hard-won lesson): STATIC catches the access-control / visibility / signature /
arithmetic classes with high precision. The reflection/skim/sync/dividend DRAIN family is NOT here —
one template (BaseUSDTWA/reflection) spawns infinite mechanics, so static over-flags every SafeMoon
clone; that family is caught by the mechanic-agnostic fork PnL sim (taxtoken_profitsim.py). This module
ONLY implements the sharp, low-FP static tells. Each detector carries its FP discriminator inline.

Exposes scan(src, name) -> [ {code, klass, sev, conf, ev, tier} ] consumed by bsc_scam_detector.REGISTRY.
"""
import re
import vuln_token_scanner as V

def _F(code, klass, sev, conf, ev, tier="CONFIRMED"):
    return {"code": code, "klass": klass, "sev": sev, "conf": conf, "ev": ev, "tier": tier}

def _gated(header, body):
    return bool(re.search(V.AC, header) or re.search(V.AC, body[:250]))

def _ext(header):
    return "external" in header or "public" in header

def scan(src, name=None):
    if not src:
        return []
    src = V.strip_mock_contracts(src)
    if name:
        src = V.deployed_scope(src, name)
    fns = list(V.fn_bodies(src))
    low = src.lower()
    out = []

    # ---- D9: internal transfer primitive exposed public/external (cftoken class) ----
    for nm, hdr, body in fns:
        if nm in ("_transfer", "_tokenTransfer", "_basicTransfer", "_transferStandard") and re.search(r"\b(public|external)\b", hdr):
            out.append(_F("D9", "ATTACKER-DRAIN", "CRIT", 0.85,
                          f"{nm} is public/external (should be internal) -> anyone calls it to move ANY holder/pair balance", "CONFIRMED"))
            break

    # ---- D10: arbitrary caller-supplied SOURCE address moved (ULME/DDC/MyAi/KR class) ----
    # public/ungated fn with an address param used as transferFrom-source or balance-debit, no `param==msg.sender`.
    for nm, hdr, body in fns:
        if not _ext(hdr) or _gated(hdr, body) or nm in ("_transfer", "transferFrom", "_tokenTransfer"):
            continue
        params = [m.group(1) for m in re.finditer(V.ADDR_PARAM, hdr)]
        srcp = [p for p in params if re.search(r"from|user|wallet|account|holder|victim|seller|owner", p, re.I)]
        for p in srcp:
            pe = re.escape(p)
            moves = (re.search(r"transferFrom\s*\(\s*" + pe + r"\b", body)
                     or re.search(r"_balances\s*\[\s*" + pe + r"\s*\]\s*[-+]?=", body)
                     or re.search(r"_(?:r|t)Owned\s*\[\s*" + pe + r"\s*\]\s*[-+]?=", body))
            guarded = re.search(pe + r"\s*==\s*(?:msg\.sender|_msgSender\(\))|(?:msg\.sender|_msgSender\(\))\s*==\s*" + pe, body)
            if moves and not guarded:
                out.append(_F("D10", "ATTACKER-DRAIN", "HIGH", 0.62,
                              f"{nm}: caller-supplied source `{p}` is moved (transferFrom/balance write) with NO `{p}==msg.sender` gate -> drain anyone who approved", "CONFIRMED"))
                break

    # ---- D11: transferFrom skips allowance when from==address(this) (LW class) ----
    for nm, hdr, body in fns:
        if nm.lower() == "transferfrom" and re.search(r"from\s*==\s*address\(this\)", body):
            # the special-case usually returns/branches before the allowance decrement
            out.append(_F("D11", "ATTACKER-DRAIN", "HIGH", 0.55,
                          "transferFrom special-cases `from==address(this)` (typically skips the allowance check) -> anyone pulls the contract's own/mintable balance", "CONFIRMED"))
            break

    # ---- D12: fee-exempt branch in transferFrom omits the allowance decrement (Carrot/NOVO class) ----
    for nm, hdr, body in fns:
        if nm.lower() == "transferfrom" and re.search(r"_isExcludedFromFee|isExcluded|_isExcluded|excludedFromFee", body):
            has_allow = re.search(r"_spendAllowance|_allowances\s*\[[^\]]*\]\s*\.\s*sub|_approve\s*\(|allowance\s*\(", body)
            if not has_allow:
                out.append(_F("D12", "ATTACKER-DRAIN", "HIGH", 0.5,
                              "transferFrom branches on fee-exclusion but has NO allowance decrement on that path -> a fee-exempt (or self-exempting) caller pulls any holder", "LEAD"))
            break

    # ---- D21: ungated public burn/destroy/autoBurn that can target the PAIR (Shadowfi/HCT/XAI/ARK/BYToken P2 family) ----
    for nm, hdr, body in fns:
        nl = nm.lower()
        if not _ext(hdr) or _gated(hdr, body):
            continue
        if re.search(r"burn|destory|destroy|autoburn|hourburn|triggerautoburn|burnpair|burnliquid", nl):
            # burns an address the caller may not own (pair / arbitrary / totalSupply-derived), not just msg.sender's own
            burns_other = (re.search(r"_balances\s*\[\s*[^]]*(pair|pool|lp|router|uniswap)", body, re.I)
                           or re.search(r"_burn\s*\(\s*[^,)]*(pair|pool|lp|uniswap)", body, re.I)
                           or re.search(r"totalSupply\s*\(\s*\)\s*[-*/]", body))
            own_only = re.search(r"_burn\s*\(\s*(?:_?msgSender\(\)|msg\.sender)", body)
            if burns_other and not own_only:
                out.append(_F("D21", "ATTACKER-DRAIN", "HIGH", 0.6,
                              f"{nm}: ungated burn can destroy the PAIR/arbitrary balance (then sync() inflates price) -> reserve drain", "CONFIRMED"))
                break

    # ---- D22: ownership/privileged setter MISSING access control (ROI/AIS class) ----
    for nm, hdr, body in fns:
        nl = nm.lower()
        if not _ext(hdr) or _gated(hdr, body):
            continue
        if re.search(r"^(transferownership|setowner|renounceownership|setadmin|addadmin|setminter|setoperator)$", nl) \
           or (re.search(r"set(owner|admin|minter|operator|governance|controller)", nl)):
            if re.search(r"_owner\s*=|owner\s*=|_admin\s*=|admin\s*=|isMinter\s*\[[^\]]*\]\s*=\s*true|_setupRole|_grantRole", body):
                out.append(_F("D22", "ATTACKER-DRAIN", "HIGH", 0.55,
                              f"{nm}: privileged/ownership setter with NO access control -> attacker seizes owner/minter/admin then drains", "CONFIRMED"))
                break

    # ---- D15: ECDSA signature malleability (TCH class): ecrecover gating value, no v/s checks ----
    if "ecrecover(" in low:
        # find an ecrecover not followed/preceded by v∈{27,28} or low-s guards, and not via OZ ECDSA
        uses_oz = "ecdsa.recover" in low or "ecdsa.tryrecover" in low
        v_check = re.search(r"v\s*==\s*27|v\s*==\s*28|v\s*!=\s*27|require\([^)]*v\s*(==|!=)", src)
        s_check = re.search(r"s\s*<=?\s*0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0|s\s*>\s*0x7fffffff|secp256k1n|low.?s|0x7FFFF", src, re.I)
        nonce = re.search(r"usedNonce|usedSig|nonces\s*\[|_nonces|usedMintRefs|seen\s*\[", src)
        if not uses_oz and not v_check and not s_check and not nonce:
            out.append(_F("D15", "ATTACKER-DRAIN", "HIGH", 0.5,
                          "raw ecrecover() gates a value action with no v∈{27,28}/low-s malleability guard and no nonce -> signature replay/forge", "LEAD"))

    # ---- D16: weak-RNG payout (RedKeys class): block-derived randomness deciding a same-tx payout ----
    for nm, hdr, body in fns:
        if re.search(r"keccak256\s*\([^)]*block\.(timestamp|number|prevrandao|difficulty)", body) and \
           re.search(r"transfer|_mint|reward|win|prize|payout|claim", body, re.I) and not re.search(r"VRF|chainlink|commit|reveal", body, re.I):
            out.append(_F("D16", "ATTACKER-DRAIN", "MED", 0.45,
                          f"{nm}: payout decided by block-derived RNG (timestamp/number/prevrandao) -> predictable, farmable same-tx", "LEAD"))
            break

    # ---- D17: predictable XOR-seed airdrop recipient in _transfer (FFIST/Utopia class) ----
    if re.search(r"uint160\([^)]*\)\s*\^|lastAirdrop|airdrop.{0,40}\^.{0,40}block\.number", src, re.I) and re.search(r"_transfer", src):
        for nm, hdr, body in fns:
            if nm in ("_transfer", "_tokenTransfer") and re.search(r"\^", body) and re.search(r"block\.number|lastAirdrop", body, re.I):
                out.append(_F("D17", "ATTACKER-DRAIN", "MED", 0.45,
                              "_transfer derives an 'airdrop' recipient from public XOR of block.number/lastAirdrop -> attacker forces recipient=pair then sync()", "LEAD"))
                break

    # ---- D18: cross-chain receiver mints with no endpoint/trusted-remote check (AK1111 class) ----
    # Only PUBLIC receive entrypoints. NOT `_credit`/`_lzReceive` — those are INTERNAL OFT hooks gated
    # upstream by the base OFTCore.lzReceive endpoint check (BasedOFT/ZEROBASE FP).
    for nm, hdr, body in fns:
        if _ext(hdr) and re.search(r"^(lzreceive|nonblockinglzreceive|ccipreceive)\d*$", nm.lower()) and re.search(r"_mint\s*\(", body):
            gated = re.search(r"msg\.sender\s*==\s*\w*endpoint|onlyEndpoint|trustedRemote|_trustedRemotes|require\([^)]*endpoint", body, re.I) or _gated(hdr, body)
            if not gated:
                out.append(_F("D18", "ATTACKER-DRAIN", "HIGH", 0.6,
                              f"{nm}: cross-chain receive mints with NO endpoint/trusted-remote check -> free mint", "CONFIRMED"))
                break

    # ---- D20: unbounded fee-share split over-debits the sender (MTToken/LAXO class) ----
    for nm, hdr, body in fns:
        if nm in ("_transfer", "_tokenTransfer", "_transferStandard"):
            # a loop crediting fee recipients amount*pct with no Σpct<=100 invariant
            if re.search(r"for\s*\([^)]*\)\s*\{[^}]*_balances\s*\[[^\]]*\]\s*\+?=\s*[^;]*\*[^;]*/\s*100", body):
                if not re.search(r"require\([^)]*<=?\s*100|totalFee\s*<=?\s*\d+|sum\w*\s*<=?\s*100", src):
                    out.append(_F("D20", "ATTACKER-DRAIN", "MED", 0.45,
                                  f"{nm}: fee split loop credits recipients amount*pct/100 with no Σpct<=100 cap -> sender over-debited, AMM pair harvestable", "LEAD"))
                    break

    # ---- reflection-family lead: public deliver/reflect/burn that mutates global reflection supply -> ROUTE TO PROFIT-SIM ----
    if re.search(r"_rTotal|_rOwned|reflectionFromToken|_getRate", src):
        for nm, hdr, body in fns:
            if _ext(hdr) and not _gated(hdr, body) and re.search(r"^(deliver|reflect|burn|reflectionFee)", nm.lower()) and re.search(r"_rTotal|_tTotal|_rOwned", body):
                out.append(_F("D-refl", "ATTACKER-DRAIN", "LOW", 0.3,
                              f"reflection token exposes public `{nm}` mutating _rTotal/_tTotal -> rate-manipulation drain class; CONFIRM via fork PnL sim (taxtoken_profitsim)", "LEAD"))
                break

    # ---- D23: LP/reward credit sized from LIVE pool reserves, not a staged snapshot (WHALE class; spot-as-oracle P30) ----
    # The settlement/credit baseline is the LIVE getReserves()/balanceOf(pair) instead of the actual-investment
    # snapshot, so an attacker pre-skews the pair reserves between stage and settle to inflate the basis and
    # over-credit themselves LP-reward/hashrate rights. Deep accounting decoupling -> SIM-CANDIDATE (static can
    # only flag the shape; confirm via a fork manipulate-reserves-then-settle PnL sim). Scans the WHOLE contract
    # (the dangerous read+use is in settle/credit HELPERS, not _transfer -> why D4's body-scan missed WHALE).
    reads_spot = bool(re.search(r"getReserves\s*\(\s*\)", src) or re.search(r"balanceOf\s*\(\s*\w*[Pp]air", src))
    credit_mech = bool(re.search(r"notifyCredit|registeredLp|_settlePending\w*LpAdd|addLp\w*[Cc]redit|hashrate", src))
    reserve_feeds_credit = bool(re.search(r"(reserve|rUsdt|rUSDT|rWhale|useR\w+|currentR\w+)\b", src)
                                and re.search(r"notifyCredit|_mint|credit", src, re.I))
    if reads_spot and credit_mech and reserve_feeds_credit:
        out.append(_F("D23", "ATTACKER-DRAIN", "MED", 0.4,
                      "LP/reward credit sized from LIVE getReserves()/pair-balance (not a staged snapshot) -> attacker pre-skews pair reserves to inflate the settlement basis and over-credit (WHALE class); CONFIRM via fork manipulate-then-settle PnL sim", "LEAD"))

    # =========================== RUG / HONEYPOT static levers (victim-protection) ===========================

    # ---- H7: can-take-back-ownership (GoPlus can_take_back_ownership) ----
    for nm, hdr, body in fns:
        nl = nm.lower()
        if _ext(hdr) and nl not in ("transferownership", "renounceownership") and re.search(r"_owner\s*=\s*(?:msg\.sender|_msgSender\(\))", body):
            if not re.search(r"onlyOwner|_checkOwner|require\([^)]*_owner\s*==\s*msg\.sender", hdr + body[:200]):
                out.append(_F("H7", "RUG-BACKDOOR", "MED", 0.45,
                              f"{nm}: sets `_owner = msg.sender` outside a current-owner gate -> ex-owner can re-claim ownership after a fake renounce", "LEAD"))
                break

    # ---- H8: hidden owner / hardcoded-address backdoor in a privileged check ----
    if re.search(r"(msg\.sender|_msgSender\(\))\s*==\s*0x[a-fA-F0-9]{40}", src) or re.search(r"require\s*\(\s*0x[a-fA-F0-9]{40}\s*==\s*msg\.sender", src):
        out.append(_F("H8", "RUG-BACKDOOR", "MED", 0.5,
                      "privileged action gated on a HARDCODED address (== msg.sender) -> hidden owner survives renounceOwnership", "LEAD"))

    # ---- H9: selfdestruct backdoor ----
    if re.search(r"\bselfdestruct\s*\(|\bsuicide\s*\(", src):
        out.append(_F("H9", "RUG-BACKDOOR", "MED", 0.4,
                      "contract contains selfdestruct/suicide -> owner can destroy logic / brick the token", "LEAD"))

    # ---- H10: sell-only extreme asymmetric tax (honeypot) ----
    m = re.search(r"sellFee\w*\s*=\s*(\d+)", src) or re.search(r"_sellTax\w*\s*=\s*(\d+)", src)
    if m and int(m.group(1)) >= 90 and re.search(r"to\s*==\s*\w*(pair|uniswap)", src, re.I):
        out.append(_F("H10", "HONEYPOT", "MED", 0.5,
                      f"sell fee = {m.group(1)}% on the to==pair branch -> sells return ~nothing (can-buy/cant-sell honeypot)", "LEAD"))

    # ---- H11: transfer logic delegated to an owner-settable external contract (RPHunter MEC) ----
    for nm, hdr, body in fns:
        if nm in ("_transfer", "_tokenTransfer") and re.search(r"\.(call|delegatecall)\s*\(", body):
            # to an address held in a settable state var (not a fixed router constant)
            if re.search(r"(logic|handler|processor|executor|hook)\w*\.(call|delegatecall)", body, re.I) or re.search(r"\bI\w*\(\s*\w*(logic|handler|hook)\w*\s*\)\.", body, re.I):
                out.append(_F("H11", "RUG-BACKDOOR", "MED", 0.4,
                              f"{nm}: delegates transfer logic to an owner-settable external contract -> can be swapped to block/skim sells later", "LEAD"))
                break

    # ---- H12: transfer pausable (owner can freeze all transfers) ----
    for nm, hdr, body in fns:
        if nm in ("_transfer", "_tokenTransfer", "_update") and re.search(r"whenNotPaused|require\s*\(\s*!\s*paused|require\s*\(\s*!\s*_paused", body):
            if re.search(r"function\s+pause\s*\(", src):
                out.append(_F("H12", "HONEYPOT", "LOW", 0.3,
                              "transfers gated by an owner-controlled pause() -> owner can freeze all holder funds", "LEAD"))
                break

    # ---- H13: per-address (personal) modifiable fee (GoPlus personal_slippage_modifiable) ----
    if re.search(r"mapping\s*\(\s*address\s*=>\s*uint\d*\s*\)\s*(public|private|internal)?\s*\w*(fee|tax|slippage)", src, re.I):
        for nm, hdr, body in fns:
            if re.search(r"set", nm.lower()) and _gated(hdr, body) and re.search(r"\w*(fee|tax|slippage)\s*\[\s*\w+\s*\]\s*=", body, re.I):
                out.append(_F("H13", "HONEYPOT", "MED", 0.4,
                              f"{nm}: owner sets a PER-ADDRESS fee/tax -> can target a victim with 100% sell tax", "LEAD"))
                break

    return out
