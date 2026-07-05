#!/usr/bin/env python3
"""
vuln_token_scanner.py — find ATM-KIND targets: small FRESH tokens with a self-contained,
permissionlessly-triggerable money bug in their OWN code (not protocols, not clones).

The ATM lesson: don't clone-match attacker bytecode (finds corpses). Instead source from
NEW DEX POOLS (fresh tokens WITH liquidity = a drain is profitable) and DETECT THE BUG CLASS
directly in the verified source. Output = review queue for responsible disclosure. NOT an exploit.

Feed:   GeckoTerminal new_pools + trending (bsc/base/ethereum), liquidity band.
Source: Etherscan V2 verified source (Sourcify fallback).
Detect (the ATM family of self-contained exploits):
  D1 forced-dump      : _transfer/transferFrom swaps OWN balance with minOut=0 (ATM bug)
  D2 open-mint        : public/external mint -> _mint(...) with NO access control (permissionless inflation)
  D3 public-drain     : public/external fn sends contract/token balance to msg.sender, NO access control
  D4 reflexive-xfer   : _transfer sizes a swap/burn off pool reserves/price -> sandwichable
  D5 open-claim       : claim/airdrop/distribute mints or sends with NO eligibility / attacker-supplied list
  D6 arb-transferFrom : transferFrom(arbitrary, msg.sender, ...) using contract allowance (approval drain)
"""
import os, sys, json, re, time, urllib.request, urllib.parse

ETHERSCAN_KEY = os.environ.get('ETHERSCAN_API_KEY','')
CHAINID = {"bsc":56, "ethereum":1, "base":8453, "arbitrum":42161, "polygon":137}
SWAP_FNS = r"swapExactTokensFor\w+|swapTokensForExactTokens"
AC = (r"(\bonly[A-Z]\w*|_checkOwner|_checkRole|hasRole|authorized|_onlyOwner|_checkMinter|whenNotPaused"
      r"|msg\.sender\s*[=!]=|[=!]=\s*msg\.sender"          # msg.sender on EITHER side of ==/!= (reversed-order guard)
      r"|_msgSender\(\)\s*[=!]=|[=!]=\s*_msgSender\(\)"    # e.g. require(fundAddress == msg.sender) was being MISSED
      r"|require\s*\([^;{}]*\[\s*msg\.sender\s*\]"          # mapping-membership guard: require(isMinter[msg.sender])
      r"|if\s*\([^;{}]*\[\s*msg\.sender\s*\]"               #   and: if(!isMinter[msg.sender]) revert  (the Aztec lesson)
      r"|require\s*\([^;{}]*\[\s*_msgSender\(\)\s*\])")
# ^ generic `only*` modifier (onlyVault/onlyMinter/onlyGov/...) — was missing custom modifiers -> D2 FP on gated mints

ADDR_PARAM = r"\baddress(?:\[\])?\s+(?:calldata\s+|memory\s+)?(\w+)"

def _send_recipients(body):
    """recipient candidates of value-sending calls: the object before a native .transfer/.send/.call{value},
    AND the FIRST arg of ERC20 safeTransfer/transfer/sendValue/_mint (the recipient position)."""
    cands = []
    for m in re.finditer(r"([A-Za-z_][\w.\(\)\[\]]*)\s*\.\s*(?:transfer|send)\s*\(", body):
        cands.append(m.group(1))                       # native: recipient.transfer(amt)
    for m in re.finditer(r"([A-Za-z_][\w.\(\)\[\]]*)\s*\.\s*call\s*\{\s*value", body):
        cands.append(m.group(1))                       # native: recipient.call{value:..}()
    for m in re.finditer(r"(?:safeTransfer|transfer|sendValue|_mint)\s*\(\s*([^,(){}]+)", body):
        cands.append(m.group(1))                       # ERC20/native-helper: first arg = recipient
    return [c.strip() for c in cands]

def _ctrl(cand, params):
    """is this recipient ATTACKER-controllable? msg.sender / _msgSender() / tx.origin, or a caller-supplied
    address PARAM used verbatim. A hardcoded/state address (devAddr, owner, treasury) is NOT controllable."""
    if re.search(r"\bmsg\.sender\b|_msgSender\s*\(\)|\btx\.origin\b", cand):
        return True
    inner = re.sub(r"^payable\s*\(|\)\s*$", "", cand).strip()
    return any(re.fullmatch(re.escape(p), inner) for p in params)

def get(u, hdr=None):
    try: return urllib.request.urlopen(urllib.request.Request(u, headers=hdr or {"User-Agent":"Mozilla/5.0","Accept":"application/json"}), timeout=30).read().decode("utf-8","replace")
    except Exception: return ""

def es_source(addr, cid):
    try:
        r = json.loads(get(f"https://api.etherscan.io/v2/api?"+urllib.parse.urlencode({"chainid":cid,"module":"contract","action":"getsourcecode","address":addr,"apikey":ETHERSCAN_KEY})))
        res = (r.get("result") or [{}])[0]
        src = res.get("SourceCode","") or ""
        if src.startswith("{{"):
            src = "\n".join(c.get("content","") if isinstance(c,dict) else str(c) for c in json.loads(src[1:-1]).get("sources",{}).values())
        return src, res.get("ContractName","")
    except Exception: return "", ""

def fn_bodies(src):
    """Yield (name, header, body) for each function (crude brace matcher)."""
    for m in re.finditer(r"function\s+(\w+)\s*\(([^)]*)\)([^\{;]*)\{", src):
        name = m.group(1); header = m.group(0); i = m.end(); depth = 1; j = i
        while j < len(src) and depth:
            if src[j]=="{": depth+=1
            elif src[j]=="}": depth-=1
            j+=1
        yield name, header, src[i:j]

def strip_mock_contracts(src):
    """Remove mock/test/harness contract blocks from FLATTENED source before detecting, so a bundled
    test helper's UNGATED mint/drain doesn't false-positive the real deployed contract (the BasedOFT FP:
    a `mint(...) public` in a `// for testing` mock made D2 fire while the real mint is onlyOwner)."""
    if not src: return src
    cuts = []
    for m in re.finditer(r"(?:abstract\s+)?contract\s+(\w+)[^{;]*\{", src):
        name = m.group(1)
        pre = src[max(0, m.start()-160):m.start()].lower()
        is_mock = bool(re.search(r"mock|test|harness|fixture|stub", name, re.I)) \
                  or "for testing" in pre or ("warning" in pre and "test" in pre)
        if not is_mock: continue
        depth = 0; j = m.end() - 1                      # brace-match the contract body
        while j < len(src):
            c = src[j]
            if c == "{": depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0: break
            j += 1
        cuts.append((m.start(), j + 1))
    if not cuts: return src
    res = []; prev = 0
    for a, b in cuts:
        res.append(src[prev:a]); prev = b
    res.append(src[prev:])
    return "".join(res)

def _contract_body(src, cname):
    """balanced body of `contract/abstract contract <cname> is ...{ }` + its inheritance names."""
    m = re.search(r"\b(?:abstract\s+contract|contract)\s+" + re.escape(cname) + r"\b([^{]*)\{", src)
    if not m: return None, []
    inh = re.findall(r"[A-Z]\w+", m.group(1))
    start = src.index("{", m.start()); depth = 0
    for i in range(start, len(src)):
        if src[i] == "{": depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0: return src[start:i + 1], inh
    return src[start:], inh

def deployed_scope(src, name):
    """restrict analysis to the DEPLOYED contract + its inheritance chain (what's actually callable on the
    token address), so an ungated mint in an UNRELATED bundled contract (preset/example) is not flagged.
    Falls back to full src if the contract can't be located."""
    if not name: return src
    seen, bodies, stack = set(), [], [name]
    while stack:
        c = stack.pop()
        if c in seen: continue
        seen.add(c)
        body, inh = _contract_body(src, c)
        if body:
            bodies.append(body)
            stack += [x for x in inh if x not in seen]
    return "\n".join(bodies) if bodies else src

def detect(src, name=None):
    src = strip_mock_contracts(src)        # drop bundled mock/test contracts (FP source) before scanning
    src = deployed_scope(src, name)        # restrict to deployed contract + ancestors (multi-contract-bundle FP fix)
    hits = []
    # D1 forced-dump (ATM) — minOut=0 swap that is ATTACKER-SIZED / hits treasury, NOT the benign
    # SafeMoon threshold fee-swap (swapBack/swapAndLiquify gated by inSwap + a swapAtAmount threshold).
    benign_feeswap = bool(re.search(r"inSwap|swapAtAmount|numTokensSell\w*|swapThreshold|swapTokensAtAmount"
                                    r"|autoSell|minReward|minPart|maxPart", src))  # threshold/cap reward-token family (TokenZero)
    for name, header, body in fn_bodies(src):
        if name not in ("_transfer","transferFrom","_update"): continue
        # the dump is reachable in the transfer path AND its amount derives from the transfer amount
        if re.search(SWAP_FNS, body) and re.search(r"(amount|tAmount|value)\s*[*]\s*\w+\s*/\s*(100|1000|10000|\w+)", body):
            for m in re.finditer(SWAP_FNS + r"\s*\(", body):
                parts=[p.strip() for p in body[m.end():m.end()+400].split(")")[0].split(",")]
                if len(parts)>=2 and parts[1] in ("0","uint256(0)"):
                    hits.append("D1:forced-dump minOut=0 (attacker-sized in _transfer)"); break
    # weaker signal: minOut=0 fee-swap that is NOT the standard threshold pattern (still worth a look)
    if not benign_feeswap and re.search(SWAP_FNS, src):
        for m in re.finditer(SWAP_FNS + r"\s*\(", src):
            parts=[p.strip() for p in src[m.end():m.end()+400].split(")")[0].split(",")]
            if len(parts)>=2 and parts[1] in ("0","uint256(0)"):
                hits.append("D1?:minOut=0 swap (non-threshold; verify amount source)"); break
    for name, header, body in fn_bodies(src):
        ext = ("external" in header or "public" in header)
        gated = bool(re.search(AC, header) or re.search(AC, body[:200]))
        if not ext or gated: continue
        nl = name.lower()
        # D2 open mint
        if re.search(r"\bmint\b", nl) and re.search(r"_mint\s*\(", body):
            hits.append(f"D2:open-mint({name})")
        # D5 open claim/airdrop — ONLY if the value-send RECIPIENT is attacker-controllable (msg.sender or a
        # caller-supplied address param), NOT a fixed recipient (devWallet rescue = AIC claimStuckTokens FP).
        if re.search(r"claim|airdrop|distribut|reward|grab", nl) and re.search(r"_mint\s*\(|transfer\s*\(|safeTransfer\s*\(", body):
            params=[m2.group(1) for m2 in re.finditer(ADDR_PARAM, header)]
            if any(_ctrl(r, params) for r in _send_recipients(body)):
                hits.append(f"D5:open-claim({name})")
        # D3 public drain: drains the contract balance to an ATTACKER-CONTROLLABLE recipient (not a fixed devWallet).
        # SKIP share-accounting fns that _mint/_burn the caller's shares — those are deposit/redeem (e.g. a basket's
        # removeAll/addAll), NOT a raw drain (verified on RangePool: removeAll burns your shares for pro-rata assets).
        if (re.search(r"balanceOf\s*\(\s*address\(this\)\s*\)", body) or "address(this).balance" in body) \
           and not re.search(r"_mint\s*\(|_burn\s*\(", body):
            params=[m2.group(1) for m2 in re.finditer(ADDR_PARAM, header)]
            if any(_ctrl(r, params) for r in _send_recipients(body)):
                hits.append(f"D3:public-drain({name})")
        # D6 arbitrary transferFrom using contract allowance
        if re.search(r"transferFrom\s*\(\s*\w+\s*,\s*msg\.sender", body):
            hits.append(f"D6:arb-transferFrom({name})")
    # D4 reflexive transfer
    for name, header, body in fn_bodies(src):
        if name in ("_transfer","transferFrom","_update") and re.search(r"getReserves|getAmountsOut|balanceOf\s*\(\s*(pair|uniswapV2Pair|_pair|lpPair)", body):
            hits.append("D4:reflexive-xfer"); break
    # D7 spoofable liquidity-classification (DTXT/ATM/BaseUSDTWA family, SlowMist 2026). A fn classifies
    # add/remove/sell by comparing balanceOf(pairedToken @ pair) vs cached getReserves(); anyone sends dust
    # of the paired token to the pair to flip the classification. THIS IS A LEAD, NOT A CONFIRMED BUG:
    # exploitable ONLY if the misclassified-as-add branch gives the seller an ADVANTAGE (skips/lowers the fee).
    #   DTXT (EXPLOITABLE): `if(isAdd){ super._transfer(from,to,amount); return; }`  -> 0 fee on a spoofed sell.
    #   YSDAO (NOT exploit): `if(isAdd){ tFee=amount*3%; _takeFee; transfer(amount-tFee); }` -> same fee, no gain.
    #   ATM: different bug (D1 forced-dump), not this.
    # Auto-isolating the isAdd BRANCH body needs real parsing (crude regex misfires) -> flag as VERIFY and
    # check by hand whether the add-branch transfers the FULL amount with no fee vs the sell-branch.
    low=src.lower()
    if ("getreserves(" in low) and re.search(r"balanceof\s*\(\s*(address\s*\(\s*)?\w*pair|balanceof\s*\(\s*usdt", low) \
       and (("_isliquidity" in low) or ("isaddliquidity" in low) or ("_isaddliquidity" in low) or re.search(r"\bisadd\w*\s*=", low)) \
       and re.search(r"if\s*\(\s*_?isadd\w*", low):
        hits.append("D7?:liquidity-classification pattern (VERIFY add-branch skips fee vs sell — DTXT-class)")
    # D8 face-value multi-asset basket (depeg-arbitrage — RangePool/RPT class, 2024). A basket that holds >=2
    # constituent stablecoins as fungible UNITS: mint credits shares for depositing ANY whitelisted token at
    # raw face value (no per-token price/oracle), AND redeem lets the caller CHOOSE which token to withdraw at
    # par. Deposit a depegged constituent (FRAX/MIM) cheap -> mint shares as if $1 -> redeem the STRONG asset
    # (DAI/LUSD) at par -> sell. Tells: mint add(address token, uint amount)->_mint ; redeem remove(address
    # token, uint...) that safeTransfers the CALLER-CHOSEN token out (+_burn) ; a token whitelist/array ; and
    # ZERO oracle reads. Pro-rata-only redeem (removeAll(uint) — splits every token by balance) is SAFE and is
    # excluded by the 2-param (address,uint) signature (it takes only uint). Precise: won't touch tax tokens.
    has_oracle = bool(re.search(r"oracle|chainlink|latestAnswer|latestRoundData|getPrice|priceOf|aggregator|consult\s*\(|\btwap\b", src, re.I))
    multi_asset = bool(re.search(r"tokens\s*\[|tokens\.length|tokenInfo|acceptedToken|whitelist|accepting", src, re.I))
    if multi_asset and not has_oracle:
        mint_tok = False; redeem_tok = False
        for fname, header, body in fn_bodies(src):
            m2 = re.search(r"\(\s*address\s+(\w+)\s*,\s*uint\w*\s+\w+\s*\)", header)   # exactly (address tok, uint amt)
            if not m2: continue
            t = re.escape(m2.group(1))
            if re.search(r"_mint\s*\(", body):
                mint_tok = True
            if re.search(r"_burn\s*\(", body) and re.search(
                    r"IERC20\s*\(\s*%s\s*\)\s*\.\s*(safeTransfer|transfer)\s*\(|(?<![\w.])%s\s*\.\s*safeTransfer\s*\(" % (t, t), body):
                redeem_tok = True
        if mint_tok and redeem_tok:
            hits.append("D8:face-value-basket (mint any token at par + caller-picks redeem asset, no oracle — depeg-arb/RangePool class)")
    return sorted(set(hits))

def feeds(chain):
    base = f"https://api.geckoterminal.com/api/v2/networks/{chain}/"
    return [base+f"new_pools?page={p}" for p in range(1,11)] + [base+f"trending_pools?page={p}" for p in range(1,4)]

def main():
    chains = sys.argv[1:] or ["bsc","base","ethereum"]
    LO, HI = 2_000, 3_000_000
    seen=set(); cands={}
    for chain in chains:
        cid = CHAINID.get(chain)
        for u in feeds(chain):
            d = json.loads(get(u) or "{}")
            for p in d.get("data", []):
                a = p.get("attributes",{})
                liq = float(a.get("reserve_in_usd") or 0)
                try: tok = p["relationships"]["base_token"]["data"]["id"].split("_")[-1]
                except Exception: continue
                if not (LO <= liq <= HI): continue
                key=(chain,tok.lower())
                if key in seen: continue
                seen.add(key); cands[key]=max(cands.get(key,0),liq)
            time.sleep(0.25)
    print(f"# {len(cands)} fresh pooled tokens in ${LO:,}-${HI:,} band across {chains}; fetching source + detecting...\n")
    flagged=[]; verified=0; unverified=0
    for (chain,tok),liq in sorted(cands.items(), key=lambda x:-x[1]):
        src,name = es_source(tok, CHAINID[chain])
        if not src or len(src)<400: unverified+=1; continue   # unverified -> skip (can't audit)
        verified+=1
        hits = detect(src)
        if hits:
            flagged.append((liq,chain,tok,name,hits))
        time.sleep(0.12)
    print(f"# coverage: {verified} verified-source scanned, {unverified} unverified-skipped")
    flagged.sort(reverse=True)
    print(f"=== {len(flagged)} FRESH TOKENS WITH A SELF-CONTAINED BUG CLASS (review + disclose) ===")
    for liq,chain,tok,name,hits in flagged:
        print(f"  ${liq:>10,.0f}  {chain:<9} {tok}  {name[:20]:<20} {', '.join(hits)}")
    json.dump([{"liq":f[0],"chain":f[1],"token":f[2],"name":f[3],"hits":f[4]} for f in flagged],
              open("D:/CLAUDE/vuln_token_queue.json","w"), indent=1)
    if not flagged: print("  (no self-contained bug-class match in band this run — re-run later; fresh deploys rotate)")
    print(f"\n# wrote -> D:/CLAUDE/vuln_token_queue.json | DISCLOSURE-ONLY: review, then warn/report. Never drain.")

if __name__ == "__main__":
    main()
