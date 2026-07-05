#!/usr/bin/env python3
"""
autoswap_detector.py — finds tokens vulnerable to the ATM-style FORCED ZERO-SLIPPAGE TREASURY DUMP:
a token whose _transfer/transferFrom triggers a DEX swap of its OWN balance with minOut hardcoded 0,
sized by the (attacker-controlled) transfer amount -> sandwichable treasury drain.

Output = DISCLOSURE material (vuln + signals + contact info) for responsible email disclosure to the team.
NOT an exploit. We find & report; we do not drain.

Usage:
  python autoswap_detector.py <token_addr> [...] [--chain bsc]
  python autoswap_detector.py --scan-bsc-trending      (pull candidate BSC tokens from DexScreener + scan)
"""
import sys, json, re, urllib.request

CHAIN_ID = {"bsc": 56, "ethereum": 1, "base": 8453, "arbitrum": 42161}
SWAP_FNS = r"swapExactTokensForTokens(SupportingFeeOnTransferTokens)?|swapExactTokensForETH(SupportingFeeOnTransferTokens)?|swapExactTokensForAVAX\w*"

def get(u, hdr=None):
    try:
        return urllib.request.urlopen(urllib.request.Request(u, headers=hdr or {"User-Agent":"Mozilla/5.0"}), timeout=30).read().decode("utf-8","replace")
    except Exception:
        return ""

def safe(s): return str(s).encode("ascii","replace").decode("ascii")

def sourcify_source(addr, cid):
    raw = get(f"https://sourcify.dev/server/files/any/{cid}/{addr}")
    if not raw or "Not Found" in raw[:120]:
        return None
    try:
        d = json.loads(raw); files = d.get("files", d)
        return "\n".join(f.get("content","") for f in files if str(f.get("name","")).endswith(".sol"))
    except Exception:
        return None

def analyze(src):
    sig = []
    if not re.search(SWAP_FNS, src): return (False, ["no DEX swap"])
    sig.append("DEX swap")
    if re.search(r"function\s+_transfer\b", src) or re.search(r"function\s+transferFrom\b", src):
        sig.append("transfer hook")
    vuln_minout = False
    for m in re.finditer(SWAP_FNS + r"\s*\(", src):
        args = src[m.end(): m.end()+400].split(")")[0]
        parts = [p.strip() for p in args.split(",")]
        if len(parts) >= 2 and parts[1] in ("0", "uint256(0)"): vuln_minout = True
    if vuln_minout: sig.append("minOut==0 (no slippage guard)")
    if re.search(r"balanceOf\s*\(\s*address\(this\)\s*\)", src): sig.append("dumps own balance")
    if re.search(r"amount\s*\*\s*\w+\s*/\s*100", src) or re.search(r"SellRate|sellToFund|numTokensSell", src): sig.append("amount-scaled dump")
    is_vuln = "minOut==0 (no slippage guard)" in sig and "DEX swap" in sig and "transfer hook" in sig
    return (is_vuln, sig)

def contacts(addr, chain):
    """DexScreener socials/website for disclosure outreach."""
    out = {}
    try:
        d = json.loads(get(f"https://api.dexscreener.com/latest/dex/tokens/{addr}"))
        for p in d.get("pairs", []) or []:
            info = p.get("info") or {}
            for w in info.get("websites", []) or []:
                out.setdefault("web", w.get("url"))
            for s in info.get("socials", []) or []:
                out.setdefault(s.get("type"), s.get("url"))
            if p.get("baseToken",{}).get("symbol"): out["symbol"] = p["baseToken"]["symbol"]
    except Exception: pass
    return out

def report(addr, chain, cid):
    src = sourcify_source(addr, cid)
    if not src:
        print(f"  {addr}: source unavailable -> skip"); return None
    vuln, sig = analyze(src)
    print(f"  {addr}: {'*** VULNERABLE' if vuln else 'not matched'}  [{', '.join(sig)}]")
    if vuln:
        c = contacts(addr, chain)
        print(f"     symbol={c.get('symbol')}  contacts: " + (", ".join(f"{k}={safe(v)}" for k,v in c.items() if k!='symbol') or "NONE found (anon deployer — disclosure likely impossible)"))
        return {"addr": addr, "signals": sig, "contacts": c}
    return None

def scan_bsc_trending():
    # DexScreener boosted/trending BSC tokens as candidate pool
    out = []
    for ep in ["https://api.dexscreener.com/token-boosts/latest/v1", "https://api.dexscreener.com/token-boosts/top/v1"]:
        try:
            d = json.loads(get(ep))
            for t in (d if isinstance(d, list) else []):
                if t.get("chainId") == "bsc" and t.get("tokenAddress"): out.append(t["tokenAddress"])
        except Exception: pass
    return list(dict.fromkeys(out))

def main():
    chain = "bsc"
    if "--chain" in sys.argv: chain = sys.argv[sys.argv.index("--chain")+1]
    cid = CHAIN_ID.get(chain, 56)
    addrs = [a for a in sys.argv[1:] if a.startswith("0x")]
    if "--scan-bsc-trending" in sys.argv:
        addrs += scan_bsc_trending(); chain="bsc"; cid=56
    print(f"# autoswap forced-dump detector (DISCLOSURE mode) | chain={chain} | {len(addrs)} tokens\n")
    hits=[]
    for a in addrs:
        r = report(a, chain, cid)
        if r: hits.append(r)
    print(f"\n# {len(hits)} vulnerable -> draft email disclosure to each team (or warn if anon). NOT to be exploited.")

if __name__ == "__main__":
    main()
