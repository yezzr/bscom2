#!/usr/bin/env python3
# DLMC-class detector: "price-inflation via parked mint".
# Root cause (DLMC $222K, BSC, 2026-06-24): an internal price = reserve / circulating, where a buy/deposit
# raises the reserve (numerator) but mints the bought tokens to address(this) so they're subtracted out of
# circulating (denominator) -> a flash-funded buy spikes the price; pre-held circulating tokens then dump at the spike.
# TELLS:
#   P) a price/rate var assigned X/Y where Y = a supply/circulating term that SUBTRACTS balanceOf(address(this)),
#      and X derives from a quoteToken.balanceOf(address(this)) reserve.
#   M) a value-in fn (transferFrom/safeTransferFrom into the contract) that ALSO _mint(address(this), ...).
# Both present = the asymmetry. Validated to fire on DLMC.
import re, sys

def fns(src):
    out=[]
    for m in re.finditer(r'function\s+([A-Za-z_]\w*)\s*\([^)]*\)([^\{;]*)\{', src):
        i=m.end()-1; depth=0; j=i
        while j<len(src):
            if src[j]=='{': depth+=1
            elif src[j]=='}':
                depth-=1
                if depth==0: break
            j+=1
        out.append((m.group(1), src[i:j+1]))
    return out

CIRC_MINUS_SELF = re.compile(r'(totalSupply\s*\(\s*\)|_?total\w*|supply)\b[\s\S]{0,200}?-\s*[\s\S]{0,40}?balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)', re.I)
RESERVE_SELF    = re.compile(r'\.\s*balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)')
PRICE_ASSIGN    = re.compile(r'(price|rate|pps|pricePer|livePrice)\w*\s*=\s*[^;]*?/[^;]*?;', re.I)
VALUE_IN        = re.compile(r'(safeTransferFrom|transferFrom)\s*\([^)]*address\s*\(\s*this\s*\)')
MINT_SELF       = re.compile(r'_?mint\s*\(\s*address\s*\(\s*this\s*\)')

def _circ_minus_self(body):
    # inline: supply ... - balanceOf(address(this))
    if CIRC_MINUS_SELF.search(body): return True
    # variable indirection: X = balanceOf(address(this));  ... <denominator> - X
    for vm in re.finditer(r'(\w+)\s*=\s*balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)', body):
        v=vm.group(1)
        if re.search(r'-\s*'+re.escape(v)+r'\b', body): return True
    return False

def detect(src):
    finds=[]
    # P: a price-update fn that divides a self-reserve by a circulating-minus-self denominator
    for name,body in fns(src):
        has_price_div = bool(PRICE_ASSIGN.search(body)) or bool(re.search(r'(newPrice|price|rate)\w*\s*=\s*[^;]*/[^;]*;',body,re.I))
        if has_price_div and _circ_minus_self(body) and RESERVE_SELF.search(body):
            finds.append(('PRICE_RESERVE_OVER_CIRCULATING', name,
                'price computed as self-reserve / (supply - balanceOf(this)) -> denominator excludes contract-parked tokens'))
            break
    # M: a value-in fn that mints to self (parks the bought tokens)
    for name,body in fns(src):
        if VALUE_IN.search(body) and MINT_SELF.search(body):
            finds.append(('PARKED_MINT_ON_BUY', name,
                '%s() pulls quote token IN and _mint(address(this)) -> bought tokens parked in contract, not circulating'%name))
            break
    exploitable = any(f[0]=='PRICE_RESERVE_OVER_CIRCULATING' for f in finds) and any(f[0]=='PARKED_MINT_ON_BUY' for f in finds)
    return exploitable, finds

if __name__=='__main__':
    src=open(sys.argv[1],encoding='utf-8',errors='ignore').read()
    exp,finds=detect(src)
    print('=== parked-mint price-inflation detector ===')
    for tag,fn,why in finds: print('  [%s] %s -> %s'%(tag,fn,why))
    print('\nVERDICT:', 'EXPLOITABLE (DLMC-class price inflation)' if exp else 'not a match')
