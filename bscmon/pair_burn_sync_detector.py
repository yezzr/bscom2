# Detects the "permissionless burn-from-PAIR + sync() reserve-deflation" class
# (AIDC $120k, Angel20-class). Root: a transfer/sell path burns tokens FROM the uniswapPair
# balance (not the seller) then calls pair.sync(), deflating the AMM reserve -> price manipulation.
#
# TIERING (FP-hardened 2026-06-29 after a band FP test: 0 false HIGH, MEDIUM 2.9% pre-tighten):
#   HIGH   = accumulated-burn-debt variant (AIDC): a SELL accrues a burn debt that is later
#            charged to the POOL -> unbounded, attacker-amplifiable, the proven-drain shape.
#   MEDIUM = permissionless burn-from-pair + sync that is NOT rate-limited and NOT owner-gated
#            (an attacker can repeat it) -> real reserve-manip lead, needs a profit check.
#   LOW    = rate-limited / time-gated / owner-gated burn-from-pair (the benign SafeMoon/Angel20
#            "auto-nuke" family) -> still flagged for review, but bounded -> low priority.
# Burn-match is strict: the destination MUST be a dead/zero sink, so a `pair != address(0)`
# null-check no longer false-fires (the DOG FP).
import re, sys

# a dead/zero SINK as the destination ARG (named or literal), matched case-insensitively so
# checksummed `0xdEaD`, `BLACK_ADDRESS`, `blackHole`, `deadWallet`, `0x000..0`, `address(0)` all hit.
DEST_SINK = re.compile(r'(dead|black|hole|burn|destroy|incinerat|zero|0x0{6,}|address\(\s*0\s*\))', re.I)

def detect(src):
    s = src; finds = []
    pair_vars = {v for v in set(re.findall(r'\b(\w*[pP]air\w*)\b', s)) if 'pair' in v.lower()} or {'uniswapPair'}
    burns_pair = False; burn_ctx = ''; burn_pos = -1
    for pv in pair_vars:
        p = re.escape(pv)
        # an ACTUAL burn FROM the pair: a move(pair -> dead-sink) or _burn(pair). The 2nd arg of a
        # move MUST be a dead sink (so a `pair != address(0)` null-check no longer false-fires).
        for pat, has_dest in (
                (r'(?:super\.)?_update\s*\(\s*' + p + r'\s*,\s*([^,)]+)', True),
                (r'_(?:token)?[Tt]ransfer\s*\(\s*' + p + r'\s*,\s*([^,)]+)', True),
                (r'_burn\s*\(\s*' + p + r'\b', False),
                (r'\bburn(?:From)?\s*\(\s*' + p + r'\b', False)):
            for m in re.finditer(pat, s):
                if (not has_dest) or DEST_SINK.search(m.group(1)):
                    burns_pair = True; burn_pos = m.start(); burn_ctx = s[max(0, m.start() - 30):m.start() + 95].strip(); break
            if burns_pair: break
        if burns_pair: break
    has_sync = bool(re.search(r'\.sync\s*\(\s*\)', s))
    if not (burns_pair and has_sync):
        return finds
    # --- tiering signals ---
    accum = bool(re.search(r'accumulat\w*[Bb]urn|burn[Dd]ebt|pendingBurn', s)) or \
            bool(re.search(r'accumulat\w*\s*\+=', s))
    # rate-limited / time-bucketed / SafeMoon-auto-LP-burn family = bounded deflation = benign
    rate_limited = bool(re.search(
        r'(lastBurn|burnInterval|burnCooldown|deflationInterval|lastDeflation|_todayMidnight|'
        r'nextBurn|burnTime|now[Hh]our|last[Hh]our|now[Dd]ay|last[Dd]ay|perHour|perDay|hourly|daily|'
        r'lpBurnFrequency|lastLpBurnTime|percentForLPBurn|autoBurnEnable|autoBurnLiquidity|burnFrequency|'
        r'block\.timestamp\s*[-]\s*last|>=\s*last\w*[Tt]ime|>\s*last\w*[Tt]ime|swapInterval|\binterval\b)', s, re.I))
    # burn reachable only behind a privileged modifier = not permissionless = benign-ish.
    # Check the FUNCTION ENCLOSING the burn site for any only<Role> modifier (incl. short ones like onlyA).
    owner_gated = False
    if not accum and burn_pos >= 0:
        fstart = s.rfind('function', 0, burn_pos)
        if fstart >= 0:
            br = s.find('{', fstart)
            hdr = s[fstart:br if br > 0 else fstart + 200]
            owner_gated = bool(re.search(r'\bonly[A-Z]\w*', hdr))
    if accum:
        sev = 'HIGH'
    elif rate_limited or owner_gated:
        sev = 'LOW'
    else:
        sev = 'MEDIUM'
    finds.append((sev, 'PAIR-BURN-SYNC-RESERVE-MANIP',
        'burns from pair to dead + sync() -> reserve deflation. accum-debt=%s rate-limited=%s owner-gated=%s' % (accum, rate_limited, owner_gated),
        burn_ctx[:80]))
    return finds

if __name__ == '__main__':
    src = open(sys.argv[1], encoding='utf-8', errors='ignore').read()
    f = detect(src)
    for sv, t, why, ctx in f: print('[%s] %s -- %s | %s' % (sv, t, why, ctx))
    print('VERDICT:', 'PAIR-BURN-SYNC EXPLOIT CLASS' if f else 'clean')
