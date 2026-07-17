#!/usr/bin/env python3
"""
bsc_forward_monitor.py - 24/7 forward monitor for the fresh-BSC-deploy exploit window.
WHY: retrospective scans are blind to deploy-fund-drain-in-a-day (AIDC: ~14h funded window).
SOURCE: GeckoTerminal new_pools + trending_pools (BSC) = fresh tokens that HAVE liquidity = the
drainable ones, with liquidity given directly (no on-chain calls, no getLogs, no RPC). For each fresh
token: fetch source -> run the arsenal (pair-burn-sync HIGH/MED/LOW + parked-mint + double-settle +
drains + BUY-GATE) -> if a risky verdict AND liquidity >= threshold -> ALERT (push to phone).
WHITE-HAT: catch + warn before the attacker. Cheap enough for GitHub Actions free tier (a handful of
HTTP calls per pass). Single-pass by default (cron/Action) or --loop for a daemon. State persists in
bsc_forward_state.json. Live alerts via env: TELEGRAM_BOT_TOKEN+TELEGRAM_CHAT_ID / DISCORD_WEBHOOK /
NTFY_TOPIC. Needs ETHERSCAN_API_KEY (source fetch); no BSC RPC required.
"""
import json, os, sys, time, urllib.request, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # CWD-independent (cron/Action safe)
from arsenal_scan import getsrc, run_arsenal
try:
    from taxtoken_profitsim import detect_buy_gate
except Exception:
    def detect_buy_gate(s): return (False, '')

HOME = os.environ.get('BSC_MON_HOME') or os.path.dirname(os.path.abspath(__file__))
os.makedirs(HOME, exist_ok=True)               # never crash on a missing state dir
STATE = os.path.join(HOME, 'bsc_forward_state.json')
ALERTS = os.path.join(HOME, 'bsc_forward_alerts.json')
MIN_LIQ_USD = float(os.environ.get('MIN_LIQ_USD') or 1000)   # alert once a risky token has >=$1k drainable liquidity (user-specified floor)
GT_PAGES = int(os.environ.get('GT_PAGES') or 10)             # GeckoTerminal serves 10 pages of new_pools (200)
MON_BUDGET_S = int(os.environ.get('MON_BUDGET_S') or 480)    # per-pass analysis budget. WHY: state is saved ONLY
# at the end of one_pass(); a COLD START (fresh deploy / GitHub cache eviction) analyses every token — measured
# ~456s for 141 tokens, i.e. ~3.2s/token (getsrc is Etherscan-rate-limited) — so a ~244-token set is ~13min,
# past the workflow's 10-min (600s) timeout. A timeout kills the run BEFORE the save, so nothing commits and the
# next run repeats the same cold start => permanent deadlock (the exact bug just fixed in pairwatch). This budget
# stops analysing new tokens partway, lets the pass SAVE what it did, and the rest are picked up next pass (a
# token not yet in `seen` is simply re-analysed later). 480s leaves headroom under 600s for the heartbeat+save tail.
BSC_RPC = os.environ.get('BSC_RPC') or 'https://bsc-rpc.publicnode.com'   # eth_getCode for the bytecode tell (no key needed)
WATCH_CAP = 6000                                             # cap the seen-set so state stays small
RISKY = {'PAIR-BURN-SYNC', 'PARKED-MINT', 'DOUBLE-SETTLE', 'BROKEN-PERMIT', 'FORCE-DUMP', 'DRAIN', 'BASKET-DEPEG'}
# ENDEMIC-NOISE classes: fire on ordinary tokens, are NOT a user drain, and have been 100% false positives.
#  - FORCE-DUMP: tax-token _transfer swaps its own balance with minOut==0. The only exposure is that swap being
#    MEV-sandwiched, which costs the TOKEN'S OWN treasury, not holders. Nearly every tax token matches.
#  - BUY-GATED (alone): an owner "enable trading" gate — that's every normal launch.
# Kept in state + COUNTED in the heartbeat (so we still see the detector is alive) but never listed as a
# candidate. Reviewed 2026-07-16: all 6 digest entries were FORCE-DUMP, none referenced pair sync()/skim().
NOISE_CLASSES = {'FORCE-DUMP'}
REVIEW_CLASSES = RISKY - NOISE_CLASSES     # what actually earns a slot in the daily digest
# Fork-sim CONFIRMED clean/not-exploitable (round-trip PnL negative or untradable) — hard-suppressed
# forever so they stop reappearing in the daily digest. Tokens are immutable: clean is permanent.
CLEARED_SEED = {
    '0xe92f7fe3eaf61df28b7b75f3faab199333c42302',  # MAMEINU
    '0xeb2b7d5691878627eff20492ca7c9a71228d931d',  # CREPE (reflection fee-swap FP)
    '0x51363f073b1e4920fda7aa9e9d84ba97ede1560e',  # Contract $1.16M
    '0xb71b52428f66e7f3b724321c7c57f545fb87122c',  # DOGSHIT
    '0xebbb9ae714a21411de0e2db13c56deeee5a9b999',  # MemeToken4
    '0x31b53de90a36e5f2372797478e4e1e2ed4ca4444',  # FatTokenV5
    '0xf9ef7eedddb3546a627b286e240a574d01947410',  # FatTokenV5 (variant)
    '0xfa989cf01ec5d35b1137c41a11566a422cc57777',  # tcc
    '0x8bec537e4eabc77422a38ac3d0bcc488d4797777',  # TRUMP
    '0x35a581894377eaddd568aab6148a7df462044444',  # PRISONP
}

def is_pushworthy(verdict):
    """Only PUSH the precise/validated classes — the noisy ones (FORCE-DUMP, DRAIN, BUY-GATED-alone,
    PAIR-BURN-SYNC MEDIUM/LOW) are tracked in state but NOT pinged, to keep phone alerts high-signal.
    (Memory: every static FORCE-DUMP candidate this session was a false positive; pair-burn-sync is
    only trustworthy at the HIGH/accum-debt tier; PARKED-MINT/DOUBLE-SETTLE/BROKEN-PERMIT are precise.)"""
    for v in verdict:
        cls = v.split(':')[0]
        if cls in ('PARKED-MINT', 'DOUBLE-SETTLE', 'BROKEN-PERMIT', 'BASKET-DEPEG'):
            return True
        if cls == 'PAIR-BURN-SYNC' and 'HIGH' in v:
            return True
    return False

def notify(text):
    """Push a LIVE alert to whichever channels are configured via env vars (all optional).
    Telegram: TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID. Discord: DISCORD_WEBHOOK. ntfy: NTFY_TOPIC.
    A notify failure must NEVER break a monitor pass."""
    tok, chat = os.environ.get('TELEGRAM_BOT_TOKEN'), os.environ.get('TELEGRAM_CHAT_ID')
    if tok and chat:
        try:
            data = urllib.parse.urlencode({'chat_id': chat, 'text': text,
                                           'disable_web_page_preview': 'true'}).encode()
            urllib.request.urlopen(urllib.request.Request(
                'https://api.telegram.org/bot%s/sendMessage' % tok, data), timeout=15)
        except Exception:
            pass
    wh = os.environ.get('DISCORD_WEBHOOK')
    if wh:
        try:
            urllib.request.urlopen(urllib.request.Request(
                wh, json.dumps({'content': text}).encode(),
                {'Content-Type': 'application/json'}), timeout=15)
        except Exception:
            pass
    topic = os.environ.get('NTFY_TOPIC')
    if topic:
        try:
            urllib.request.urlopen(urllib.request.Request(
                'https://ntfy.sh/' + topic, text.encode('utf-8'),
                {'Title': 'BSC monitor alert'}), timeout=15)
        except Exception:
            pass

def jget(url):
    for _ in range(3):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'M', 'Accept': 'application/json'})
            return json.loads(urllib.request.urlopen(req, timeout=25).read())
        except Exception:
            time.sleep(0.8)
    return {}

def getcode(token):
    """Runtime bytecode via eth_getCode (public node, no key). '' on failure — never crash a pass."""
    try:
        payload = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getCode',
                              'params': [token, 'latest']}).encode()
        req = urllib.request.Request(BSC_RPC, payload, {'Content-Type': 'application/json',
                                                        'User-Agent': 'Mozilla/5.0'})
        return (json.loads(urllib.request.urlopen(req, timeout=15).read()).get('result') or '').lower()
    except Exception:
        return ''

# Burn selectors seen in the pair-burn-sync drain family (JL/BYToken/AIDC/STO). We do NOT rely on
# function NAMES (JL's burn entry is a hidden 0xb1faeac6) — any of these present alongside sync/skim is the tell.
_BURN_SELS = ('42966c68', '9dc29fac', '89afcb44', 'b1faeac6', '6b2fb3a3')  # burn(uint256)/burn(addr,uint)/pair burn/hidden/misc
_MANIP_SELS = ('fff6cae9', 'bc25cf77')     # sync() + skim() — either commits/extracts a corrupted pair reserve
_EIP1967_IMPL = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'
_EIP1967_BEACON = '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50'
def _rpc(method, params):
    try:
        payload = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        req = urllib.request.Request(BSC_RPC, payload, {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'})
        return json.loads(urllib.request.urlopen(req, timeout=15).read()).get('result')
    except Exception:
        return None
def _impl_code(token):
    """EIP-1967 proxy -> implementation code so a sync/burn in the impl isn't missed (getCode(proxy)=stub).
    Handles direct-impl-slot AND beacon proxies (factory-cloned token families). Custom proxies evade."""
    r = _rpc('eth_getStorageAt', [token, _EIP1967_IMPL, 'latest'])
    if r and int(r, 16) != 0:
        return getcode('0x' + r[-40:])
    b = _rpc('eth_getStorageAt', [token, _EIP1967_BEACON, 'latest'])          # beacon proxy
    if b and int(b, 16) != 0:
        impl = _rpc('eth_call', [{'to': '0x' + b[-40:], 'data': '0x5c60da1b'}, 'latest'])   # beacon.implementation()
        if impl and int(impl, 16) != 0:
            return getcode('0x' + impl[-40:])
    return ''
def _impl_addr(token):
    """CURRENT EIP-1967 implementation address (direct slot, or via beacon.implementation()), else None.
    Deliberately excludes EIP-1167 clones: a clone's impl is hardcoded in its stub bytecode and can NEVER change,
    so caching a clone's verdict is safe. EIP-1967 proxies are UPGRADEABLE — a clean impl can be swapped for a
    malicious one and the seen-cache would never re-score it. Recording this address is what makes a swap visible."""
    try:
        r = _rpc('eth_getStorageAt', [token, _EIP1967_IMPL, 'latest'])
        if r and int(r, 16) != 0:
            return '0x' + r[-40:]
        b = _rpc('eth_getStorageAt', [token, _EIP1967_BEACON, 'latest'])
        if b and int(b, 16) != 0:
            impl = _rpc('eth_call', [{'to': '0x' + b[-40:], 'data': '0x5c60da1b'}, 'latest'])
            if impl and int(impl, 16) != 0:
                return '0x' + impl[-40:]
    except Exception:
        return None      # unreadable -> None (never fabricate an address; a wrong one would fake a "swap")
    return None

_IMPL_PASS = {}    # token -> current impl, memoised for THIS pass (the swap check reads it twice: gate + body)
def _cur_impl(token, info):
    """Current impl if it DIFFERS from the recorded one, else None. Memoised per pass so the gate and the body
    don't each pay an RPC read. Returns None on an unreadable slot — a failed read must never look like a swap."""
    if token not in _IMPL_PASS:
        _IMPL_PASS[token] = _impl_addr(token)
    cur = _IMPL_PASS[token]
    if cur and cur.lower() != (info.get('impl') or '').lower():
        return cur
    return None

def _clone_impl(code):
    """EIP-1167 minimal-proxy (clone): impl embedded in the ~45-byte stub. Scam factories mass-clone ONE
    drain impl; the stub has no sync/burn, so parse the embedded impl and scan it. Deterministic, no RPC."""
    m = '363d3d373d3d3d363d73'
    i = code.find(m)
    if i != -1 and len(code) >= i + len(m) + 40:
        impl = '0x' + code[i + len(m):i + len(m) + 40]
        try:
            if int(impl, 16) != 0:
                return impl
        except Exception:
            pass
    return None

def _burn_from_pair(src):
    low = src.lower().replace(' ', '')
    return any(k in low for k in ('_burn(pair', '_burn(uniswap', '_burn(pancake', '_burn(targetpool', '_burn(_pair',
                                  '_burn(lppair', '_burn(pool', 'balances[pair]-=', '_balances[pair]-=', 'balanceof[pair]'))

def bytecode_burn_sync(token, src=None):
    """Pair-burn-sync tell on BYTECODE (unverified-safe). sync/skim + a burn selector -> HIGH. sync/skim WITHOUT a
    known burn selector could be a hidden-burn drain (PHX) OR a LEGIT sync-caller (e.g. a rebase/LP token). When
    VERIFIED source is available, require the burn-from-pair pattern for HIGH; verified-but-absent -> legit, drop
    (kills the $91.8M-token class of FP). Unverified -> keep HIGH (can't disambiguate; the JL/PHX hidden-burn case)."""
    own = getcode(token) or ''
    code = own + _impl_code(token)                       # + EIP-1967 direct/beacon impl
    ci = _clone_impl(own)                                # + EIP-1167 minimal-proxy clone impl
    if ci:
        code += (getcode(ci) or '')
    if not any(s in code for s in _MANIP_SELS):         # no sync()/skim() reference -> not this class
        return None
    if any(s in code for s in _BURN_SELS):
        return 'PAIR-BURN-SYNC:SYNC/SKIM+BURN(HIGH)'
    if src:                                              # verified source available -> trust it to disambiguate
        return 'PAIR-BURN-SYNC:SRC-BURN-FROM-PAIR(HIGH)' if _burn_from_pair(src) else None
    return 'PAIR-BURN-SYNC:UNVERIFIED-SYNC/SKIM(HIGH)'   # unverified -> keep HIGH (hidden-burn class)

def gt_pools():
    """token(lower) -> (pool, liq_usd, name). Fresh + trending BSC pools from GeckoTerminal.

    RATE LIMIT (measured 2026-07-17): GeckoTerminal allows ~30 calls/min. This slept 0.6s between pages =
    ~100/min, so it was being 429'd PART-WAY THROUGH every pass and silently returning partial pools — the
    feed looked fine, it just quietly stopped early. (It also fooled me into declaring trending_pools "dead":
    a burst test 429'd it to 0 rows. Spaced out it serves 20/page.) 2.5s/page keeps us inside the limit;
    GT_PAGES=10 x 2 endpoints x 2.5s = ~50s per pass, which is nothing on a 10-min cron."""
    out = {}
    for path in ('new_pools', 'trending_pools'):
        for pg in range(1, GT_PAGES + 1):
            d = jget('https://api.geckoterminal.com/api/v2/networks/bsc/%s?page=%d' % (path, pg))
            rows = d.get('data') or []
            for p in rows:
                attr = p.get('attributes', {}) or {}
                pool = attr.get('address', '')
                liq = float(attr.get('reserve_in_usd') or 0)
                nm = attr.get('name', '') or ''
                bt = (((p.get('relationships', {}) or {}).get('base_token', {}) or {}).get('data') or {}).get('id', '')
                if bt.startswith('bsc_') and pool:
                    a = bt.split('_', 1)[1].lower()
                    if a not in out or liq > out[a][1]:
                        out[a] = (pool, liq, nm)
            if not rows:
                break
            time.sleep(2.5)          # GT allows ~30 calls/min; 0.6s = 100/min = silent 429s mid-pass
    return out

def ds_pools():
    """token(lower) -> (pool, liq_usd, name) from DexScreener (free, no key). Sources the latest
    token profiles + boosts (a different freshness signal than GeckoTerminal), then batch-resolves
    each to its best BSC pair + liquidity. Failures degrade to {} so GT alone still works."""
    out = {}
    toks = []
    try:
        # MEASURED 2026-07-17: token-profiles/latest and token-boosts/latest are PAID-PROMOTION feeds — 30 items
        # each, ZERO on BSC — so this whole lane returned {} and contributed nothing while looking alive. The
        # search endpoint actually returns live BSC pairs; query the quote assets every BSC pair is priced in.
        for q in ('WBNB', 'USDT', 'USDC', 'BUSD', 'CAKE'):
            d = jget('https://api.dexscreener.com/latest/dex/search?q=' + q)
            for p in (d.get('pairs') or []):
                if (p.get('chainId') or '').lower() != 'bsc':
                    continue
                base = ((p.get('baseToken') or {}).get('address') or '').lower()
                pool = p.get('pairAddress') or ''
                liq = float(((p.get('liquidity') or {}).get('usd')) or 0)
                nm = (p.get('baseToken') or {}).get('symbol') or ''
                if base and pool and (base not in out or liq > out[base][1]):
                    out[base] = (pool, liq, nm)          # search already carries pool+liq: no second lookup needed
            time.sleep(0.4)
        toks = list(dict.fromkeys(toks))                       # dedup, keep order
        for i in range(0, len(toks), 30):                      # DexScreener tokens endpoint takes up to 30 comma-joined
            d = jget('https://api.dexscreener.com/latest/dex/tokens/' + ','.join(toks[i:i + 30]))
            for p in (d.get('pairs') or []):
                if (p.get('chainId') or '').lower() != 'bsc':
                    continue
                base = ((p.get('baseToken') or {}).get('address') or '').lower()
                pool = p.get('pairAddress') or ''
                liq = float(((p.get('liquidity') or {}).get('usd')) or 0)
                nm = (p.get('baseToken') or {}).get('symbol') or ''
                if base and pool and (base not in out or liq > out[base][1]):
                    out[base] = (pool, liq, nm)
            time.sleep(0.4)
    except Exception:
        pass
    return out

def load(p, d):
    try:
        return json.load(open(p))
    except Exception:
        return d

def _str_set(v):
    """Coerce a persisted value into a set of lowercased address strings, tolerating ANY legacy/corrupt shape.
    WHY: new code loads OLD cached state on deploy. noise_today shipped first as an INT counter, later as a set
    (stored as a sorted list); `set(x.lower() for x in <int>)` -> TypeError -> the monitor crashes EVERY run on
    the old cache = dead on arrival. Never trust the stored type; degrade to empty rather than crash."""
    if isinstance(v, (list, tuple, set)):
        return {str(x).lower() for x in v if isinstance(x, str)}
    return set()

def one_pass():
    _t0 = time.time()          # per-pass clock -> MON_BUDGET_S time-boxes new-token analysis (cold-start guard)
    st = load(STATE, {})
    seen = st.get('seen', {})          # token -> {verdict, name, pool, alerted}
    if not isinstance(seen, dict):     # legacy/corrupt state (e.g. seen persisted as a list) -> seen.get() would
        seen = {}                      # crash on every token; reset rather than die (tokens re-analysed next pass)
    review_today = st.get('review_today', []) if isinstance(st.get('review_today'), list) else []   # risky-but-unconfirmed since last heartbeat
    # endemic FORCE-DUMP/BUY-GATED hits: counted, never listed. A SET (not a counter) because suppressed tokens
    # are never added to `reviewed`/`review_today`, so every cron pass re-evaluates them — an int would count the
    # same token once per pass (~48x/day) and report a wildly inflated number.
    noise_today = _str_set(st.get('noise_today'))     # tolerant of the legacy INT-counter shape (would crash)
    hb_date = st.get('hb_date', '')             # last calendar day a heartbeat digest was sent
    # PERSISTENT DEDUP: a token surfaced in a prior heartbeat digest (reviewed) or fork-confirmed
    # clean (cleared) must NEVER be re-listed — tokens are immutable, so a clean verdict is permanent.
    # This kills the "same tokens reported every single day" noise.
    reviewed = _str_set(st.get('reviewed'))                      # already shown in a past digest
    cleared = _str_set(st.get('cleared')) | CLEARED_SEED         # fork-confirmed clean / not-exploitable, hard-suppress
    alerts = load(ALERTS, [])
    pools = gt_pools()
    for token, (pool, liq, name) in ds_pools().items():        # union DexScreener (max liquidity per token)
        if token not in pools or liq > pools[token][1]:
            pools[token] = (pool, liq, name)
    analyzed = 0
    fired = 0
    budget_hit = False
    for token, (pool, liq, name) in pools.items():
        if time.time() - _t0 > MON_BUDGET_S:
            # out of time this pass -> STOP analysing (break, don't return) so the heartbeat + state save still
            # run and commit what we did. Un-analysed tokens aren't in `seen`, so next pass picks them up.
            budget_hit = True
            print('budget %ds hit; analysed %d, deferring rest to next pass' % (MON_BUDGET_S, analyzed), flush=True)
            break
        info = seen.get(token)
        if info is None:
            cn, src = getsrc(token)     # Etherscan source (no RPC)
            verdict = []
            if src:
                verdict = [x[0] + (':' + x[1] if x[1] else '') for x in run_arsenal(src)]
                g, why = detect_buy_gate(src)
                if g:
                    verdict.append('BUY-GATED:' + why[:50])
            # BYTECODE tell — runs on EVERY token incl. UNVERIFIED (the JL gap: JL had no source so the
            # source arsenal above saw nothing). Catches the pair-burn-sync drain class by capability.
            bts = bytecode_burn_sync(token, src)   # pass the already-fetched source -> verified-source FP filter
            if bts:
                verdict.append(bts)
            # remember WHETHER the verdict was formed without source. A fresh deploy is usually analyzed before
            # the dev verifies it, so src='' -> the FP filter cannot run -> UNVERIFIED-SYNC/SKIM(HIGH). Cached
            # forever, that becomes a PERMANENT false HIGH even after the source appears. (SIMP: verified later,
            # burns its OWN balance and DONATES to the pair -> the filter drops it once source is readable.)
            info = {'verdict': verdict, 'name': cn or name, 'pool': pool, 'alerted': False,
                    'nosrc': not bool(src), 'impl': _impl_addr(token)}
            seen[token] = info
            analyzed += 1
        elif info.get('impl') and _cur_impl(token, info) is not None:
            # UPGRADEABLE proxy whose IMPLEMENTATION CHANGED since we scored it. The seen-cache scores a token
            # exactly once, so a proxy that was clean and is later upgraded to a drain would NEVER be re-scored —
            # and an impl swap on an already-FUNDED token is precisely the rug-via-upgrade pattern. Re-analyze the
            # NEW impl and clear `alerted` so a newly-malicious upgrade can page. (Unreadable -> no swap claimed;
            # never re-score on a failed read.)
            old_impl = info.get('impl')                  # capture BEFORE overwrite (the notify prints both)
            new_impl = _cur_impl(token, info)
            cn3, src3 = getsrc(token)
            v3 = []
            if src3:
                v3 = [x[0] + (':' + x[1] if x[1] else '') for x in run_arsenal(src3)]
                g3, why3 = detect_buy_gate(src3)
                if g3:
                    v3.append('BUY-GATED:' + why3[:50])
            bts3 = bytecode_burn_sync(token, src3)
            if bts3:
                v3.append(bts3)
            print('*** IMPL SWAP %s: %s -> %s | verdict %s' % (token, old_impl, new_impl, v3), flush=True)
            info['verdict'] = v3; info['impl'] = new_impl; info['nosrc'] = not bool(src3)
            info['name'] = cn3 or info.get('name')
            info['alerted'] = False            # a new impl is a NEW risk -> let the alert path re-evaluate it
            if is_pushworthy(v3):
                notify('BSC PROXY UPGRADE + risky\n%s\nimpl swapped %s -> %s\nliq ~$%d\n%s\nhttps://bscscan.com/token/%s'
                       % (info.get('name') or '?', old_impl, new_impl, liq, ' '.join(v3), token))
        elif any('UNVERIFIED' in v for v in info.get('verdict', [])) and info.get('recheck_n', 0) < 8:
            # RE-CHECK only tokens whose verdict RESTS ON "unverified source" — the FP-prone class. Gating on the
            # VERDICT STRING (not a new 'nosrc' field) matters twice over: (1) it works on ALREADY-CACHED entries,
            # so SIMP — which predates the field — actually gets re-checked; (2) it's a handful of tokens, not the
            # ~6k watched set, so we don't re-fetch source for every never-verified scam deploy on every pass
            # (that'd be ~20min/pass at Etherscan's 5/sec and would break the Action). Capped at 8 tries: a token
            # the dev never verifies must not be retried forever.
            info['recheck_n'] = info.get('recheck_n', 0) + 1
            cn2, src2 = getsrc(token)
            if src2:
                v2 = [x[0] + (':' + x[1] if x[1] else '') for x in run_arsenal(src2)]
                g2, why2 = detect_buy_gate(src2)
                if g2:
                    v2.append('BUY-GATED:' + why2[:50])
                bts2 = bytecode_burn_sync(token, src2)
                if bts2:
                    v2.append(bts2)
                old_verdict = list(info.get('verdict', []))          # capture BEFORE overwrite
                was_push = is_pushworthy(old_verdict) and info.get('alerted')
                info['verdict'] = v2; info['nosrc'] = False; info['rechecked'] = True
                info['name'] = cn2 or info.get('name')
                if was_push and not is_pushworthy(v2):
                    # we already paged on an unverified-source guess that the source now disproves -> RETRACT.
                    # Leaving a false HIGH standing is how a warn-lane loses credibility.
                    notify('BSC alert RETRACTED (source now verified)\n%s\nwas: %s\nnow: %s\n'
                           'The earlier HIGH rested on UNVERIFIED source; published source clears it.\n'
                           'https://bscscan.com/token/%s'
                           % (info.get('name') or '?', ' '.join(old_verdict) or '-',
                              ' '.join(v2) or 'clean', token))
        if token.lower() in cleared:
            continue                                            # fork-confirmed clean — never alert or review again
        if is_pushworthy(info.get('verdict', [])) and not info.get('alerted') and liq >= MIN_LIQ_USD:
            info['alerted'] = True
            fired += 1
            rec = {'token': token, 'name': info.get('name'), 'pool': pool, 'liq_usd': round(liq),
                   'verdict': info['verdict'], 'note': 'HIGH-CONFIDENCE risky + funded',
                   'ts': time.strftime('%Y-%m-%d %H:%M')}
            alerts.append(rec)
            print('*** ALERT %s (%s) $%d %s' % (token, info.get('name'), liq, info['verdict']), flush=True)
            notify('BSC fresh-deploy ALERT\n%s — %s\nliq ~$%d\n%s\ntoken: %s\nhttps://bscscan.com/token/%s'
                   % (info.get('name') or '?', rec['note'], liq, ' '.join(info['verdict']), token, token))
        elif (liq >= MIN_LIQ_USD and not info.get('alerted')
              and token.lower() not in reviewed         # never re-surface a token shown in a prior digest
              and token not in {r['token'] for r in review_today}):
            vs = info.get('verdict', [])
            classes = {v.split(':')[0] for v in vs}
            if classes & REVIEW_CLASSES:
                # REVIEW tier: funded + a real risky class fired but NOT the high-confidence push tier.
                # The cap is checked INSIDE: a drain-class token must never fall through to the noise bucket
                # just because the digest is full (it also carrying FORCE-DUMP would have mis-binned it).
                if len(review_today) < 300:
                    review_today.append({'token': token, 'name': info.get('name'), 'liq': round(liq),
                                         'verdict': ' '.join(vs)[:80]})
            elif (classes & NOISE_CLASSES) or any(v.startswith('BUY-GATED') for v in vs):
                # endemic pattern (sandwichable tax-swap / trading gate) -> COUNT it so we know the detector is
                # alive, but never list it. Listing these is what made the digest 100% noise.
                if len(noise_today) < 20000:            # bound state growth if a digest ever fails to fire
                    noise_today.add(token.lower())
    # prune the seen-set: always keep alerted, then newest others up to the cap
    if len(seen) > WATCH_CAP:
        alerted = {k: v for k, v in seen.items() if v.get('alerted')}
        others = [k for k in seen if not seen[k].get('alerted')]
        room = max(0, WATCH_CAP - len(alerted))
        seen = {**alerted, **{k: seen[k] for k in others[-room:]}}
    # daily heartbeat + REVIEW digest — fires once per calendar day so you always know it's alive
    today = time.strftime('%Y-%m-%d')
    if today != hb_date:
        top = sorted(review_today, key=lambda r: -r['liq'])[:10]
        lines = ['BSC monitor — daily heartbeat ✅ alive.',
                 'Scanned %d pools, watching %d tokens, %d confirmed alerts all-time.' % (len(pools), len(seen), len(alerts)),
                 '%d REVIEW candidates in the last ~day (drain-class only — eyeball):' % len(review_today)]
        for r in top:
            lines.append('· %s $%d [%s] bscscan.com/token/%s' % (r['name'] or '?', r['liq'], r['verdict'], r['token']))
        if not top:
            lines.append('(no drain-class candidates — quiet day)')
        if noise_today:
            # observability without noise: prove the detectors ran without pasting endemic tax tokens
            lines.append('(+%d endemic FORCE-DUMP/BUY-GATED hits suppressed — sandwichable tax-swap, not a user drain)'
                         % len(noise_today))
        notify('\n'.join(lines))
        # mark everything surfaced this digest as reviewed so it NEVER repeats in a future heartbeat
        for r in review_today:
            reviewed.add(r['token'].lower())
        if len(reviewed) > 20000:                       # bound the ledger (addresses only)
            reviewed = set(list(reviewed)[-20000:])
        review_today = []
        noise_today = set()                             # reset with the digest window, else it grows forever
        hb_date = today
    json.dump({'seen': seen, 'review_today': review_today, 'noise_today': sorted(noise_today), 'hb_date': hb_date,
               'reviewed': sorted(reviewed), 'cleared': sorted(cleared)}, open(STATE, 'w'))
    json.dump(alerts, open(ALERTS, 'w'), indent=1)
    print('%s | pools(GT+DS) %d | newly analyzed %d | seen %d | review %d | alerts this pass %d (total %d)'
          % (time.strftime('%H:%M:%S'), len(pools), analyzed, len(seen), len(review_today), fired, len(alerts)), flush=True)
    # SELFTEST: when set (manual runs), ping Telegram to prove the deployed runner->Telegram path is
    # alive. Scheduled runs leave this unset and stay silent unless there's a real precise+funded hit.
    if os.environ.get('SELFTEST', '').strip().lower() in ('1', 'true', 'yes'):
        notify('BSC monitor SELF-TEST — pipeline alive on GitHub.\n'
               'Scanned %d fresh pools this pass; %d real alert(s). '
               'Scheduled runs stay silent unless a precise + funded hit.' % (len(pools), fired))

if __name__ == '__main__':
    # When launched windowless (cron/Action with no console) redirect output to a logfile, and dodge
    # any console-close signal. Use --stdout to keep console/journald output instead.
    if '--stdout' not in sys.argv:
        try:
            sys.stdout = sys.stderr = open(os.path.join(HOME, 'bsc_forward_monitor.log'), 'a', buffering=1, encoding='utf-8')
        except Exception:
            pass
    if '--loop' in sys.argv:
        i = sys.argv.index('--loop')
        period = int(sys.argv[i + 1]) if len(sys.argv) > i + 1 else 120
        print('forward monitor (GeckoTerminal source): looping every %ds' % period, flush=True)
        while True:
            try:
                one_pass()
            except Exception as e:
                print('pass error:', e, flush=True)
            time.sleep(period)
    else:
        one_pass()
