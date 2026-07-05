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
GT_PAGES = int(os.environ.get('GT_PAGES') or 6)              # GeckoTerminal pages per endpoint
WATCH_CAP = 6000                                             # cap the seen-set so state stays small
RISKY = {'PAIR-BURN-SYNC', 'PARKED-MINT', 'DOUBLE-SETTLE', 'BROKEN-PERMIT', 'FORCE-DUMP', 'DRAIN', 'BASKET-DEPEG'}

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

def gt_pools():
    """token(lower) -> (pool, liq_usd, name). Fresh + trending BSC pools from GeckoTerminal."""
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
            time.sleep(0.6)
    return out

def ds_pools():
    """token(lower) -> (pool, liq_usd, name) from DexScreener (free, no key). Sources the latest
    token profiles + boosts (a different freshness signal than GeckoTerminal), then batch-resolves
    each to its best BSC pair + liquidity. Failures degrade to {} so GT alone still works."""
    out = {}
    toks = []
    try:
        for url in ('https://api.dexscreener.com/token-profiles/latest/v1',
                    'https://api.dexscreener.com/token-boosts/latest/v1'):
            d = jget(url)
            for it in (d if isinstance(d, list) else []):
                if (it.get('chainId') or '').lower() == 'bsc':
                    ta = (it.get('tokenAddress') or '').lower()
                    if ta:
                        toks.append(ta)
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

def one_pass():
    st = load(STATE, {})
    seen = st.get('seen', {})          # token -> {verdict, name, pool, alerted}
    review_today = st.get('review_today', [])   # risky-but-unconfirmed tokens seen since the last heartbeat
    hb_date = st.get('hb_date', '')             # last calendar day a heartbeat digest was sent
    alerts = load(ALERTS, [])
    pools = gt_pools()
    for token, (pool, liq, name) in ds_pools().items():        # union DexScreener (max liquidity per token)
        if token not in pools or liq > pools[token][1]:
            pools[token] = (pool, liq, name)
    analyzed = 0
    fired = 0
    for token, (pool, liq, name) in pools.items():
        info = seen.get(token)
        if info is None:
            cn, src = getsrc(token)     # Etherscan source (no RPC)
            verdict = []
            if src:
                verdict = [x[0] + (':' + x[1] if x[1] else '') for x in run_arsenal(src)]
                g, why = detect_buy_gate(src)
                if g:
                    verdict.append('BUY-GATED:' + why[:50])
            info = {'verdict': verdict, 'name': cn or name, 'pool': pool, 'alerted': False}
            seen[token] = info
            analyzed += 1
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
        elif (liq >= MIN_LIQ_USD and not info.get('alerted') and len(review_today) < 300
              and any(v.split(':')[0] in RISKY or v.startswith('BUY-GATED') for v in info.get('verdict', []))
              and token not in {r['token'] for r in review_today}):
            # REVIEW tier: funded + a risky/gated detector fired but NOT the high-confidence class.
            # Tracked for the daily digest only (mostly false positives) — never an instant ping.
            review_today.append({'token': token, 'name': info.get('name'), 'liq': round(liq),
                                 'verdict': ' '.join(info['verdict'])[:80]})
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
                 '%d REVIEW candidates in the last ~day (risky-but-UNCONFIRMED — mostly false positives, eyeball only):' % len(review_today)]
        for r in top:
            lines.append('· %s $%d [%s] bscscan.com/token/%s' % (r['name'] or '?', r['liq'], r['verdict'], r['token']))
        if not top:
            lines.append('(none tripped even the review tier — quiet day)')
        notify('\n'.join(lines))
        review_today = []
        hb_date = today
    json.dump({'seen': seen, 'review_today': review_today, 'hb_date': hb_date}, open(STATE, 'w'))
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
