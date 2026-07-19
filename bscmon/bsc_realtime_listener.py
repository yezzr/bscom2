#!/usr/bin/env python3
"""
bsc_realtime_listener.py — the INSTANT-detection front-end (replaces the lagging GeckoTerminal poll).

The gap it fixes: the cron+aggregator monitor surfaced tokens HOURS after launch (GeckoTerminal only
lists a pool once indexed / trending, + up to 30min cron), so we saw tokens near their RUG, not their
BIRTH. Liquidity-deposit is an ON-CHAIN event — so we watch the chain directly: subscribe to PancakeSwap
V2 `PairCreated` over an Alchemy websocket -> fires within ~1 block (~0.5s) of a new pair. The moment a
pair appears with a real base-asset reserve, we pull source, run the arsenal, and (for the FP-heavy
FORCE-DUMP class) fork-sim CONFIRM before pinging. Precise classes ping instantly.

HOSTING: this is a PERSISTENT process (a websocket listener) — GitHub Actions CANNOT host it (batch
scheduler). Run it on an always-on host: a free VM (Oracle Cloud free tier / Fly.io / Railway) or adapt
`handle_pair()` behind an Alchemy-webhook -> Cloudflare Worker for a serverless variant. Env: ALCHEMY_KEY
(or BSC_WSS_URL), TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, [MIN_LIQ_USD], [CONFIRM=1 to fork-sim gate].

WHITE-HAT / ~$0 EV on these $1k tokens — value is being in-window on the RARE genuinely-exploitable
fresh deploy, to warn before the attacker. Not for draining.
"""
import os, json, asyncio, threading, time, urllib.request, urllib.parse
try:
    import websockets
except Exception:
    websockets = None
from arsenal_scan import getsrc, run_arsenal
try:
    from bsc_forward_monitor import notify, is_pushworthy
    try: from bsc_forward_monitor import detect_buy_gate
    except Exception:
        def detect_buy_gate(s): return (False, '')
    # BYTECODE detector (unverified-safe). WITHOUT this the realtime lane skipped every UNVERIFIED token
    # ("v1; bytecode mode is a later add") -> blind to the FCOW/0x8837 pair-burn-sync class in real time,
    # which is the exact class that drained. This is the whole point of the fast lane.
    try: from bsc_forward_monitor import bytecode_burn_sync
    except Exception:
        def bytecode_burn_sync(token, src=None): return None
except Exception:
    def notify(t): print('[NOTIFY]', t)
    def is_pushworthy(v):
        for x in v:
            if x.split(':')[0] in ('PARKED-MINT','DOUBLE-SETTLE','BROKEN-PERMIT','BASKET-DEPEG'): return True
            if x.split(':')[0]=='PAIR-BURN-SYNC' and 'HIGH' in x: return True
        return False
    def detect_buy_gate(s): return (False, '')
    def bytecode_burn_sync(token, src=None): return None

# Endpoints: prefer Alchemy (reliable log streaming) when ALCHEMY_KEY is set as a SECRET (safe on a public
# repo — it's not in code); fall back to keyless publicnode. publicnode's free pool is flaky for log subs.
_AK = os.environ.get('ALCHEMY_KEY')
WSS = os.environ.get('BSC_WSS_URL') or (
    'wss://bnb-mainnet.g.alchemy.com/v2/%s' % _AK if _AK else 'wss://bsc-rpc.publicnode.com')
HTTP = os.environ.get('BSC_RPC_URL') or (
    'https://bnb-mainnet.g.alchemy.com/v2/%s' % _AK if _AK else 'https://bsc-rpc.publicnode.com')
MIN_LIQ_USD = float(os.environ.get('MIN_LIQ_USD') or 1000)
CONFIRM = os.environ.get('CONFIRM', '1') == '1'    # fork-sim confirm the FP-heavy FORCE-DUMP class before ping
HEARTBEAT_SECS = int(os.environ.get('HEARTBEAT_SECS') or 7200)   # visibility ping every 2h (proves alive+working)
STATS = {'pairs': 0, 'funded': 0, 'alerts': 0, 'start': time.time()}   # for the heartbeat

# both PancakeSwap factories — fresh liquidity lands on V2 AND V3 now
FACTORY_V2 = '0xca143ce32fe78f1f7019d7d551a6402fc5350c73'
FACTORY_V3 = '0x0bfbcf9fa4f9c56b0f40a671ad40e0805a091865'
PAIRCREATED = '0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9'   # V2 PairCreated
POOLCREATED = '0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118'   # V3 PoolCreated
# base assets we can value the drainable side in (addr -> (symbol, usd_per_token, decimals))
BASES = {
    '0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c': ('WBNB', 600.0, 18),
    '0x55d398326f99059ff775485246999027b3197955': ('USDT', 1.0, 18),
    '0xe9e7cea3dedca5984780bafc599bd69add087d56': ('BUSD', 1.0, 18),
    '0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d': ('USDC', 1.0, 18),
}
seen = set()

def _rpc(method, params):
    body = json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode()
    try:
        # publicnode (and most public RPCs) return 403 WITHOUT a User-Agent — required, not optional.
        return json.loads(urllib.request.urlopen(urllib.request.Request(
            HTTP, body, {'Content-Type':'application/json', 'User-Agent':'Mozilla/5.0'}), timeout=20).read()).get('result')
    except Exception:
        return None

def _balance_of(token, holder):
    """token.balanceOf(holder) via eth_call — DEX-version-agnostic (works for V2 pairs AND V3 pools)."""
    data = '0x70a08231' + '0'*24 + holder.lower().replace('0x', '')
    r = _rpc('eth_call', [{'to': token, 'data': data}, 'latest'])
    try: return int(r, 16)
    except Exception: return 0

def base_liquidity_usd(pool, token0, token1):
    """USD value of the BASE side actually held by the pool — reads base.balanceOf(pool), so it works
    for a V2 pair or a V3 pool identically (no getReserves dependency). Returns (usd, base_sym, newtoken)."""
    for tok, other in ((token0, token1), (token1, token0)):
        b = BASES.get(tok.lower())
        if b:
            sym, px, dec = b
            bal = _balance_of(tok, pool)
            return bal / (10**dec) * px, sym, other
    return 0.0, None, None

def fork_confirm(token, pair, liq):
    """Fork-sim the FORCE-DUMP class before pinging (the FP-heavy one). Returns True iff EXPLOITABLE."""
    try:
        import taxtoken_profitsim as T
        v = T.sim(token, pair, liq)
        return isinstance(v, tuple) and str(v[0]).lower().startswith('exploit')
    except Exception as e:
        print('  fork_confirm err', str(e)[:80]); return False

# A pair is CREATED with $0 liquidity; the LP is added seconds-to-minutes later in a separate tx. So we
# don't judge at creation — we WATCH the pair and re-poll its liquidity until it crosses the floor (then
# run the arsenal) or times out (never funded). This fires at the liquidity-DEPOSIT moment, not creation.
pending = {}                 # pair(lower) -> (token0, token1, first_ts)
plock = threading.Lock()
POLL_EVERY = 20              # re-check pending pairs' liquidity this often (s)
HTTP_POLL_EVERY = int(os.environ.get('HTTP_POLL_EVERY') or 5)   # redundant HTTP fast-lane cadence (WS-down cover)
HEALTHCHECK_URL = os.environ.get('HEALTHCHECK_URL')            # optional dead-man's-switch (healthchecks.io etc.)
PENDING_TTL = 900           # keep watching a new pair up to 15 min for liquidity to land
MAX_PENDING = 600           # cap the watchlist (free-endpoint rate safety)

def _process_funded(token0, token1, pair, liq, base, token):
    """Pair has crossed the liquidity floor -> pull source, run the arsenal, alert on a real class."""
    cn, src = getsrc(token)
    STATS['funded'] += 1                              # a funded pair we actually fetched + scanned
    verdict = []
    if src:                                           # source arsenal (verified tokens)
        verdict = [x[0] + (':' + x[1] if x[1] else '') for x in run_arsenal(src)]
        g, why = detect_buy_gate(src)
        if g:
            verdict.append('BUY-GATED:' + why[:50])
    # BYTECODE detector runs on EVERY token incl. UNVERIFIED (src=='' for FCOW/0x8837). This is the fix for the
    # "unverified -> skip" hole: the fast lane now catches the pair-burn-sync drain class in real time, not just
    # the poll lane. src is passed so the verified-source FP filter still applies when source IS available.
    bts = bytecode_burn_sync(token, src)
    if bts:
        verdict.append(bts)
    if not verdict:
        return
    classes = {v.split(':')[0] for v in verdict}
    precise = is_pushworthy(verdict)                  # precise classes: ping instantly
    ping, tag = precise, 'PRECISE'
    if not precise and 'FORCE-DUMP' in classes and CONFIRM:   # FP-heavy: fork-sim CONFIRM before ping
        if fork_confirm(token, pair, liq):
            ping, tag = True, 'FORK-CONFIRMED-EXPLOITABLE'
    if ping:
        STATS['alerts'] += 1
        notify('LIVE FRESH-DEPLOY [%s]  ~$%.0f %s liq\n%s (%s)\nverdict: %s\nbscscan.com/token/%s'
               % (tag, liq, base or '?', token, cn, ', '.join(verdict), token))
        print('  >>> ALERTED', token, tag, verdict, flush=True)
    else:
        print('  seen risky-but-unconfirmed', token, verdict, flush=True)

def _check_once(token0, token1, pair):
    """Cheap liquidity poll. Returns True = STOP watching (funded+processed, or no base pairing),
    False = keep watching (base-paired but not yet funded to the floor)."""
    liq, base, token = base_liquidity_usd(pair, token0, token1)
    if not token:
        return True                                   # no base asset we can value -> never a target
    if liq < MIN_LIQ_USD:
        return False                                  # base-paired but LP not deposited yet -> keep watching
    if pair.lower() in seen:
        return True
    seen.add(pair.lower())
    _process_funded(token0, token1, pair, liq, base, token)
    return True

def handle_pair(token0, token1, pair):
    """New pair created. Try once (some bots add LP in the same tx); else queue for liquidity re-poll."""
    if pair.lower() in seen: return
    try:
        done = _check_once(token0, token1, pair)
    except Exception as e:
        print('  check err', str(e)[:80]); done = False
    if not done:
        with plock:
            if len(pending) < MAX_PENDING and pair.lower() not in pending:
                pending[pair.lower()] = (token0, token1, time.time())

_last_hb = [time.time()]
def _repoll_loop():
    """Every POLL_EVERY s, re-check watched pairs' liquidity; process the instant one funds; drop on TTL.
    Also emits a periodic HEARTBEAT so silence is distinguishable from death (BSC new-pair rate is genuinely
    low, ~0.1/min, so long gaps with zero alerts are NORMAL — the heartbeat proves it's alive + processing)."""
    while True:
        time.sleep(POLL_EVERY)
        now = time.time()
        if now - _last_hb[0] >= HEARTBEAT_SECS:
            up = (now - STATS['start']) / 3600.0
            notify('listener heartbeat: %.1fh up | %d new pairs seen, %d funded+scanned, %d ALERTS | %d on liq-watchlist'
                   % (up, STATS['pairs'], STATS['funded'], STATS['alerts'], len(pending)))
            _last_hb[0] = now
        with plock:
            items = list(pending.items())
        for p, (t0, t1, ts) in items:
            drop = (p in seen) or (now - ts > PENDING_TTL)
            if not drop:
                try: drop = _check_once(t0, t1, p)    # True once funded+processed (or no base)
                except Exception: drop = False
            if drop:
                with plock: pending.pop(p, None)

_dispatched = set()
_dlock = threading.Lock()
def _dispatch(token0, token1, pair):
    """IDEMPOTENT dispatch: the WS lane AND the HTTP-poll lane both call this, so a check-and-add under a lock is
    what stops a pair being processed twice (double alert). `seen` alone wasn't enough — it's set only AFTER
    processing, leaving an in-flight race between the two lanes."""
    p = pair.lower()
    with _dlock:
        if p in _dispatched:
            return
        _dispatched.add(p)
        if len(_dispatched) > 20000:
            _dispatched.clear()             # bound memory; `seen` still dedups anything already processed
    threading.Thread(target=handle_pair, args=(token0, token1, pair), daemon=True).start()

def _healthping():
    """DEAD-MAN'S-SWITCH (fixes 'both jobs crash and you don't notice'): ping an external monitor each poll cycle.
    If BOTH overlapping listener jobs die, these pings STOP and the monitor (healthchecks.io / any uptime service)
    alerts YOU -> a total crash becomes VISIBLE instead of a silent coverage hole. Opt-in via HEALTHCHECK_URL."""
    if not HEALTHCHECK_URL:
        return
    try:
        urllib.request.urlopen(urllib.request.Request(HEALTHCHECK_URL, headers={'User-Agent': 'M'}), timeout=10)
    except Exception:
        pass

# getLogs-capable BSC nodes, ROTATED, so the HTTP fallback doesn't itself depend on one flaky endpoint (the whole
# point of #2). publicnode/dataseed cap getLogs at ~50 blocks; the poller's 10-block range stays under that.
_POLL_RPCS = [u for u in dict.fromkeys([HTTP, 'https://bsc-rpc.publicnode.com',
              'https://bsc-dataseed.bnbchain.org', 'https://1rpc.io/bnb']) if u]
def _rpc_any(method, params):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    for u in _POLL_RPCS:
        try:
            r = json.loads(urllib.request.urlopen(urllib.request.Request(
                u, body, {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}), timeout=15).read())
            if 'result' in r and r['result'] is not None:
                return r['result']
        except Exception:
            continue
    return None

def _http_poll_loop():
    """REDUNDANT fast lane (fixes WS flakiness): poll PairCreated/PoolCreated over HTTP every HTTP_POLL_EVERY s,
    ROTATING getLogs nodes. WS gives ~0.5s but free BSC WSS drops often; this keeps the fast lane alive at ~5s when
    the WS is down — still HOURS faster than the cron poll. Dedup with the WS path via _dispatch. Filtered to the
    same V2+V3 factories as the WS sub (spoof-flood safe). Also drives the dead-man's-switch."""
    last = None
    while True:
        try:
            _healthping()
            h = _rpc_any('eth_blockNumber', [])
            head = int(h, 16) if h else None
            if head:
                frm = (last + 1) if last else head - 10
                # CAP the range under publicnode's ~50-block getLogs limit. If the poller ever falls behind (a run
                # of failures), an uncapped range would exceed 50 -> every getLogs fails -> death spiral. Skipping
                # ahead drops a few blocks from THIS fast lane, but pairwatch's complete scan covers them.
                if head - frm > 45:
                    frm = head - 45
                if frm <= head:
                    logs = _rpc_any('eth_getLogs', [{'fromBlock': hex(frm), 'toBlock': hex(head),
                                                     'address': [FACTORY_V2, FACTORY_V3],
                                                     'topics': [[PAIRCREATED, POOLCREATED]]}])
                    if isinstance(logs, list):
                        for lg in logs:
                            tps = lg.get('topics', [])
                            if len(tps) < 3:
                                continue
                            t0 = '0x' + tps[1][-40:]; t1 = '0x' + tps[2][-40:]
                            data = lg.get('data', '')
                            pool = ('0x' + data[26:66]) if tps[0].lower() == PAIRCREATED else ('0x' + data[90:130])
                            _dispatch(t0, t1, pool)
                        last = head             # advance only on a real answer (None -> retry same range)
        except Exception as e:
            print('http-poll err', str(e)[:90], flush=True)
        time.sleep(HTTP_POLL_EVERY)

async def run():
    if websockets is None:
        print('!! pip install websockets'); return
    threading.Thread(target=_repoll_loop, daemon=True).start()   # liquidity-deposit watcher
    threading.Thread(target=_http_poll_loop, daemon=True).start()  # redundant fast lane (WS-down cover) + dead-man switch
    sub = {'jsonrpc':'2.0','id':1,'method':'eth_subscribe',
           'params':['logs', {'address': [FACTORY_V2, FACTORY_V3],
                              'topics': [[PAIRCREATED, POOLCREATED]]}]}
    while True:
        try:
            async with websockets.connect(WSS, ping_interval=20, max_size=None) as ws:
                await ws.send(json.dumps(sub))
                ack = await ws.recv()
                print('subscribed to V2 PairCreated + V3 PoolCreated:', ack[:120], flush=True)
                # report the ENDPOINT so uptime is VERIFIABLE: Alchemy = reliable streaming; publicnode = flaky
                # (means ALCHEMY_KEY secret is unset -> gap-2 coverage is degraded). This is how you confirm the
                # fast lane is actually receiving on a good pipe, not just "up".
                endpoint = 'Alchemy (reliable)' if _AK else 'publicnode (FLAKY — set ALCHEMY_KEY secret!)'
                notify('bsc_realtime_listener LIVE via %s — V2+V3 PairCreated, ~0.5s detection.' % endpoint)
                async for msg in ws:
                    d = json.loads(msg)
                    log = d.get('params', {}).get('result')
                    if not log: continue
                    tps = log.get('topics', [])
                    if len(tps) < 3: continue
                    t0 = '0x' + tps[1][-40:]
                    t1 = '0x' + tps[2][-40:]
                    data = log.get('data', '')
                    if tps[0].lower() == PAIRCREATED:          # V2: data = pair(w0) + len(w1)
                        pool = '0x' + data[26:66]; kind = 'V2'
                    else:                                      # V3: data = tickSpacing(w0) + pool(w1)
                        pool = '0x' + data[90:130]; kind = 'V3'
                    STATS['pairs'] += 1
                    print(time.strftime('%H:%M:%S'), kind, 'new', t0, t1, '->', pool, flush=True)
                    _dispatch(t0, t1, pool)
        except Exception as e:
            print('ws error, reconnecting in 5s:', str(e)[:120], flush=True)
            await asyncio.sleep(5)

if __name__ == '__main__':
    asyncio.run(run())
