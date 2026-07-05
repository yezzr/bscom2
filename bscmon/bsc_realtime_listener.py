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
except Exception:
    def notify(t): print('[NOTIFY]', t)
    def is_pushworthy(v):
        for x in v:
            if x.split(':')[0] in ('PARKED-MINT','DOUBLE-SETTLE','BROKEN-PERMIT','BASKET-DEPEG'): return True
            if x.split(':')[0]=='PAIR-BURN-SYNC' and 'HIGH' in x: return True
        return False
    def detect_buy_gate(s): return (False, '')

# KEYLESS public BSC endpoints by default (no Alchemy key needed -> nothing to leak on a public repo).
# Override with BSC_WSS_URL / BSC_RPC_URL secrets if you later want a dedicated (higher-rate) provider.
WSS = os.environ.get('BSC_WSS_URL') or 'wss://bsc-rpc.publicnode.com'
HTTP = os.environ.get('BSC_RPC_URL') or 'https://bsc-rpc.publicnode.com'
MIN_LIQ_USD = float(os.environ.get('MIN_LIQ_USD') or 1000)
CONFIRM = os.environ.get('CONFIRM', '1') == '1'    # fork-sim confirm the FP-heavy FORCE-DUMP class before ping

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
        return json.loads(urllib.request.urlopen(urllib.request.Request(
            HTTP, body, {'Content-Type':'application/json'}), timeout=20).read()).get('result')
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

def handle_pair(token0, token1, pair):
    """Evaluate a freshly-created pair the instant it appears. (Host-agnostic entry point:
    an Alchemy-webhook -> Cloudflare Worker variant would call this with the decoded log.)"""
    if pair.lower() in seen: return
    seen.add(pair.lower())
    liq, base, token = base_liquidity_usd(pair, token0, token1)
    if not token or liq < MIN_LIQ_USD:
        return                                        # no base pairing or not yet funded to the floor
    cn, src = getsrc(token)
    if not src:
        return                                        # unverified -> skip (v1; bytecode mode is a later add)
    verdict = [x[0] + (':' + x[1] if x[1] else '') for x in run_arsenal(src)]
    gated, gsig = detect_buy_gate(src)
    if not verdict:
        return
    classes = {v.split(':')[0] for v in verdict}
    # precise classes: ping instantly. FP-heavy FORCE-DUMP: fork-sim confirm first.
    precise = is_pushworthy(verdict)
    force_dump = 'FORCE-DUMP' in classes
    ping = precise
    tag = 'PRECISE'
    if not precise and force_dump and CONFIRM:
        if fork_confirm(token, pair, liq):
            ping, tag = True, 'FORK-CONFIRMED-EXPLOITABLE'
    if ping:
        notify('LIVE FRESH-DEPLOY [%s]  ~$%.0f %s liq\n%s (%s)\nverdict: %s\nbscscan.com/token/%s'
               % (tag, liq, base or '?', token, cn, ', '.join(verdict), token))
        print('  >>> ALERTED', token, tag, verdict, flush=True)
    else:
        print('  seen risky-but-unconfirmed', token, verdict, flush=True)

def _dispatch(token0, token1, pair):
    threading.Thread(target=handle_pair, args=(token0, token1, pair), daemon=True).start()

async def run():
    if websockets is None:
        print('!! pip install websockets'); return
    sub = {'jsonrpc':'2.0','id':1,'method':'eth_subscribe',
           'params':['logs', {'address': [FACTORY_V2, FACTORY_V3],
                              'topics': [[PAIRCREATED, POOLCREATED]]}]}
    while True:
        try:
            async with websockets.connect(WSS, ping_interval=20, max_size=None) as ws:
                await ws.send(json.dumps(sub))
                ack = await ws.recv()
                print('subscribed to V2 PairCreated + V3 PoolCreated:', ack[:120], flush=True)
                notify('bsc_realtime_listener LIVE — watching PancakeSwap V2+V3 factories (instant on-chain liquidity).')
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
                    print(time.strftime('%H:%M:%S'), kind, 'new', t0, t1, '->', pool, flush=True)
                    _dispatch(t0, t1, pool)
        except Exception as e:
            print('ws error, reconnecting in 5s:', str(e)[:120], flush=True)
            await asyncio.sleep(5)

if __name__ == '__main__':
    asyncio.run(run())
