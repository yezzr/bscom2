#!/usr/bin/env python3
"""
old_funded_radar.py - the COOK LANE: a daily targeting engine for OLD + FUNDED + THINLY-AUDITED
protocols (where latent logic bugs sit for years, like Cook Finance's 4.3-year-old IssuanceModuleV2).
SOURCE: DeFiLlama /protocols (free, no key) — funded protocols + TVL + age (listedAt) + staleness
(change_7d) + audit count. Cross-refs Immunefi public bounties to TAG which targets actually PAY.
Ranks by EV (bounty-backed + funded + old + thin-audit + flat/declining) and pushes a daily digest
of NEW candidates to Telegram. You then run the auditor-pro rig on the top pick.
HONEST SCOPE: this is TARGETING, not an auto-auditor — it surfaces "audit this one," not a verdict.
It sees DeFiLlama-LISTED protocols; a fully delisted/abandoned one won't appear (that needs on-chain
enumeration). Pure DeFiLlama+Immunefi+Telegram — no Etherscan/RPC key needed.
"""
import json, os, sys, time, math, urllib.request, urllib.parse

HOME = os.environ.get('RADAR_HOME') or os.path.dirname(os.path.abspath(__file__))
os.makedirs(HOME, exist_ok=True)
SEEN = os.path.join(HOME, 'old_funded_seen.json')
MIN_TVL = float(os.environ.get('MIN_TVL') or 100000)        # $1k is too low to be worth auditing; default $100k
MAX_TVL = float(os.environ.get('MAX_TVL') or 10000000)      # cap out the institutional fortresses (BlackRock/Tether/etc.) — the Cook sweet spot is small+obscure
MAX_AUDITS = int(os.environ.get('MAX_AUDITS') or 1)         # thin-audit only (0 or 1 audits) — where bugs survive
AGE_DAYS = int(os.environ.get('AGE_DAYS') or 365)           # "old" = listed at least this long ago
STALE_MAX = float(os.environ.get('STALE_MAX') or 5)         # flat/declining: 7d TVL change <= this %
TOP_N = int(os.environ.get('TOP_N') or 8)                   # candidates per daily digest
CATS = {'Yield', 'Vaults', 'CDP', 'Lending', 'Derivatives', 'Yield Aggregator', 'Liquid Staking',
        'Synthetics', 'Options', 'Insurance', 'RWA', 'Indexes', 'Farm', 'Leveraged Farming',
        'Algo-Stables', 'Yield Lottery', 'Liquid Restaking', 'Restaking', 'Structured Products'}
NON_EVM = {'solana', 'aptos', 'sui', 'near', 'tron', 'cardano', 'cosmos', 'osmosis', 'sei', 'ton',
           'starknet', 'stacks', 'algorand', 'tezos', 'hedera', 'icp', 'stellar', 'bitcoin',
           'multiversx', 'elrond', 'fuel', 'bittensor', 'neo', 'radix', 'waves', 'vechain', 'flow',
           'injective', 'thorchain', 'mina', 'massa', 'concordia', 'everscale', 'wax', 'eos',
           'icon', 'obyte', 'ergo', 'wanchain', 'terra', 'kava', 'aurora', 'terra classic', 'secret'}
# Chains where a contract's SOURCE is verifiable on a block explorer (Etherscan V2 family) — i.e. the
# ones we can actually AUDIT and where DeFiLlama's TVL corresponds to real on-chain value we can read.
EVM_CHAINS = {'ethereum', 'bsc', 'binance', 'base', 'arbitrum', 'arbitrum nova', 'polygon',
              'polygon zkevm', 'optimism', 'avalanche', 'avax', 'fantom', 'gnosis', 'xdai', 'linea',
              'scroll', 'blast', 'mantle', 'zksync era', 'era', 'celo', 'moonbeam', 'moonriver',
              'metis', 'fraxtal', 'mode', 'manta', 'mantra', 'taiko', 'kaia', 'klaytn', 'opbnb',
              'core', 'zircuit', 'sonic', 'berachain', 'unichain', 'ink', 'soneium', 'hyperliquid'}

def notify(text):
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
                wh, json.dumps({'content': text}).encode(), {'Content-Type': 'application/json'}), timeout=15)
        except Exception:
            pass

def jget(url):
    for _ in range(3):
        try:
            return json.loads(urllib.request.urlopen(
                urllib.request.Request(url, headers={'User-Agent': 'M', 'Accept': 'application/json'}), timeout=40).read())
        except Exception:
            time.sleep(1.0)
    return None

def immunefi_names():
    """{normalized project name: maxBounty} for EVM-ecosystem Immunefi programs (tag payers + show real $)."""
    d = jget('https://immunefi.com/public-api/bounties.json') or []
    out = {}
    evm = {'ethereum', 'arbitrum', 'optimism', 'base', 'bsc', 'polygon', 'avalanche', 'fantom', 'eth',
           'gnosis', 'linea', 'scroll', 'blast', 'mantle', 'zksync', 'metis', 'moonbeam', 'celo'}
    for b in (d if isinstance(d, list) else []):
        n = (b.get('project') or b.get('name') or '').strip().lower()
        eco = [e.lower() for e in (b.get('ecosystem') or [])]
        if n and any(e in evm for e in eco):           # only EVM-ecosystem bounties (we can't audit the rest)
            out[n] = max(out.get(n, 0), b.get('maxBounty') or 0)
    return out

def load(p, d):
    try:
        return json.load(open(p))
    except Exception:
        return d

def protocol_health(slug):
    """The LIVENESS + AUDITABILITY gate — turns a DeFiLlama listing into a real, auditable, mail-able
    target (or rejects it as a ghost). Returns (evm_tvl, alive).
      evm_tvl : value sitting ONLY on source-verifiable EVM chains (Cega's $ was mostly Solana; MUX-style
                targets keep it). A protocol whose money lives on a chain we can't read source for is not
                a target regardless of its headline TVL.
      alive   : the protocol has NOT collapsed to a husk vs its own historical peak — this is what kills the
                wound-down v1s (Cega's Ethereum vaults were EMPTY: residual DeFiLlama TVL, nothing live to
                find a bug in). A target you can actually audit + disclose to a team must still be running."""
    d = jget('https://api.llama.fi/protocol/' + slug)
    if not isinstance(d, dict):
        return 0.0, False
    et = 0.0
    for k, v in (d.get('currentChainTvls') or {}).items():
        kl = k.lower()
        if '-' in kl:                                   # skip 'Ethereum-borrowed'/'-staking'/'-pool2' sub-buckets
            continue
        if kl in EVM_CHAINS:
            et += (v or 0)
    alive = True
    series = d.get('tvl') or []
    if isinstance(series, list) and len(series) >= 10:
        vals = [pt.get('totalLiquidityUSD', 0) or 0 for pt in series if isinstance(pt, dict)]
        if vals:
            peak, cur = max(vals), vals[-1]
            if peak > 0 and cur < 0.10 * peak:          # <10% of its own peak = wound-down husk, not a live target
                alive = False
    return et, alive

def one_pass():
    now = time.time()
    prots = jget('https://api.llama.fi/protocols')
    if not prots:
        print('!! DeFiLlama unreachable')
        return
    bounties = immunefi_names()
    seen = set(load(SEEN, []))
    cands = []
    for p in prots:
        tvl = p.get('tvl') or 0
        if tvl < MIN_TVL or tvl > MAX_TVL:                   # in-band only: funded-enough, not a watched fortress
            continue
        if p.get('category') not in CATS:
            continue
        chains = [c.lower() for c in (p.get('chains') or [])]
        if not chains or all(c in NON_EVM for c in chains):
            continue                                        # EVM-auditable only
        listed = p.get('listedAt') or now
        if (now - listed) < AGE_DAYS * 86400:
            continue                                        # must be OLD
        if (p.get('change_7d') or 0) > STALE_MAX:
            continue                                        # must be flat/declining (unwatched-ish)
        audits = 0
        try:
            audits = int(p.get('audits') or 0)
        except Exception:
            audits = 0
        if audits > MAX_AUDITS:
            continue                                        # thin-audit only
        name = p.get('name', '')
        if name in seen:
            continue
        nm_l = name.strip().lower()
        # bounty match: exact normalized, else a whole-name prefix match (len>=5 to avoid short-word aliasing
        # like 'lido' → 'lido impact staking'). We still SHOW the $ amount so any false match is obvious.
        bounty = bounties.get(nm_l, 0)
        if not bounty:
            for bn, mb in bounties.items():
                if len(bn) >= 5 and (nm_l == bn or nm_l.startswith(bn + ' ') or bn.startswith(nm_l + ' ')):
                    bounty = max(bounty, mb)
        paid = bounty > 0
        age_d = int((now - listed) / 86400)
        declining = (p.get('change_7d') or 0) < 0
        # PRE-RANK score (picks which ~35 get the on-chain liveness check below). NOT bounty-driven — a
        # bounty is only a mild bonus; the target set is EVERY old+thin-audit+funded protocol, bounty or
        # not, because the play is disclose-to-the-team-directly (a formal bounty is a nice-to-have).
        slug = p.get('slug') or name.strip().lower().replace(' ', '-')
        score = (1.4 if paid else 1.0) * (2.0 - audits) * (1.0 + age_d / 700.0) \
                * (1.3 if declining else 1.0) * math.log10(max(tvl, 10))
        cands.append({'score': score, 'name': name, 'slug': slug, 'tvl': round(tvl),
                      'cat': p.get('category'), 'audits': audits, 'paid': paid, 'bounty': bounty,
                      'age_d': age_d, 'declining': declining, 'url': p.get('url', ''),
                      'chains': [c for c in chains if c not in NON_EVM][:3]})
    cands.sort(key=lambda x: -x['score'])
    # LIVENESS + AUDITABILITY GATE: only surface targets that hold REAL value on a source-verifiable EVM
    # chain AND are still running (not a wound-down husk). This is the fix for the ghost problem — Cega
    # passed every cheap filter but its EVM vaults were empty; this gate would have dropped it.
    verified = []
    for c in cands[:35]:
        et, alive = protocol_health(c['slug'])
        if et >= MIN_TVL and alive:
            c['evm_tvl'] = round(et)
            c['score'] = (1.4 if c['paid'] else 1.0) * (2.0 - c['audits']) * (1.0 + c['age_d'] / 700.0) \
                         * (1.3 if c['declining'] else 1.0) * math.log10(max(et, 10))  # re-rank on REAL evm value
            verified.append(c)
        time.sleep(0.25)
        if len(verified) >= TOP_N * 2:
            break
    verified.sort(key=lambda x: -x['score'])
    top = verified[:TOP_N]
    if top:
        lines = ['AUDIT-LANE candidates (old + LIVE EVM value + thin-audit, %d) — audit + disclose direct:' % len(top)]
        for c in top:
            tag = ('has $%s bounty too' % f"{c['bounty']:,}") if c['paid'] else 'no bounty — reach out to the team'
            lines.append('%s  $%s LIVE EVM TVL  %s  audits=%d  %dd old\n  chains: %s | %s\n  %s'
                         % (c['name'], f"{c['evm_tvl']:,}", c['cat'], c['audits'], c['age_d'],
                            ', '.join(c['chains']) or '?', tag, c['url']))
        notify('\n'.join(lines))
        for c in top:
            seen.add(c['name'])
    json.dump(sorted(seen), open(SEEN, 'w'))
    print('%s | scanned %d | candidates %d | pushed %d (seen total %d)'
          % (time.strftime('%H:%M:%S'), len(prots), len(cands), len(top), len(seen)), flush=True)

if __name__ == '__main__':
    if '--stdout' not in sys.argv:
        try:
            sys.stdout = sys.stderr = open(os.path.join(HOME, 'old_funded_radar.log'), 'a', buffering=1, encoding='utf-8')
        except Exception:
            pass
    one_pass()
