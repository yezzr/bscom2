import json, urllib.request, urllib.parse, sys, time, threading, os, traceback
import concurrent.futures as cf
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # CWD-independent (systemd/cron safe)
sys.path.insert(0,'hunt')
# import the arsenal defensively — core detectors are pure-stdlib; detectors_extra needs slither
# (heavy, optional) so guard it: on a clean VM it's skipped and its (already no-op here) calls degrade.
import parked_mint_detector, broken_permit_detector, autoswap_detector, double_settle_detector, drain_detectors, pair_burn_sync_detector
try:
    import vuln_token_scanner            # D8 face-value multi-asset basket (RangePool depeg-arb class)
except Exception:
    vuln_token_scanner = None
try:
    import detectors_extra
except Exception:
    detectors_extra = None
ESK=os.environ.get('ETHERSCAN_API_KEY') or ''
def getsrc(a):
    u='https://api.etherscan.io/v2/api?'+urllib.parse.urlencode({'chainid':56,'module':'contract','action':'getsourcecode','address':a,'apikey':ESK})
    for _ in range(3):
        try:
            res=json.loads(urllib.request.urlopen(urllib.request.Request(u,headers={'User-Agent':'M'}),timeout=20).read()).get('result')
            if isinstance(res,list) and res:
                s=res[0].get('SourceCode') or ''
                if s.startswith('{'):
                    j=json.loads(s[1:-1]) if s.startswith('{{') else json.loads(s); srcs=j.get('sources',j)
                    s='\n'.join(v.get('content','') for v in srcs.values()) if isinstance(srcs,dict) else s
                return res[0].get('ContractName'),s
        except: time.sleep(0.5)
    return None,''
def run_arsenal(src):
    sl=src.lower(); hits=[]
    def add(l,d=''): hits.append((l,str(d)[:60]))
    try:
        ex,_=parked_mint_detector.detect(src)
        if ex: add('PARKED-MINT')
    except: pass
    try:
        f=broken_permit_detector.detect(src)
        if f: add('BROKEN-PERMIT',[x[1] for x in f])
    except: pass
    try:
        v,sig=autoswap_detector.analyze(src)
        if v: add('FORCE-DUMP',sig)
    except: pass
    try:
        f=double_settle_detector.analyze_transfer_override(src)
        if f: add('DOUBLE-SETTLE',len(f))
    except: pass
    try:
        f=drain_detectors.scan(src)
        hi=[x for x in (f or []) if str(x.get('tier','')).upper() in ('HIGH','CRITICAL') or str(x.get('sev','')).upper() in ('HIGH','CRITICAL')]
        if hi: add('DRAIN',[x.get('klass') for x in hi][:3])
    except: pass
    try:
        if detectors_extra.detect_share_inflation(sl): add('SHARE-INFLATION')
    except: pass
    try:
        if detectors_extra.detect_readonly_reentrancy(sl): add('READONLY-REENTRANCY')
    except: pass
    try:
        if detectors_extra.detect_liq_math(sl): add('LIQ-MATH')
    except: pass
    try:
        f=pair_burn_sync_detector.detect(src)
        if f: add('PAIR-BURN-SYNC',[x[0]+':'+x[1] for x in f])
    except: pass
    try:
        d8=[h for h in vuln_token_scanner.detect(src) if h.startswith('D8')]   # only the basket class; D1-D7 overlap autoswap/drain
        if d8: add('BASKET-DEPEG','face-value multi-asset basket (RangePool depeg-arb): mint-any-at-par + caller-picks-redeem, no oracle')
    except: pass
    return hits

if __name__=='__main__':
    if sys.argv[1].endswith('.sol'):
        s=open(sys.argv[1],encoding='utf-8',errors='ignore').read()
        print('arsenal hits:', run_arsenal(s))
    elif sys.argv[1].startswith('0x'):
        cn,s=getsrc(sys.argv[1]); print(cn, '->', run_arsenal(s) if s else 'no source')
