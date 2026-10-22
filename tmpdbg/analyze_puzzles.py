#!/usr/bin/env python3
"""Analyze raw_transactions_all_puzzles.json + all raw_transactions_*.json:
parse scriptSigs, extract (r,s,pubkey), recompute nothing from chain but check:
- same pubkey across multiple puzzle addresses (key-reuse across targets)
- nonce reuse across the whole puzzle set
- high-S, r==x overflow flags
- small-key detection: recover candidates via ECDSA recovery and test d*G==Q for low-bit d
  (puzzle numbers are tiny keys; brute-force range check is cheap for <2^40 only — instead
   use signature recovery to get Q, then compare against known puzzle pubkeys)
"""
import json, glob, hashlib
from collections import defaultdict
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
p = n  # secp256k1 field prime differs; use curve params from ecdsa
from ecdsa.curves import SECP256k1
n = SECP256k1.order
G = SECP256k1.generator

def b58(payload):
    chk=hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    num=int.from_bytes(payload+chk,'big'); out=''
    while num: num,c=divmod(num,58); out='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'[c]+out
    return '1'*(len(payload)-len(payload.lstrip(b'\x00')))+out

def parse_tx(hex_str):
    b=bytes.fromhex(hex_str)
    if len(b) < 10: return []
    pos=4
    vin=int.from_bytes(b[pos:pos+4],'little'); pos+=4
    ins=[]
    for _ in range(vin):
        if pos+36>len(b): return ins
        prev=b[pos:pos+36]; pos+=36
        vsize=int.from_bytes(b[pos:pos+4],'little'); pos+=4
        if vsize > len(b) or pos+vsize > len(b): return ins
        script=b[pos:pos+vsize]; pos+=vsize
        seq=int.from_bytes(b[pos:pos+4],'little'); pos+=4
        ins.append((prev.hex(),script))
    return ins

def parse_scriptsig(sc):
    # P2PKH: PUSH(71/72/73 DER) PUSH(33/65 pubkey)
    out={}
    i=0
    def push():
        nonlocal i
        if i>=len(sc): return None
        l=sc[i]; i+=1
        if l==0 or l>75: return None
        d=sc[i:i+l]; i+=l; return d
    sig=push(); pk=push()
    if sig and pk and sig[0]==0x30:
        # DER parse r,s
        j=2
        rl=sig[j]; r=int.from_bytes(sig[j+1:j+1+rl],'big'); j+=1+rl
        sl=sig[j]; s=int.from_bytes(sig[j+1:j+1+sl],'big')
        out['r']=r; out['s']=s; out['pubkey']=pk.hex(); out['hashtype']=sig[-1]
    return out

results=defaultdict(list)
all_sigs=[]
for f in sorted(glob.glob('data/raw_transactions_*.json')):
    txs=json.load(open(f))
    tag=f.split('raw_transactions_')[1].replace('.json','')
    cnt=0
    for t in txs:
        for prev,sc in parse_tx(t['raw_hex']):
            sd=parse_scriptsig(sc)
            if sd:
                sd['txid']=t['txid']; sd['src']=tag; sd['addresses']=t.get('addresses',[])
                all_sigs.append(sd); cnt+=1
    results[tag]=cnt
print("parsed signatures per file:")
for k,v in sorted(results.items(), key=lambda x:-x[1])[:25]: print(f"  {k}: {v}")
print("total parsed:", len(all_sigs))

byq=defaultdict(list); byr=defaultdict(list)
for s in all_sigs:
    byq[s['pubkey']].append(s); byr[s['r']].append(s)

reuse=[(r,v) for r,v in byr.items() if len(v)>1]
print("\npuzzle-set nonce reuse (same r):", len(reuse))
for r,v in reuse[:5]:
    print("  r=",hex(r)[:20],"across",[(x['src'],x['txid'][:10]) for x in v])

multi_addr={k:[a for rec in v for a in rec['addresses']] for k,v in byq.items() if len(set(tuple(rec['addresses']) for rec in v))>1}
print("pubkeys signing to multiple puzzle addresses:", len(multi_addr))
for k,a in list(multi_addr.items())[:10]: print("  ",k[:16],"->",sorted(set(a)))

hs=sum(1 for s in all_sigs if s['s']>n//2)
print("high-S:",hs,"of",len(all_sigs))

# hashtype distribution
ht=defaultdict(int)
for s in all_sigs: ht[s['hashtype']]+=1
print("sighash types:",dict(ht))

json.dump({'total':len(all_sigs),'reuse':len(reuse),'high_s':hs},open('tmpdbg/puzzle_results.json','w'))
