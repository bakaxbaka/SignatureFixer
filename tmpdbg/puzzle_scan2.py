#!/usr/bin/env python3
import json, hashlib
from collections import defaultdict
from ecdsa.curves import SECP256k1
n = SECP256k1.order

def varint(b,pos):
    v=b[pos]
    if v<0xfd: return v,pos+1
    if v==0xfd: return int.from_bytes(b[pos+1:pos+3],'little'),pos+3
    if v==0xfe: return int.from_bytes(b[pos+1:pos+5],'little'),pos+5
    return int.from_bytes(b[pos+1:pos+9],'little'),pos+9

def parse_tx(hex_str):
    b=bytes.fromhex(hex_str)
    if len(b)<6: return []
    pos=4
    vin,pos=varint(b,pos)
    ins=[]
    for _ in range(vin):
        if pos+36>len(b): return ins
        prev=b[pos:pos+36]; pos+=36
        l,pos=varint(b,pos)
        if pos+l>len(b): return ins
        script=b[pos:pos+l]; pos+=l
        pos+=4
        ins.append((prev[::-1].hex(),script))
    return ins

def parse_scriptsig(sc):
    i=0; pushes=[]
    while i<len(sc):
        op=sc[i]
        if 0<op<=75:
            pushes.append(sc[i+1:i+1+op]); i+=1+op
        elif op==0x4c:
            ll=sc[i+1]; pushes.append(sc[i+2:i+2+ll]); i+=2+ll
        elif op==0x4d:
            ll=int.from_bytes(sc[i+1:i+3],'little'); pushes.append(sc[i+3:i+3+ll]); i+=3+ll
        else: break
    pk=None; sg=None
    for p in pushes:
        if len(p) in (33,65) and p[0] in (2,3,4): pk=p
        elif len(p)>60 and p[0]==0x30: sg=p
    if not pk or not sg: return None
    j=2
    rl=sg[j]; r=int.from_bytes(sg[j+1:j+1+rl],'big'); j+=1+rl
    sl=sg[j]; s=int.from_bytes(sg[j+1:j+1+sl],'big')
    return {'r':r,'s':s,'pubkey':pk.hex(),'hashtype':sg[-1]}

d=json.load(open('data/raw_transactions_all_puzzles.json'))
sigs=[]; no_sig=[]
for t in d:
    found=False
    for prev,sc in parse_tx(t['raw_hex']):
        sd=parse_scriptsig(sc)
        if sd:
            sd['txid']=t['txid']; sd['addresses']=t.get('addresses',[])
            sigs.append(sd); found=True
    if not found: no_sig.append((t['txid'],t.get('addresses')))
print("puzzle tx:",len(d)," with-sig:",len(sigs)," without-parsed-sig:",len(no_sig))
for x in no_sig[:8]: print("  no sig:",x)

byq=defaultdict(list); byr=defaultdict(list)
for s in sigs:
    byq[s['pubkey']].append(s); byr[s['r']].append(s)

reuse={r:v for r,v in byr.items() if len(v)>1}
print("\nnonce reuse groups (same r across puzzle spends):",len(reuse))
for r,v in list(reuse.items())[:10]:
    same_q = len(set(x['pubkey'] for x in v))==1
    print("  r=",hex(r)[:26],"count=",len(v),"same_pubkey=",same_q,"txids=",[x['txid'][:12] for x in v])

multi={k:len(v) for k,v in byq.items() if len(v)>1}
print("pubkeys used in >1 spend:",multi)

hs=sum(1 for s in sigs if s['s']>n//2)
print("high-S:",hs,"/",len(sigs))
ht=defaultdict(int)
for s in sigs: ht[s['hashtype']]+=1
print("sighash types:",dict(ht))
json.dump({'parsed':len(sigs),'no_sig':[list(x) for x in no_sig],
 'reuse':{hex(r):[x['txid'] for x in v] for r,v in reuse.items()},
 'multi_spend':multi,'high_s':hs},open('tmpdbg/puzzle_scan2.json','w'),indent=1)
