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

def der_rs(sg):
    # sg: DER sequence WITHOUT sighash byte
    if sg[0]!=0x30: return None
    total=sg[1]
    body=sg[2:2+total]
    j=0
    if body[j]!=0x02: return None
    j+=1; rl=body[j]; j+=1
    r=int.from_bytes(body[j:j+rl],'big'); j+=rl
    if body[j]!=0x02: return None
    j+=1; sl=body[j]; j+=1
    s=int.from_bytes(body[j:j+sl],'big')
    return r,s

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
    rs=der_rs(sg)
    if not rs: return None
    return {'r':rs[0],'s':rs[1],'pubkey':pk.hex(),'hashtype':sg[-1]}

d=json.load(open('data/raw_transactions_all_puzzles.json'))
sigs=[]
for t in d:
    for prev,sc in parse_tx(t['raw_hex']):
        sd=parse_scriptsig(sc)
        if sd:
            sd['txid']=t['txid']; sd['addresses']=t.get('addresses',[])
            sigs.append(sd)
print("parsed:",len(sigs))

byq=defaultdict(list); byr=defaultdict(list)
for s in sigs:
    byq[s['pubkey']].append(s); byr[s['r']].append(s)

reuse={r:v for r,v in byr.items() if len(v)>1}
same_q_reuse={r:v for r,v in reuse.items() if len(set(x['pubkey'] for x in v))==1}
print("distinct r values:",len(byr))
print("nonce-reuse groups (same r):",len(reuse)," of which same-pubkey (solvable):",len(same_q_reuse))
for r,v in list(reuse.items())[:8]:
    print("  r=",hex(r)[:22],"count=",len(v),"distinct pubkeys=",len(set(x['pubkey'] for x in v)))
if same_q_reuse:
    for r,v in same_q_reuse.items(): print("  SOLVABLE:",v[0]['pubkey'][:20],[x['txid'][:12] for x in v])

multi={k:len(v) for k,v in byq.items() if len(v)>1}
print("pubkeys with multiple spends:",len(multi))

hs=sum(1 for s in sigs if s['s']>n//2)
print("high-S:",hs,"/",len(sigs))
rng=sum(1 for s in sigs if not (1<=s['r']<n and 1<=s['s']<n))
print("range violations:",rng)
ht=defaultdict(int)
for s in sigs: ht[s['hashtype']]+=1
print("sighash types:",dict(ht))
json.dump({'parsed':len(sigs),'reuse_groups':len(reuse),
 'solvable_reuse':[{'r':hex(r),'pubkey':v[0]['pubkey'],'txids':[x['txid'] for x in v]} for r,v in same_q_reuse.items()],
 'multi_spend_pubkeys':multi,'high_s':hs},open('tmpdbg/puzzle_final.json','w'),indent=1)
