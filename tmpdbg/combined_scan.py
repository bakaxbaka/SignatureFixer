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
    return int.from_bytes(pos and int.from_bytes(b[pos+1:pos+9],'little') or 0,pos+9)

def parse_tx(hex_str):
    b=bytes.fromhex(hex_str); pos=4; out=[]
    try: vin,pos=varint(b,pos)
    except Exception: return out
    for _ in range(min(vin,100)):
        if pos+36>len(b): return out
        prev=b[pos:pos+36]; pos+=36
        l,pos=varint(b,pos)
        if pos+l>len(b): return out
        script=b[pos:pos+l]; pos+=l; pos+=4
        out.append((prev[::-1].hex(),script))
    return out

def der_rs(sg):
    if sg[0]!=0x30: return None
    body=sg[2:2+sg[1]]; j=0
    if body[j]!=0x02: return None
    j+=1; rl=body[j]; j+=1
    r=int.from_bytes(body[j:j+rl],'big'); j+=rl
    if body[j]!=0x02: return None
    j+=1; sl=body[j]; j+=1
    return r,int.from_bytes(body[j:j+sl],'big')

def parse_scriptsig(sc):
    i=0; pushes=[]
    while i<len(sc):
        op=sc[i]
        if 0<op<=75: pushes.append(sc[i+1:i+1+op]); i+=1+op
        elif op==0x4c: ll=sc[i+1]; pushes.append(sc[i+2:i+2+ll]); i+=2+ll
        else: break
    pk=next((p for p in pushes if len(p) in (33,65) and p[0] in (2,3,4)),None)
    sg=next((p for p in pushes if len(p)>60 and p[0]==0x30),None)
    if not pk or not sg: return None
    rs=der_rs(sg)
    if not rs: return None
    return {'r':rs[0],'s':rs[1],'pubkey':pk.hex()}

# puzzle spends
pz=json.load(open('data/raw_transactions_all_puzzles.json'))
psig=[]
for t in pz:
    for prev,sc in parse_tx(t['raw_hex']):
        sd=parse_scriptsig(sc)
        if sd: sd['txid']=t['txid']; psig.append(sd)

# main corpus
d=json.load(open('data/verified_signatures.json')); msig=d['sigs']

all_by_r=defaultdict(list)
for s in psig: all_by_r[s['r']].append(('puzzle',s))
for s in msig: all_by_r[int(s['r'])].append(('corpus',s))

cross=[(r,v) for r,v in all_by_r.items() if len(set(src for src,_ in v))>1]
sameq=[(r,v) for r,v in all_by_r.items() if len(v)>1 and len(set(x['pubkey'] for _,x in v))==1]
print("puzzle sigs:",len(psig)," corpus sigs:",len(msig))
print("cross-source r collisions (puzzle vs corpus):",len(cross))
for r,v in cross[:5]: print("  r=",hex(r)[:22],[(s,x['txid'][:10]) for s,x in v])
print("same-pubkey nonce reuse anywhere (solvable):",len(sameq))
for r,v in sameq[:5]: print("  ",v[0][1]['pubkey'][:20],[x['txid'][:10] for _,x in v])

# per-address group stats for top puzzle addresses
byaddr=defaultdict(int)
for s in msig: byaddr[s['address']]+=1
top=sorted(byaddr.items(),key=lambda x:-x[1])[:8]
print("busiest address groups:",top)
