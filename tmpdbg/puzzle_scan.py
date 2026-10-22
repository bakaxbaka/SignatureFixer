#!/usr/bin/env python3
import json, hashlib
from collections import defaultdict
from ecdsa.curves import SECP256k1
n = SECP256k1.order

def inv(a): return pow(a,-1,n)
def b58(payload):
    chk=hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    num=int.from_bytes(payload+chk,'big'); out=''
    while num: num,c=divmod(num,58); out='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'[c]+out
    return '1'*(len(payload)-len(payload.lstrip(b'\x00')))+out

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # placeholder replaced below
# field prime for secp256k1:
PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

def parse_tx(hex_str):
    b=bytes.fromhex(hex_str)
    if len(b)<10: return []
    pos=4
    vin=int.from_bytes(b[pos:pos+4],'little'); pos+=4
    ins=[]
    for _ in range(vin):
        if pos+36>len(b): return ins
        prev=b[pos:pos+36]; pos+=36
        vsize=int.from_bytes(b[pos:pos+4],'little'); pos+=4
        if vsize>len(b) or pos+vsize>len(b): return ins
        script=b[pos:pos+vsize]; pos+=vsize
        seq=int.from_bytes(b[pos:pos+4],'little'); pos+=4
        ins.append((prev[::-1].hex(),script))
    return ins

def parse_scriptsig(sc):
    i=0; pushes=[]
    while i<len(sc) and len(pushes)<3:
        l=sc[i]
        if 0<l<=75:
            pushes.append(sc[i+1:i+1+l]); i+=1+l
        elif l==0x4c:
            ll=sc[i+1]; pushes.append(sc[i+2:i+2+ll]); i+=2+ll
        else: break
    for pk in pushes:
        if len(pk) in (33,65) and pk[0] in (2,3,4):
            sig=[s for s in pushes if len(s)>60 and s[0]==0x30]
            if not sig: return None
            sg=sig[0]; j=2
            rl=sg[j]; r=int.from_bytes(sg[j+1:j+1+rl],'big'); j+=1+rl
            sl=sg[j]; s=int.from_bytes(sg[j+1:j+1+sl],'big')
            return {'r':r,'s':s,'pubkey':pk.hex(),'hashtype':sg[-1]}
    return None

d=json.load(open('data/raw_transactions_all_puzzles.json'))
sigs=[]
for t in d:
    for prev,sc in parse_tx(t['raw_hex']):
        sd=parse_scriptsig(sc)
        if sd:
            sd['txid']=t['txid']; sd['addresses']=t.get('addresses',[])
            sigs.append(sd)
print("puzzle signatures parsed:",len(sigs),"of",len(d),"tx")

byq=defaultdict(list); byr=defaultdict(list)
for s in sigs:
    byq[s['pubkey']].append(s); byr[s['r']].append(s)

reuse={r:v for r,v in byr.items() if len(v)>1}
print("nonce reuse groups (same r):",len(reuse))
for r,v in list(reuse.items())[:10]:
    print("  r=",hex(r)[:24]," count=",len(v)," txids=",[x['txid'][:12] for x in v])

multi={k:[sorted(set(a for rec in v for a in rec['addresses'])) for k_,vv in [(k,v)]][0] for k,v in byq.items() if len(v)>1}
print("pubkeys with >1 spend:",{k[:16]:len(v) for k,v in byq.items() if len(v)>1})

hs=sum(1 for s in sigs if s['s']>n//2)
print("high-S:",hs,"/",len(sigs))

ht=defaultdict(int)
for s in sigs: ht[s['hashtype']]+=1
print("sighash types:",dict(ht))

# pubkey->address verification from raw scriptPubKeys is out of scope here (spending tx), 
# but record which puzzle addresses appear as targets in outputs:
json.dump({'parsed':len(sigs),'reuse':{hex(r):[x['txid'] for x in v] for r,v in reuse.items()},
           'high_s':hs}, open('tmpdbg/puzzle_scan.json','w'), indent=1)
