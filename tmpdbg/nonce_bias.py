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
    b=bytes.fromhex(hex_str); pos=4; out=[]
    vin,pos=varint(b,pos)
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

pz=json.load(open('data/raw_transactions_all_puzzles.json'))
psig=[]
for t in pz:
    for prev,sc in parse_tx(t['raw_hex']):
        sd=parse_scriptsig(sc)
        if sd: sd['txid']=t['txid']; sd['addresses']=t.get('addresses',[]); psig.append(sd)

# canonical pubkey -> puzzle address mapping via hash160 of the compressed key
def b58(payload):
    chk=hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    num=int.from_bytes(payload+chk,'big'); out=''
    while num: num,c=divmod(num,58); out='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'[c]+out
    return '1'*(len(payload)-len(payload.lstrip(b'\x00')))+out
def addr_of(pkhex):
    b=bytes.fromhex(pkhex)
    comp=b if len(b)==33 else bytes([2+(b[-1]&1)])+b[1:33]
    h=hashlib.new('ripemd160',hashlib.sha256(comp).digest()).digest()
    c=b58(b'\x00'+h)
    u=(b'\x04'+comp[1:33]) if len(b)==33 else b
    hu=hashlib.new('ripemd160',hashlib.sha256(u).digest()).digest()
    return c, b58(b'\x00'+hu)

byq=defaultdict(list)
for s in psig: byq[s['pubkey']].append(s)
solvable=[]
for k,v in byq.items():
    if len(v)<2: continue
    rs={x['r'] for x in v}
    solvable.append((k,len(v),len(rs)))
print("puzzle pubkeys with >=2 spends:",len(solvable))
for k,c,dr in sorted(solvable,key=lambda x:-x[1])[:25]:
    a=addr_of(k)
    print(f"  {k[:16]}... spends={c} distinct_r={dr} addr={'/'.join(a)}")

# bit-length distribution of r across puzzle set (small r => tiny k => kangaroo/HNP candidate)
bl=defaultdict(int)
for s in psig: bl[s['r'].bit_length()//16*16]+=1
print("\npuzzle r bit-length buckets:",sorted(bl.items()))
tiny=[(hex(s['r']),s['pubkey'],s['txid']) for s in psig if s['r'].bit_length()<64]
print("tiny-r (<64 bits):",len(tiny)); [print("  ",x) for x in tiny[:10]]
json.dump({'multi_spend_pubkeys':[{'pubkey':k,'spends':c,'distinct_r':dr,'addresses':list(addr_of(k))} for k,c,dr in solvable],
           'tiny_r':[list(x) for x in tiny]}, open('tmpdbg/puzzle_bias.json','w'),indent=1)
