import json, hashlib
from collections import defaultdict, Counter
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

d = json.load(open('data/verified_signatures.json'))
sigs = d['sigs']

def hash160(b): return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()
def b58check(payload):
    a=hashlib.sha256(payload).digest(); b=hashlib.sha256(a).digest()
    alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num=int.from_bytes(payload+b[:4],'big'); out=''
    while num: num,c=divmod(num,58); out=alphabet[c]+out
    out='1'*(len(payload)-(len(payload.lstrip(bytes(1)) and payload or payload))) # noop
    pad=len(payload)-len(payload.lstrip(b'\x00')) if isinstance(payload,bytes) else 0
    return '1'*pad+out

# P2PKH compressed/uncompressed address from pubkey hex
def addr_from_pub(qhex):
    b=bytes.fromhex(qhex)
    comp = b if len(b)==33 else bytes([2+(b[64]&1)])+b[1:33]
    ucomp = (bytes([4])+comp[1:33]) if len(b)==33 else b
    out=[]
    for pk in (comp,ucomp):
        h=hash160(pk); pay=b'\x00'+h
        out.append(b58check(pay))
    return out

mism=0; checked=0
for s in sigs[:500]:
    if s.get('type')!='P2PKH': continue
    checked+=1
    addrs=addr_from_pub(s['pubkey'])
    if s['address'] not in addrs: mism+=1
print(f"P2PKH addr check sample {checked}, mismatches {mism}")

# group sizes by pubkey_fp
byq=defaultdict(list)
for i,s in enumerate(sigs): byq[s['pubkey']].append(i)
sizes=sorted((len(v),k) for k,v in byq.items())[::-1]
print("top groups:", [(k[:10],v) for v,k in sizes[:10]])

# z uniqueness per group (double-spend style: same txid different vin?)
byt=defaultdict(set)
for s in sigs: byt[(s['txid'],s['idx'])].add(int(s['z']))
multi_z=sum(1 for v in byt.values() if len(v)>1)
print("records with conflicting z for same (txid,idx):", multi_z)

# skipped records
sk=d['skipped']
print("skipped sample:", sk[:2] if isinstance(sk,list) else type(sk))
if isinstance(sk,list):
    reasons=Counter(x.get('reason','?') if isinstance(x,dict) else str(x)[:40] for x in sk)
    print(reasons.most_common(10))

# high-S per biggest group (effective nonce -k implication)
big=k=sizes[0][1]
hs=sum(1 for i in sizes[0][1:] for _ in [0])
grp=[sigs[i] for i in byt and list(byq[k])]
hs=sum(1 for i in byq[k] if int(sigs[i]['s'])>n//2)
print(f"largest group {k[:12]}... size {len(byq[k])}, high-S within it: {hs}")

# bit-length histogram of s across corpus (bias detect proxy)
hist=Counter(int(s['s']).bit_length()//8*8 for s in sigs)
print("s bit-length buckets (8-bit):", sorted(hist.items()))
hist_r=Counter(int(s['r']).bit_length()//8*8 for s in sigs)
print("r short (<248 bits):", sum(v for k_,v in hist_r.items() if k_<248))
