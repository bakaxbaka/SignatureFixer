import json, hashlib, csv
from collections import defaultdict
from ecdsa.curves import SECP256k1
n = SECP256k1.order

d=json.load(open('data/verified_signatures.json')); sigs=d['sigs']
# per-address nonce reuse across the 40 address CSV files (already fetched corpus has r values)
byq=defaultdict(list)
for s in sigs: byq[s['pubkey']].append(s)
multi={k:len(v) for k,v in byq.items() if len(v)>1}
print("corpus pubkeys with >=2 signatures:",len(multi),"of",len(byq))
# same-r within a pubkey?
sr=0
for k,v in byq.items():
    rs=[int(x['r']) for x in v]
    if len(rs)!=len(set(rs)): sr+=1
print("pubkeys with internal r collision:",sr)
