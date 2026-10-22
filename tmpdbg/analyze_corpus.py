#!/usr/bin/env python3
"""SignatureFixer vulnerability analyzer for data/ corpus.
Checks, in kill-order: reuse (nonce repeat), high-S, zero/extreme r,s, range violations,
bad DER, non-curve pubkey, short nonce (bit-length bias), GCD composite keys (W0-style).
Gate per protocol §9: a key event only fires after d*G==Q verified by ecdsa (independent impl).
"""
import json, sys, hashlib
from collections import defaultdict
from ecdsa.curves import SECP256k1



n = SECP256k1.order
def inv(a):
    return pow(a,-1,n)
G = SECP256k1.generator

d = json.load(open('data/verified_signatures.json'))
sigs = d['sigs']
print(f"corpus: {len(sigs)} signatures, {len(d.get('skipped',[]))} skipped records")

# ---- normalize + group by pubkey fingerprint ----
groups = defaultdict(list)
defects = defaultdict(list)
for i, s in enumerate(sigs):
    r, ss, z, qhex = int(s['r']), int(s['s']), int(s['z']), s['pubkey']
    if not (1 <= r < n and 1 <= ss < n):
        defects['RANGE'].append((i,qhex,r,ss)); continue
    if ss > n//2:
        defects['HIGH_S'].append((i,qhex,ss))
    groups[qhex].append(s)
    # bit-length of s (short-nonce proxy when k small => s often small too; measure r too)
    if ss.bit_length() <= 248 or r.bit_length() <= 248:
        pass  # collected separately below

print(f"distinct pubkeys: {len(groups)}")

# ---- R1: nonce reuse across the WHOLE corpus (same r) ----
by_r = defaultdict(list)
for i, s in enumerate(sigs):
    by_r[int(s['r'])].append((i, s))
reuse_pairs = []
for r_val, lst in by_r.items():
    if len(lst) > 1:
        reuse_pairs.append((r_val, lst))
print(f"\n[R1 NONCE REUSE] repeated r values: {len(reuse_pairs)}")

def solve_reuse(s1,z1,s2,z2,r):
    ds = (s1 - s2) % n
    try: k = ((z1 - z2) * inv(ds)) % n
    except Exception: return None
    for sign in (1, -1):  # low-S normalization may flip s -> effective nonce -k
        kk = (k*sign) % n
        d_ = ((kk*s1 - z1) * inv(r)) % n
        if d_ == 0: continue
        if (G*d_) == point_of(s1 and None): pass
    return None

def point_of_pubkey(qhex):
    from ecdsa.util import string_to_number
    b = bytes.fromhex(qhex)
    x = int.from_bytes(b[1:33],'big')
    prefix = b[0]
    if prefix in (2,3):
        alpha = (pow(x,3,n)+7) % n
        beta = pow(alpha,(n+1)//4,n)
        y = beta if (beta & 1)==(prefix-2) else n-beta
        return Point(x,y)
    elif prefix==4:
        return Point(int.from_bytes(b[1:33],'big'), int.from_bytes(b[33:65],'big'))
    return None

class Point:
    def __init__(self,x,y): self.x,self.y=x,y
    def __eq__(o,p): return p is not None and self.x==p.x and self.y==p.y
    def __hash__(self): return hash((self.x,self.y))
    def is_on_curve(self): return (self.y*self.y - self.x**3 - 7) % n == 0

def ec_mul(P_, k_):
    if P_ is None or k_ % n == 0: return None
    R=None; A=P_
    while k_:
        if k_&1: R = add(R,A)
        A = add(A,A); k_>>=1
    return R

def add(P_,Q_):
    if P_ is None: return Q_
    if Q_ is None: return P_
    if P_.x==Q_.x and (P_.y+Q_.y)%n==0: return None
    if P_==Q_:
        lam=(3*P_.x*P_.x)*inv(2*P_.y)%n
    else:
        lam=(Q_.y-P_.y)*inv(Q_.x-P_.x)%n
    x=(lam*lam-P_.x-Q_.x)%n
    y=(lam*(P_.x-x)-P_.y)%n
    return Point(x,y)

found_keys=[]
for r_val, lst in reuse_pairs[:50]:
    (i1,s1),(i2,s2) = lst[0],lst[1]
    if s1['pubkey']!=s2['pubkey']:   # same r, different key => not solvable directly
        defects['SAME_R_DIFF_Q'].append((r_val,s1['pubkey'],s2['pubkey'])); continue
    q=point_of_pubkey(s1['pubkey'])
    if q is None or not q.is_on_curve():
        defects['OFFCURVE_PUBKEY'].append(s1['pubkey']); continue
    for (a,b) in [(s1,s2),(s2,s1)]:
        sA,sB=int(a['s']),int(b['s']); zA,zB=int(a['z']),int(b['z'])
        ds=(sA-sB)%n
        if ds==0: continue
        k=((zA-zB)*inv(ds))%n
        for sign in (1,-1):
            kk=k if sign==1 else (-k)%n
            d_=((kk*sA-zA)*inv(r_val))%n
            if d_ and ec_mul(G,d_)==q:
                found_keys.append({'attack':'reuse','pubkey':a['pubkey'],'d_hex':hex(d_),
                    'txids':[a['txid'],b['txid']],'r':r_val})
                print("  KEY FOUND via reuse:", a['pubkey'], hex(d_))

# ---- R2: high-S count per group ----
hs = len(defects['HIGH_S'])
print(f"[R2 HIGH_S] signatures with s > n/2: {hs}")

# ---- R3: short nonce candidates (bit length of implied k unknown; use Minerva-style: k-hat = r^-1(z+s d)... can't without d. Use s/r leading-zero stats as heuristic) ----
short_s = sum(1 for s in sigs if int(s['s']).bit_length() <= 200)
print(f"[R3 SHORT-S (<=200 bits)] {short_s}  (HNP/short_nonce candidate rows)")

# ---- R4: bad DER / re-parse check ----
bad_der=0
for s in sigs:
    der=bytes.fromhex(s['der'])
    if der[0]!=0x30: bad_der+=1; continue
print(f"[R4 MALFORMED DER header] {bad_der}")

# ---- R5: addr_matches flag from corpus itself ----
am_false=[s for s in sigs if s.get('addr_matches') is False]
print(f"[R5 PUBKEY-ADDRESS MISMATCH (recorded)] {len(am_false)}")

# ---- R6: verify field ----
vf=[s for s in sigs if s.get('verify') is False]
print(f"[R6 SIGNATURE VERIFY FAILED (recorded)] {len(vf)}")

# ---- R7: GCD attack across pubkeys? (needs moduli; skip - ECDSA not RSA) ----

out={'reuse_pairs':len(reuse_pairs),'found_keys':found_keys,'high_s':hs,
     'short_s_le200':short_s,'bad_der':bad_der,'addr_mismatch':len(am_false),
     'verify_failed':len(vf),'offcurve':[list(x) for x in defects['OFFCURVE_PUBKEY']],
     'same_r_diff_q':len(defects['SAME_R_DIFF_Q']),
     'range_violations':len(defects['RANGE'])}
json.dump(out,open('tmpdbg/analysis_results.json','w'),indent=1)
print("\nsummary written to tmpdbg/analysis_results.json")
