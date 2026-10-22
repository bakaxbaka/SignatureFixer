import { CURVE, pointMul, G } from "../shared/keys/secp256k1";
const P = pointMul(3n, G)!;
console.log("3G on curve:", (P.y*P.y - (P.x**3n + 7n)) % CURVE.p === 0n ? "true" : ((P.y*P.y - (P.x**3n + 7n)) % CURVE.p).toString(16));
console.log("P:", P.x.toString(16).padStart(64,"0"), P.y.toString(16).slice(0,8));
// manual double of G
const p = CURVE.p;
const modm = (a: bigint) => ((a % p) + p) % p;
const inv = (a: bigint) => { let [old_r,r]=[a,p]; let [old_s,s]=[1n,0n]; while(r){const q=old_r/r; [old_r,r]=[r,old_r-q*r];[old_s,s]=[s,old_s-q*s];} return modm(old_s); };
const lam = modm(3n*G.x!*G.x! * inv(2n*G.y!));
const x3 = modm(lam*lam - 2n*G.x!);
console.log("manual 2G x:", x3.toString(16).padStart(64,"0"));
