import { pointMulG } from "../shared/keys/recover";
const exp: Record<number,string> = {
  2: "c55fb844d7e1ddd492eb0b66344de41a740e3ced5a4f14ae085e7fc1c83c8021",
  3: "0f6fca96harden" };
for (const k of [2n,3n,255n]) {
  const p = pointMulG(k);
  console.log(String(k)+":", p?.x.toString(16).padStart(64,"0").slice(0,20));
}
// expected 3G x = f9308a019258c31049344f85f89d5229b531c845836f99b0860445...? known: 3G.x=f9308a019258c31049344f85f89d5229b531c845836f99b08604453fbb3ac04c? let me just print pointMul too
import { pointMul, G } from "../shared/keys/secp256k1";
for (const k of [2n,3n,255n]) console.log("pointMul "+k+":", pointMul(k,G)?.x.toString(16).padStart(64,"0").slice(0,20));
