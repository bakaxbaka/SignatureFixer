import { pointMulG } from "../shared/keys/recover";
import { pointMul, G, CURVE } from "../shared/keys/secp256k1";
for (const k of [1n, 2n, 3n, 255n, 256n, 0xdeadbeefn]) {
  const a = pointMulG(k), b = pointMul(k, G);
  const match = (!!a && !!b && a.x===b.x && a.y===b.y) || (!a && !b);
  console.log(k.toString(), "match:", match, a?.x.toString(16).slice(0,8), b?.x.toString(16).slice(0,8));
}
