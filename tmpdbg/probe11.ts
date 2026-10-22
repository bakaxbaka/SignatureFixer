import { CURVE, mod } from "../shared/keys/secp256k1";
console.log("p:", CURVE.p.toString(16));
console.log("expected p: fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
console.log("n:", CURVE.n.toString(16));
console.log("gx:", CURVE.gx.toString(16).slice(0,16));
console.log("b:", CURVE.b.toString(16), "a:", CURVE.a.toString(16));
