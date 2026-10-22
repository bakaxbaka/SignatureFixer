import * as bitcoin from "bitcoinjs-lib";
console.log("bjl version:", require("bitcoinjs-lib/package.json").version);
const pub = Buffer.from("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","hex");
try { const p = bitcoin.payments.p2pkh({pubkey: pub}); console.log("p2pkh:", p.address); } catch(e:any){ console.log("p2pkh err:", e.message); }
try { const p = bitcoin.payments.p2wpkh({pubkey: pub}); console.log("p2wpkh:", p.address); } catch(e:any){ console.log("p2wpkh err:", e.message); }
// ecc?
try { const ecc = (require("@bitcoinerlab/secp256k1")("@bitcoinerlab/secp256k1".default.default; console.log("isPrivate(1):", ecc.isPrivate(Buffer.from("0000000000000000000000000000000000000000000000000000000000000001","hex"))); console.log("pointFromScalar:", Buffer.from(ecc.pointFromScalar(Buffer.from("0000000000000000000000000000000000000000000000000000000000000001","hex"), true)).toString("hex")); } catch(e:any){ console.log("ecc err:", e.message); }
