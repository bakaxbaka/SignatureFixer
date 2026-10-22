const bitcoin = require("bitcoinjs-lib");
const pub = Buffer.from("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","hex");
try { console.log("p2pkh:", bitcoin.payments.p2pkh({pubkey: pub}).address); } catch(e){ console.log("p2pkh err:", e.message); }
try { console.log("p2wpkh:", bitcoin.payments.p2wpkh({pubkey: pub}).address); } catch(e){ console.log("p2wpkh err:", e.message); }
const ecc = require("@bitcoinerlab/secp256k1").default;
const d = Buffer.alloc(32); d[31]=1;
console.log("isPrivate(d=1):", ecc.isPrivate(d));
console.log("pointFromScalar:", Buffer.from(ecc.pointFromScalar(d, true)).toString("hex"));
// base58 of 0x80 + 32bytes(=1) + no comp + checksum -> expected 5HueCGU...
