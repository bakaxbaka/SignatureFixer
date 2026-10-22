import base58 from "bs58";
import { createHash } from "node:crypto";
import { toWIF } from "../shared/keys/derive";
const sha = (b: Uint8Array) => new Uint8Array(createHash("sha256").update(b).digest());
const D1 = "0000000000000000000000000000000000000000000000000000000000000001";
// manual uncompressed WIF for d=1
const payload = Buffer.alloc(37); payload[0]=0x80; Buffer.from(D1,"hex").copy(payload,1);
const chk = sha(sha(new Uint8Array(payload)));
const wif = base58.encode(Buffer.concat([payload, Buffer.from(chk.slice(0,4))]));
console.log("manual uncomp:", wif);
console.log("lib uncomp   :", toWIF(D1, false));
console.log("lib comp     :", toWIF(D1, true));
