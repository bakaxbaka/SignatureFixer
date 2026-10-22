import { pointMulG, verifyDgEqualsQ } from "../shared/keys/recover";
import { pubkeyFromD, deriveAll, toWIF } from "../shared/keys/derive";
const D1 = "0000000000000000000000000000000000000000000000000000000000000001";
console.log("pubkey d=1:", pubkeyFromD(D1).compressed);
console.log("pointMulG(1):", pointMulG(1n)?.x.toString(16));
try { console.log("deriveAll:", JSON.stringify(deriveAll(D1).addresses.map(a=>a.address))); } catch(e:any){ console.log("deriveAll err:", e.message); }
try { console.log("wif:", toWIF(D1, true)); } catch(e:any){ console.log("wif err:", e.message); }
