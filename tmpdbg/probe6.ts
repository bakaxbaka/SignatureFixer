import { toWIF } from "../shared/keys/derive";
const D1 = "0000000000000000000000000000000000000000000000000000000000000001";
console.log("comp:", toWIF(D1, true));
console.log("uncomp:", toWIF(D1, false));
