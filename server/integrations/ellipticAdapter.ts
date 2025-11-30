import type { EC } from "elliptic";

export interface LibraryVerifyParams {
  curve: string;
  msgHashHex: string;
  derHex: string;
  pubkeyHex: string;
}

export type LibraryVerifyFn = (params: LibraryVerifyParams) => Promise<boolean>;

/**
 * Create an adapter around elliptic's ec("secp256k1") instance.
 * You can have multiple versions by resolving different node_modules or bundling.
 */
export function makeEllipticVerifyAdapter(ecInstance: EC): LibraryVerifyFn {
  return async ({ curve, msgHashHex, derHex, pubkeyHex }) => {
    const msg = Buffer.from(msgHashHex, "hex");
    const sig = Buffer.from(derHex, "hex");
    const key = ecInstance.keyFromPublic(pubkeyHex, "hex");

    try {
      const ok = key.verify(msg, sig);
      return ok === true;
    } catch {
      return false;
    }
  };
}

/**
 * Example adapter for noble-secp256k1, if you use it.
 */
// import * as nobleSecp from "@noble/secp256k1";
// export function makeNobleVerifyAdapter(): LibraryVerifyFn {
//   return async ({ curve, msgHashHex, derHex, pubkeyHex }) => {
//     if (curve !== "secp256k1") return false;
//     const msg = Buffer.from(msgHashHex, "hex");
//     const sig = Buffer.from(derHex, "hex");
//     const pub = Buffer.from(pubkeyHex, "hex");
//     try {
//       return nobleSecp.verify(sig, msg, pub);
//     } catch {
//       return false;
//     }
//   };
// }
