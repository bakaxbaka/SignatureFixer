export interface LibraryVerifyParams {
  curve: string;
  msgHashHex: string;
  derHex: string;
  pubkeyHex: string;
}

export type LibraryVerifyFn = (params: LibraryVerifyParams) => Promise<boolean>;

export function makeEllipticVerifyAdapter(ecInstance: any): LibraryVerifyFn {
  return async ({ curve, msgHashHex, derHex, pubkeyHex }) => {
    try {
      const msg = Buffer.from(msgHashHex, "hex");
      const sig = Buffer.from(derHex, "hex");
      const key = ecInstance.keyFromPublic(pubkeyHex, "hex");
      const ok = key.verify(msg, sig);
      return ok === true;
    } catch {
      return false;
    }
  };
}
