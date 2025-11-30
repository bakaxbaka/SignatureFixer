export interface DerLooseResult {
  ok: boolean;
  rHex: string;
  sHex: string;
  error?: string;
}

export function parseDerLoose(sigHex: string): DerLooseResult {
  try {
    const buf = Buffer.from(sigHex, "hex");

    let firstInt = buf.indexOf(0x02, 2);
    if (firstInt < 0) throw new Error("No R integer tag (0x02) found");
    let lenR = buf[firstInt + 1];
    const rBytes = buf.slice(firstInt + 2, firstInt + 2 + lenR);

    const secondInt = buf.indexOf(0x02, firstInt + 2 + lenR);
    if (secondInt < 0) throw new Error("No S integer tag (0x02) found");
    let lenS = buf[secondInt + 1];
    const sBytes = buf.slice(secondInt + 2, secondInt + 2 + lenS);

    return {
      ok: true,
      rHex: rBytes.toString("hex"),
      sHex: sBytes.toString("hex"),
    };
  } catch (e: any) {
    return { ok: false, rHex: "", sHex: "", error: e.message };
  }
}
