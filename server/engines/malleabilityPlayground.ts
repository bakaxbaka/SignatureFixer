import { analyzeDerStrict } from "../crypto/derStrict";

export type CveEncodingType =
  | "canonical"
  | "BER-padding-r"
  | "BER-padding-s"
  | "BER-padding-both"
  | "BER-length-mismatch"
  | "wrong-seq-tag"
  | "trailing-garbage";

export interface MalleabilityVariant {
  id: string;
  encodingType: CveEncodingType;
  derHex: string;
}

export function generateCveStyleVariants(canonicalDerHex: string): MalleabilityVariant[] {
  const base = Buffer.from(canonicalDerHex, "hex");
  const variants: MalleabilityVariant[] = [];

  variants.push({
    id: "canonical",
    encodingType: "canonical",
    derHex: base.toString("hex"),
  });

  const buf = Buffer.from(canonicalDerHex, "hex");
  const clone = () => Buffer.from(buf);

  variants.push({
    id: "ber-pad-r",
    encodingType: "BER-padding-r",
    derHex: addLeadingZeroToR(buf).toString("hex"),
  });

  variants.push({
    id: "ber-pad-s",
    encodingType: "BER-padding-s",
    derHex: addLeadingZeroToS(buf).toString("hex"),
  });

  variants.push({
    id: "ber-pad-both",
    encodingType: "BER-padding-both",
    derHex: addLeadingZeroToS(addLeadingZeroToR(buf)).toString("hex"),
  });

  {
    const b = clone();
    if (b.length > 2) {
      b[1] = b[1] + 1;
    }
    variants.push({
      id: "ber-length",
      encodingType: "BER-length-mismatch",
      derHex: b.toString("hex"),
    });
  }

  {
    const b = clone();
    b[0] = 0x31;
    variants.push({
      id: "wrong-seq-tag",
      encodingType: "wrong-seq-tag",
      derHex: b.toString("hex"),
    });
  }

  {
    const b = Buffer.concat([clone(), Buffer.from("deadbeef", "hex")]);
    variants.push({
      id: "trailing-garbage",
      encodingType: "trailing-garbage",
      derHex: b.toString("hex"),
    });
  }

  return variants;
}

function addLeadingZeroToR(buf: Buffer): Buffer {
  const out = Buffer.from(buf);
  let offset = 2;
  if (out[offset] !== 0x02) return out;
  offset++;
  const lenR = out[offset];
  out[offset] = lenR + 1;
  const before = out.slice(0, offset + 1);
  const rBytes = out.slice(offset + 1, offset + 1 + lenR);
  const after = out.slice(offset + 1 + lenR);
  return Buffer.concat([before, Buffer.from([0x00]), rBytes, after]);
}

function addLeadingZeroToS(buf: Buffer): Buffer {
  const out = Buffer.from(buf);
  let offset = 2;
  if (out[offset] !== 0x02) return out;
  offset++;
  const lenR = out[offset];
  offset += 1 + lenR;

  if (out[offset] !== 0x02) return out;
  offset++;
  const lenS = out[offset];
  out[offset] = lenS + 1;
  const before = out.slice(0, offset + 1);
  const sBytes = out.slice(offset + 1, offset + 1 + lenS);
  const after = out.slice(offset + 1 + lenS);
  return Buffer.concat([before, Buffer.from([0x00]), sBytes, after]);
}
