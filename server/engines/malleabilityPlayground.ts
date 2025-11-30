import { analyzeDerStrict } from "../crypto/derStrict";
import type { CveEncodingType } from "./cve42461";

export interface MalleabilityVariant {
  id: string;
  encodingType: CveEncodingType;
  derHex: string;
}

/**
 * High-level: given a canonical DER, generate:
 *  - canonical
 *  - extra zero before R
 *  - extra zero before S
 *  - both padded
 *  - length-mismatch (len too big or too small)
 *  - wrong SEQ tag
 *  - trailing garbage
 */
export function generateCveStyleVariants(canonicalDerHex: string): MalleabilityVariant[] {
  const base = Buffer.from(canonicalDerHex, "hex");
  const variants: MalleabilityVariant[] = [];

  // 0) canonical
  variants.push({
    id: "canonical",
    encodingType: "canonical",
    derHex: base.toString("hex"),
  });

  // parse positions of R/S using strict analyzer (for offsets)
  const strict = analyzeDerStrict(canonicalDerHex);
  if (!strict.isCanonical) {
    // still generate some naive variants, but ideally canonical input
  }
  const buf = Buffer.from(canonicalDerHex, "hex");

  // helper to clone
  const clone = () => Buffer.from(buf);

  // 1) BER-padding-r
  variants.push({
    id: "ber-pad-r",
    encodingType: "BER-padding-r",
    derHex: addLeadingZeroToR(buf).toString("hex"),
  });

  // 2) BER-padding-s
  variants.push({
    id: "ber-pad-s",
    encodingType: "BER-padding-s",
    derHex: addLeadingZeroToS(buf).toString("hex"),
  });

  // 3) BER-padding-both
  variants.push({
    id: "ber-pad-both",
    encodingType: "BER-padding-both",
    derHex: addLeadingZeroToS(addLeadingZeroToR(buf)).toString("hex"),
  });

  // 4) BER-length-mismatch (increase SEQ length by 1)
  {
    const b = clone();
    if (b.length > 2) {
      b[1] = b[1] + 1; // incorrect length
    }
    variants.push({
      id: "ber-length",
      encodingType: "BER-length-mismatch",
      derHex: b.toString("hex"),
    });
  }

  // 5) wrong-seq-tag
  {
    const b = clone();
    b[0] = 0x31; // SET
    variants.push({
      id: "wrong-seq-tag",
      encodingType: "wrong-seq-tag",
      derHex: b.toString("hex"),
    });
  }

  // 6) trailing garbage
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

// Helpers: modify R/S length+value in a naive ASN.1 way

function addLeadingZeroToR(buf: Buffer): Buffer {
  const out = Buffer.from(buf);
  // find first INTEGER (R)
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
  // first INTEGER (R)
  let offset = 2;
  if (out[offset] !== 0x02) return out;
  offset++;
  const lenR = out[offset];
  offset += 1 + lenR;

  // second INTEGER (S)
  if (out[offset] !== 0x02) return out;
  offset++;
  const lenS = out[offset];
  out[offset] = lenS + 1;
  const before = out.slice(0, offset + 1);
  const sBytes = out.slice(offset + 1, offset + 1 + lenS);
  const after = out.slice(offset + 1 + lenS);
  return Buffer.concat([before, Buffer.from([0x00]), sBytes, after]);
}
