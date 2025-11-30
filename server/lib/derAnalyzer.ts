import type { SignatureDerIssue, SighashTypeName } from "../../client/src/types/txInspector";

const curveN = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const halfN = curveN >> 1n;

export interface DerAnalysisResult {
  rHex: string;
  sHex: string;
  sighashName: SighashTypeName;
  isHighS: boolean;
  isCanonical: boolean;
  rangeValid: boolean;
  derIssues: SignatureDerIssue[];
  warnings: string[];
}

export function analyzeDerSignature(derHex: string, sighashType?: number): DerAnalysisResult {
  const issues: SignatureDerIssue[] = [];
  const warnings: string[] = [];

  let rHex = "";
  let sHex = "";
  let isCanonical = true;
  let rangeValid = true;
  let isHighS = false;

  try {
    const buf = Buffer.from(derHex, "hex");

    let sig = buf;
    if (sighashType === undefined && buf.length > 0) {
      sighashType = buf[buf.length - 1];
      sig = buf.slice(0, -1);
    } else if (sighashType !== undefined && buf.length > 0) {
      sig = buf.slice(0, -1);
    }

    if (sig[0] !== 0x30) {
      isCanonical = false;
      issues.push({
        code: "BAD_SEQ_TAG",
        message: "Signature does not start with SEQUENCE (0x30)",
      });
    }

    const totalLen = sig[1];
    if (totalLen + 2 !== sig.length) {
      isCanonical = false;
      issues.push({
        code: "BAD_LENGTH",
        message: "SEQUENCE length does not match actual length",
      });
    }

    let offset = 2;
    if (sig[offset] !== 0x02) {
      isCanonical = false;
      issues.push({
        code: "BAD_LENGTH",
        message: "R integer does not start with 0x02",
      });
    }
    offset++;
    const lenR = sig[offset++];
    const rBytes = sig.slice(offset, offset + lenR);
    offset += lenR;

    if (sig[offset] !== 0x02) {
      isCanonical = false;
      issues.push({
        code: "BAD_LENGTH",
        message: "S integer does not start with 0x02",
      });
    }
    offset++;
    const lenS = sig[offset++];
    const sBytes = sig.slice(offset, offset + lenS);
    offset += lenS;

    if (offset !== sig.length) {
      isCanonical = false;
      issues.push({
        code: "TRAILING_GARBAGE",
        message: "Extra data after S integer",
      });
    }

    if (rBytes.length === 0 || (rBytes[0] === 0x00 && rBytes.length === 1)) {
      isCanonical = false;
    }
    if (rBytes.length > 1 && rBytes[0] === 0x00 && (rBytes[1] & 0x80) === 0) {
      isCanonical = false;
      issues.push({
        code: "EXTRA_PADDING_R",
        message: "Unnecessary leading zero in R",
      });
    }

    if (sBytes.length === 0 || (sBytes[0] === 0x00 && sBytes.length === 1)) {
      isCanonical = false;
    }
    if (sBytes.length > 1 && sBytes[0] === 0x00 && (sBytes[1] & 0x80) === 0) {
      isCanonical = false;
      issues.push({
        code: "EXTRA_PADDING_S",
        message: "Unnecessary leading zero in S",
      });
    }

    rHex = rBytes.toString("hex");
    sHex = sBytes.toString("hex");

    const r = BigInt("0x" + rHex);
    const s = BigInt("0x" + sHex);

    if (r <= 0n || r >= curveN) {
      rangeValid = false;
      issues.push({
        code: "OUT_OF_RANGE_R",
        message: "R not in [1, n-1]",
      });
    }
    if (s <= 0n || s >= curveN) {
      rangeValid = false;
      issues.push({
        code: "OUT_OF_RANGE_S",
        message: "S not in [1, n-1]",
      });
    }

    isHighS = s > halfN;
    if (isHighS) {
      warnings.push("High-S signature (non-canonical under BIP62 conventions)");
    }
  } catch (e: any) {
    isCanonical = false;
    warnings.push("Error parsing DER signature: " + e.message);
  }

  return {
    rHex,
    sHex,
    sighashName: classifySighashType(sighashType ?? 0x01),
    isHighS,
    isCanonical,
    rangeValid,
    derIssues: issues,
    warnings,
  };
}

export function classifySighashType(type: number): SighashTypeName {
  const base = type & 0x1f;
  const acp = (type & 0x80) !== 0;

  if (base === 0x01 && !acp) return "SIGHASH_ALL";
  if (base === 0x02 && !acp) return "SIGHASH_NONE";
  if (base === 0x03 && !acp) return "SIGHASH_SINGLE";
  if (base === 0x01 && acp) return "SIGHASH_ALL|ANYONECANPAY";
  if (base === 0x02 && acp) return "SIGHASH_NONE|ANYONECANPAY";
  if (base === 0x03 && acp) return "SIGHASH_SINGLE|ANYONECANPAY";
  return "UNKNOWN";
}
