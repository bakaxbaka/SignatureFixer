import type { SignatureDerIssue, SighashTypeName } from "../../client/src/types/txInspector";
import { classifySighashType } from "./sighashTypes";
import { getCurveOrder } from "./curveParams";

export interface DerStrictResult {
  rHex: string;
  sHex: string;
  isCanonical: boolean;
  rangeValid: boolean;
  isHighS: boolean;
  sighashType?: number;
  sighashName?: SighashTypeName;
  derIssues: SignatureDerIssue[];
  warnings: string[];
}

export function analyzeDerStrict(sigWithOptionalSighashHex: string, curve: string = "secp256k1"): DerStrictResult {
  const issues: SignatureDerIssue[] = [];
  const warnings: string[] = [];

  let rHex = "";
  let sHex = "";
  let isCanonical = true;
  let rangeValid = true;
  let isHighS = false;
  let sighashType: number | undefined;
  let sighashName: SighashTypeName | undefined;

  try {
    const full = Buffer.from(sigWithOptionalSighashHex, "hex");

    if (full.length > 9) {
      sighashType = full[full.length - 1];
    }

    const sig = sighashType !== undefined ? full.slice(0, -1) : full;

    if (sig[0] !== 0x30) {
      isCanonical = false;
      issues.push({
        code: "BAD_SEQ_TAG",
        message: "Signature does not start with 0x30 (SEQUENCE)",
      });
    }

    const totalLen = sig[1];
    if (totalLen + 2 !== sig.length) {
      isCanonical = false;
      issues.push({
        code: "BAD_LENGTH",
        message: "SEQUENCE length mismatch",
      });
    }

    let offset = 2;

    if (sig[offset] !== 0x02) {
      isCanonical = false;
      issues.push({
        code: "BAD_LENGTH",
        message: "R INTEGER does not start with 0x02",
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
        message: "S INTEGER does not start with 0x02",
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
        message: "Trailing data after S INTEGER",
      });
    }

    if (rBytes.length > 1 && rBytes[0] === 0x00 && (rBytes[1] & 0x80) === 0) {
      isCanonical = false;
      issues.push({
        code: "EXTRA_PADDING_R",
        message: "Unnecessary leading zero in R",
      });
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

    const curveN = getCurveOrder(curve);
    const halfN = curveN >> 1n;

    const r = BigInt("0x" + rHex);
    const s = BigInt("0x" + sHex);

    if (r <= 0n || r >= curveN) {
      rangeValid = false;
      issues.push({
        code: "OUT_OF_RANGE_R",
        message: "R is not in [1, n-1]",
      });
    }
    if (s <= 0n || s >= curveN) {
      rangeValid = false;
      issues.push({
        code: "OUT_OF_RANGE_S",
        message: "S is not in [1, n-1]",
      });
    }

    isHighS = s > halfN;
    if (isHighS) {
      warnings.push("High-S value (non-canonical under BIP62)");
    }

    if (sighashType !== undefined) {
      sighashName = classifySighashType(sighashType);
    }
  } catch (e: any) {
    isCanonical = false;
    warnings.push("DER parse error: " + e.message);
  }

  return {
    rHex,
    sHex,
    isCanonical,
    rangeValid,
    isHighS,
    sighashType,
    sighashName,
    derIssues: issues,
    warnings,
  };
}
