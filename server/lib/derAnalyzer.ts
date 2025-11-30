/**
 * DER Analyzer
 * Analyzes DER signatures for canonical encoding and range validity
 */

import type { SignatureDerIssue, SighashTypeName } from "../../client/src/types/txInspector";

const SECP256K1_ORDER = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
const HALF_ORDER = SECP256K1_ORDER >> BigInt(1);

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

export function analyzeDerSignature(derHex: string, sighashByte: number): DerAnalysisResult {
  const issues: SignatureDerIssue[] = [];
  const warnings: string[] = [];
  
  const der = Buffer.from(derHex, "hex");
  let rHex = "";
  let sHex = "";
  let isCanonical = true;
  let rangeValid = true;
  let isHighS = false;

  try {
    // Remove sighash byte
    const derNoSighash = der.slice(0, der.length - 1);

    // Check sequence tag
    if (derNoSighash[0] !== 0x30) {
      issues.push({ code: "BAD_SEQ_TAG", message: "Expected 0x30 sequence tag" });
      isCanonical = false;
    }

    // Parse R
    let offset = 2;
    const rLen = derNoSighash[offset];
    offset++;
    
    if (derNoSighash[offset] === 0x00 && rLen > 1) {
      issues.push({ code: "EXTRA_PADDING_R", message: "Extra leading zero in R" });
      isCanonical = false;
    }

    rHex = derNoSighash.slice(offset, offset + rLen).toString("hex");
    const rValue = BigInt("0x" + rHex);

    if (rValue === BigInt(0) || rValue >= SECP256K1_ORDER) {
      issues.push({ code: "OUT_OF_RANGE_R", message: "R out of valid range" });
      rangeValid = false;
    }

    offset += rLen;

    // Parse S
    const sLen = derNoSighash[offset];
    offset++;

    if (derNoSighash[offset] === 0x00 && sLen > 1) {
      issues.push({ code: "EXTRA_PADDING_S", message: "Extra leading zero in S" });
      isCanonical = false;
    }

    sHex = derNoSighash.slice(offset, offset + sLen).toString("hex");
    const sValue = BigInt("0x" + sHex);

    if (sValue === BigInt(0) || sValue >= SECP256K1_ORDER) {
      issues.push({ code: "OUT_OF_RANGE_S", message: "S out of valid range" });
      rangeValid = false;
    }

    if (sValue > HALF_ORDER) {
      isHighS = true;
      warnings.push("High S value - not strictly canonical");
    }

    offset += sLen;

    // Check for trailing garbage
    if (offset !== derNoSighash.length) {
      issues.push({ code: "TRAILING_GARBAGE", message: "Trailing garbage after signature" });
      isCanonical = false;
    }
  } catch (e) {
    issues.push({ code: "BAD_LENGTH", message: (e as Error).message });
    isCanonical = false;
  }

  const sighashName = getSighashName(sighashByte);

  return {
    rHex,
    sHex,
    sighashName,
    isHighS,
    isCanonical: isCanonical && !isHighS,
    rangeValid,
    derIssues: issues,
    warnings,
  };
}

function getSighashName(byte: number): SighashTypeName {
  const base = byte & 0x1f;
  const anyonecanpay = (byte & 0x80) !== 0;

  let name: "SIGHASH_ALL" | "SIGHASH_NONE" | "SIGHASH_SINGLE" = "SIGHASH_ALL";
  if (base === 0x00 || base === 0x01) name = "SIGHASH_ALL";
  else if (base === 0x02) name = "SIGHASH_NONE";
  else if (base === 0x03) name = "SIGHASH_SINGLE";

  if (anyonecanpay) {
    return (name + "|ANYONECANPAY") as SighashTypeName;
  }
  return name;
}
