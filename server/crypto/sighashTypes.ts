import type { SighashTypeName } from "../../client/src/types/txInspector";

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
