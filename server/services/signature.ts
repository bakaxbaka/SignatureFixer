import type { TxInputAnalysis } from "../../client/src/types/txInspector";

export interface ExtractedSignature {
  derHex: string;
  pubkeyHex?: string;
  sighashType: number;
  prevOutputScriptHex: string;
  prevOutputValueSats: number;
}

export function extractInputSignature(inp: TxInputAnalysis): ExtractedSignature | null {
  if (inp.isCoinbase) return null;

  if (!inp.valueSats) return null;

  if (inp.scriptSigHex && inp.scriptSigHex.length > 0) {
    const buf = Buffer.from(inp.scriptSigHex, "hex");
    let offset = 0;
    if (offset >= buf.length) return null;

    const sigLen = buf[offset];
    offset++;
    const sig = buf.slice(offset, offset + sigLen);
    offset += sigLen;

    const pubLen = buf[offset];
    offset++;
    const pub = buf.slice(offset, offset + pubLen);

    const sighashType = sig[sig.length - 1];
    const der = sig.slice(0, -1);

    const prevOutputScriptHexPlaceholder = "";

    return {
      derHex: der.toString("hex"),
      pubkeyHex: pub.toString("hex"),
      sighashType,
      prevOutputScriptHex: prevOutputScriptHexPlaceholder,
      prevOutputValueSats: inp.valueSats,
    };
  }

  if (inp.witness && inp.witness.length === 2) {
    const sigBuf = Buffer.from(inp.witness[0], "hex");
    const pubBuf = Buffer.from(inp.witness[1], "hex");
    const sighashType = sigBuf[sigBuf.length - 1];
    const der = sigBuf.slice(0, -1);

    const prevOutputScriptHexPlaceholder = "";

    return {
      derHex: der.toString("hex"),
      pubkeyHex: pubBuf.toString("hex"),
      sighashType,
      prevOutputScriptHex: prevOutputScriptHexPlaceholder,
      prevOutputValueSats: inp.valueSats,
    };
  }

  return null;
}
