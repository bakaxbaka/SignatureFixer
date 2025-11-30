import type { InspectTxRequest, InspectTxResponse } from "../../client/src/types/txInspector";
import { decodeRawTx } from "../lib/txDecode";
import { fetchPrevTx, buildPrevOutput } from "./utxoFetcher";
import { classifyScriptPubKey, decodeAddressFromScript } from "../lib/scriptAnalyzer";
import { extractInputSignature } from "./signature";
import { computeSighashZ } from "../lib/sighashCompute";
import { analyzeDerSignature } from "../lib/derAnalyzer";
import { NETWORK } from "../config/network";
import { getTxHex } from "./explorers/txHexFetcher";

export async function inspectTx(req: InspectTxRequest): Promise<InspectTxResponse> {
  try {
    if (!req.txid && !req.rawTxHex) {
      return { ok: false, error: "txid or rawTxHex is required" };
    }

    let rawTxHex = req.rawTxHex?.trim();
    if (!rawTxHex && req.txid) {
      rawTxHex = await getTxHex(req.txid);
      if (!rawTxHex) {
        return { ok: false, error: "Could not fetch transaction by txid" };
      }
    }
    if (!rawTxHex) {
      return { ok: false, error: "Empty rawTxHex after fetch" };
    }

    const decoded = decodeRawTx(rawTxHex);

    const enrichedInputs = await Promise.all(
      decoded.inputs.map(async (inp) => {
        if (inp.isCoinbase) return inp;

        const prevTx = await fetchPrevTx(inp.prevTxid);
        if (!prevTx) return inp;

        const prevOut = buildPrevOutput(prevTx, inp.prevVout);
        if (!prevOut) return inp;

        const scriptType = classifyScriptPubKey(prevOut.scriptPubKeyHex);
        const address = decodeAddressFromScript(prevOut.scriptPubKeyHex);

        return {
          ...inp,
          valueSats: prevOut.valueSats,
          scriptType,
          address,
          prevOutputScriptHex: prevOut.scriptPubKeyHex,
        } as any;
      })
    );

    const signatureAnalyses = await Promise.all(
      enrichedInputs.map(async (inp: any, index) => {
        if (inp.isCoinbase) return null;

        const sigInfo = extractInputSignature(inp);
        if (!sigInfo) return null;

        const { derHex, pubkeyHex, sighashType } = sigInfo;

        const zHex = computeSighashZ({
          rawTxHex,
          decodedTx: decoded,
          inputIndex: index,
          sighashType,
          prevOutputScriptHex: sigInfo.prevOutputScriptHex || inp.prevOutputScriptHex || "",
          prevOutputValueSats: sigInfo.prevOutputValueSats ?? inp.valueSats ?? 0,
        });

        const derAnalysis = analyzeDerSignature(derHex, sighashType);

        return {
          derHex,
          rHex: derAnalysis.rHex,
          sHex: derAnalysis.sHex,
          zHex,
          sighashType,
          sighashName: derAnalysis.sighashName,
          pubkeyHex,
          isHighS: derAnalysis.isHighS,
          isCanonicalDer: derAnalysis.isCanonical,
          rangeValid: derAnalysis.rangeValid,
          derIssues: derAnalysis.derIssues,
          warnings: derAnalysis.warnings,
        };
      })
    );

    const finalInputs = enrichedInputs.map((inp: any, i: number) => ({
      ...inp,
      signature: signatureAnalyses[i],
    }));

    const finalOutputs = decoded.outputs.map((out) => {
      const scriptType = classifyScriptPubKey(out.scriptPubKeyHex);
      const address = decodeAddressFromScript(out.scriptPubKeyHex);
      return {
        ...out,
        scriptType,
        address,
      };
    });

    const totalInputSats = finalInputs.map((i: any) => i.valueSats ?? 0).reduce((a: number, b: number) => a + b, 0);
    const totalOutputSats = finalOutputs.map((o) => o.valueSats).reduce((a: number, b: number) => a + b, 0);
    const feeSats = totalInputSats > 0 && totalOutputSats >= 0 ? totalInputSats - totalOutputSats : undefined;
    const feeRateSatPerVbyte = feeSats != null && decoded.vsizeBytes ? Math.round(feeSats / decoded.vsizeBytes) : undefined;

    const summaryFlags = {
      hasHighS: signatureAnalyses.some((s) => s?.isHighS),
      hasNonCanonicalDer: signatureAnalyses.some((s) => s && !s.isCanonicalDer),
      hasWeirdSighash: signatureAnalyses.some((s) => s && s.sighashName !== "SIGHASH_ALL"),
      hasRangeViolations: signatureAnalyses.some((s) => s && !s.rangeValid),
      hasMultiInputSameKey: detectMultiInputSameKey(finalInputs),
      hasRReuseWithinTx: detectRReuseWithinTx(signatureAnalyses),
    };

    return {
      ok: true,
      network: NETWORK,
      txid: decoded.txid,
      rawTxHex,
      version: decoded.version,
      locktime: decoded.locktime,
      sizeBytes: decoded.sizeBytes,
      vsizeBytes: decoded.vsizeBytes,
      weight: decoded.weight,
      totalInputSats,
      totalOutputSats,
      feeSats,
      feeRateSatPerVbyte,
      inputs: finalInputs,
      outputs: finalOutputs,
      summaryFlags,
    };
  } catch (err: any) {
    console.error("inspectTx error:", err);
    return { ok: false, error: err.message || "Unexpected error in inspectTx" };
  }
}

function detectMultiInputSameKey(inputs: any[]): boolean {
  const seen = new Map<string, number[]>();
  inputs.forEach((inp, idx) => {
    const pk = inp.signature?.pubkeyHex;
    if (!pk) return;
    const arr = seen.get(pk) || [];
    arr.push(idx);
    seen.set(pk, arr);
  });
  return Array.from(seen.values()).some((indices) => indices.length > 1);
}

function detectRReuseWithinTx(sigs: (any | null)[]): boolean {
  const seen = new Map<string, number[]>();
  sigs.forEach((s, idx) => {
    if (!s) return;
    const r = s.rHex;
    const arr = seen.get(r) || [];
    arr.push(idx);
    seen.set(r, arr);
  });
  return Array.from(seen.values()).some((indices) => indices.length > 1);
}
