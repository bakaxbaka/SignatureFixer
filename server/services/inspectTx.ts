/**
 * Transaction Inspection Service
 * Main orchestrator for end-to-end TX analysis
 */

import type { InspectTxRequest, InspectTxResponse } from "../../client/src/types/txInspector";
import { decodeRawTx } from "../lib/txDecode";
import { classifyScriptPubKey, decodeAddressFromScript } from "../lib/scriptAnalyzer";
import { extractInputSignature } from "../lib/signatureAnalyzer";
import { computeSighashZ } from "../lib/sighashCompute";
import { analyzeDerSignature } from "../lib/derAnalyzer";
import { getTxHex } from "./explorers/txHexFetcher";

export async function inspectTx(req: InspectTxRequest): Promise<InspectTxResponse> {
  try {
    if (!req.txid && !req.rawTxHex) {
      return { ok: false, error: "txid or rawTxHex is required" };
    }

    // Normalize input
    let rawTxHex = req.rawTxHex?.trim().toLowerCase();
    
    if (!rawTxHex && req.txid) {
      rawTxHex = await getTxHex(req.txid);
      if (!rawTxHex) {
        return { ok: false, error: "Could not fetch transaction by txid" };
      }
    }

    if (!rawTxHex) {
      return { ok: false, error: "Empty rawTxHex after fetch" };
    }

    // Decode TX
    const decoded = decodeRawTx(rawTxHex);

    // Enrich inputs with UTXO data
    const enrichedInputs = decoded.inputs.map((inp) => {
      const scriptType = classifyScriptPubKey(inp.scriptSig || "");
      const address = decodeAddressFromScript(inp.scriptSig || "");

      return {
        ...inp,
        scriptType,
        address,
        valueSats: undefined, // Would fetch from previous TX in production
      };
    });

    // Extract and analyze signatures
    const signatureAnalyses = enrichedInputs.map((inp, index) => {
      if (inp.isCoinbase) return null;

      const sigInfo = extractInputSignature(inp);
      if (!sigInfo) return null;

      const { derHex, pubkeyHex, sighashType } = sigInfo;

      // Compute sighash preimage z
      const zHex = computeSighashZ({
        rawTxHex,
        decodedTx: decoded,
        inputIndex: index,
        sighashType,
        prevOutputScriptHex: inp.scriptSig,
        prevOutputValueSats: inp.valueSats,
      });

      // Analyze DER signature
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
    });

    // Stitch signature info back into inputs
    const finalInputs = enrichedInputs.map((inp, i) => ({
      ...inp,
      signature: signatureAnalyses[i],
    }));

    // Compute summary flags
    const totalInputSats = finalInputs.reduce((sum, i) => sum + (i.valueSats ?? 0), 0);
    const totalOutputSats = decoded.outputs.reduce((sum, o) => sum + o.valueSats, 0);
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
      network: "mainnet",
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
      inputs: finalInputs as any,
      outputs: decoded.outputs as any,
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
