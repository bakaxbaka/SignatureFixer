import type { TxOutputAnalysis } from "../../client/src/types/txInspector";
import { decodeRawTx, type DecodedTx } from "../lib/txDecode";

const txCache = new Map<string, DecodedTx>();

export async function fetchPrevTx(txid: string): Promise<DecodedTx | null> {
  if (txCache.has(txid)) return txCache.get(txid)!;

  const raw = await fetchRawTxByTxid(txid);
  if (!raw) return null;

  const decoded = decodeRawTx(raw);
  txCache.set(txid, decoded);
  return decoded;
}

export async function fetchRawTxByTxid(txid: string): Promise<string | null> {
  console.warn("fetchRawTxByTxid: stub called for", txid);
  return null;
}

export function buildPrevOutput(
  prevTx: DecodedTx,
  vout: number
): { valueSats: number; scriptPubKeyHex: string } | null {
  const out = prevTx.outputs[vout];
  if (!out) return null;
  return {
    valueSats: out.valueSats,
    scriptPubKeyHex: out.scriptPubKeyHex,
  };
}
