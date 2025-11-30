/**
 * Transaction Decoder
 * Parses raw TX hex into structure with inputs, outputs, version, locktime, etc.
 */

import * as bitcoin from "bitcoinjs-lib";

export interface DecodedTx {
  txid: string;
  version: number;
  locktime: number;
  inputs: Array<{
    index: number;
    prevTxid: string;
    prevVout: number;
    sequence: number;
    scriptSig?: string;
    witness?: string[];
    isCoinbase: boolean;
  }>;
  outputs: Array<{
    index: number;
    valueSats: number;
    scriptPubKeyHex: string;
  }>;
  sizeBytes: number;
  vsizeBytes: number;
  weight: number;
  isSegwit: boolean;
}

export function decodeRawTx(rawTxHex: string): DecodedTx {
  const sanitized = rawTxHex.trim().toLowerCase();
  const buffer = Buffer.from(sanitized, "hex");

  // Parse with bitcoinjs-lib
  const tx = bitcoin.Transaction.fromBuffer(buffer);

  // Calculate txid
  const txid = tx.getId();

  // Calculate weight & size
  const size = buffer.length;
  const weight = tx.weight();
  const vsize = Math.ceil(weight / 4);
  const isSegwit = weight > size * 4;

  // Parse inputs
  const inputs = tx.ins.map((inp, index) => ({
    index,
    prevTxid: Buffer.from(inp.hash as any).reverse().toString("hex"),
    prevVout: inp.index,
    sequence: inp.sequence,
    scriptSig: inp.script.toString("hex"),
    witness: inp.witness ? inp.witness.map((w) => w.toString("hex")) : undefined,
    isCoinbase: index === 0 && Buffer.from(inp.hash as any).every((b) => b === 0) && inp.index === 0xffffffff,
  }));

  // Parse outputs
  const outputs = tx.outs.map((out, index) => ({
    index,
    valueSats: typeof out.value === "bigint" ? Number(out.value) : out.value,
    scriptPubKeyHex: out.script.toString("hex"),
  }));

  return {
    txid,
    version: tx.version,
    locktime: tx.locktime,
    inputs,
    outputs,
    sizeBytes: size,
    vsizeBytes: vsize,
    weight,
    isSegwit,
  };
}
