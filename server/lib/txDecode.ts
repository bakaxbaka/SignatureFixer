import { Transaction, toBuffer } from "./bjl";
import type { TxInputAnalysis, TxOutputAnalysis } from "../../client/src/types/txInspector";

export interface DecodedTx {
  txid: string;
  version: number;
  locktime: number;
  sizeBytes: number;
  vsizeBytes: number;
  weight: number;
  inputs: TxInputAnalysis[];
  outputs: TxOutputAnalysis[];
}

export function decodeRawTx(rawTxHex: string): DecodedTx {
  const buf = Buffer.from(rawTxHex, "hex");
  const tx = Transaction.fromBuffer(buf);

  const inputs: TxInputAnalysis[] = tx.ins.map((input, index) => {
    const prevTxid = toBuffer(input.hash).reverse().toString("hex");
    const prevVout = input.index;
    const scriptSigHex = toBuffer(input.script).toString("hex") || "";
    const isCoinbase = prevTxid === "0".repeat(64);

    return {
      index,
      prevTxid,
      prevVout,
      sequence: input.sequence,
      scriptSigHex,
      scriptSigAsm: "",
      witness: input.witness?.map((w) => toBuffer(w).toString("hex")) || [],
      scriptType: "unknown",
      valueSats: undefined,
      address: undefined,
      isCoinbase,
      pubkeyHex: undefined,
      signature: null,
      samePubkeyAsInputs: [],
    };
  });

  const outputs: TxOutputAnalysis[] = tx.outs.map((out, index) => ({
    index,
    valueSats: typeof out.value === "bigint" ? Number(out.value) : out.value,
    scriptPubKeyHex: toBuffer(out.script).toString("hex"),
    scriptPubKeyAsm: "",
    scriptType: "unknown",
    address: undefined,
    isChangeGuess: false,
  }));

  return {
    txid: tx.getId(),
    version: tx.version,
    locktime: tx.locktime,
    sizeBytes: buf.length,
    vsizeBytes: tx.virtualSize(),
    weight: tx.weight(),
    inputs,
    outputs,
  };
}
