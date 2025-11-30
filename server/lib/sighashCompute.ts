import { Transaction } from "bitcoinjs-lib";
import type { DecodedTx } from "./txDecode";

export interface SighashContext {
  rawTxHex: string;
  decodedTx: DecodedTx;
  inputIndex: number;
  sighashType: number;
  prevOutputScriptHex: string;
  prevOutputValueSats: number;
}

export function computeSighashZ(ctx: SighashContext): string {
  try {
    const { rawTxHex, inputIndex, sighashType } = ctx;
    const buf = Buffer.from(rawTxHex, "hex");
    const tx = Transaction.fromBuffer(buf);

    const hash = tx.hashForSignature(
      inputIndex,
      Buffer.from(ctx.prevOutputScriptHex, "hex"),
      sighashType
    );

    return hash.toString("hex");
  } catch (e) {
    return "";
  }
}
