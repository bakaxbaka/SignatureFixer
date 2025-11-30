// Bitcoin transaction signing using bitcoinjs-lib
import * as bitcoin from "bitcoinjs-lib";

export interface SigningParams {
  wif: string;
  prevTxId: string;
  prevVout: number;
  prevValue: number;
  prevScriptHex: string;
  destValue: number;
  destScriptHex: string;
}

export interface SigningResult {
  txHex: string;
  txId: string;
  error?: string;
}

export function buildAndSignTx(params: SigningParams): SigningResult {
  try {
    const network = bitcoin.networks.bitcoin;
    const keyPair = bitcoin.ECPair.fromWIF(params.wif, network);
    
    const psbt = new bitcoin.Psbt({ network });

    // Add input (SegWit P2WPKH or legacy)
    psbt.addInput({
      hash: params.prevTxId,
      index: params.prevVout,
      witnessUtxo: {
        script: Buffer.from(params.prevScriptHex, "hex"),
        value: params.prevValue,
      },
    });

    // Add output
    psbt.addOutput({
      value: params.destValue,
      script: Buffer.from(params.destScriptHex, "hex"),
    });

    // Sign input 0
    psbt.signInput(0, keyPair);

    // Validate and finalize
    try {
      psbt.validateSignaturesOfInput(0);
    } catch (e) {
      console.warn("Signature validation warning:", (e as Error).message);
    }
    
    psbt.finalizeAllInputs();

    // Extract final transaction
    const tx = psbt.extractTransaction();
    const txHex = tx.toHex();
    const txId = tx.getId();

    return { txHex, txId };
  } catch (e) {
    return {
      txHex: "",
      txId: "",
      error: `Signing failed: ${(e as Error).message}`,
    };
  }
}

// Extract signatures from a signed transaction hex
export function extractSignaturesFromTxHex(txHex: string): Array<{
  index: number;
  signature: string;
  pubkey: string;
}> {
  try {
    const tx = bitcoin.Transaction.fromHex(txHex);
    const signatures: Array<{ index: number; signature: string; pubkey: string }> = [];

    tx.ins.forEach((input, idx) => {
      if (input.witness && input.witness.length > 0) {
        // SegWit witness format: [signature, pubkey, ...]
        signatures.push({
          index: idx,
          signature: input.witness[0].toString("hex"),
          pubkey: input.witness[1]?.toString("hex") || "",
        });
      } else if (input.script && input.script.length > 0) {
        // Legacy scriptSig format (harder to parse, simple approach)
        signatures.push({
          index: idx,
          signature: input.script.toString("hex"),
          pubkey: "",
        });
      }
    });

    return signatures;
  } catch (e) {
    console.error("Failed to extract signatures:", (e as Error).message);
    return [];
  }
}
