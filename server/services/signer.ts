import * as bitcoin from "bitcoinjs-lib";
import { generateAllMutations, type MutationResult } from "./derMutator";

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
  signatures?: Array<{ index: number; signature: string; pubkey: string }>;
  mutations?: MutationResult[];
  error?: string;
}

export function buildAndSignTx(params: SigningParams): SigningResult {
  try {
    const network = bitcoin.networks.bitcoin;
    const keyPair = bitcoin.ECPair.fromWIF(params.wif, network);
    
    const psbt = new bitcoin.Psbt({ network });

    psbt.addInput({
      hash: params.prevTxId,
      index: params.prevVout,
      witnessUtxo: {
        script: Buffer.from(params.prevScriptHex, "hex"),
        value: params.prevValue,
      },
    });

    psbt.addOutput({
      value: params.destValue,
      script: Buffer.from(params.destScriptHex, "hex"),
    });

    psbt.signInput(0, keyPair);

    try {
      psbt.validateSignaturesOfInput(0);
    } catch (e) {
      console.warn("Signature validation warning:", (e as Error).message);
    }
    
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();
    const txHex = tx.toHex();
    const txId = tx.getId();

    // Extract signatures from the transaction
    const signatures = extractSignaturesFromTxHex(txHex);

    // Generate DER malleability mutations for the first signature
    let mutations: MutationResult[] = [];
    if (signatures.length > 0) {
      const firstSig = signatures[0].signature;
      // Ensure signature has sighash byte
      const sigWithSighash = firstSig.length % 2 === 0 && !firstSig.endsWith("01") 
        ? firstSig + "01" 
        : firstSig;
      mutations = generateAllMutations(sigWithSighash);
    }

    return { txHex, txId, signatures, mutations };
  } catch (e) {
    return {
      txHex: "",
      txId: "",
      error: `Signing failed: ${(e as Error).message}`,
    };
  }
}

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
        signatures.push({
          index: idx,
          signature: input.witness[0].toString("hex"),
          pubkey: input.witness[1]?.toString("hex") || "",
        });
      } else if (input.script && input.script.length > 0) {
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
