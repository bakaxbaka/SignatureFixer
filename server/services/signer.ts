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
  signatures?: Array<{ index: number; signature: string; pubkey: string; type: string }>;
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

// Enhanced signature extraction with full SegWit support
export function extractSignaturesFromTxHex(txHex: string): Array<{
  index: number;
  signature: string;
  pubkey: string;
  type: string;
}> {
  try {
    // Parse transaction structure manually for full SegWit support
    let offset = 0;
    const buf = Buffer.from(txHex, "hex");

    // Read version (4 bytes)
    offset += 4;

    // Check for SegWit marker + flag
    let isSegWit = false;
    if (buf[offset] === 0x00 && buf[offset + 1] === 0x01) {
      isSegWit = true;
      offset += 2; // Skip marker and flag
    }

    // Read input count (varint)
    const inputCountRead = readVarInt(buf, offset);
    const inputCount = inputCountRead.value;
    offset = inputCountRead.offset;

    const signatures: Array<{ index: number; signature: string; pubkey: string; type: string }> = [];

    // Parse inputs (but skip scriptSig in SegWit)
    for (let i = 0; i < inputCount; i++) {
      offset += 32 + 4; // txid (32) + vout (4)

      // Read scriptSig length
      const scriptLenRead = readVarInt(buf, offset);
      const scriptLen = scriptLenRead.value;
      offset = scriptLenRead.offset;

      // Skip scriptSig (empty for SegWit, but might have data for legacy)
      offset += scriptLen;

      // Skip sequence
      offset += 4;
    }

    // Read output count (varint)
    const outputCountRead = readVarInt(buf, offset);
    const outputCount = outputCountRead.value;
    offset = outputCountRead.offset;

    // Skip outputs
    for (let i = 0; i < outputCount; i++) {
      offset += 8; // value (8 bytes)

      const scriptPubKeyLenRead = readVarInt(buf, offset);
      const scriptPubKeyLen = scriptPubKeyLenRead.value;
      offset = scriptPubKeyLenRead.offset;

      offset += scriptPubKeyLen;
    }

    // Parse witness data if SegWit
    if (isSegWit) {
      for (let i = 0; i < inputCount; i++) {
        const witnessCountRead = readVarInt(buf, offset);
        const witnessCount = witnessCountRead.value;
        offset = witnessCountRead.offset;

        // For P2WPKH: witness has 2 items [signature, pubkey]
        if (witnessCount === 2) {
          // Read signature
          const sigLenRead = readVarInt(buf, offset);
          const sigLen = sigLenRead.value;
          offset = sigLenRead.offset;

          const signature = buf.slice(offset, offset + sigLen).toString("hex");
          offset += sigLen;

          // Read pubkey
          const pubkeyLenRead = readVarInt(buf, offset);
          const pubkeyLen = pubkeyLenRead.value;
          offset = pubkeyLenRead.offset;

          const pubkey = buf.slice(offset, offset + pubkeyLen).toString("hex");
          offset += pubkeyLen;

          signatures.push({
            index: i,
            signature,
            pubkey,
            type: "P2WPKH",
          });
        } else if (witnessCount > 0) {
          // Other witness types: just collect first item as signature
          const firstLenRead = readVarInt(buf, offset);
          const firstLen = firstLenRead.value;
          offset = firstLenRead.offset;

          const sig = buf.slice(offset, offset + firstLen).toString("hex");
          offset += firstLen;

          // Skip remaining witness items
          for (let j = 1; j < witnessCount; j++) {
            const lenRead = readVarInt(buf, offset);
            offset = lenRead.offset + lenRead.value;
          }

          signatures.push({
            index: i,
            signature: sig,
            pubkey: "",
            type: "SegWit",
          });
        }
      }
    } else {
      // Legacy transaction - use bitcoinjs-lib
      try {
        const tx = bitcoin.Transaction.fromHex(txHex);
        tx.ins.forEach((input, idx) => {
          if (input.script && input.script.length > 0) {
            signatures.push({
              index: idx,
              signature: input.script.toString("hex"),
              pubkey: "",
              type: "Legacy",
            });
          }
        });
      } catch (e) {
        console.warn("Fallback legacy parsing failed");
      }
    }

    return signatures;
  } catch (e) {
    console.error("Failed to extract signatures:", (e as Error).message);
    return [];
  }
}

// Helper: read varint from buffer
function readVarInt(buf: Buffer, offset: number): { value: number; offset: number } {
  const byte = buf[offset];
  if (byte < 0xfd) {
    return { value: byte, offset: offset + 1 };
  } else if (byte === 0xfd) {
    return { value: buf.readUInt16LE(offset + 1), offset: offset + 3 };
  } else if (byte === 0xfe) {
    return { value: buf.readUInt32LE(offset + 1), offset: offset + 5 };
  } else {
    // 0xff - 64 bit, just return low 32 bits for simplicity
    return { value: buf.readUInt32LE(offset + 1), offset: offset + 9 };
  }
}
