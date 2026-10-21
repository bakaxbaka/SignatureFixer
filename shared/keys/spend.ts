/**
 * shared/keys/spend.ts — S2/S3: check_balance + sign_spend.
 * Runtime: inproc. Reuses the repo's existing multi-endpoint fetcher (§3 "reuse as-is")
 * for UTXO lookup; signing goes through server/services/signer.ts (bitcoinjs-lib v7 PSBT).
 */
import { deriveAll, MAINNET, TESTNET, type Network } from "./derive";
import { buildAndSignTx } from "../../server/services/signer";

export interface UtxoSource {
  /** returns confirmed+unconfirmed UTXOs for an address */
  getUtxos(address: string, network?: "mainnet" | "testnet"): Promise<Utxo[]>;
}

export interface Utxo {
  txid: string;
  vout: number;
  valueSats: number;
  scriptPubKeyHex?: string;
  height?: number;
}

export interface BalanceHit {
  address: string;
  scriptType: string;
  compressed: boolean;
  totalSats: number;
  utxos: Utxo[];
}

/**
 * S2: sweep every derived address of candidate d against a UTXO source.
 * Tells you which candidate is the target — a funded hit is what separates
 * "we found a key" from a coincidence.
 */
export async function checkBalance(
  privkeyHex: string,
  source: UtxoSource,
  net: Network = MAINNET,
): Promise<BalanceHit[]> {
  const d = deriveAll(privkeyHex, net);
  const network = net === TESTNET ? ("testnet" as const) : ("mainnet" as const);
  const hits: BalanceHit[] = [];
  for (const a of d.addresses) {
    try {
      const utxos = await source.getUtxos(a.address, network);
      const total = utxos.reduce((s, u) => s + u.valueSats, 0);
      if (total > 0) {
        hits.push({ address: a.address, scriptType: a.scriptType, compressed: a.compressed, totalSats: total, utxos });
      }
    } catch {
      // unreachable explorer for this address form — record nothing, never fatal (R11 handled by caller)
    }
  }
  return hits;
}

export interface SpendRequest {
  privkeyHex: string;
  utxo: Utxo;
  prevScriptHex: string; // scriptPubKey of the funding output
  destAddress: string;   // where coins go (faucet-controlled in tests)
  feeSats?: number;
  network?: Network;
}

export interface SpendResult {
  rawTxHex: string;
  txId: string;
  psbtBase64?: string;
  error?: string;
}

/**
 * S3: prove control — sign a real spend of the recovered key's UTXO.
 * P2PKH/P2WPKH paths via bitcoinjs-lib v7 PSBT; PSBT returned as fallback proof.
 */
export async function signSpend(req: SpendRequest): Promise<SpendResult> {
  const net = req.network ?? MAINNET;
  const d = deriveAll(req.privkeyHex, net);
  const wif = d.wif;
  const value = req.utxo.valueSats;
  const fee = req.feeSats ?? 1000;
  const destValue = value - fee;
  if (destValue <= 0) return { rawTxHex: "", txId: "", error: "UTXO value below fee" };

  // encode destination address → scriptPubKey
  const bitcoin = await import("bitcoinjs-lib");
  let destScript: Buffer;
  try {
    destScript = Buffer.from(bitcoin.address.toOutputScript(req.destAddress, net.params));
  } catch (e: any) {
    return { rawTxHex: "", txId: "", error: "bad destination address: " + e.message };
  }

  const res = buildAndSignTx({
    wif,
    prevTxId: req.utxo.txid,
    prevVout: req.utxo.vout,
    prevValue: value,
    prevScriptHex: req.prevScriptHex,
    destValue,
    destScriptHex: destScript.toString("hex"),
  });
  if (res.error) return { rawTxHex: "", txId: "", error: res.error };
  return { rawTxHex: res.txHex, txId: res.txId };
}
