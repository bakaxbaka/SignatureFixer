import { torJson } from "../networking/torFetcher";
import fetch from "node-fetch";

export interface BroadcastResult {
  success: boolean;
  txid?: string;
  endpoint?: string;
  message?: string;
  error?: string;
}

// Broadcast TX hex to blockchain
export async function broadcastTransaction(txHex: string): Promise<BroadcastResult> {
  console.log(`[Broadcaster] Broadcasting TX: ${txHex.slice(0, 20)}...`);

  // Try Blockstream API
  try {
    console.log("[Broadcaster] Trying Blockstream...");
    const res = await fetch("https://blockstream.info/api/tx", {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: txHex,
    });
    if (res.ok) {
      const txid = await res.text();
      console.log(`[Broadcaster] ✓ Blockstream success: ${txid}`);
      return { success: true, txid, endpoint: "blockstream" };
    }
  } catch (e) {
    console.warn("[Broadcaster] Blockstream failed:", (e as Error).message);
  }

  // Try Mempool API
  try {
    console.log("[Broadcaster] Trying Mempool...");
    const res = await fetch("https://mempool.space/api/tx", {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: txHex,
    });
    if (res.ok) {
      const txid = await res.text();
      console.log(`[Broadcaster] ✓ Mempool success: ${txid}`);
      return { success: true, txid, endpoint: "mempool" };
    }
  } catch (e) {
    console.warn("[Broadcaster] Mempool failed:", (e as Error).message);
  }

  // Try BlockCypher API
  try {
    console.log("[Broadcaster] Trying BlockCypher...");
    const data = await torJson("https://api.blockcypher.com/v1/btc/main/txs/push", {}, false);
    if (data) {
      console.log(`[Broadcaster] ✓ BlockCypher success: ${data.tx?.hash}`);
      return { success: true, txid: data.tx?.hash, endpoint: "blockcypher" };
    }
  } catch (e) {
    console.warn("[Broadcaster] BlockCypher failed:", (e as Error).message);
  }

  return {
    success: false,
    error: "All broadcast endpoints failed",
  };
}

// Get transaction status
export async function getTxStatus(txid: string): Promise<any> {
  try {
    // Try Blockstream first
    const data = await torJson(`https://blockstream.info/api/tx/${txid}`, {}, true);
    if (data) {
      return {
        confirmed: data.status?.confirmed || false,
        confirmations: data.status?.block_height || 0,
        blocktime: data.status?.block_time,
        endpoint: "blockstream",
      };
    }
  } catch (e) {
    console.warn("Status check failed:", (e as Error).message);
  }
  return { confirmed: false, confirmations: 0 };
}
