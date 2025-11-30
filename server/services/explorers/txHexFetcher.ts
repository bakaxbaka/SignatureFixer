// Transaction Hex Fetcher - Unified interface for raw tx hex across all APIs
import { torJson } from "../networking/torFetcher";
import fetch from "node-fetch";

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
  return res.text();
}

// Blockchain.info: /rawtx/{txid}?format=hex
async function hexFromBlockchain(txid: string): Promise<string> {
  const url = `https://blockchain.info/rawtx/${txid}?format=hex`;
  return (await fetchText(url)).trim();
}

// Blockstream / Esplora: /api/tx/:txid/hex
async function hexFromBlockstream(txid: string): Promise<string> {
  const url = `https://blockstream.info/api/tx/${txid}/hex`;
  return (await fetchText(url)).trim();
}

// Mempool.space: /api/tx/:txid/hex
async function hexFromMempool(txid: string): Promise<string> {
  const url = `https://mempool.space/api/tx/${txid}/hex`;
  return (await fetchText(url)).trim();
}

// BlockCypher: includeHex=true
async function hexFromBlockcypher(txid: string): Promise<string> {
  const url = `https://api.blockcypher.com/v1/btc/main/txs/${txid}?includeHex=true`;
  const json = await torJson(url, {}, true);
  if (!json.hex) throw new Error("No hex field in BlockCypher response");
  return (json.hex as string).trim();
}

// Unified helper - tries multiple sources in order
export async function getTxHex(txid: string): Promise<string> {
  const providers = [
    hexFromBlockchain,
    hexFromBlockstream,
    hexFromMempool,
    hexFromBlockcypher,
  ];

  let lastErr: any = null;
  for (const fn of providers) {
    try {
      const hex = await fn(txid);
      // Validate hex format
      if (!/^[0-9a-fA-F]+$/.test(hex)) throw new Error("Invalid hex format");
      return hex;
    } catch (e) {
      lastErr = e;
      continue;
    }
  }

  throw new Error(`All providers failed for txid ${txid}: ${lastErr?.message || ""}`);
}
