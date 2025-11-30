// ======================================================================
// Multi-Endpoint Blockchain Fetcher: Blockstream → Mempool → BlockCypher
// Prioritizes APIs that return FULL transaction data with signatures
// ======================================================================

import { normalizeTx } from './normalizer';

export interface AddressData {
  address: string;
  totalTx: number;
  txs: any[];
  source?: string;
}

export async function fetchAddressData(address: string): Promise<AddressData> {
  // Priority: APIs with full tx data (scriptsig/witness)
  
  try {
    console.log(`[Fetcher] Trying Blockstream for ${address}`);
    const result = await fetchBlockstream(address);
    result.source = 'blockstream.info';
    return result;
  } catch (e) {
    console.warn(`[Fetcher] Blockstream failed: ${(e as Error).message} → trying Mempool.space`);
  }

  try {
    console.log(`[Fetcher] Trying Mempool.space for ${address}`);
    const result = await fetchMempool(address);
    result.source = 'mempool.space';
    return result;
  } catch (e) {
    console.warn(`[Fetcher] Mempool.space failed: ${(e as Error).message} → trying BlockCypher`);
  }

  try {
    console.log(`[Fetcher] Trying BlockCypher for ${address}`);
    const result = await fetchBlockcypher(address);
    result.source = 'blockcypher.com';
    return result;
  } catch (e) {
    console.warn(`[Fetcher] BlockCypher failed: ${(e as Error).message} → ALL ENDPOINTS FAILED`);
  }

  throw new Error("All blockchain APIs failed");
}

// Blockstream.info - PRIMARY (has full vin/vout with scriptsig/witness)
async function fetchBlockstream(address: string): Promise<AddressData> {
  const listUrl = `https://blockstream.info/api/address/${address}/txs`;

  const txsRes = await fetch(listUrl);
  if (!txsRes.ok) throw new Error(`Blockstream txs HTTP ${txsRes.status}`);
  const txList = await txsRes.json();

  try {
    const infoUrl = `https://blockstream.info/api/address/${address}`;
    const infoRes = await fetch(infoUrl);
    if (infoRes.ok) {
      const infoJson = await infoRes.json();
      const totalTx = (infoJson.chain_stats?.tx_count || 0) + (infoJson.mempool_stats?.tx_count || 0);
      return {
        address,
        totalTx,
        txs: (txList || []).map(normalizeTx)
      };
    }
  } catch (e) {
    // Ignore
  }

  return {
    address,
    totalTx: (txList || []).length,
    txs: (txList || []).map(normalizeTx)
  };
}

// Mempool.space - SECONDARY (has full vin/vout with scriptsig/witness)
async function fetchMempool(address: string): Promise<AddressData> {
  const listUrl = `https://mempool.space/api/address/${address}/txs`;

  const res = await fetch(listUrl);
  if (!res.ok) throw new Error(`Mempool HTTP ${res.status}`);

  const txList = await res.json();

  return {
    address,
    totalTx: (txList || []).length,
    txs: (txList || []).map(normalizeTx)
  };
}

// BlockCypher - TERTIARY (limited but better than nothing)
async function fetchBlockcypher(address: string): Promise<AddressData> {
  const url = `https://api.blockcypher.com/v1/btc/main/addrs/${address}?limit=50&txlimit=50`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`BlockCypher HTTP ${res.status}`);

  const json = await res.json();

  return {
    address,
    totalTx: json.n_tx || 0,
    txs: (json.txs || json.txrefs || []).map(normalizeTx)
  };
}
