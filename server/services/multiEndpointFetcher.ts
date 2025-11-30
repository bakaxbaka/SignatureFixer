// ======================================================================
// Unified Fetcher: Blockchain.info → Blockstream → Mempool.space → BlockCypher
// ======================================================================

export interface AddressData {
  address: string;
  totalTx: number;
  txs: any[];
}

export async function fetchAddressData(address: string): Promise<AddressData> {
  try {
    console.log(`[Fetcher] Trying Blockchain.info for ${address}`);
    return await fetchBlockchainInfo(address);
  } catch (e) {
    console.warn(`[Fetcher] Blockchain.info failed: ${(e as Error).message} → trying Blockstream`);
  }

  try {
    console.log(`[Fetcher] Trying Blockstream for ${address}`);
    return await fetchBlockstream(address);
  } catch (e) {
    console.warn(`[Fetcher] Blockstream failed: ${(e as Error).message} → trying Mempool.space`);
  }

  try {
    console.log(`[Fetcher] Trying Mempool.space for ${address}`);
    return await fetchMempool(address);
  } catch (e) {
    console.warn(`[Fetcher] Mempool.space failed: ${(e as Error).message} → trying BlockCypher`);
  }

  try {
    console.log(`[Fetcher] Trying BlockCypher for ${address}`);
    return await fetchBlockcypher(address);
  } catch (e) {
    console.warn(`[Fetcher] BlockCypher failed: ${(e as Error).message} → ALL ENDPOINTS FAILED`);
  }

  throw new Error("All blockchain APIs failed");
}

// ======================================================================
// 1) Blockchain.info (primary - single call, no pagination)
// ======================================================================
async function fetchBlockchainInfo(address: string): Promise<AddressData> {
  const url = `https://blockchain.info/rawaddr/${address}?offset=0&limit=50`;
  const res = await fetch(url);
  
  if (res.status === 429) throw new Error("Rate limited");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  
  const json = await res.json();
  
  return {
    address,
    totalTx: json.n_tx || 0,
    txs: json.txs || []
  };
}

// ======================================================================
// 2) Blockstream.info fallback
// ======================================================================
async function fetchBlockstream(address: string): Promise<AddressData> {
  const infoUrl = `https://blockstream.info/api/address/${address}`;
  const listUrl = `https://blockstream.info/api/address/${address}/txs`;

  const infoRes = await fetch(infoUrl);
  if (!infoRes.ok) throw new Error(`Blockstream address HTTP ${infoRes.status}`);
  const infoJson = await infoRes.json();

  const txsRes = await fetch(listUrl);
  if (!txsRes.ok) throw new Error(`Blockstream txs HTTP ${txsRes.status}`);
  const txList = await txsRes.json();

  return {
    address,
    totalTx: (infoJson.chain_stats?.tx_count || 0) + (infoJson.mempool_stats?.tx_count || 0),
    txs: txList || []
  };
}

// ======================================================================
// 3) Mempool.space fallback
// ======================================================================
async function fetchMempool(address: string): Promise<AddressData> {
  const listUrl = `https://mempool.space/api/address/${address}/txs`;

  const res = await fetch(listUrl);
  if (!res.ok) throw new Error(`Mempool HTTP ${res.status}`);

  const txList = await res.json();

  return {
    address,
    totalTx: (txList || []).length,
    txs: txList || []
  };
}

// ======================================================================
// 4) BlockCypher final fallback
// ======================================================================
async function fetchBlockcypher(address: string): Promise<AddressData> {
  const url = `https://api.blockcypher.com/v1/btc/main/addrs/${address}?limit=50&txlimit=50`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`BlockCypher HTTP ${res.status}`);

  const json = await res.json();

  return {
    address,
    totalTx: json.n_tx || 0,
    txs: json.txrefs || []
  };
}
