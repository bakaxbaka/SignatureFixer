// ======================================================================
// Unified Fetcher: Blockstream → Mempool.space → BlockCypher
// Prioritizes APIs that return FULL transaction data with signatures
// ======================================================================

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

// ======================================================================
// Normalize to standard format: hash, inputs[], outputs[], time, tx_index
// ======================================================================
function normalizeTx(tx: any): any {
  // Standardize field names
  const hash = tx.hash || tx.txid || tx.tx_hash || '';
  
  const inputs = (tx.inputs || tx.vin || []).map((inp: any) => ({
    script: inp.script || inp.scriptsig || inp.scriptSig || '',
    scriptSig: inp.script || inp.scriptsig || inp.scriptSig || '',
    witness: inp.witness || inp.witness_data || [],
    prev_out: {
      script: inp.prev_out?.script || inp.prevout?.scriptpubkey || inp.output_script || '',
      value: inp.prev_out?.value || inp.prevout?.value || inp.output_value || 0,
      addr: inp.prev_out?.addr || inp.prevout?.address || inp.addresses?.[0] || ''
    },
    output_index: inp.output_index || inp.vout || 0,
    output_value: inp.output_value || inp.prev_out?.value || inp.prevout?.value || 0
  }));

  const outputs = (tx.outputs || tx.vout || []).map((out: any) => ({
    script: out.script || out.scriptpubkey || '',
    value: out.value || 0,
    addr: out.addr || out.address || out.scriptpubkey || ''
  }));

  return {
    hash,
    tx_index: tx.tx_index || tx.status?.block_index || -1,
    time: tx.time || tx.status?.block_time || (tx.received ? new Date(tx.received).getTime() / 1000 : Date.now() / 1000),
    inputs,
    outputs
  };
}

// ======================================================================
// Blockstream.info - PRIMARY (has full vin/vout with scriptsig/witness)
// ======================================================================
async function fetchBlockstream(address: string): Promise<AddressData> {
  const listUrl = `https://blockstream.info/api/address/${address}/txs`;

  const txsRes = await fetch(listUrl);
  if (!txsRes.ok) throw new Error(`Blockstream txs HTTP ${txsRes.status}`);
  const txList = await txsRes.json();

  // Get address info for total count
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
    // Ignore info fetch failure
  }

  return {
    address,
    totalTx: (txList || []).length,
    txs: (txList || []).map(normalizeTx)
  };
}

// ======================================================================
// Mempool.space - SECONDARY (has full vin/vout with scriptsig/witness)
// ======================================================================
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

// ======================================================================
// BlockCypher - TERTIARY (limited but better than nothing)
// ======================================================================
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
