// ======================================================================
// Unified Fetcher: Blockchain.info → Blockstream → Mempool.space → BlockCypher
// Normalizes all transaction formats to Blockchain.info standard
// ======================================================================

export interface AddressData {
  address: string;
  totalTx: number;
  txs: any[];
  source?: string;
}

export async function fetchAddressData(address: string): Promise<AddressData> {
  try {
    console.log(`[Fetcher] Trying Blockchain.info for ${address}`);
    const result = await fetchBlockchainInfo(address);
    result.source = 'blockchain.info';
    return result;
  } catch (e) {
    console.warn(`[Fetcher] Blockchain.info failed: ${(e as Error).message} → trying Blockstream`);
  }

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
// Normalize transaction to Blockchain.info format (hash, inputs, outputs, time, tx_index)
// ======================================================================
function normalizeTx(tx: any, source: 'blockchain' | 'blockstream' | 'mempool' | 'blockcypher'): any {
  if (source === 'blockchain') {
    // Ensure inputs/outputs exist with required fields
    return {
      ...tx,
      inputs: (tx.inputs || []).map((inp: any) => ({
        script: inp.script || inp.scriptSig || '',
        scriptSig: inp.script || inp.scriptSig || '',
        witness: inp.witness || [],
        prev_out: inp.prev_out || { script: '', value: 0, addr: '' },
        output_index: inp.output_index || 0,
        output_value: inp.output_value || 0
      }))
    };
  }

  if (source === 'blockstream') {
    // Blockstream format: txid, vin, vout, status
    const normalized: any = {
      hash: tx.txid,
      tx_index: tx.status?.block_index || -1,
      time: tx.status?.block_time || Date.now() / 1000,
      inputs: (tx.vin || []).map((vin: any) => ({
        script: vin.scriptsig || vin.scriptSig || '',
        scriptSig: vin.scriptsig || vin.scriptSig || '',
        witness: vin.witness || [],
        prev_out: {
          script: vin.prevout?.scriptpubkey || '',
          value: vin.prevout?.value || 0,
          addr: vin.prevout?.scriptpubkey || ''
        },
        output_index: vin.vout || 0,
        output_value: vin.prevout?.value || 0
      })),
      outputs: (tx.vout || []).map((vout: any) => ({
        script: vout.scriptpubkey || '',
        value: vout.value || 0,
        addr: vout.scriptpubkey || ''
      }))
    };
    return normalized;
  }

  if (source === 'mempool') {
    // Mempool format: txid, vin, vout, status (similar to blockstream but different details)
    const normalized: any = {
      hash: tx.txid,
      tx_index: -1,
      time: tx.status?.block_time || Date.now() / 1000,
      inputs: (tx.vin || []).map((vin: any) => ({
        script: vin.scriptsig || '',
        scriptSig: vin.scriptsig || '',
        witness: vin.witness || [],
        prev_out: {
          script: vin.prevout?.scriptpubkey || '',
          value: vin.prevout?.value || 0,
          addr: vin.prevout?.address || ''
        },
        output_index: vin.vout || 0,
        output_value: vin.prevout?.value || 0
      })),
      outputs: (tx.vout || []).map((vout: any) => ({
        script: vout.scriptpubkey || '',
        value: vout.value || 0,
        addr: vout.address || ''
      }))
    };
    return normalized;
  }

  if (source === 'blockcypher') {
    // BlockCypher format: tx_hash, inputs, outputs, received, confirmed
    const normalized: any = {
      hash: tx.tx_hash || tx.hash,
      tx_index: -1,
      time: tx.received ? new Date(tx.received).getTime() / 1000 : Date.now() / 1000,
      inputs: (tx.inputs || []).map((inp: any) => ({
        script: inp.script || inp.script_signature || '',
        scriptSig: inp.script || inp.script_signature || '',
        witness: inp.witness_data ? (typeof inp.witness_data === 'string' ? [inp.witness_data] : inp.witness_data) : [],
        prev_out: {
          script: inp.output_script || '',
          value: inp.output_value || 0,
          addr: inp.addresses?.[0] || ''
        },
        output_index: inp.output_index || 0,
        output_value: inp.output_value || 0
      })),
      outputs: (tx.outputs || []).map((out: any) => ({
        script: out.script || '',
        value: out.value || 0,
        addr: out.addresses?.[0] || ''
      }))
    };
    return normalized;
  }

  return tx;
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
    txs: (json.txs || []).map((tx: any) => normalizeTx(tx, 'blockchain'))
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
    txs: (txList || []).map((tx: any) => normalizeTx(tx, 'blockstream'))
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
    txs: (txList || []).map((tx: any) => normalizeTx(tx, 'mempool'))
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
    txs: (json.txrefs || []).map((txRef: any) => {
      // For BlockCypher txrefs, we need to fetch full tx details
      // But for now, normalize what we have
      return normalizeTx({
        tx_hash: txRef.tx_hash,
        inputs: txRef.inputs || [],
        outputs: txRef.outputs || [],
        received: txRef.received || new Date().toISOString()
      }, 'blockcypher');
    })
  };
}
