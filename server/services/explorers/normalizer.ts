// ======================================================================
// Transaction Normalizer - Converts API responses to standard format
// ======================================================================

export function normalizeTx(tx: any): any {
  // Standardize field names across all blockchain APIs
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
