export interface UTXO {
  txid: string;
  vout: number;
  value: number;
  scriptPubKey: string;
  confirmed: boolean;
  address?: string;
}

// Fast direct UTXO fetcher without Tor (for quick responses)
export async function getUTXOsFast(address: string): Promise<UTXO[]> {
  const utxos: UTXO[] = [];

  // Try Blockstream API (direct, no Tor)
  try {
    console.log("[FastUTXO] Trying Blockstream for:", address);
    const res = await Promise.race([
      fetch(`https://blockstream.info/api/address/${address}`, { signal: AbortSignal.timeout(5000) }),
      new Promise<Response>((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000))
    ]);
    
    if (res && res.ok) {
      const data = await res.json() as any;
      if (data.utxo && Array.isArray(data.utxo)) {
        utxos.push(...data.utxo.map((u: any) => ({
          txid: u.txid,
          vout: u.vout,
          value: u.value,
          scriptPubKey: "",
          confirmed: u.status?.confirmed !== false,
          address,
        })));
        console.log("[FastUTXO] Blockstream found", utxos.length, "UTXOs");
        if (utxos.length > 0) return utxos;
      }
    }
  } catch (e) {
    console.warn("[FastUTXO] Blockstream failed:", (e as Error).message);
  }

  // Try Mempool API
  try {
    console.log("[FastUTXO] Trying Mempool for:", address);
    const res = await Promise.race([
      fetch(`https://mempool.space/api/address/${address}/utxo`, { signal: AbortSignal.timeout(5000) }),
      new Promise<Response>((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000))
    ]);
    
    if (res && res.ok) {
      const data = await res.json() as any;
      if (Array.isArray(data)) {
        utxos.push(...data.map((u: any) => ({
          txid: u.txid,
          vout: u.vout,
          value: u.value,
          scriptPubKey: "",
          confirmed: u.status?.confirmed !== false,
          address,
        })));
        console.log("[FastUTXO] Mempool found", utxos.length, "UTXOs");
        if (utxos.length > 0) return utxos;
      }
    }
  } catch (e) {
    console.warn("[FastUTXO] Mempool failed:", (e as Error).message);
  }

  // Try BlockCypher API
  try {
    console.log("[FastUTXO] Trying BlockCypher for:", address);
    const res = await Promise.race([
      fetch(`https://api.blockcypher.com/v1/btc/main/addrs/${address}?unspentOnly=true`, { signal: AbortSignal.timeout(5000) }),
      new Promise<Response>((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000))
    ]);
    
    if (res && res.ok) {
      const data = await res.json() as any;
      if (data.txrefs && Array.isArray(data.txrefs)) {
        utxos.push(...data.txrefs.map((u: any) => ({
          txid: u.tx_hash,
          vout: u.tx_output_n,
          value: u.value,
          scriptPubKey: "",
          confirmed: !u.unconfirmed,
          address,
        })));
        console.log("[FastUTXO] BlockCypher found", utxos.length, "UTXOs");
        if (utxos.length > 0) return utxos;
      }
    }
  } catch (e) {
    console.warn("[FastUTXO] BlockCypher failed:", (e as Error).message);
  }

  console.warn("[FastUTXO] No UTXOs found for address:", address);
  throw new Error(`No UTXOs found for address ${address}`);
}
