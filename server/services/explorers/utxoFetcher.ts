import { torJson } from "../networking/torFetcher";

export interface UTXO {
  txid: string;
  vout: number;
  value: number;
  scriptPubKey: string;
  confirmed: boolean;
  address?: string;
}

export async function getUTXOs(address: string): Promise<UTXO[]> {
  const utxos: UTXO[] = [];

  // Try Blockstream API
  try {
    const data = await torJson(`https://blockstream.info/api/address/${address}`, {}, true);
    if (data.utxo) {
      utxos.push(...data.utxo.map((u: any) => ({
        txid: u.txid,
        vout: u.vout,
        value: u.value,
        scriptPubKey: u.status?.hex || "",
        confirmed: u.status?.confirmed !== false,
        address,
      })));
      if (utxos.length > 0) return utxos;
    }
  } catch (e) {
    console.warn("Blockstream UTXO fetch failed:", (e as Error).message);
  }

  // Try Mempool API
  try {
    const data = await torJson(`https://mempool.space/api/address/${address}/utxo`, {}, true);
    if (Array.isArray(data)) {
      utxos.push(...data.map((u: any) => ({
        txid: u.txid,
        vout: u.vout,
        value: u.value,
        scriptPubKey: "",
        confirmed: u.status?.confirmed !== false,
        address,
      })));
      if (utxos.length > 0) return utxos;
    }
  } catch (e) {
    console.warn("Mempool UTXO fetch failed:", (e as Error).message);
  }

  // Try BlockCypher API
  try {
    const data = await torJson(
      `https://api.blockcypher.com/v1/btc/main/addrs/${address}?unspentOnly=true`,
      {},
      true
    );
    if (data.txrefs) {
      utxos.push(...data.txrefs.map((u: any) => ({
        txid: u.tx_hash,
        vout: u.tx_output_n,
        value: u.value,
        scriptPubKey: "",
        confirmed: !u.unconfirmed,
        address,
      })));
      if (utxos.length > 0) return utxos;
    }
  } catch (e) {
    console.warn("BlockCypher UTXO fetch failed:", (e as Error).message);
  }

  if (utxos.length === 0) {
    throw new Error("No UTXOs found or all endpoints failed");
  }

  return utxos;
}
