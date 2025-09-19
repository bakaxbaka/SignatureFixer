import { z } from "zod";

interface UTXOData {
  utxos: Array<{
    txid: string;
    vout: number;
    value: number;
    confirmations: number;
    script: string;
  }>;
  totalValue: number;
  totalUTXOs: number;
  source: string;
}

interface DecodedTransaction {
  txid: string;
  version: number;
  inputs: Array<{
    txid: string;
    vout: number;
    script: string;
    sequence: number;
    signature?: {
      r: string;
      s: string;
      sighashType: number;
      publicKey: string;
      derEncoded: string;
    };
  }>;
  outputs: Array<{
    value: number;
    script: string;
    address?: string;
  }>;
  locktime: number;
  signatures: Array<{
    inputIndex: number;
    r: string;
    s: string;
    sighashType: number;
    publicKey: string;
    derEncoded: string;
  }>;
}

class BitcoinService {
  private readonly BLOCKCHAIN_API = 'https://blockchain.info';
  private readonly BLOCKSTREAM_API = 'https://blockstream.info/api';
  private readonly SOCHAIN_API = 'https://sochain.com/api/v2';

  async fetchUTXOs(address: string, networkType: string = 'mainnet'): Promise<UTXOData> {
    const errors: string[] = [];
    
    // Try Blockchain.com first
    try {
      return await this.fetchUTXOsBlockchainCom(address);
    } catch (error) {
      errors.push(`Blockchain.com: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }

    // Try Blockstream as fallback
    try {
      return await this.fetchUTXOsBlockstream(address, networkType);
    } catch (error) {
      errors.push(`Blockstream: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }

    // Try SoChain as final fallback
    try {
      return await this.fetchUTXOsSoChain(address, networkType);
    } catch (error) {
      errors.push(`SoChain: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }

    throw new Error(`All APIs failed: ${errors.join(', ')}`);
  }

  private async fetchUTXOsBlockchainCom(address: string): Promise<UTXOData> {
    const response = await fetch(`${this.BLOCKCHAIN_API}/unspent?active=${address}&format=json`);
    
    if (!response.ok) {
      throw new Error(`Blockchain.com API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    
    if (!data.unspent_outputs) {
      return {
        utxos: [],
        totalValue: 0,
        totalUTXOs: 0,
        source: 'blockchain.com'
      };
    }

    const utxos = data.unspent_outputs.map((utxo: any) => ({
      txid: utxo.tx_hash_big_endian,
      vout: utxo.tx_output_n,
      value: utxo.value,
      confirmations: utxo.confirmations || 0,
      script: utxo.script,
    }));

    return {
      utxos,
      totalValue: utxos.reduce((sum: number, utxo: any) => sum + utxo.value, 0),
      totalUTXOs: utxos.length,
      source: 'blockchain.com'
    };
  }

  private async fetchUTXOsBlockstream(address: string, networkType: string): Promise<UTXOData> {
    const baseUrl = networkType === 'testnet' 
      ? 'https://blockstream.info/testnet/api'
      : this.BLOCKSTREAM_API;
    
    const response = await fetch(`${baseUrl}/address/${address}/utxo`);
    
    if (!response.ok) {
      throw new Error(`Blockstream API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    
    const utxos = data.map((utxo: any) => ({
      txid: utxo.txid,
      vout: utxo.vout,
      value: utxo.value,
      confirmations: utxo.status.confirmed ? utxo.status.block_height : 0,
      script: '', // Blockstream doesn't provide script in UTXO endpoint
    }));

    return {
      utxos,
      totalValue: utxos.reduce((sum: number, utxo: any) => sum + utxo.value, 0),
      totalUTXOs: utxos.length,
      source: 'blockstream.info'
    };
  }

  private async fetchUTXOsSoChain(address: string, networkType: string): Promise<UTXOData> {
    const network = networkType === 'testnet' ? 'BTCTEST' : 'BTC';
    const response = await fetch(`${this.SOCHAIN_API}/get_tx_unspent/${network}/${address}`);
    
    if (!response.ok) {
      throw new Error(`SoChain API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    
    if (data.status !== 'success' || !data.data.txs) {
      return {
        utxos: [],
        totalValue: 0,
        totalUTXOs: 0,
        source: 'sochain.com'
      };
    }

    const utxos = data.data.txs.map((utxo: any) => ({
      txid: utxo.txid,
      vout: utxo.output_no,
      value: Math.round(parseFloat(utxo.value) * 100000000), // Convert BTC to satoshis
      confirmations: utxo.confirmations,
      script: utxo.script_hex || '',
    }));

    return {
      utxos,
      totalValue: utxos.reduce((sum: number, utxo: any) => sum + utxo.value, 0),
      totalUTXOs: utxos.length,
      source: 'sochain.com'
    };
  }

  async decodeTransaction(rawTx: string): Promise<DecodedTransaction> {
    // This is a simplified transaction decoder
    // In a real implementation, you would use a proper Bitcoin library
    try {
      const buffer = Buffer.from(rawTx, 'hex');
      
      // Basic transaction parsing (simplified)
      const version = buffer.readUInt32LE(0);
      let offset = 4;

      // Parse inputs
      const inputCount = this.readVarInt(buffer, offset);
      offset = inputCount.offset;
      
      const inputs = [];
      const signatures = [];
      
      for (let i = 0; i < inputCount.value; i++) {
        const input = this.parseInput(buffer, offset);
        inputs.push(input.input);
        
        if (input.signature) {
          signatures.push({
            inputIndex: i,
            ...input.signature
          });
        }
        
        offset = input.offset;
      }

      // Parse outputs
      const outputCount = this.readVarInt(buffer, offset);
      offset = outputCount.offset;
      
      const outputs = [];
      for (let i = 0; i < outputCount.value; i++) {
        const output = this.parseOutput(buffer, offset);
        outputs.push(output.output);
        offset = output.offset;
      }

      const locktime = buffer.readUInt32LE(offset);

      // Calculate transaction ID (simplified)
      const txid = this.calculateTxId(buffer);

      return {
        txid,
        version,
        inputs,
        outputs,
        locktime,
        signatures
      };
    } catch (error) {
      throw new Error(`Failed to decode transaction: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private readVarInt(buffer: Buffer, offset: number): { value: number; offset: number } {
    if (offset >= buffer.length) {
      throw new Error(`VarInt read offset ${offset} exceeds buffer length ${buffer.length}`);
    }
    
    const first = buffer.readUInt8(offset);
    
    if (first < 0xfd) {
      return { value: first, offset: offset + 1 };
    } else if (first === 0xfd) {
      if (offset + 2 >= buffer.length) {
        throw new Error(`VarInt read would exceed buffer bounds`);
      }
      return { value: buffer.readUInt16LE(offset + 1), offset: offset + 3 };
    } else if (first === 0xfe) {
      if (offset + 4 >= buffer.length) {
        throw new Error(`VarInt read would exceed buffer bounds`);
      }
      return { value: buffer.readUInt32LE(offset + 1), offset: offset + 5 };
    } else {
      // For simplicity, assuming we won't encounter 8-byte integers
      throw new Error('64-bit VarInt not supported in this implementation');
    }
  }

  private parseInput(buffer: Buffer, offset: number): {
    input: any;
    signature?: any;
    offset: number;
  } {
    if (offset + 36 > buffer.length) {
      throw new Error(`Input parse would exceed buffer bounds: offset ${offset + 36} > length ${buffer.length}`);
    }
    
    const txid = buffer.subarray(offset, offset + 32).reverse().toString('hex');
    const vout = buffer.readUInt32LE(offset + 32);
    offset += 36;

    const scriptLength = this.readVarInt(buffer, offset);
    offset = scriptLength.offset;

    if (offset + scriptLength.value > buffer.length) {
      throw new Error(`Script read would exceed buffer bounds: offset ${offset + scriptLength.value} > length ${buffer.length}`);
    }

    const script = buffer.subarray(offset, offset + scriptLength.value).toString('hex');
    offset += scriptLength.value;

    if (offset + 4 > buffer.length) {
      throw new Error(`Sequence read would exceed buffer bounds: offset ${offset + 4} > length ${buffer.length}`);
    }

    const sequence = buffer.readUInt32LE(offset);
    offset += 4;

    // Try to extract signature from script
    let signature;
    try {
      signature = this.extractSignatureFromScript(script);
    } catch (error) {
      // Signature extraction failed, continue without it
    }

    return {
      input: {
        txid,
        vout,
        script,
        sequence,
        signature
      },
      signature,
      offset
    };
  }

  private parseOutput(buffer: Buffer, offset: number): {
    output: any;
    offset: number;
  } {
    if (offset + 8 > buffer.length) {
      throw new Error(`Output value read would exceed buffer bounds: offset ${offset + 8} > length ${buffer.length}`);
    }
    
    const value = buffer.readBigUInt64LE(offset);
    offset += 8;

    const scriptLength = this.readVarInt(buffer, offset);
    offset = scriptLength.offset;

    if (offset + scriptLength.value > buffer.length) {
      throw new Error(`Output script read would exceed buffer bounds: offset ${offset + scriptLength.value} > length ${buffer.length}`);
    }

    const script = buffer.subarray(offset, offset + scriptLength.value).toString('hex');
    offset += scriptLength.value;

    // Try to extract address from script (simplified)
    let address;
    try {
      address = this.extractAddressFromScript(script);
    } catch (error) {
      // Address extraction failed
    }

    return {
      output: {
        value: Number(value),
        script,
        address
      },
      offset
    };
  }

  private extractSignatureFromScript(script: string): any {
    try {
      const buffer = Buffer.from(script, 'hex');
      
      if (buffer.length < 70) return null; // Too short for a signature
      
      // Look for DER signature (starts with 0x30)
      let sigStart = -1;
      for (let i = 0; i < buffer.length - 1; i++) {
        if (buffer[i] === 0x30 && buffer[i + 1] > 0x40 && buffer[i + 1] < 0x50) {
          sigStart = i;
          break;
        }
      }
      
      if (sigStart === -1) return null;
      
      const sigLength = buffer[sigStart + 1] + 2;
      const derSignature = buffer.subarray(sigStart, sigStart + sigLength);
      const sighashType = buffer[sigStart + sigLength];
      
      // Parse DER signature
      const { r, s } = this.parseDERSignature(derSignature);
      
      // Try to find public key (typically follows signature)
      let publicKey = '';
      const pubKeyStart = sigStart + sigLength + 1;
      if (pubKeyStart < buffer.length) {
        const pubKeyLength = buffer[pubKeyStart];
        if (pubKeyLength === 33 || pubKeyLength === 65) {
          publicKey = buffer.subarray(pubKeyStart + 1, pubKeyStart + 1 + pubKeyLength).toString('hex');
        }
      }
      
      return {
        r,
        s,
        sighashType,
        publicKey,
        derEncoded: derSignature.toString('hex')
      };
    } catch (error) {
      return null;
    }
  }

  private parseDERSignature(derSig: Buffer): { r: string; s: string } {
    // Basic DER parsing
    let offset = 2; // Skip 0x30 and length
    
    // R value
    if (derSig[offset] !== 0x02) throw new Error('Invalid DER signature');
    offset++;
    const rLength = derSig[offset];
    offset++;
    const r = derSig.subarray(offset, offset + rLength).toString('hex');
    offset += rLength;
    
    // S value
    if (derSig[offset] !== 0x02) throw new Error('Invalid DER signature');
    offset++;
    const sLength = derSig[offset];
    offset++;
    const s = derSig.subarray(offset, offset + sLength).toString('hex');
    
    return { r, s };
  }

  private extractAddressFromScript(script: string): string | undefined {
    // Simplified address extraction
    // This would need a proper Bitcoin script interpreter
    return undefined;
  }

  private calculateTxId(buffer: Buffer): string {
    // Simplified txid calculation
    // In reality, this would be a double SHA256 of the transaction
    const crypto = require('crypto');
    const hash = crypto.createHash('sha256').update(buffer).digest();
    const txid = crypto.createHash('sha256').update(hash).digest();
    return txid.reverse().toString('hex');
  }

  async getRawTransaction(txid: string, networkType: string = 'mainnet'): Promise<string> {
    try {
      // Try Blockstream first for raw transaction hex
      const baseUrl = networkType === 'testnet' 
        ? 'https://blockstream.info/testnet/api'
        : this.BLOCKSTREAM_API;
      
      const response = await fetch(`${baseUrl}/tx/${txid}/hex`);
      
      if (response.ok) {
        return await response.text();
      }
    } catch (error) {
      console.warn('Blockstream raw tx API failed, trying Blockchain.com');
    }

    try {
      // Fallback to Blockchain.com
      const response = await fetch(`${this.BLOCKCHAIN_API}/rawtx/${txid}?format=hex`);
      
      if (response.ok) {
        return await response.text();
      }
    } catch (error) {
      console.warn('Blockchain.com raw tx API failed');
    }

    throw new Error('Failed to fetch raw transaction from all APIs');
  }

  async getTransactionDetails(txid: string, networkType: string = 'mainnet'): Promise<any> {
    try {
      // Try Blockstream first
      const baseUrl = networkType === 'testnet' 
        ? 'https://blockstream.info/testnet/api'
        : this.BLOCKSTREAM_API;
      
      const response = await fetch(`${baseUrl}/tx/${txid}`);
      
      if (response.ok) {
        return await response.json();
      }
    } catch (error) {
      console.warn('Blockstream API failed, trying Blockchain.com');
    }

    try {
      // Fallback to Blockchain.com
      const response = await fetch(`${this.BLOCKCHAIN_API}/rawtx/${txid}?format=json`);
      
      if (response.ok) {
        return await response.json();
      }
    } catch (error) {
      console.warn('Blockchain.com API failed');
    }

    throw new Error('Failed to fetch transaction details from all APIs');
  }
}

export const bitcoinService = new BitcoinService();
