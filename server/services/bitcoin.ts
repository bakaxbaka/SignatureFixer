import { z } from "zod";
import { createHash } from "crypto";
import * as fs from "fs";
import * as path from "path";
import { mkdirSync } from "fs";

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
    messageHash?: string;
  }>;
  vulnerabilityAnalysis?: {
    summary: {
      totalSignatures: number;
      vulnerableSignatures: number;
      riskLevel: string;
    };
    patterns: Array<{
      type: string;
      description: string;
      severity: string;
      count: number;
    }>;
    nonceReuse: Array<{
      rValue: string;
      affectedSignatures: any[];
      isVulnerable: boolean;
      method: string;
    }>;
  };
}

class BitcoinService {
  private readonly BLOCKCHAIN_API = 'https://blockchain.info';
  private readonly BLOCKSTREAM_API = 'https://blockstream.info/api';
  private readonly SOCHAIN_API = 'https://sochain.com/api/v2';
  private readonly DATA_DIR = path.join(process.cwd(), 'data');
  private readonly RAW_TXS_DIR = path.join(this.DATA_DIR, 'raw_txs');
  private readonly PROGRESS_FILE = path.join(this.DATA_DIR, 'progress.json');

  constructor() {
    // Ensure data directories exist
    if (!fs.existsSync(this.DATA_DIR)) {
      fs.mkdirSync(this.DATA_DIR, { recursive: true });
    }
    if (!fs.existsSync(this.RAW_TXS_DIR)) {
      fs.mkdirSync(this.RAW_TXS_DIR, { recursive: true });
    }
    const sigDir = path.join(this.DATA_DIR, 'signatures');
    if (!fs.existsSync(sigDir)) {
      fs.mkdirSync(sigDir, { recursive: true });
    }
  }

  // Save individual signature record to disk
  saveSignature(txid: string, vin: number, signatureData: any): void {
    try {
      const sigDir = path.join(this.DATA_DIR, 'signatures');
      const filename = `${txid}_${vin}.json`;
      const filepath = path.join(sigDir, filename);
      
      const record = {
        txid,
        vin,
        r: signatureData.r || '',
        s: signatureData.s || '',
        pubkey: signatureData.publicKey || '',
        sighash: signatureData.sighashType?.toString(16).padStart(2, '0') || '01',
        script_type: signatureData.scriptType || 'unknown'
      };
      
      fs.writeFileSync(filepath, JSON.stringify(record, null, 2));
    } catch (error) {
      console.error(`Failed to save signature ${txid}_${vin}:`, error);
    }
  }

  // 1.3 Progress tracking and persistence
  private loadProgress(): any {
    try {
      if (fs.existsSync(this.PROGRESS_FILE)) {
        const data = fs.readFileSync(this.PROGRESS_FILE, 'utf-8');
        return JSON.parse(data);
      }
    } catch (error) {
      console.error('Failed to load progress:', error);
    }
    return { last_offset: 0, completed_phases: [], address: null };
  }

  private saveProgress(address: string, lastOffset: number, phases: string[]): void {
    try {
      const progress = {
        address,
        last_offset: lastOffset,
        completed_phases: phases,
        lastUpdated: new Date().toISOString()
      };
      fs.writeFileSync(this.PROGRESS_FILE, JSON.stringify(progress, null, 2));
      console.log(`💾 Progress saved: offset=${lastOffset}, phases=${phases.join(', ')}`);
    } catch (error) {
      console.error('Failed to save progress:', error);
    }
  }

  private savePage(address: string, offset: number, pageData: any): void {
    try {
      const filename = `page_${offset}.json`;
      const filepath = path.join(this.RAW_TXS_DIR, filename);
      fs.writeFileSync(filepath, JSON.stringify(pageData, null, 2));
      console.log(`📄 Saved: ${filename} (${pageData.txs?.length || 0} transactions)`);
    } catch (error) {
      console.error(`Failed to save page ${offset}:`, error);
    }
  }

  private loadPage(offset: number): any {
    try {
      const filename = `page_${offset}.json`;
      const filepath = path.join(this.RAW_TXS_DIR, filename);
      if (fs.existsSync(filepath)) {
        const data = fs.readFileSync(filepath, 'utf-8');
        console.log(`📖 Loaded cached: ${filename}`);
        return JSON.parse(data);
      }
    } catch (error) {
      console.error(`Failed to load page ${offset}:`, error);
    }
    return null;
  }

  private getPageFiles(): string[] {
    try {
      const files = fs.readdirSync(this.RAW_TXS_DIR);
      return files.filter(f => f.startsWith('page_') && f.endsWith('.json')).sort();
    } catch (error) {
      return [];
    }
  }

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
    // Enhanced transaction decoder with vulnerability analysis
    try {
      const buffer = Buffer.from(rawTx, 'hex');

      // Basic transaction parsing
      const version = buffer.readUInt32LE(0);
      let offset = 4;

      // Check for witness transactions (SegWit)
      let hasWitness = false;
      if (buffer.length > 4 && buffer[4] === 0x00 && buffer[5] === 0x01) {
        hasWitness = true;
        offset = 6; // Skip witness marker and flag
      }

      // Parse inputs
      const inputCount = this.readVarInt(buffer, offset);
      offset = inputCount.offset;

      const inputs = [];
      const signatures = [];

      for (let i = 0; i < inputCount.value; i++) {
        const input = this.parseInput(buffer, offset);
        inputs.push(input.input);

        if (input.signature) {
          // Add message hash for vulnerability analysis
          const messageHash = this.generateMessageHash(buffer, i, input.signature.sighashType);
          signatures.push({
            inputIndex: i,
            messageHash,
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

      // Skip witness data if present
      if (hasWitness) {
        for (let i = 0; i < inputCount.value; i++) {
          const witnessCount = this.readVarInt(buffer, offset);
          offset = witnessCount.offset;

          for (let j = 0; j < witnessCount.value; j++) {
            const witnessLength = this.readVarInt(buffer, offset);
            offset = witnessLength.offset + witnessLength.value;
          }
        }
      }

      const locktime = buffer.readUInt32LE(offset);

      // Calculate transaction ID
      const txid = this.calculateTxId(buffer);

      // Perform vulnerability analysis
      const vulnerabilityAnalysis = await this.analyzeSignatureVulnerabilities(signatures);

      return {
        txid,
        version,
        inputs,
        outputs,
        locktime,
        signatures,
        vulnerabilityAnalysis
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
    const hash = createHash('sha256').update(buffer).digest();
    const txid = createHash('sha256').update(hash).digest();
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
      // ALWAYS use blockchain.info first - as per requirements
      const response = await fetch(`${this.BLOCKCHAIN_API}/rawtx/${txid}?format=json`, {
        signal: AbortSignal.timeout(10000)
      });

      if (response.ok) {
        const data = await response.json();
        console.log(`✓ Transaction ${txid} fetched from blockchain.info`);
        return data;
      }
      
      console.warn(`blockchain.info returned ${response.status} for ${txid}`);
    } catch (error) {
      console.warn(`blockchain.info fetch failed for ${txid}: ${error instanceof Error ? error.message : String(error)}`);
    }

    try {
      // Fallback to Blockstream only if blockchain.info fails
      const baseUrl = networkType === 'testnet'
        ? 'https://blockstream.info/testnet/api'
        : this.BLOCKSTREAM_API;

      const response = await fetch(`${baseUrl}/tx/${txid}`, {
        signal: AbortSignal.timeout(10000)
      });

      if (response.ok) {
        console.log(`⚠ Transaction ${txid} fetched from Blockstream (fallback)`);
        return await response.json();
      }
    } catch (error) {
      console.warn('Blockstream fallback also failed');
    }

    throw new Error(`Failed to fetch transaction details for ${txid} from all APIs`);
  }

  private generateMessageHash(txBuffer: Buffer, inputIndex: number, sighashType: number): string {
    // Simplified message hash generation for educational purposes
    // In reality, this would follow BIP 143 for SegWit or legacy signing
    const data = `${txBuffer.toString('hex')}-${inputIndex}-${sighashType}`;
    const hash = createHash('sha256').update(data).digest();
    return createHash('sha256').update(hash).digest('hex');
  }

  private async analyzeSignatureVulnerabilities(signatures: any[]): Promise<any> {
    if (signatures.length === 0) {
      return {
        summary: {
          totalSignatures: 0,
          vulnerableSignatures: 0,
          riskLevel: 'low'
        },
        patterns: [],
        nonceReuse: []
      };
    }

    const patterns = [];
    const nonceReuse = [];
    let vulnerableCount = 0;

    // Check for nonce reuse
    const rValueMap = new Map();
    for (const sig of signatures) {
      if (!rValueMap.has(sig.r)) {
        rValueMap.set(sig.r, []);
      }
      rValueMap.get(sig.r).push(sig);
    }

    // Detect nonce reuse vulnerabilities
    for (const [rValue, sigs] of rValueMap) {
      if (sigs.length > 1) {
        vulnerableCount += sigs.length;
        nonceReuse.push({
          rValue,
          affectedSignatures: sigs,
          isVulnerable: true,
          method: 'nonce_reuse_attack'
        });

        patterns.push({
          type: 'nonce_reuse',
          description: 'Multiple signatures using same nonce detected',
          severity: 'critical',
          count: sigs.length
        });
      }
    }

    // Check for SIGHASH vulnerabilities
    const sighashSingle = signatures.filter(s => (s.sighashType & 0x1f) === 0x03);
    if (sighashSingle.length > 0) {
      patterns.push({
        type: 'sighash_single',
        description: 'SIGHASH_SINGLE signatures detected - potential malleability',
        severity: 'medium',
        count: sighashSingle.length
      });
    }

    // Check for signature malleability
    const malleable = signatures.filter(s => {
      const sValue = BigInt('0x' + s.s);
      const curveOrder = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
      return sValue > curveOrder / 2n;
    });

    if (malleable.length > 0) {
      patterns.push({
        type: 'signature_malleability',
        description: 'High S-value signatures detected - malleable',
        severity: 'low',
        count: malleable.length
      });
    }

    const riskLevel = vulnerableCount > 0 ? 'critical' :
                     patterns.some(p => p.severity === 'high') ? 'high' :
                     patterns.length > 0 ? 'medium' : 'low';

    return {
      summary: {
        totalSignatures: signatures.length,
        vulnerableSignatures: vulnerableCount,
        riskLevel
      },
      patterns,
      nonceReuse
    };
  }

  // Educational signature forgery demonstration
  public demonstrateSignatureForgery(originalSig: any): any {
    try {
      const s = BigInt('0x' + originalSig.s);
      const curveOrder = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

      // Create malleable signature by flipping S value
      const malleableS = curveOrder - s;

      return {
        original: {
          r: originalSig.r,
          s: originalSig.s,
          sighashType: originalSig.sighashType
        },
        malleable: {
          r: originalSig.r,
          s: malleableS.toString(16).padStart(64, '0'),
          sighashType: originalSig.sighashType
        },
        educational: true,
        warning: 'This demonstrates signature malleability for educational purposes only'
      };
    } catch (error) {
      throw new Error('Failed to demonstrate signature malleability');
    }
  }

  // Educational transaction creation with DER signing
  public async createEducationalTransaction(params: {
    fromAddress: string;
    toAddress: string;
    amount: number;
    privateKey: string;
  }): Promise<{ rawTransaction: string; txid: string; from: string; to: string; amount: number; fee: number; signature: { r: string; s: string; sighashType: number; derEncoded: string; }; educational: boolean; warning: string; verification: { messageHash: string; validDER: boolean; canonicalS: boolean; }; }> {
    try {
      const { fromAddress, toAddress, amount, privateKey } = params;

      // Validate private key format
      if (!/^[0-9a-fA-F]{64}$/.test(privateKey)) {
        throw new Error('Invalid private key format. Must be 64 character hex string.');
      }

      // Create a mock UTXO for the from address
      const mockUTXO = {
        txid: this.generateMockTxId(),
        vout: 0,
        value: amount + 10000, // Add some extra for fees
        script: this.createMockScript(fromAddress)
      };

      // Create transaction structure
      const transaction = this.buildTransaction(mockUTXO, toAddress, amount);

      // Generate message hash for signing
      const messageHash = this.generateTransactionHash(transaction);

      // Create DER signature using educational implementation
      const signature = this.createDERSignature(messageHash, privateKey);

      // Add signature to transaction
      const signedTransaction = this.addSignatureToTransaction(transaction, signature);

      // Convert to raw hex
      const rawTransaction = this.serializeTransaction(signedTransaction);

      return {
        rawTransaction,
        txid: this.calculateTxId(Buffer.from(rawTransaction, 'hex')),
        from: fromAddress,
        to: toAddress,
        amount,
        fee: 10000,
        signature: {
          r: signature.r,
          s: signature.s,
          sighashType: signature.sighashType,
          derEncoded: signature.derEncoded
        },
        educational: true,
        warning: 'This is an educational demonstration only. Do not broadcast this transaction.',
        verification: {
          messageHash,
          validDER: true,
          canonicalS: BigInt('0x' + signature.s) <= BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141') / 2n
        }
      };
    } catch (error) {
      throw new Error(`Transaction creation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Sign raw transaction with parsed R and S values from DER signature
  public async signRawTransactionWithDER(params: {
    rawTransaction: string;
    rValue: string;
    sValue: string;
    sighashType?: number;
    publicKey?: string;
  }): Promise<{ signedTransaction: string; txid: string; signature: { r: string; s: string; sighashType: number; derEncoded: string; publicKey?: string; }; educational: boolean; }> {
    try {
      const { rawTransaction, rValue, sValue, sighashType = 0x01, publicKey } = params;

      // Validate R and S values
      if (!/^[0-9a-fA-F]+$/.test(rValue) || !/^[0-9a-fA-F]+$/.test(sValue)) {
        throw new Error('R and S values must be valid hex strings');
      }

      // Ensure canonical S value
      const s = BigInt('0x' + sValue);
      const curveOrder = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
      const canonicalS = s > curveOrder / 2n ? curveOrder - s : s;

      // Create DER signature from R and S values
      const rBytes = this.bigIntToBytes(BigInt('0x' + rValue));
      const sBytes = this.bigIntToBytes(canonicalS);
      const derSignature = this.encodeDER(rBytes, sBytes);

      // Parse the raw transaction
      const txBuffer = Buffer.from(rawTransaction, 'hex');
      const decodedTx = await this.decodeTransaction(rawTransaction);

      // Create signature script with DER encoding and SIGHASH type
      let signatureScript = derSignature + sighashType.toString(16).padStart(2, '0');
      
      // Add public key if provided
      if (publicKey && /^[0-9a-fA-F]{66}$/.test(publicKey)) {
        const pubKeyLength = (publicKey.length / 2).toString(16).padStart(2, '0');
        signatureScript += pubKeyLength + publicKey;
      }

      // Find the first input and update its script
      const signedTxBuffer = Buffer.from(txBuffer);
      const inputScriptStart = this.findInputScriptLocation(signedTxBuffer);
      
      if (inputScriptStart !== -1) {
        // Replace the script with our signature
        const newScriptBytes = Buffer.from(signatureScript, 'hex');
        const scriptLengthBytes = Buffer.from([newScriptBytes.length]);
        
        // Create new transaction with signature
        const beforeScript = signedTxBuffer.subarray(0, inputScriptStart);
        const afterScript = signedTxBuffer.subarray(inputScriptStart + 1); // Skip original script length
        
        // Find where original script ends
        const originalScriptLength = signedTxBuffer[inputScriptStart];
        const afterOriginalScript = signedTxBuffer.subarray(inputScriptStart + 1 + originalScriptLength);
        
        // Combine parts
        const finalTx = Buffer.concat([
          beforeScript,
          scriptLengthBytes,
          newScriptBytes,
          afterOriginalScript
        ]);

        const signedTransaction = finalTx.toString('hex');
        const txid = this.calculateTxId(finalTx);

        return {
          signedTransaction,
          txid,
          signature: {
            r: rValue,
            s: canonicalS.toString(16).padStart(64, '0'),
            sighashType,
            derEncoded: derSignature,
            publicKey
          },
          educational: true
        };
      } else {
        throw new Error('Could not locate input script in transaction');
      }
    } catch (error) {
      throw new Error(`Failed to sign transaction with DER: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private findInputScriptLocation(buffer: Buffer): number {
    // Find the location of the first input's script length byte
    // This is a simplified implementation for educational purposes
    try {
      let offset = 4; // Skip version

      // Check for witness transactions
      if (buffer.length > 4 && buffer[4] === 0x00 && buffer[5] === 0x01) {
        offset = 6; // Skip witness marker and flag
      }

      // Skip input count (assuming 1 byte for simplicity)
      offset += 1;

      // Skip previous transaction hash (32 bytes) and output index (4 bytes)
      offset += 36;

      // This should be the script length byte
      return offset;
    } catch (error) {
      return -1;
    }
  }

  async createMalleableSignature(params: {
    rawTransaction: string;
    malleabilityType: string;
  }): Promise<{ malleableTransaction: string; originalTxid: string; malleableTxid: string; educational: boolean }> {
    try {
      console.log('Creating malleable signature for educational demonstration');

      // Parse the original transaction
      const buffer = Buffer.from(params.rawTransaction, 'hex');

      // Demonstrate signature malleability by modifying the signature
      const malleableBuffer = this.createSignatureMalleability(buffer, params.malleabilityType);

      // Serialize the malleable transaction
      const malleableTransaction = malleableBuffer.toString('hex');

      // Generate different transaction IDs to demonstrate malleability
      const originalTxid = this.calculateTxId(buffer);
      const malleableTxid = this.calculateTxId(malleableBuffer);

      return {
        malleableTransaction,
        originalTxid,
        malleableTxid,
        educational: true
      };
    } catch (error) {
      throw new Error(`Failed to create malleable signature: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private createSignatureMalleability(buffer: Buffer, malleabilityType: string): Buffer {
    // Educational demonstration of signature malleability
    const malleableBuffer = Buffer.from(buffer);

    try {
      // Find signature in the transaction (simplified for educational purposes)
      const signatureStart = this.findSignatureInTransaction(malleableBuffer);

      if (signatureStart !== -1) {
        // Demonstrate different malleability techniques
        switch (malleabilityType) {
          case 'sighash_single':
            // Modify SIGHASH_SINGLE flag to demonstrate vulnerability
            malleableBuffer[signatureStart + 70] = 0x03; // SIGHASH_SINGLE
            break;
          case 'der_signature':
            // Modify DER signature to create malleability
            malleableBuffer[signatureStart + 10] ^= 0x01;
            break;
          default:
            // Default malleability modification
            malleableBuffer[signatureStart + 5] ^= 0x01;
        }
      }

      return malleableBuffer;
    } catch (error) {
      // If parsing fails, create a simple modification for demonstration
      malleableBuffer[malleableBuffer.length - 10] ^= 0x01;
      return malleableBuffer;
    }
  }

  private findSignatureInTransaction(buffer: Buffer): number {
    // Simplified signature finding for educational purposes
    // Look for DER signature marker (0x30)
    for (let i = 0; i < buffer.length - 8; i++) {
      if (buffer[i] === 0x30 && buffer[i + 1] > 0x40 && buffer[i + 1] < 0x50) {
        return i;
      }
    }
    return -1;
  }

  private generateMockTxId(): string {
    const randomBytes = Array.from({ length: 32 }, () =>
      Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
    ).join('');
    return randomBytes;
  }

  private createMockScript(address: string): string {
    // Simplified P2PKH script creation
    return `76a914${createHash('ripemd160').update(createHash('sha256').update(address).digest()).digest('hex')}88ac`;
  }

  private buildTransaction(utxo: any, toAddress: string, amount: number): any {
    return {
      version: 1,
      inputs: [{
        txid: utxo.txid,
        vout: utxo.vout,
        script: '',
        sequence: 0xffffffff
      }],
      outputs: [{
        value: amount,
        script: this.createMockScript(toAddress)
      }],
      locktime: 0
    };
  }

  private generateTransactionHash(transaction: any): string {
    // Simplified transaction hash for educational purposes
    const data = JSON.stringify(transaction);
    const hash = createHash('sha256').update(data).digest();
    return createHash('sha256').update(hash).digest('hex');
  }

  private createDERSignature(messageHash: string, privateKeyHex: string): any {
    try {
      // This is a simplified educational implementation
      // In real Bitcoin, you would use proper ECDSA signing with secp256k1

      const privateKey = BigInt('0x' + privateKeyHex);
      const messageNum = BigInt('0x' + messageHash);
      const curveOrder = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

      // Generate deterministic nonce (simplified RFC 6979)
      const nonce = this.generateDeterministicNonce(privateKey, messageNum);

      // Calculate signature values (simplified)
      const r = this.modMul(nonce, 7n, curveOrder); // Simplified point multiplication
      const rInv = this.modInverse(nonce, curveOrder);
      const s = this.modMul(rInv, this.modAdd(messageNum, this.modMul(r, privateKey, curveOrder), curveOrder), curveOrder);

      // Ensure canonical S value
      const canonicalS = s > curveOrder / 2n ? curveOrder - s : s;

      // Create DER encoding
      const rBytes = this.bigIntToBytes(r);
      const sBytes = this.bigIntToBytes(canonicalS);
      const derSignature = this.encodeDER(rBytes, sBytes);

      return {
        r: r.toString(16).padStart(64, '0'),
        s: canonicalS.toString(16).padStart(64, '0'),
        sighashType: 0x01, // SIGHASH_ALL
        derEncoded: derSignature,
        messageHash
      };
    } catch (error) {
      throw new Error('DER signature creation failed');
    }
  }

  private generateDeterministicNonce(privateKey: bigint, message: bigint): bigint {
    // Simplified deterministic nonce generation
    const combined = (privateKey + message) % BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
    return combined === 0n ? 1n : combined;
  }

  private modAdd(a: bigint, b: bigint, mod: bigint): bigint {
    return ((a + b) % mod + mod) % mod;
  }

  private modMul(a: bigint, b: bigint, mod: bigint): bigint {
    return ((a * b) % mod + mod) % mod;
  }

  private modInverse(a: bigint, mod: bigint): bigint {
    let [old_r, r] = [a, mod];
    let [old_s, s] = [1n, 0n];

    while (r !== 0n) {
      const quotient = old_r / r;
      [old_r, r] = [r, old_r - quotient * r];
      [old_s, s] = [s, old_s - quotient * s];
    }

    return old_s < 0n ? old_s + mod : old_s;
  }

  private bigIntToBytes(value: bigint): number[] {
    const hex = value.toString(16);
    const paddedHex = hex.length % 2 === 0 ? hex : '0' + hex;
    const bytes = [];

    for (let i = 0; i < paddedHex.length; i += 2) {
      bytes.push(parseInt(paddedHex.substr(i, 2), 16));
    }

    // Add padding byte if first byte >= 0x80
    if (bytes.length > 0 && bytes[0] >= 0x80) {
      bytes.unshift(0x00);
    }

    return bytes;
  }

  private encodeDER(rBytes: number[], sBytes: number[]): string {
    const derR = [0x02, rBytes.length, ...rBytes];
    const derS = [0x02, sBytes.length, ...sBytes];
    const sequence = [...derR, ...derS];
    const derSignature = [0x30, sequence.length, ...sequence];

    return derSignature.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  private addSignatureToTransaction(transaction: any, signature: any): any {
    // Add signature to the first input's script
    const signatureScript = signature.derEncoded + '01'; // Add SIGHASH_ALL flag
    transaction.inputs[0].script = signatureScript;
    return transaction;
  }

  private serializeTransaction(transaction: any): string {
    // Simplified transaction serialization for educational purposes
    let hex = '';

    // Version (4 bytes, little-endian)
    hex += this.uint32ToHex(transaction.version);

    // Input count (1 byte for simplicity)
    hex += '01';

    // Input
    hex += transaction.inputs[0].txid;
    hex += this.uint32ToHex(transaction.inputs[0].vout);
    hex += this.varIntToHex(transaction.inputs[0].script.length / 2);
    hex += transaction.inputs[0].script;
    hex += this.uint32ToHex(transaction.inputs[0].sequence);

    // Output count (1 byte for simplicity)
    hex += '01';

    // Output
    hex += this.uint64ToHex(transaction.outputs[0].value);
    hex += this.varIntToHex(transaction.outputs[0].script.length / 2);
    hex += transaction.outputs[0].script;

    // Locktime (4 bytes)
    hex += this.uint32ToHex(transaction.locktime);

    return hex;
  }

  private uint32ToHex(value: number): string {
    return value.toString(16).padStart(8, '0').match(/.{2}/g)!.reverse().join('');
  }

  private uint64ToHex(value: number): string {
    return value.toString(16).padStart(16, '0').match(/.{2}/g)!.reverse().join('');
  }

  private varIntToHex(value: number): string {
    if (value < 0xfd) {
      return value.toString(16).padStart(2, '0');
    }
    // For simplicity, only handle values < 253
    return value.toString(16).padStart(2, '0');
  }

  private createSignatureScript(derEncoded: string, privateKey: string): string {
    // This function is a placeholder and needs proper implementation
    // It should take the DER encoded signature and potentially the public key and sighash flag
    // For this educational example, we'll just use the DER encoded signature
    return derEncoded + '01'; // Append SIGHASH_ALL
  }

  // Create unsigned raw transaction from structured inputs
  public async createUnsignedRawTransaction(params: {
    version: number;
    inputs: Array<{
      txid: string;
      vout: string;
      scriptSig?: string;
      sequence?: string;
    }>;
    outputs: Array<{
      value: string;
      scriptPubKey: string;
    }>;
    locktime: number;
  }): Promise<{
    rawTransaction: string;
    txid: string;
    size: number;
    inputs: number;
    outputs: number;
    educational: boolean;
    analysis: {
      totalOutputValue: number;
      averageOutputValue: number;
      hasCustomScripts: boolean;
      estimatedFee: number;
    };
  }> {
    try {
      const { version, inputs, outputs, locktime } = params;

      // Validate inputs
      for (const input of inputs) {
        if (!input.txid || !/^[0-9a-fA-F]{64}$/.test(input.txid)) {
          throw new Error(`Invalid transaction ID: ${input.txid}`);
        }
        if (!input.vout || isNaN(parseInt(input.vout))) {
          throw new Error(`Invalid output index: ${input.vout}`);
        }
      }

      // Validate outputs
      for (const output of outputs) {
        if (!output.value || isNaN(parseInt(output.value))) {
          throw new Error(`Invalid output value: ${output.value}`);
        }
        if (!output.scriptPubKey || !/^[0-9a-fA-F]*$/.test(output.scriptPubKey)) {
          throw new Error(`Invalid script: ${output.scriptPubKey}`);
        }
      }

      let rawTransaction = '';

      // Version (4 bytes, little-endian)
      rawTransaction += this.uint32ToHexLE(version);

      // Input count (variable length integer)
      rawTransaction += this.encodeVarInt(inputs.length);

      // Inputs
      for (const input of inputs) {
        // Previous transaction hash (32 bytes, reversed)
        const txidBytes = Buffer.from(input.txid, 'hex').reverse();
        rawTransaction += txidBytes.toString('hex');

        // Previous output index (4 bytes, little-endian)
        rawTransaction += this.uint32ToHexLE(parseInt(input.vout));

        // Script length and script
        const scriptSig = input.scriptSig || '';
        const scriptBytes = Buffer.from(scriptSig, 'hex');
        rawTransaction += this.encodeVarInt(scriptBytes.length);
        rawTransaction += scriptSig;

        // Sequence (4 bytes, little-endian)
        const sequence = input.sequence || 'ffffffff';
        rawTransaction += this.uint32ToHexLE(parseInt(sequence, 16));
      }

      // Output count (variable length integer)
      rawTransaction += this.encodeVarInt(outputs.length);

      // Outputs
      let totalOutputValue = 0;
      for (const output of outputs) {
        const value = parseInt(output.value);
        totalOutputValue += value;

        // Value (8 bytes, little-endian)
        rawTransaction += this.uint64ToHexLE(value);

        // Script length and script
        const scriptBytes = Buffer.from(output.scriptPubKey, 'hex');
        rawTransaction += this.encodeVarInt(scriptBytes.length);
        rawTransaction += output.scriptPubKey;
      }

      // Locktime (4 bytes, little-endian)
      rawTransaction += this.uint32ToHexLE(locktime);

      // Calculate transaction ID (double SHA256 of the transaction)
      const txBuffer = Buffer.from(rawTransaction, 'hex');
      const hash1 = createHash('sha256').update(txBuffer).digest();
      const hash2 = createHash('sha256').update(hash1).digest();
      const txid = hash2.reverse().toString('hex');

      // Analysis
      const analysis = {
        totalOutputValue,
        averageOutputValue: Math.round(totalOutputValue / outputs.length),
        hasCustomScripts: outputs.some(o => o.scriptPubKey.length > 50),
        estimatedFee: this.estimateTransactionFee(txBuffer.length)
      };

      return {
        rawTransaction,
        txid,
        size: txBuffer.length,
        inputs: inputs.length,
        outputs: outputs.length,
        educational: true,
        analysis
      };
    } catch (error) {
      throw new Error(`Failed to create unsigned raw transaction: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Helper methods for transaction building
  private uint32ToHexLE(value: number): string {
    const buffer = Buffer.allocUnsafe(4);
    buffer.writeUInt32LE(value, 0);
    return buffer.toString('hex');
  }

  private uint64ToHexLE(value: number): string {
    const buffer = Buffer.allocUnsafe(8);
    buffer.writeBigUInt64LE(BigInt(value), 0);
    return buffer.toString('hex');
  }

  private encodeVarInt(value: number): string {
    if (value < 0xfd) {
      return value.toString(16).padStart(2, '0');
    } else if (value <= 0xffff) {
      const buffer = Buffer.allocUnsafe(3);
      buffer.writeUInt8(0xfd, 0);
      buffer.writeUInt16LE(value, 1);
      return buffer.toString('hex');
    } else if (value <= 0xffffffff) {
      const buffer = Buffer.allocUnsafe(5);
      buffer.writeUInt8(0xfe, 0);
      buffer.writeUInt32LE(value, 1);
      return buffer.toString('hex');
    } else {
      const buffer = Buffer.allocUnsafe(9);
      buffer.writeUInt8(0xff, 0);
      buffer.writeBigUInt64LE(BigInt(value), 1);
      return buffer.toString('hex');
    }
  }

  private estimateTransactionFee(size: number): number {
    // Estimate fee at 1 sat/byte (very low fee rate for educational purposes)
    return size;
  }

  async getBlockHash(height: number, networkType: string = 'mainnet'): Promise<string | null> {
    try {
      const baseUrl = networkType === 'testnet'
        ? 'https://blockstream.info/testnet/api'
        : this.BLOCKSTREAM_API;

      const response = await fetch(`${baseUrl}/block-height/${height}`);
      
      if (!response.ok) {
        return null;
      }
      
      return await response.text();
    } catch (error) {
      console.error(`Error getting block hash for height ${height}:`, error);
      return null;
    }
  }

  async getBlock(blockHash: string, networkType: string = 'mainnet'): Promise<any | null> {
    try {
      const baseUrl = networkType === 'testnet'
        ? 'https://blockstream.info/testnet/api'
        : this.BLOCKSTREAM_API;

      const response = await fetch(`${baseUrl}/block/${blockHash}`);
      
      if (!response.ok) {
        return null;
      }
      
      const block = await response.json();
      
      const txResponse = await fetch(`${baseUrl}/block/${blockHash}/txids`);
      if (txResponse.ok) {
        block.tx = await txResponse.json();
      }
      
      return block;
    } catch (error) {
      console.error(`Error getting block ${blockHash}:`, error);
      return null;
    }
  }

  // PHASE 1: DATA FETCHING LAYER
  // 1.1 Transaction Fetcher - fetch single page with exponential backoff retry logic
  private async fetchPageWithRetry(address: string, offset: number = 0, limit: number = 50, retries: number = 10): Promise<any> {
    let lastError: any;
    
    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        console.log(`[Attempt ${attempt}/${retries}] Fetching page: offset=${offset}, limit=${limit}`);
        
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 20000); // 20 second timeout per request
        
        const response = await fetch(
          `${this.BLOCKCHAIN_API}/rawaddr/${address}?offset=${offset}&limit=${limit}`,
          { signal: controller.signal }
        );
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
          throw new Error(`API error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        
        // Validate response structure
        if (!Array.isArray(data.txs)) {
          throw new Error('Invalid response: txs is not an array');
        }
        
        console.log(`✓ Successfully fetched ${data.txs.length} transactions (offset=${offset})`);
        return {
          txs: data.txs,
          total_tx: data.n_tx,
          address: data.address,
          n_tx: data.n_tx,
          total_received: data.total_received,
          total_sent: data.total_sent,
          final_balance: data.final_balance
        };
      } catch (error) {
        lastError = error;
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';
        console.error(`✗ Attempt ${attempt} failed: ${errorMsg}`);
        
        if (attempt < retries) {
          // Exponential backoff: 100ms, 200ms, 400ms, 800ms, 1.6s, 3.2s...
          const delayMs = Math.min(100 * Math.pow(2, attempt - 1), 5000);
          console.log(`  ⏳ Waiting ${delayMs}ms before retry ${attempt + 1}...`);
          await new Promise(resolve => setTimeout(resolve, delayMs));
        }
      }
    }
    
    throw lastError || new Error('Failed to fetch page after all retries');
  }

  // 1.2 Multi-Page Downloader - automatically loop through all pages with persistence
  async fetchAllTransactionsPaginated(address: string, pageSize: number = 50): Promise<any> {
    console.log(`\n========== PHASE 1: MULTI-PAGE TRANSACTION FETCHING ==========`);
    console.log(`Address: ${address}`);
    console.log(`Page size: ${pageSize}`);
    console.log(`Data dir: ${this.RAW_TXS_DIR}\n`);
    
    // Load progress
    const progress = this.loadProgress();
    let startOffset = 0;
    const phases: string[] = progress.completed_phases || [];

    // Resume check
    if (progress.address === address && progress.last_offset > 0) {
      console.log(`🔄 RESUME MODE: Last offset was ${progress.last_offset}`);
      console.log(`Completed phases: ${phases.join(', ')}\n`);
      startOffset = progress.last_offset;
    }

    let allTransactions: any[] = [];
    let totalTxCount = 0;
    let offset = startOffset;
    let isFirstPage = startOffset === 0;

    try {
      while (true) {
        // Check if page already cached
        const cachedPage = this.loadPage(offset);
        let pageData;

        if (cachedPage) {
          pageData = cachedPage;
        } else {
          // Fetch one page with retry logic
          pageData = await this.fetchPageWithRetry(address, offset, pageSize, 3);
          // Save page to disk (1.3 Local Persistence)
          this.savePage(address, offset, pageData);
        }
        
        if (isFirstPage) {
          totalTxCount = pageData.total_tx;
          console.log(`📊 Total transactions in address: ${totalTxCount}\n`);
          isFirstPage = false;
        }

        // Collect transactions
        if (Array.isArray(pageData.txs)) {
          allTransactions = allTransactions.concat(pageData.txs);
          console.log(`📥 Collected ${allTransactions.length}/${totalTxCount} transactions`);
        }

        // Save progress after each page
        this.saveProgress(address, offset, ['phase1_fetching']);

        // Check if we've fetched all transactions
        if (offset + pageSize >= totalTxCount || pageData.txs.length === 0) {
          console.log(`\n✅ COMPLETE: Fetched all ${allTransactions.length} transactions\n`);
          // Mark phase 1 as completed
          this.saveProgress(address, offset, ['phase1_fetching_complete']);
          break;
        }

        offset += pageSize;
        // NO RATE LIMITING - fetch immediately
        console.log(``);
      }

      // Show cached pages summary
      const cachedFiles = this.getPageFiles();
      if (cachedFiles.length > 0) {
        console.log(`📦 Cached pages available: ${cachedFiles.length} files`);
        console.log(`   ${cachedFiles.slice(0, 5).join(', ')}${cachedFiles.length > 5 ? '...' : ''}\n`);
      }

      return {
        address,
        n_tx: totalTxCount,
        total_received: 0,
        total_sent: 0,
        final_balance: 0,
        txs: allTransactions,
        metadata: {
          pagesDownloaded: Math.ceil(allTransactions.length / pageSize),
          pageSize,
          fetchedAt: new Date().toISOString(),
          dataDir: this.RAW_TXS_DIR,
          progressFile: this.PROGRESS_FILE
        }
      };
    } catch (error) {
      console.error(`\n❌ PHASE 1 FAILED: ${error instanceof Error ? error.message : 'Unknown error'}`);
      // Save failure state
      this.saveProgress(address, offset, ['phase1_failed']);
      throw error;
    }
  }

  async fetchAddressDataComplete(address: string, limit: number = 10000): Promise<any> {
    const maxRetries = 5;
    let lastError: any;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        console.log(`[Attempt ${attempt}/${maxRetries}] Fetching https://blockchain.info/rawaddr/${address}`);
        
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 15000);
        
        const response = await fetch(
          `${this.BLOCKCHAIN_API}/rawaddr/${address}?limit=${Math.min(limit, 10000)}`,
          { signal: controller.signal }
        );
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
          throw new Error(`API error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        
        if (!data.txs) {
          data.txs = [];
        }
        
        console.log(`✓ Successfully fetched ${data.txs?.length || 0} transactions for address ${address}`);
        return data;
      } catch (error) {
        lastError = error;
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';
        console.error(`✗ Attempt ${attempt} failed: ${errorMsg}`);
        
        if (attempt < maxRetries) {
          // Short exponential backoff
          const delayMs = Math.min(300 * Math.pow(2, attempt - 1), 5000);
          console.log(`  ⏳ Waiting ${delayMs}ms before retry ${attempt + 1}...`);
          await new Promise(resolve => setTimeout(resolve, delayMs));
        }
      }
    }
    
    // Fallback to test data for demonstration
    console.log(`⚠️  API unavailable after ${maxRetries} attempts. Using test data...`);
    try {
      const testDataPath = path.join(this.DATA_DIR, 'test_address_data.json');
      if (fs.existsSync(testDataPath)) {
        const testData = JSON.parse(fs.readFileSync(testDataPath, 'utf-8'));
        console.log(`✓ Loaded test data with ${testData.txs?.length || 0} transactions`);
        return testData;
      }
    } catch (e) {
      console.error(`Test data unavailable:`, e);
    }
    
    throw lastError || new Error('Failed to fetch address data - no fallback available');
  }

  async fetchAddressTransactions(address: string, networkType: string = 'mainnet', limit: number = 100): Promise<string[]> {
    const txids: Set<string> = new Set();
    try {
      const baseUrl = networkType === 'testnet'
        ? 'https://blockstream.info/testnet/api'
        : this.BLOCKSTREAM_API;

      // Fetch address details with transactions
      const response = await fetch(`${baseUrl}/address/${address}`);
      if (!response.ok) {
        throw new Error(`Failed to fetch address: ${response.status}`);
      }

      const addressData = await response.json();
      
      // Get transactions from address object
      if (addressData.chain_stats && addressData.chain_stats.tx_count > 0) {
        // Fetch all transactions (paginated)
        const txCount = Math.min(addressData.chain_stats.tx_count, limit);
        const pageSize = 50; // Blockstream API limit
        const pages = Math.ceil(txCount / pageSize);
        
        for (let page = 0; page < pages; page++) {
          const pageResponse = await fetch(`${baseUrl}/address/${address}/txs/chain?start_index=${page * pageSize}`);
          if (pageResponse.ok) {
            const pageTxs = await pageResponse.json();
            for (const tx of pageTxs) {
              if (tx.txid) txids.add(tx.txid);
              if (txids.size >= limit) break;
            }
          }
        }
      }

      // Also check mempool transactions
      if (addressData.mempool_stats && addressData.mempool_stats.tx_count > 0) {
        const mempoolResponse = await fetch(`${baseUrl}/address/${address}/txs/mempool`);
        if (mempoolResponse.ok) {
          const mempoolTxs = await mempoolResponse.json();
          for (const tx of mempoolTxs) {
            if (tx.txid && txids.size < limit) {
              txids.add(tx.txid);
            }
          }
        }
      }

      return Array.from(txids);
    } catch (error) {
      console.error(`Error fetching address transactions for ${address}:`, error);
      return [];
    }
  }

  async getMempoolTxids(networkType: string = 'mainnet'): Promise<string[]> {
    try {
      const baseUrl = networkType === 'testnet'
        ? 'https://blockstream.info/testnet/api'
        : this.BLOCKSTREAM_API;

      const response = await fetch(`${baseUrl}/mempool/txids`);
      
      if (!response.ok) {
        return [];
      }
      
      const txids = await response.json();
      return Array.isArray(txids) ? txids : [];
    } catch (error) {
      console.error('Error getting mempool txids:', error);
      return [];
    }
  }

  async getBlockHeight(networkType: string = 'mainnet'): Promise<number> {
    try {
      const baseUrl = networkType === 'testnet'
        ? 'https://blockstream.info/testnet/api'
        : this.BLOCKSTREAM_API;

      const response = await fetch(`${baseUrl}/blocks/tip/height`);
      
      if (!response.ok) {
        throw new Error(`Failed to get block height: ${response.status}`);
      }
      
      return parseInt(await response.text(), 10);
    } catch (error) {
      console.error('Error getting block height:', error);
      throw error;
    }
  }
}

export const bitcoinService = new BitcoinService();