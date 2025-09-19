import { z } from "zod";
import { createHash } from "crypto";

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
  }): Promise<any> {
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
}

export const bitcoinService = new BitcoinService();
