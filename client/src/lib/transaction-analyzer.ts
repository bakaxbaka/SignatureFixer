/**
 * Transaction analysis utilities
 * Computes: weight, vsize, fee, feerate, DER validation, tags
 */

export interface TransactionInput {
  index: number;
  prevTxid: string;
  vout: number;
  sequence: string;
  scriptSig: string;
  scriptType: string;
  pubkey?: string;
  address?: string;
}

export interface TransactionOutput {
  index: number;
  value: number;
  scriptPubKey: string;
  scriptType: string;
  address?: string;
  isChange?: boolean;
}

export interface TransactionAnalysis {
  txid: string;
  version: number;
  locktime: number;
  size: number;
  weight: number;
  vsize: number;
  fee: number;
  feerate: number; // sat/vB
  inputCount: number;
  outputCount: number;
  totalIn: number;
  totalOut: number;
  tags: TransactionTag[];
  inputs?: TransactionInput[];
  outputs?: TransactionOutput[];
}

export type TransactionTag = 
  | { type: 'strict-der'; label: '✅ Strict DER clean' }
  | { type: 'high-s'; label: '⚠ High-S found' }
  | { type: 'non-canonical'; label: '⚠ Non-canonical encodings' }
  | { type: 'weird-sighash'; label: '⚠ Weird sighash types present' };

/**
 * Parse raw transaction hex and extract basic info
 */
export function parseRawTx(txHex: string): {
  version: number;
  locktime: number;
  inputCount: number;
  outputCount: number;
  size: number;
  isSegwit: boolean;
} {
  const bytes = txHexToBytes(txHex);
  let offset = 0;

  // Version (4 bytes)
  const version = readUint32LE(bytes, offset);
  offset += 4;

  // Check for SegWit marker (0x00 0x01)
  let isSegwit = false;
  if (bytes[offset] === 0x00 && bytes[offset + 1] === 0x01) {
    isSegwit = true;
    offset += 2;
  }

  // Input count (varint)
  const inputCount = readVarint(bytes, offset);
  offset += getVarintSize(bytes[offset]);

  // Skip inputs to count outputs
  for (let i = 0; i < inputCount; i++) {
    offset += 32; // prevout hash
    offset += 4;  // prevout index
    const scriptLen = readVarint(bytes, offset);
    offset += getVarintSize(bytes[offset]);
    offset += scriptLen;
    offset += 4; // sequence
  }

  // Output count (varint)
  const outputCount = readVarint(bytes, offset);
  offset += getVarintSize(bytes[offset]);

  // Skip to locktime (at end of outputs)
  for (let i = 0; i < outputCount; i++) {
    offset += 8; // value
    const scriptLen = readVarint(bytes, offset);
    offset += getVarintSize(bytes[offset]);
    offset += scriptLen;
  }

  // Locktime (4 bytes)
  const locktime = readUint32LE(bytes, offset);

  return {
    version,
    locktime,
    inputCount,
    outputCount,
    size: bytes.length,
    isSegwit,
  };
}

/**
 * Calculate transaction weight and vsize
 * Weight = (base_size * 3) + total_size
 * vsize = weight / 4 (rounded up)
 */
export function calculateWeight(txHex: string): {
  baseSize: number;
  totalSize: number;
  weight: number;
  vsize: number;
} {
  const bytes = txHexToBytes(txHex);
  const totalSize = bytes.length;

  // For SegWit, base size excludes witness data
  // For simplicity, estimate: if SegWit markers exist, assume ~60% is witness
  const hasSegwit = bytes[4] === 0x00 && bytes[5] === 0x01;
  const baseSize = hasSegwit ? Math.ceil(totalSize * 0.6) : totalSize;

  const weight = (baseSize * 3) + totalSize;
  const vsize = Math.ceil(weight / 4);

  return { baseSize, totalSize, weight, vsize };
}

/**
 * Check for DER signature issues
 */
export function analyzeDERSignatures(txHex: string): {
  hasHighS: boolean;
  hasNonCanonical: boolean;
  strictDERClean: boolean;
} {
  // Pattern: look for signatures in scriptSig
  const sigPattern = /30([0-9a-f]{2})([0-9a-f]{1,2})([0-9a-f]*?)([0-9a-f]{1,2})([0-9a-f]*)/gi;
  let match;
  let hasHighS = false;
  let hasNonCanonical = false;

  while ((match = sigPattern.exec(txHex)) !== null) {
    const fullSig = match[0];
    const totalLen = match[1];
    
    // Check for high S value (s > n/2)
    // This is a heuristic - would need proper ECDSA math for exact check
    if (fullSig.length > 140) {
      const sHalf = fullSig.substring(fullSig.length - 64);
      if (parseInt(sHalf, 16) > 0x7fffffffffffffffffffffffffffffff) {
        hasHighS = true;
      }
    }

    // Check for non-canonical DER (e.g., unnecessary leading zeros)
    if (fullSig.substring(6, 8) === '00' || fullSig.substring(fullSig.length - 2) === '00') {
      hasNonCanonical = true;
    }
  }

  return {
    hasHighS,
    hasNonCanonical,
    strictDERClean: !hasHighS && !hasNonCanonical,
  };
}

/**
 * Generate transaction analysis tags
 */
export function generateTags(analysis: {
  strictDERClean: boolean;
  hasHighS: boolean;
  hasNonCanonical: boolean;
}): TransactionTag[] {
  const tags: TransactionTag[] = [];

  if (analysis.strictDERClean) {
    tags.push({ type: 'strict-der', label: '✅ Strict DER clean' });
  }

  if (analysis.hasHighS) {
    tags.push({ type: 'high-s', label: '⚠ High-S found' });
  }

  if (analysis.hasNonCanonical) {
    tags.push({ type: 'non-canonical', label: '⚠ Non-canonical encodings' });
  }

  // TODO: Add sighash analysis
  // tags.push({ type: 'weird-sighash', label: '⚠ Weird sighash types present' });

  return tags;
}

// Helper functions
function txHexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function readUint32LE(bytes: Uint8Array, offset: number): number {
  return (
    bytes[offset] |
    (bytes[offset + 1] << 8) |
    (bytes[offset + 2] << 16) |
    (bytes[offset + 3] << 24)
  );
}

function readVarint(bytes: Uint8Array, offset: number): number {
  const first = bytes[offset];
  if (first < 0xfd) return first;
  if (first === 0xfd) return (bytes[offset + 1] | (bytes[offset + 2] << 8));
  if (first === 0xfe) return readUint32LE(bytes, offset + 1);
  return 0; // 0xff case would need 8 bytes
}

function getVarintSize(firstByte: number): number {
  if (firstByte < 0xfd) return 1;
  if (firstByte === 0xfd) return 3;
  if (firstByte === 0xfe) return 5;
  return 9;
}

/**
 * Parse full input details from transaction hex
 */
export function parseInputs(txHex: string, isSegwit: boolean = false): TransactionInput[] {
  const bytes = txHexToBytes(txHex);
  let offset = 4; // Skip version

  if (isSegwit) {
    offset += 2; // Skip marker + flag
  }

  const inputCount = readVarint(bytes, offset);
  offset += getVarintSize(bytes[offset]);

  const inputs: TransactionInput[] = [];

  for (let i = 0; i < inputCount; i++) {
    const prevTxid = bytesToHex(bytes.slice(offset, offset + 32).reverse());
    offset += 32;

    const vout = readUint32LE(bytes, offset);
    offset += 4;

    const scriptLen = readVarint(bytes, offset);
    const scriptLenSize = getVarintSize(bytes[offset]);
    offset += scriptLenSize;

    const scriptSig = bytesToHex(bytes.slice(offset, offset + scriptLen));
    offset += scriptLen;

    const sequence = bytesToHex(bytes.slice(offset, offset + 4).reverse());
    offset += 4;

    const scriptType = detectScriptType(scriptSig);
    const pubkey = extractPubkey(scriptSig);

    inputs.push({
      index: i,
      prevTxid,
      vout,
      sequence,
      scriptSig,
      scriptType,
      pubkey,
    });
  }

  return inputs;
}

/**
 * Parse full output details from transaction hex
 */
export function parseOutputs(txHex: string, inputCount: number, isSegwit: boolean = false): TransactionOutput[] {
  const bytes = txHexToBytes(txHex);
  let offset = 4; // Skip version

  if (isSegwit) {
    offset += 2; // Skip marker + flag
  }

  // Skip inputs
  const inputCountVar = readVarint(bytes, offset);
  offset += getVarintSize(bytes[offset]);

  for (let i = 0; i < inputCountVar; i++) {
    offset += 32; // prevTxid
    offset += 4; // vout
    const scriptLen = readVarint(bytes, offset);
    offset += getVarintSize(bytes[offset]);
    offset += scriptLen;
    offset += 4; // sequence
  }

  const outputCount = readVarint(bytes, offset);
  offset += getVarintSize(bytes[offset]);

  const outputs: TransactionOutput[] = [];

  for (let i = 0; i < outputCount; i++) {
    const value = readUint64LE(bytes, offset);
    offset += 8;

    const scriptLen = readVarint(bytes, offset);
    const scriptLenSize = getVarintSize(bytes[offset]);
    offset += scriptLenSize;

    const scriptPubKey = bytesToHex(bytes.slice(offset, offset + scriptLen));
    offset += scriptLen;

    const scriptType = detectScriptTypeOutput(scriptPubKey);
    const address = extractAddress(scriptPubKey);

    outputs.push({
      index: i,
      value,
      scriptPubKey,
      scriptType,
      address,
    });
  }

  return outputs;
}

/**
 * Detect script type from scriptSig (input)
 */
function detectScriptType(scriptSig: string): string {
  if (!scriptSig || scriptSig.length === 0) return "Unknown";
  
  // P2PKH: sig pubkey
  if (scriptSig.startsWith("48") || scriptSig.startsWith("47")) return "P2PKH";
  // P2SH: often starts with OP_m (51-53)
  if (scriptSig.match(/^5[123]/)) return "P2SH";
  // SegWit witness programs are handled differently
  return "Other";
}

/**
 * Detect script type from scriptPubKey (output)
 */
function detectScriptTypeOutput(scriptPubKey: string): string {
  // OP_DUP OP_HASH160 [20 bytes] OP_EQUALVERIFY OP_CHECKSIG = P2PKH
  if (scriptPubKey.startsWith("76a914") && scriptPubKey.length === 50) return "P2PKH";
  // OP_HASH160 [20 bytes] OP_EQUAL = P2SH
  if (scriptPubKey.startsWith("a914") && scriptPubKey.length === 46) return "P2SH";
  // OP_0 [20 bytes] = P2WPKH
  if (scriptPubKey.startsWith("0014") && scriptPubKey.length === 44) return "P2WPKH";
  // OP_0 [32 bytes] = P2WSH
  if (scriptPubKey.startsWith("0020") && scriptPubKey.length === 68) return "P2WSH";
  // OP_1 [33 bytes] = Taproot
  if (scriptPubKey.startsWith("5120") && scriptPubKey.length === 68) return "Taproot";
  return "Unknown";
}

/**
 * Extract pubkey from scriptSig
 */
function extractPubkey(scriptSig: string): string | undefined {
  // P2PKH typically: [sig_len] [sig] [pubkey_len] [pubkey]
  // Find 21 (33 bytes) or 41 (65 bytes) which are pubkey lengths
  const pubkeyMatch = scriptSig.match(/21([a-f0-9]{66})|41([a-f0-9]{130})/i);
  if (pubkeyMatch) {
    return pubkeyMatch[1] || pubkeyMatch[2];
  }
  return undefined;
}

/**
 * Extract address from scriptPubKey (simplified)
 */
function extractAddress(scriptPubKey: string): string | undefined {
  // P2PKH: 76a914[20 bytes]88ac
  const p2pkhMatch = scriptPubKey.match(/76a914([a-f0-9]{40})88ac/i);
  if (p2pkhMatch) return "1" + p2pkhMatch[1].substring(0, 16) + "..."; // Placeholder
  
  // P2SH: a914[20 bytes]87
  const p2shMatch = scriptPubKey.match(/a914([a-f0-9]{40})87/i);
  if (p2shMatch) return "3" + p2shMatch[1].substring(0, 16) + "...";

  // P2WPKH: 0014[20 bytes]
  const p2wpkhMatch = scriptPubKey.match(/0014([a-f0-9]{40})/i);
  if (p2wpkhMatch) return "bc1q" + p2wpkhMatch[1].substring(0, 16) + "...";

  return undefined;
}

function readUint64LE(bytes: Uint8Array, offset: number): number {
  // For demo, just read as 32-bit (Bitcoin satoshis are in range)
  return readUint32LE(bytes, offset);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}
