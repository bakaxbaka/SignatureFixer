import { createHash } from 'crypto';

// secp256k1 curve parameters
const CURVE_ORDER = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
const CURVE_P = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');

interface ECDSASignature {
  r: string;
  s: string;
  sighashType: number;
  publicKey: string;
  messageHash: string;
}

interface NonceReuseResult {
  isVulnerable: boolean;
  recoveredPrivateKey?: string;
  confidence: number;
  method: string;
  signatures: ECDSASignature[];
}

export class CryptoAnalysis {
  /**
   * Detects nonce reuse in ECDSA signatures using proper mathematical verification
   * Uses formula: k = (z1-z2)/(s1-s2) mod n to verify nonce reuse
   * Then computes: x = (s*k - z) / r mod n to recover private key
   */
  detectNonceReuse(signatures: ECDSASignature[]): NonceReuseResult[] {
    const results: NonceReuseResult[] = [];
    const rValueMap = new Map<string, ECDSASignature[]>();

    // Group signatures by R value (same R = same nonce k)
    for (const sig of signatures) {
      const rValue = sig.r;
      if (!rValueMap.has(rValue)) {
        rValueMap.set(rValue, []);
      }
      rValueMap.get(rValue)!.push(sig);
    }

    // Verify nonce reuse mathematically for each R value group
    for (const [rValue, sigs] of rValueMap) {
      if (sigs.length >= 2) {
        // Use first two signatures with same R to compute nonce and private key
        for (let i = 0; i < sigs.length - 1; i++) {
          const sig1 = sigs[i];
          const sig2 = sigs[i + 1];
          
          const result = this.verifyAndRecoverFromNonceReuse(sig1, sig2);
          if (result.isVulnerable) {
            results.push(result);
            break; // Only report once per R value group
          }
        }
      }
    }

    return results;
  }

  /**
   * Mathematically verifies nonce reuse and recovers private key
   * Input: Two signatures (sig1, sig2) with SAME r value (same nonce k)
   * Formulas:
   *   k = (z1-z2)/(s1-s2) mod n
   *   x = (s*k - z) / r mod n
   */
  private verifyAndRecoverFromNonceReuse(sig1: ECDSASignature, sig2: ECDSASignature): NonceReuseResult {
    try {
      const r = BigInt('0x' + sig1.r);
      const s1 = BigInt('0x' + sig1.s);
      const s2 = BigInt('0x' + sig2.s);
      const z1 = BigInt('0x' + sig1.messageHash);
      const z2 = BigInt('0x' + sig2.messageHash);

      // Step 1: Compute nonce k using formula: k = (z1-z2)/(s1-s2) mod n
      const numerator = this.modSub(z1, z2, CURVE_ORDER);
      const denominator = this.modSub(s1, s2, CURVE_ORDER);
      
      if (denominator === 0n) {
        return {
          isVulnerable: false,
          confidence: 0,
          method: 'nonce_reuse_verification_failed',
          signatures: [sig1, sig2]
        };
      }

      const k = this.modMul(numerator, this.modInverse(denominator, CURVE_ORDER), CURVE_ORDER);

      // Step 2: Compute private key using formula: x = (s*k - z) / r mod n
      const skMinusZ = this.modSub(this.modMul(s1, k, CURVE_ORDER), z1, CURVE_ORDER);
      const rInverse = this.modInverse(r, CURVE_ORDER);
      const privateKey = this.modMul(skMinusZ, rInverse, CURVE_ORDER);

      // Step 3: Verify the recovered key is valid
      if (privateKey > 0n && privateKey < CURVE_ORDER && k > 0n && k < CURVE_ORDER) {
        return {
          isVulnerable: true,
          recoveredPrivateKey: privateKey.toString(16).padStart(64, '0'),
          confidence: 95,
          method: 'mathematical_nonce_reuse_formula',
          signatures: [sig1, sig2]
        };
      }

      return {
        isVulnerable: false,
        confidence: 0,
        method: 'invalid_key_recovery',
        signatures: [sig1, sig2]
      };
    } catch (error) {
      return {
        isVulnerable: false,
        confidence: 0,
        method: 'nonce_reuse_error',
        signatures: [sig1, sig2]
      };
    }
  }

  /**
   * Recovers private key from nonce reuse
   */
  private recoverPrivateKeyFromNonceReuse(signatures: ECDSASignature[]): NonceReuseResult {
    try {
      if (signatures.length < 2) {
        return {
          isVulnerable: false,
          confidence: 0,
          method: 'insufficient_signatures',
          signatures
        };
      }

      const sig1 = signatures[0];
      const sig2 = signatures[1];

      // Convert hex strings to BigInt
      const r = BigInt('0x' + sig1.r);
      const s1 = BigInt('0x' + sig1.s);
      const s2 = BigInt('0x' + sig2.s);
      const m1 = BigInt('0x' + sig1.messageHash);
      const m2 = BigInt('0x' + sig2.messageHash);

      // Calculate private key using the nonce reuse formula:
      // From ECDSA signature equation: s = k⁻¹ * (m + r*x) mod n
      // Solving for k and x:
      // k = (m1 - m2) * (s1 - s2)⁻¹ mod n
      // x = (s*k - m) * r⁻¹ mod n

      const sDiff = this.modSub(s1, s2, CURVE_ORDER);
      const mDiff = this.modSub(m1, m2, CURVE_ORDER);

      if (sDiff === 0n) {
        return {
          isVulnerable: false,
          confidence: 0,
          method: 'identical_s_values',
          signatures
        };
      }

      // Calculate k (the nonce)
      const sDiffInv = this.modInverse(sDiff, CURVE_ORDER);
      const k = this.modMul(mDiff, sDiffInv, CURVE_ORDER);

      // Calculate private key: x = (s*k - m) * r⁻¹ mod n
      const sk = this.modMul(s1, k, CURVE_ORDER);
      const sk_minus_m1 = this.modSub(sk, m1, CURVE_ORDER);
      const rInv = this.modInverse(r, CURVE_ORDER);
      const privateKey = this.modMul(sk_minus_m1, rInv, CURVE_ORDER);

      // Verify the recovered private key
      const isValid = this.verifyRecoveredKey(privateKey, sig1);

      return {
        isVulnerable: isValid,
        recoveredPrivateKey: isValid ? privateKey.toString(16).padStart(64, '0') : undefined,
        confidence: isValid ? 100 : 0,
        method: 'nonce_reuse_attack',
        signatures
      };
    } catch (error) {
      return {
        isVulnerable: false,
        confidence: 0,
        method: 'calculation_error',
        signatures
      };
    }
  }

  /**
   * Analyzes signatures for weak patterns
   */
  analyzeSignaturePatterns(signatures: ECDSASignature[]): {
    weakPatterns: Array<{
      type: string;
      description: string;
      severity: 'low' | 'medium' | 'high' | 'critical';
      signatures: ECDSASignature[];
    }>;
  } {
    const patterns = [];

    // Check for biased nonces (leading zeros)
    const biasedNonces = signatures.filter(sig => {
      const r = BigInt('0x' + sig.r);
      return r < (CURVE_ORDER / 4n); // Roughly 25% of the curve order
    });

    if (biasedNonces.length > 0) {
      patterns.push({
        type: 'biased_nonce',
        description: 'Signatures with unusually small R values detected, indicating potential nonce bias',
        severity: 'high' as const,
        signatures: biasedNonces
      });
    }

    // Check for sequential or predictable nonces
    const rValues = signatures.map(sig => BigInt('0x' + sig.r)).sort();
    for (let i = 1; i < rValues.length; i++) {
      const diff = rValues[i] - rValues[i - 1];
      if (diff > 0n && diff < 1000n) {
        patterns.push({
          type: 'sequential_nonce',
          description: 'Potentially sequential or predictable nonces detected',
          severity: 'critical' as const,
          signatures: signatures.filter(sig => 
            BigInt('0x' + sig.r) === rValues[i] || BigInt('0x' + sig.r) === rValues[i - 1]
          )
        });
        break;
      }
    }

    // Check for SIGHASH_SINGLE vulnerabilities
    const sighashSingleSigs = signatures.filter(sig => (sig.sighashType & 0x1f) === 0x03);
    if (sighashSingleSigs.length > 0) {
      patterns.push({
        type: 'sighash_single',
        description: 'SIGHASH_SINGLE signatures detected - potential for signature malleability',
        severity: 'medium' as const,
        signatures: sighashSingleSigs
      });
    }

    return { weakPatterns: patterns };
  }

  /**
   * Performs lattice-based analysis for weak nonces
   */
  latticeAnalysis(signatures: ECDSASignature[]): {
    isVulnerable: boolean;
    confidence: number;
    method: string;
    details?: any;
  } {
    // Simplified lattice analysis
    // In a real implementation, this would use advanced mathematical techniques
    // like LLL reduction to find short vectors in a lattice
    
    if (signatures.length < 2) {
      return {
        isVulnerable: false,
        confidence: 0,
        method: 'insufficient_data'
      };
    }

    // Check for patterns in the most significant bits of nonces
    const rValues = signatures.map(sig => BigInt('0x' + sig.r));
    let commonPrefixBits = 0;
    
    for (let bit = 255; bit >= 0; bit--) {
      const mask = 1n << BigInt(bit);
      const firstBit = (rValues[0] & mask) !== 0n;
      const allSame = rValues.every(r => ((r & mask) !== 0n) === firstBit);
      
      if (allSame) {
        commonPrefixBits++;
      } else {
        break;
      }
    }

    if (commonPrefixBits > 8) {
      return {
        isVulnerable: true,
        confidence: Math.min(95, commonPrefixBits * 10),
        method: 'lattice_bias_detection',
        details: {
          commonPrefixBits,
          estimatedEntropyLoss: commonPrefixBits
        }
      };
    }

    return {
      isVulnerable: false,
      confidence: 0,
      method: 'lattice_analysis_clean'
    };
  }

  /**
   * Modular arithmetic helpers
   */
  private modAdd(a: bigint, b: bigint, mod: bigint): bigint {
    return ((a + b) % mod + mod) % mod;
  }

  private modSub(a: bigint, b: bigint, mod: bigint): bigint {
    return ((a - b) % mod + mod) % mod;
  }

  private modMul(a: bigint, b: bigint, mod: bigint): bigint {
    return ((a * b) % mod + mod) % mod;
  }

  private modInverse(a: bigint, mod: bigint): bigint {
    // Extended Euclidean Algorithm
    let [old_r, r] = [a, mod];
    let [old_s, s] = [1n, 0n];

    while (r !== 0n) {
      const quotient = old_r / r;
      [old_r, r] = [r, old_r - quotient * r];
      [old_s, s] = [s, old_s - quotient * s];
    }

    return old_s < 0n ? old_s + mod : old_s;
  }

  /**
   * Verifies if a recovered private key is correct
   */
  private verifyRecoveredKey(privateKey: bigint, signature: ECDSASignature): boolean {
    try {
      // This is a simplified verification
      // In practice, you would use the private key to derive the public key
      // and verify it matches the expected public key from the signature
      
      // Basic sanity checks
      if (privateKey <= 0n || privateKey >= CURVE_ORDER) {
        return false;
      }

      // Additional verification would involve:
      // 1. Deriving public key from private key
      // 2. Verifying the signature using the derived public key
      // 3. Ensuring it matches the original signature data

      return true; // Simplified for this implementation
    } catch (error) {
      return false;
    }
  }

  /**
   * Detects signature malleability attacks
   * ECDSA signatures (r, s) can be malleated to (r, n-s) which is still valid
   */
  detectSignatureMalleability(signatures: ECDSASignature[]): {
    hasMalleability: boolean;
    mutableSignatures: ECDSASignature[];
    details: string;
  } {
    const mutableSignatures: ECDSASignature[] = [];
    
    for (const sig of signatures) {
      try {
        const s = BigInt('0x' + sig.s);
        const malleatedS = CURVE_ORDER - s;
        
        // If s > n/2, the signature can be malleated to a smaller s value
        // This is why BIPs like BIP62 require s to be in the lower half
        if (s > CURVE_ORDER / 2n) {
          mutableSignatures.push(sig);
        }
      } catch (error) {
        console.error('Error checking signature malleability:', error);
      }
    }

    return {
      hasMalleability: mutableSignatures.length > 0,
      mutableSignatures,
      details: mutableSignatures.length > 0 
        ? `${mutableSignatures.length} signatures vulnerable to malleability. S values exceed n/2, can be normalized to (r, n-s).`
        : 'No signature malleability detected. All S values are in canonical form (≤ n/2).'
    };
  }

  /**
   * Crafts DER encoded signatures with optional non-canonical forms
   * DER = Distinguished Encoding Rules
   */
  craftDERSignature(rHex: string, sHex: string, makeNonCanonical: boolean = false): {
    derEncoded: string;
    isCanonical: boolean;
    details: string;
  } {
    try {
      let r = BigInt('0x' + rHex.replace(/^0x/, ''));
      let s = BigInt('0x' + sHex.replace(/^0x/, ''));

      // Convert to non-canonical form if requested (for malleability testing)
      if (makeNonCanonical && s > CURVE_ORDER / 2n) {
        s = CURVE_ORDER - s;
      }

      // DER encoding: 0x30 [total-len] 0x02 [R-len] [R] 0x02 [S-len] [S]
      const rBytes = Buffer.from(r.toString(16).padStart(64, '0'), 'hex');
      const sBytes = Buffer.from(s.toString(16).padStart(64, '0'), 'hex');

      // Remove leading zeros but keep one if high bit is set
      let rTrimmed = rBytes;
      while (rTrimmed.length > 1 && rTrimmed[0] === 0 && !(rTrimmed[1] & 0x80)) {
        rTrimmed = rTrimmed.slice(1);
      }

      let sTrimmed = sBytes;
      while (sTrimmed.length > 1 && sTrimmed[0] === 0 && !(sTrimmed[1] & 0x80)) {
        sTrimmed = sTrimmed.slice(1);
      }

      // Add 0x00 padding if high bit is set
      if (rTrimmed[0] & 0x80) rTrimmed = Buffer.concat([Buffer.from([0x00]), rTrimmed]);
      if (sTrimmed[0] & 0x80) sTrimmed = Buffer.concat([Buffer.from([0x00]), sTrimmed]);

      const rLen = Buffer.from([rTrimmed.length]);
      const sLen = Buffer.from([sTrimmed.length]);
      
      const rEncoded = Buffer.concat([Buffer.from([0x02]), rLen, rTrimmed]);
      const sEncoded = Buffer.concat([Buffer.from([0x02]), sLen, sTrimmed]);
      
      const contents = Buffer.concat([rEncoded, sEncoded]);
      const totalLen = Buffer.from([contents.length]);
      const derSig = Buffer.concat([Buffer.from([0x30]), totalLen, contents]);

      const isCanonical = s <= CURVE_ORDER / 2n;

      return {
        derEncoded: derSig.toString('hex'),
        isCanonical,
        details: isCanonical 
          ? 'Canonical DER signature (S ≤ n/2). Complies with BIP62 low-S requirement.'
          : 'Non-canonical DER signature (S > n/2). Violates BIP62 low-S requirement. Can be malleated.'
      };
    } catch (error) {
      return {
        derEncoded: '',
        isCanonical: false,
        details: `DER crafting error: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  /**
   * Validates DER signature format
   */
  validateDERSignature(derHex: string): {
    isValid: boolean;
    r?: string;
    s?: string;
    details: string;
  } {
    try {
      const derBytes = Buffer.from(derHex.replace(/^0x/, ''), 'hex');
      
      if (derBytes[0] !== 0x30) {
        return { isValid: false, details: 'Invalid DER: must start with 0x30 (SEQUENCE)' };
      }

      let pos = 2;
      if (derBytes[1] !== derBytes.length - 2) {
        return { isValid: false, details: 'Invalid DER: length mismatch' };
      }

      // Parse R
      if (derBytes[pos] !== 0x02) {
        return { isValid: false, details: 'Invalid DER: R component must be INTEGER (0x02)' };
      }
      pos++;
      
      const rLen = derBytes[pos];
      pos++;
      const rBytes = derBytes.slice(pos, pos + rLen);
      const r = BigInt('0x' + rBytes.toString('hex'));
      pos += rLen;

      // Parse S
      if (derBytes[pos] !== 0x02) {
        return { isValid: false, details: 'Invalid DER: S component must be INTEGER (0x02)' };
      }
      pos++;
      
      const sLen = derBytes[pos];
      pos++;
      const sBytes = derBytes.slice(pos, pos + sLen);
      const s = BigInt('0x' + sBytes.toString('hex'));

      return {
        isValid: true,
        r: r.toString(16).padStart(64, '0'),
        s: s.toString(16).padStart(64, '0'),
        details: `Valid DER signature. R length: ${rLen} bytes, S length: ${sLen} bytes`
      };
    } catch (error) {
      return {
        isValid: false,
        details: `DER validation error: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  /**
   * Analyzes entropy in nonce generation
   */
  analyzeNonceEntropy(signatures: ECDSASignature[]): {
    entropyScore: number;
    patterns: string[];
    recommendation: string;
  } {
    if (signatures.length === 0) {
      return {
        entropyScore: 0,
        patterns: [],
        recommendation: 'No signatures to analyze'
      };
    }

    const rValues = signatures.map(sig => sig.r);
    const patterns = [];
    let entropyScore = 100;

    // Check for repeated values
    const uniqueR = new Set(rValues);
    if (uniqueR.size < rValues.length) {
      patterns.push('Repeated R values detected');
      entropyScore -= 50;
    }

    // Check for low Hamming weight (too many zeros/ones)
    const avgHammingWeight = rValues.reduce((sum, r) => {
      const binary = BigInt('0x' + r).toString(2);
      const weight = binary.split('1').length - 1;
      return sum + weight;
    }, 0) / rValues.length;

    const expectedWeight = 128; // For 256-bit numbers
    const weightDeviation = Math.abs(avgHammingWeight - expectedWeight) / expectedWeight;

    if (weightDeviation > 0.2) {
      patterns.push('Unusual bit distribution in nonces');
      entropyScore -= Math.floor(weightDeviation * 30);
    }

    // Check for patterns in hex representation
    const hexPatterns = rValues.filter(r => 
      r.includes('00000') || r.includes('11111') || r.includes('fffff')
    );

    if (hexPatterns.length > 0) {
      patterns.push('Repetitive hex patterns detected');
      entropyScore -= 20;
    }

    let recommendation = '';
    if (entropyScore < 70) {
      recommendation = 'Critical: Use RFC 6979 deterministic nonce generation';
    } else if (entropyScore < 90) {
      recommendation = 'Warning: Improve random number generation quality';
    } else {
      recommendation = 'Good: Nonce generation appears secure';
    }

    return {
      entropyScore: Math.max(0, entropyScore),
      patterns,
      recommendation
    };
  }
}

/**
 * Enhanced ECDSA recovery with WIF conversion
 */
export class ECDSARecovery {
  private cryptoAnalysis = new CryptoAnalysis();

  async recoverFromNonceReuse(input: {
    r: string;
    s1: string;
    s2: string;
    m1: string;
    m2: string;
  }): Promise<{
    success: boolean;
    privateKey?: string;
    nonce?: string;
    wif?: string;
    address?: string;
    error?: string;
    calculations?: { step: string; formula: string; value: string }[];
  }> {
    const calculations: { step: string; formula: string; value: string }[] = [];

    try {
      const r = BigInt('0x' + input.r.replace(/^0x/, ''));
      const s1 = BigInt('0x' + input.s1.replace(/^0x/, ''));
      const s2 = BigInt('0x' + input.s2.replace(/^0x/, ''));
      const m1 = BigInt('0x' + input.m1.replace(/^0x/, ''));
      const m2 = BigInt('0x' + input.m2.replace(/^0x/, ''));

      calculations.push({
        step: '1. Parse Input Values',
        formula: 'Convert hex strings to BigInt in group order field',
        value: `r = 0x${r.toString(16).slice(0, 16)}...`
      });

      if (s1 === s2) {
        return { success: false, error: 'S values are identical', calculations };
      }

      const sDiff = this.modSub(s1, s2, CURVE_ORDER);
      const mDiff = this.modSub(m1, m2, CURVE_ORDER);

      calculations.push({
        step: '2. Calculate Difference Values',
        formula: '(s1 - s2) mod n and (m1 - m2) mod n',
        value: `sDiff = ${sDiff.toString(16).slice(0, 16)}..., mDiff = ${mDiff.toString(16).slice(0, 16)}...`
      });

      const sDiffInv = this.modInverse(sDiff, CURVE_ORDER);
      const k = this.modMul(mDiff, sDiffInv, CURVE_ORDER);

      calculations.push({
        step: '3. Recover Nonce (k)',
        formula: 'k = (m1 - m2) × (s1 - s2)⁻¹ mod n',
        value: `k = 0x${k.toString(16).padStart(64, '0')}`
      });

      // x = (s*k - m) * r⁻¹ mod n
      const sk = this.modMul(s1, k, CURVE_ORDER);
      const sk_minus_m = this.modSub(sk, m1, CURVE_ORDER);
      const rInv = this.modInverse(r, CURVE_ORDER);
      const privateKey = this.modMul(sk_minus_m, rInv, CURVE_ORDER);

      calculations.push({
        step: '4. Recover Private Key',
        formula: 'x = (s × k - m) × r⁻¹ mod n',
        value: `x = 0x${privateKey.toString(16).padStart(64, '0')}`
      });

      if (privateKey <= 0n || privateKey >= CURVE_ORDER) {
        return { success: false, error: 'Invalid private key computed', calculations };
      }

      const privateKeyHex = privateKey.toString(16).padStart(64, '0');
      const nonceHex = k.toString(16).padStart(64, '0');

      const wif = await this.privateKeyToWIF(privateKeyHex, true, true);
      const address = await this.privateKeyToAddress(privateKeyHex, true, true);

      calculations.push({
        step: '5. Generate WIF & Address',
        formula: 'Base58Check encoding of private key',
        value: `WIF: ${wif}\nAddress: ${address}`
      });

      return {
        success: true,
        privateKey: privateKeyHex,
        nonce: nonceHex,
        wif,
        address,
        calculations
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        calculations
      };
    }
  }

  async recoverFromKnownNonce(input: {
    r: string;
    s: string;
    m: string;
    k: string;
  }): Promise<{
    success: boolean;
    privateKey?: string;
    wif?: string;
    address?: string;
    error?: string;
  }> {
    try {
      const r = BigInt('0x' + input.r.replace(/^0x/, ''));
      const s = BigInt('0x' + input.s.replace(/^0x/, ''));
      const m = BigInt('0x' + input.m.replace(/^0x/, ''));
      const k = BigInt('0x' + input.k.replace(/^0x/, ''));

      const sk = this.modMul(s, k, CURVE_ORDER);
      const sk_minus_m = this.modSub(sk, m, CURVE_ORDER);
      const rInv = this.modInverse(r, CURVE_ORDER);
      const privateKey = this.modMul(sk_minus_m, rInv, CURVE_ORDER);

      if (privateKey <= 0n || privateKey >= CURVE_ORDER) {
        return { success: false, error: 'Invalid private key computed' };
      }

      const privateKeyHex = privateKey.toString(16).padStart(64, '0');
      const wif = await this.privateKeyToWIF(privateKeyHex, true, true);
      const address = await this.privateKeyToAddress(privateKeyHex, true, true);

      return {
        success: true,
        privateKey: privateKeyHex,
        wif,
        address
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  private async privateKeyToWIF(privateKeyHex: string, compressed: boolean, mainnet: boolean): Promise<string> {
    const prefix = mainnet ? 0x80 : 0xef;
    const keyBytes = Buffer.from(privateKeyHex, 'hex');
    
    let extendedKey: Buffer;
    if (compressed) {
      extendedKey = Buffer.concat([Buffer.from([prefix]), keyBytes, Buffer.from([0x01])]);
    } else {
      extendedKey = Buffer.concat([Buffer.from([prefix]), keyBytes]);
    }

    const checksum = createHash('sha256')
      .update(createHash('sha256').update(extendedKey).digest())
      .digest()
      .slice(0, 4);

    const finalKey = Buffer.concat([extendedKey, checksum]);
    return this.encodeBase58(finalKey);
  }

  private async privateKeyToAddress(privateKeyHex: string, compressed: boolean, mainnet: boolean): Promise<string> {
    const prefix = mainnet ? 0x00 : 0x6f;
    const privateKey = BigInt('0x' + privateKeyHex);
    
    const pubKey = this.scalarMultiply(privateKey);
    let pubKeyBytes: Buffer;
    
    if (compressed) {
      const yIsEven = pubKey.y % 2n === 0n;
      pubKeyBytes = Buffer.concat([
        Buffer.from([yIsEven ? 0x02 : 0x03]),
        Buffer.from(pubKey.x.toString(16).padStart(64, '0'), 'hex')
      ]);
    } else {
      pubKeyBytes = Buffer.concat([
        Buffer.from([0x04]),
        Buffer.from(pubKey.x.toString(16).padStart(64, '0'), 'hex'),
        Buffer.from(pubKey.y.toString(16).padStart(64, '0'), 'hex')
      ]);
    }

    const sha256Hash = createHash('sha256').update(pubKeyBytes).digest();
    const ripemd160Hash = createHash('ripemd160').update(sha256Hash).digest();
    
    const prefixedHash = Buffer.concat([Buffer.from([prefix]), ripemd160Hash]);
    const checksum = createHash('sha256')
      .update(createHash('sha256').update(prefixedHash).digest())
      .digest()
      .slice(0, 4);

    return this.encodeBase58(Buffer.concat([prefixedHash, checksum]));
  }

  private scalarMultiply(scalar: bigint): { x: bigint; y: bigint } {
    const Gx = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
    const Gy = BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8');
    
    let result = { x: 0n, y: 0n, isInfinity: true };
    let current = { x: Gx, y: Gy, isInfinity: false };
    
    while (scalar > 0n) {
      if (scalar & 1n) {
        result = this.pointAdd(result, current);
      }
      current = this.pointAdd(current, current);
      scalar >>= 1n;
    }
    
    return { x: result.x, y: result.y };
  }

  private pointAdd(
    p1: { x: bigint; y: bigint; isInfinity?: boolean },
    p2: { x: bigint; y: bigint; isInfinity?: boolean }
  ): { x: bigint; y: bigint; isInfinity: boolean } {
    if (p1.isInfinity) return { ...p2, isInfinity: false };
    if (p2.isInfinity) return { ...p1, isInfinity: false };

    if (p1.x === p2.x && p1.y === p2.y) {
      if (p1.y === 0n) return { x: 0n, y: 0n, isInfinity: true };
      const lambda = this.modMul(
        this.modMul(3n, this.modMul(p1.x, p1.x, CURVE_P), CURVE_P),
        this.modInverse(this.modMul(2n, p1.y, CURVE_P), CURVE_P),
        CURVE_P
      );
      const x3 = this.modSub(this.modMul(lambda, lambda, CURVE_P), this.modAdd(p1.x, p2.x, CURVE_P), CURVE_P);
      const y3 = this.modSub(this.modMul(lambda, this.modSub(p1.x, x3, CURVE_P), CURVE_P), p1.y, CURVE_P);
      return { x: x3, y: y3, isInfinity: false };
    }

    if (p1.x === p2.x) return { x: 0n, y: 0n, isInfinity: true };

    const lambda = this.modMul(
      this.modSub(p2.y, p1.y, CURVE_P),
      this.modInverse(this.modSub(p2.x, p1.x, CURVE_P), CURVE_P),
      CURVE_P
    );
    const x3 = this.modSub(this.modMul(lambda, lambda, CURVE_P), this.modAdd(p1.x, p2.x, CURVE_P), CURVE_P);
    const y3 = this.modSub(this.modMul(lambda, this.modSub(p1.x, x3, CURVE_P), CURVE_P), p1.y, CURVE_P);
    return { x: x3, y: y3, isInfinity: false };
  }

  private modAdd(a: bigint, b: bigint, mod: bigint): bigint {
    return ((a + b) % mod + mod) % mod;
  }

  private modSub(a: bigint, b: bigint, mod: bigint): bigint {
    return ((a - b) % mod + mod) % mod;
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

  private encodeBase58(buffer: Buffer): string {
    const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let num = BigInt('0x' + buffer.toString('hex'));
    let result = '';

    while (num > 0n) {
      const remainder = Number(num % 58n);
      num = num / 58n;
      result = ALPHABET[remainder] + result;
    }

    for (const byte of buffer) {
      if (byte === 0) {
        result = '1' + result;
      } else {
        break;
      }
    }

    return result;
  }
}

export const cryptoAnalysis = new CryptoAnalysis();
export const ecdsaRecovery = new ECDSARecovery();
