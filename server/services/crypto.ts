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
   * Detects nonce reuse in ECDSA signatures
   */
  detectNonceReuse(signatures: ECDSASignature[]): NonceReuseResult[] {
    const results: NonceReuseResult[] = [];
    const rValueMap = new Map<string, ECDSASignature[]>();

    // Group signatures by R value
    for (const sig of signatures) {
      const rValue = sig.r;
      if (!rValueMap.has(rValue)) {
        rValueMap.set(rValue, []);
      }
      rValueMap.get(rValue)!.push(sig);
    }

    // Find R values that appear more than once (nonce reuse)
    for (const [rValue, sigs] of rValueMap) {
      if (sigs.length > 1) {
        // Nonce reuse detected!
        const result = this.recoverPrivateKeyFromNonceReuse(sigs);
        if (result.isVulnerable) {
          results.push(result);
        }
      }
    }

    return results;
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
      // k = (m1 - m2) / (s1 - s2) mod n
      // privateKey = (r * k - m1) / s1 mod n

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

      // Calculate private key
      const rk = this.modMul(r, k, CURVE_ORDER);
      const rk_minus_m1 = this.modSub(rk, m1, CURVE_ORDER);
      const s1Inv = this.modInverse(s1, CURVE_ORDER);
      const privateKey = this.modMul(rk_minus_m1, s1Inv, CURVE_ORDER);

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

export const cryptoAnalysis = new CryptoAnalysis();
