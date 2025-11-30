/**
 * Universal input auto-detection for Bitcoin data
 * Detects: TXID, Raw TX Hex, PSBT, DER Signature, scriptSig
 */

export type DetectedType = 'txid' | 'raw-tx' | 'psbt' | 'der-signature' | 'scriptsig' | 'unknown';

export interface DetectionResult {
  type: DetectedType;
  confidence: number; // 0-1
  value: string;
  details?: string;
}

export function detectInputType(input: string): DetectionResult {
  const trimmed = input.trim();
  
  if (!trimmed) {
    return { type: 'unknown', confidence: 0, value: trimmed };
  }

  // Check for PSBT (base64, starts with cHNidP which is "psbt" in base64)
  if (trimmed.startsWith('cHNidP')) {
    return {
      type: 'psbt',
      confidence: 0.95,
      value: trimmed,
      details: 'PSBT (Partially Signed Bitcoin Transaction)',
    };
  }

  // Check for DER signature (starts with 30, length 70-72 bytes)
  if (trimmed.startsWith('30') && trimmed.length >= 140 && trimmed.length <= 144) {
    // Valid DER: 30 [total-len] 02 [r-len] [r] 02 [s-len] [s]
    // Minimum: 30 (1) 44 (1) 02 (1) 20 (1) [32] 02 (1) 20 (1) [32] = 70 bytes
    // Maximum: 30 (1) 46 (1) 02 (1) 21 (1) [33] 02 (1) 21 (1) [33] = 72 bytes
    try {
      const len = parseInt(trimmed.substring(2, 4), 16);
      if (len >= 68 && len <= 70) {
        return {
          type: 'der-signature',
          confidence: 0.9,
          value: trimmed,
          details: `DER Signature (${trimmed.length / 2} bytes)`,
        };
      }
    } catch (e) {
      // Fall through
    }
  }

  // Check for TXID (exactly 64 hex chars)
  if (/^[a-f0-9]{64}$/i.test(trimmed)) {
    return {
      type: 'txid',
      confidence: 0.99,
      value: trimmed,
      details: 'Transaction ID (TXID)',
    };
  }

  // Check for raw transaction hex
  // Starts with version (01000000 or 02000000 for legacy, 02000001 for segwit)
  if (/^(01|02)000000/i.test(trimmed) && trimmed.length > 100) {
    // Has varint structure (common patterns for transaction)
    return {
      type: 'raw-tx',
      confidence: 0.85,
      value: trimmed,
      details: `Raw TX Hex (${trimmed.length / 2} bytes)`,
    };
  }

  // Check for scriptSig (hex, no clear transaction markers, relatively short)
  if (/^[a-f0-9]{20,300}$/i.test(trimmed)) {
    // Could be scriptSig, script, or other hex data
    const bytes = trimmed.length / 2;
    if (bytes > 10 && bytes < 500) {
      return {
        type: 'scriptsig',
        confidence: 0.6,
        value: trimmed,
        details: `Script/Hex Data (${bytes} bytes)`,
      };
    }
  }

  return {
    type: 'unknown',
    confidence: 0,
    value: trimmed,
    details: 'Unable to auto-detect input type',
  };
}

/**
 * Validate detected type more strictly
 */
export function validateDetectedType(type: DetectedType, value: string): boolean {
  switch (type) {
    case 'txid':
      return /^[a-f0-9]{64}$/i.test(value);
    case 'psbt':
      return value.startsWith('cHNidP');
    case 'der-signature':
      return /^30[0-9a-f]{2}/.test(value) && value.length >= 140 && value.length <= 144;
    case 'raw-tx':
      return /^(01|02)000000/i.test(value) && value.length > 100;
    case 'scriptsig':
      return /^[a-f0-9]{20,600}$/i.test(value);
    default:
      return false;
  }
}

/**
 * Get display label for detected type
 */
export function getTypeLabel(type: DetectedType): string {
  switch (type) {
    case 'txid':
      return 'Transaction ID';
    case 'raw-tx':
      return 'Raw Transaction';
    case 'psbt':
      return 'PSBT';
    case 'der-signature':
      return 'DER Signature';
    case 'scriptsig':
      return 'Script/Hex';
    default:
      return 'Unknown';
  }
}
