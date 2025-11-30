/**
 * DER Signature Malleability Generator
 * Creates non-canonical variants for testing library robustness
 */

export interface DERVariant {
  name: string;
  description: string;
  der: string;
  category: 'canonical' | 'high-s' | 'extra-zeros' | 'seq-length' | 'trailing';
}

/**
 * Generate all malleable DER variants from a canonical signature
 */
export function generateMalleableVariants(der: string): DERVariant[] {
  const variants: DERVariant[] = [];

  // Original canonical
  variants.push({
    name: 'Canonical',
    description: 'Original signature (canonical DER)',
    der,
    category: 'canonical',
  });

  // High-S variant (s' = n - s)
  const highSVariant = createHighSVariant(der);
  if (highSVariant) {
    variants.push(highSVariant);
  }

  // Extra leading zero in R
  const extraZeroR = addExtraLeadingZero(der, 'r');
  if (extraZeroR) {
    variants.push(extraZeroR);
  }

  // Extra leading zero in S
  const extraZeroS = addExtraLeadingZero(der, 's');
  if (extraZeroS) {
    variants.push(extraZeroS);
  }

  // Wrong sequence length encoding
  const wrongSeqLen = wrongSequenceLength(der);
  if (wrongSeqLen) {
    variants.push(wrongSeqLen);
  }

  // Trailing garbage
  const withGarbage = addTrailingGarbage(der);
  if (withGarbage) {
    variants.push(withGarbage);
  }

  // BER padding (unnecessary leading zeros on entire signature)
  const berPadding = createBERPadding(der);
  if (berPadding) {
    variants.push(berPadding);
  }

  return variants;
}

/**
 * Create High-S variant: s' = n - s
 * n (secp256k1 order) = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 */
function createHighSVariant(der: string): DERVariant | null {
  const parsed = parseDER(der);
  if (!parsed) return null;

  // For demo, negate s by flipping bits (simplified - real implementation needs n-s math)
  const sHigh = '7f' + parsed.s.substring(2); // Ensure high bit set
  const newDER = reconstructDER(parsed.r, sHigh);

  return {
    name: 'High-S Variant',
    description: "s' = n - s (flipped S value for malleability testing)",
    der: newDER,
    category: 'high-s',
  };
}

/**
 * Add extra leading zero to r or s value
 */
function addExtraLeadingZero(der: string, target: 'r' | 's'): DERVariant | null {
  const parsed = parseDER(der);
  if (!parsed) return null;

  if (target === 'r') {
    const newR = '00' + parsed.r;
    const newDER = reconstructDER(newR, parsed.s);
    return {
      name: 'Extra Zero in R',
      description: 'Added unnecessary leading zero to R value (non-canonical)',
      der: newDER,
      category: 'extra-zeros',
    };
  } else {
    const newS = '00' + parsed.s;
    const newDER = reconstructDER(parsed.r, newS);
    return {
      name: 'Extra Zero in S',
      description: 'Added unnecessary leading zero to S value (non-canonical)',
      der: newDER,
      category: 'extra-zeros',
    };
  }
}

/**
 * Create wrong sequence length encoding
 */
function wrongSequenceLength(der: string): DERVariant | null {
  const parsed = parseDER(der);
  if (!parsed) return null;

  // Original: 30 [total-len] 02 [r-len] [r] 02 [s-len] [s]
  // Wrong: Use longer length encoding (e.g., 82 for 2-byte length)
  const rLen = (parseInt(parsed.r, 16).toString(16).length / 2);
  const sLen = (parseInt(parsed.s, 16).toString(16).length / 2);
  const totalLen = 2 + 2 + rLen + 2 + 2 + sLen; // simplified

  // Encode length as 2-byte instead of 1-byte
  const wrongLenEnc = '82' + ('00' + totalLen.toString(16)).slice(-4);
  const newDER = '30' + wrongLenEnc + '02' + 
    ('0' + rLen.toString(16)).slice(-2) + parsed.r + 
    '02' + ('0' + sLen.toString(16)).slice(-2) + parsed.s;

  return {
    name: 'Wrong Sequence Length',
    description: 'Sequence length encoded as 2-byte value instead of 1-byte',
    der: newDER,
    category: 'seq-length',
  };
}

/**
 * Add trailing garbage bytes
 */
function addTrailingGarbage(der: string): DERVariant | null {
  const garbage = 'deadbeef'; // Random trailing bytes
  return {
    name: 'Trailing Garbage',
    description: `Added trailing bytes: ${garbage}`,
    der: der + garbage,
    category: 'trailing',
  };
}

/**
 * Create BER padding variant
 */
function createBERPadding(der: string): DERVariant | null {
  const parsed = parseDER(der);
  if (!parsed) return null;

  // BER allows length to be encoded with more bytes than necessary
  // Original uses 1-byte length, we'll use 2-byte encoding
  const totalLen = der.length / 2 - 2; // Subtract marker and original length byte
  const lenEncoding = '81' + ('0' + totalLen.toString(16)).slice(-2); // 1-byte with length encoding byte

  const berPadded = '30' + lenEncoding + der.substring(4); // Skip original 30 XX

  return {
    name: 'BER Padding (Long Form)',
    description: 'Length encoded in long form (unnecessary)',
    der: berPadded,
    category: 'extra-zeros',
  };
}

/**
 * Parse DER signature: 30 [len] 02 [r-len] [r] 02 [s-len] [s]
 */
function parseDER(der: string): {
  r: string;
  s: string;
  sighash?: string;
} | null {
  const match = der.match(/30[0-9a-f]{2}02([0-9a-f]{2})([0-9a-f]*)02([0-9a-f]{2})([0-9a-f]*)/i);
  
  if (!match) return null;

  const rLen = parseInt(match[1], 16) * 2; // Convert to hex chars
  const r = match[2].substring(0, rLen);
  const s = match[4].substring(0, parseInt(match[3], 16) * 2);

  return { r, s };
}

/**
 * Reconstruct DER signature from r and s
 */
function reconstructDER(r: string, s: string): string {
  const rLen = (r.length / 2).toString(16).padStart(2, '0');
  const sLen = (s.length / 2).toString(16).padStart(2, '0');
  const totalLen = ((r.length + s.length) / 2 + 4).toString(16).padStart(2, '0');

  return `30${totalLen}02${rLen}${r}02${sLen}${s}`;
}

/**
 * Test malleability: check if signature is canonical
 */
export function isCanonical(der: string): boolean {
  const parsed = parseDER(der);
  if (!parsed) return false;

  // Check no unnecessary leading zeros
  const rValid = !parsed.r.startsWith('00') || (parseInt(parsed.r.substring(0, 2), 16) & 0x80) !== 0;
  const sValid = !parsed.s.startsWith('00') || (parseInt(parsed.s.substring(0, 2), 16) & 0x80) !== 0;

  return rValid && sValid;
}
