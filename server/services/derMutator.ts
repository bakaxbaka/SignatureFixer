// ======================================================================
// DER Signature Mutator - Generate malleated/forged signature variants
// Used for testing and vulnerability analysis
// ======================================================================

const SECP256K1_N = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

export type DerMutation = 
  | "HIGH_S"              // s' = N - s
  | "ZERO_PAD_R"          // Add leading 0x00 to r
  | "ZERO_PAD_S"          // Add leading 0x00 to s
  | "TRAILING_GARBAGE"    // Append deadbeef to end
  | "WRONG_R_LENGTH"      // Increment r length field
  | "WRONG_S_LENGTH"      // Increment s length field
  | "NON_MINIMAL_R"       // Prepend 0x00 to r if high bit not set
  | "NON_MINIMAL_S";      // Prepend 0x00 to s if high bit not set

export interface MutationResult {
  mutation: DerMutation;
  original: string;
  mutated: string;
  description: string;
  isValid: boolean;
  reason?: string;
}

// Helpers: hex string ↔ Uint8Array
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function bigIntToBytes(n: bigint): Uint8Array {
  const hex = n.toString(16).padStart(64, '0');
  return hexToBytes(hex);
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt('0x' + bytesToHex(bytes));
}

// Parse DER signature (without sighash byte)
interface ParsedDER {
  r: Uint8Array;
  s: Uint8Array;
  isValid: boolean;
}

export function parseDER(derHex: string): ParsedDER {
  try {
    const bytes = hexToBytes(derHex.slice(0, -2)); // Remove sighash byte
    
    if (bytes[0] !== 0x30) return { r: new Uint8Array(), s: new Uint8Array(), isValid: false };
    
    let pos = 2; // Skip 0x30 and length
    
    // Parse R
    if (bytes[pos] !== 0x02) return { r: new Uint8Array(), s: new Uint8Array(), isValid: false };
    pos++;
    const rLen = bytes[pos];
    pos++;
    const r = bytes.slice(pos, pos + rLen);
    pos += rLen;
    
    // Parse S
    if (bytes[pos] !== 0x02) return { r: new Uint8Array(), s: new Uint8Array(), isValid: false };
    pos++;
    const sLen = bytes[pos];
    pos++;
    const s = bytes.slice(pos, pos + sLen);
    
    return { r, s, isValid: true };
  } catch (e) {
    return { r: new Uint8Array(), s: new Uint8Array(), isValid: false };
  }
}

// Build strict DER signature
function buildDER(r: Uint8Array, s: Uint8Array, sighashByte: string): string {
  const rHex = bytesToHex(r);
  const sHex = bytesToHex(s);
  
  // Build DER: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s]
  const rLen = rHex.length / 2;
  const sLen = sHex.length / 2;
  const totalLen = 2 + rLen + 2 + sLen; // Two 0x02 tags + r + s
  
  return `30${totalLen.toString(16).padStart(2, '0')}02${rLen.toString(16).padStart(2, '0')}${rHex}02${sLen.toString(16).padStart(2, '0')}${sHex}${sighashByte}`;
}

// Generate mutation
export function mutateDER(origDerHex: string, mutation: DerMutation): MutationResult {
  const sighashByte = origDerHex.slice(-2);
  const parsed = parseDER(origDerHex);
  
  if (!parsed.isValid) {
    return {
      mutation,
      original: origDerHex,
      mutated: origDerHex,
      description: "Failed to parse original DER",
      isValid: false,
      reason: "Invalid original DER format"
    };
  }
  
  let newR = parsed.r;
  let newS = parsed.s;
  let description = '';
  
  try {
    if (mutation === "HIGH_S") {
      const sBI = bytesToBigInt(newS);
      const sPrime = SECP256K1_N - sBI;
      newS = bigIntToBytes(sPrime);
      description = "Convert S to high-S variant (N - S)";
    } 
    else if (mutation === "ZERO_PAD_R") {
      newR = new Uint8Array([0x00, ...newR]);
      description = "Prepend leading zero byte to R";
    } 
    else if (mutation === "ZERO_PAD_S") {
      newS = new Uint8Array([0x00, ...newS]);
      description = "Prepend leading zero byte to S";
    } 
    else if (mutation === "TRAILING_GARBAGE") {
      const mutated = buildDER(newR, newS, sighashByte) + "deadbeef";
      return {
        mutation,
        original: origDerHex,
        mutated,
        description: "Append deadbeef garbage to end",
        isValid: false,
        reason: "Extra trailing bytes invalidate DER"
      };
    }
    else if (mutation === "WRONG_R_LENGTH") {
      // Manually build DER with wrong length
      const rHex = bytesToHex(newR);
      const sHex = bytesToHex(newS);
      const wrongRLen = (newR.length + 1) % 256;
      const sLen = newS.length;
      const totalLen = 2 + newR.length + 1 + 2 + sLen; // +1 for wrong r length
      const mutated = `30${totalLen.toString(16).padStart(2, '0')}02${wrongRLen.toString(16).padStart(2, '0')}${rHex}02${sLen.toString(16).padStart(2, '0')}${sHex}${sighashByte}`;
      return {
        mutation,
        original: origDerHex,
        mutated,
        description: "Increment R length field (creates parse mismatch)",
        isValid: false,
        reason: "Length field mismatch"
      };
    }
    else if (mutation === "WRONG_S_LENGTH") {
      const rHex = bytesToHex(newR);
      const sHex = bytesToHex(newS);
      const rLen = newR.length;
      const wrongSLen = (newS.length + 1) % 256;
      const totalLen = 2 + rLen + 2 + newS.length + 1;
      const mutated = `30${totalLen.toString(16).padStart(2, '0')}02${rLen.toString(16).padStart(2, '0')}${rHex}02${wrongSLen.toString(16).padStart(2, '0')}${sHex}${sighashByte}`;
      return {
        mutation,
        original: origDerHex,
        mutated,
        description: "Increment S length field (creates parse mismatch)",
        isValid: false,
        reason: "Length field mismatch"
      };
    }
    else if (mutation === "NON_MINIMAL_R") {
      if (newR[0] < 0x80) {
        newR = new Uint8Array([0x00, ...newR]);
      }
      description = "R non-minimal encoding (unnecessary leading zero if high bit not set)";
    }
    else if (mutation === "NON_MINIMAL_S") {
      if (newS[0] < 0x80) {
        newS = new Uint8Array([0x00, ...newS]);
      }
      description = "S non-minimal encoding (unnecessary leading zero if high bit not set)";
    }
    
    const mutated = buildDER(newR, newS, sighashByte);
    return {
      mutation,
      original: origDerHex,
      mutated,
      description,
      isValid: true
    };
  } catch (e) {
    return {
      mutation,
      original: origDerHex,
      mutated: origDerHex,
      description: `Mutation failed: ${(e as Error).message}`,
      isValid: false,
      reason: (e as Error).message
    };
  }
}

// Generate all mutations for a signature
export function generateAllMutations(derHex: string): MutationResult[] {
  const mutations: DerMutation[] = [
    "HIGH_S",
    "ZERO_PAD_R",
    "ZERO_PAD_S",
    "TRAILING_GARBAGE",
    "WRONG_R_LENGTH",
    "WRONG_S_LENGTH",
    "NON_MINIMAL_R",
    "NON_MINIMAL_S"
  ];
  
  return mutations.map(m => mutateDER(derHex, m));
}
