/**
 * CVE-2024-42461 Detection Engine
 * Tests if a library/wallet accepts non-canonical DER signature encodings
 * Vulnerable: elliptic 6.5.6 and similar libraries that accept BER variants
 * Fixed: libraries that enforce strict DER canonicalization
 */

export interface Cve42461TestCase {
  id: string;
  encodingType: "canonical" | "BER-padding" | "BER-length" | "trailing-garbage";
  shouldVerify: boolean;
  didVerify: boolean;
  derHex?: string;
  description?: string;
}

export interface Cve42461Report {
  libraryName: string;
  acceptsCanonicalDER: boolean;
  acceptsBERVariants: boolean;
  vulnerable: boolean; // true if any non-canonical encodings are accepted
  testCases: Cve42461TestCase[];
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
  summary: string;
  timestamp: number;
}

/**
 * Generate test DER signatures in various encoding formats
 * All encodings represent the same (r, s) pair
 */
export function generateTestSignatures(rHex: string, sHex: string) {
  // Ensure r and s are properly padded
  const r = rHex.padStart(64, "0");
  const s = sHex.padStart(64, "0");

  // Canonical DER: strict format
  const canonicalDER = encodeCanonicalDER(r, s);

  // BER variant 1: Padding with leading zeros (should be rejected)
  const berPadding = encodeWithPadding(r, s);

  // BER variant 2: Long form length encoding (should be rejected)
  const berLength = encodeLongFormLength(r, s);

  // BER variant 3: Trailing garbage (should be rejected)
  const trailingGarbage = canonicalDER + "00";

  return {
    canonical: {
      hex: canonicalDER,
      description: "Strict canonical DER format - must verify",
      shouldVerify: true,
    },
    berPadding: {
      hex: berPadding,
      description:
        "BER with unnecessary padding - should be rejected by strict verifiers",
      shouldVerify: false,
    },
    berLength: {
      hex: berLength,
      description:
        "BER with long-form length - should be rejected by strict verifiers",
      shouldVerify: false,
    },
    trailingGarbage: {
      hex: trailingGarbage,
      description: "Canonical DER + trailing bytes - should be rejected",
      shouldVerify: false,
    },
  };
}

function encodeCanonicalDER(r: string, s: string): string {
  // Remove leading zeros but keep one if MSB is set
  let rTrimmed = r.replace(/^0+/, "0") || "0";
  let sTrimmed = s.replace(/^0+/, "0") || "0";

  // Add leading 0 if high bit is set (for positive representation)
  if (parseInt(rTrimmed[0], 16) >= 8) rTrimmed = "0" + rTrimmed;
  if (parseInt(sTrimmed[0], 16) >= 8) sTrimmed = "0" + sTrimmed;

  const rLen = rTrimmed.length / 2;
  const sLen = sTrimmed.length / 2;

  // DER structure: 30 [total-len] 02 [r-len] [r] 02 [s-len] [s]
  const rPart = `02${rLen.toString(16).padStart(2, "0")}${rTrimmed}`;
  const sPart = `02${sLen.toString(16).padStart(2, "0")}${sTrimmed}`;
  const totalLen = (rPart.length + sPart.length) / 2;

  return `30${totalLen.toString(16).padStart(2, "0")}${rPart}${sPart}`;
}

function encodeWithPadding(r: string, s: string): string {
  // Add unnecessary leading zeros
  const rPadded = "00" + r;
  const sPadded = "00" + s;

  const rLen = rPadded.length / 2;
  const sLen = sPadded.length / 2;

  const rPart = `02${rLen.toString(16).padStart(2, "0")}${rPadded}`;
  const sPart = `02${sLen.toString(16).padStart(2, "0")}${sPadded}`;
  const totalLen = (rPart.length + sPart.length) / 2;

  return `30${totalLen.toString(16).padStart(2, "0")}${rPart}${sPart}`;
}

function encodeLongFormLength(r: string, s: string): string {
  let rTrimmed = r.replace(/^0+/, "0") || "0";
  let sTrimmed = s.replace(/^0+/, "0") || "0";

  if (parseInt(rTrimmed[0], 16) >= 8) rTrimmed = "0" + rTrimmed;
  if (parseInt(sTrimmed[0], 16) >= 8) sTrimmed = "0" + sTrimmed;

  const rLen = rTrimmed.length / 2;
  const sLen = sTrimmed.length / 2;

  const rPart = `02${rLen.toString(16).padStart(2, "0")}${rTrimmed}`;
  const sPart = `02${sLen.toString(16).padStart(2, "0")}${sTrimmed}`;
  const totalLen = (rPart.length + sPart.length) / 2;

  // Use long-form length encoding: 81 [len] instead of [len] for values <= 255
  // This is non-canonical for lengths < 128
  const longFormLen = "81" + totalLen.toString(16).padStart(2, "0");

  return `30${longFormLen}${rPart}${sPart}`;
}

/**
 * Create a test report by testing a verify function against various encodings
 */
export async function testLibraryVulnerability(
  libraryName: string,
  verifyFunction: (
    derSignature: string,
    messageHash: string,
    publicKey: string
  ) => Promise<boolean> | boolean,
  testMessageHash: string = "aa" + "aa".repeat(31), // 32 bytes of 0xaa
  testPublicKey: string =
    "03" + "aa".repeat(32) // 33-byte compressed pubkey
): Promise<Cve42461Report> {
  const testCases: Cve42461TestCase[] = [];
  let acceptedBER = false;
  let acceptedCanonical = false;

  // Test with known test vectors
  const testR = "6e" + "00".repeat(31); // R value
  const testS = "77" + "00".repeat(31); // S value

  const signatures = generateTestSignatures(testR, testS);

  // Test canonical (must accept)
  try {
    const result = await Promise.resolve(
      verifyFunction(signatures.canonical.hex, testMessageHash, testPublicKey)
    );
    acceptedCanonical = !!result;
    testCases.push({
      id: "canonical",
      encodingType: "canonical",
      shouldVerify: true,
      didVerify: result,
      derHex: signatures.canonical.hex,
      description: signatures.canonical.description,
    });
  } catch (e) {
    testCases.push({
      id: "canonical",
      encodingType: "canonical",
      shouldVerify: true,
      didVerify: false,
      derHex: signatures.canonical.hex,
      description: "Threw error: " + (e as Error).message,
    });
  }

  // Test BER variants (should reject)
  for (const [variant, data] of Object.entries(signatures).slice(1)) {
    try {
      const result = await Promise.resolve(
        verifyFunction(data.hex, testMessageHash, testPublicKey)
      );
      if (result) acceptedBER = true;
      testCases.push({
        id: variant,
        encodingType: variant as any,
        shouldVerify: false,
        didVerify: result,
        derHex: data.hex,
        description: data.description,
      });
    } catch (e) {
      testCases.push({
        id: variant,
        encodingType: variant as any,
        shouldVerify: false,
        didVerify: false,
        derHex: data.hex,
        description: "Threw error: " + (e as Error).message,
      });
    }
  }

  const vulnerable = acceptedBER;
  let severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE" = "NONE";
  let summary = "Library enforces strict DER canonicalization - SECURE";

  if (vulnerable) {
    severity = "CRITICAL";
    summary =
      "VULNERABLE: Library accepts non-canonical BER encodings like elliptic 6.5.6";
  } else if (!acceptedCanonical) {
    severity = "MEDIUM";
    summary = "WARNING: Library rejects even canonical DER signatures";
  }

  return {
    libraryName,
    acceptsCanonicalDER: acceptedCanonical,
    acceptsBERVariants: acceptedBER,
    vulnerable,
    testCases,
    severity,
    summary,
    timestamp: Date.now(),
  };
}

/**
 * Export report as human-readable format
 */
export function formatReport(report: Cve42461Report): string {
  let output = `\n=== CVE-2024-42461 Analysis Report ===\n`;
  output += `Library: ${report.libraryName}\n`;
  output += `Severity: ${report.severity}\n`;
  output += `Status: ${report.summary}\n`;
  output += `Timestamp: ${new Date(report.timestamp).toISOString()}\n\n`;

  output += `Test Results:\n`;
  output += `- Accepts Canonical DER: ${report.acceptsCanonicalDER ? "✓" : "✗"}\n`;
  output += `- Accepts BER Variants: ${report.acceptsBERVariants ? "✓" : "✗"}\n`;
  output += `- Overall Vulnerable: ${report.vulnerable ? "YES - CRITICAL" : "NO - SECURE"}\n\n`;

  output += `Detailed Test Cases:\n`;
  report.testCases.forEach((tc) => {
    const status = tc.didVerify === tc.shouldVerify ? "✓" : "✗";
    output += `${status} [${tc.encodingType}] Should: ${tc.shouldVerify}, Did: ${tc.didVerify}\n`;
    if (tc.description) output += `  └─ ${tc.description}\n`;
  });

  return output;
}
