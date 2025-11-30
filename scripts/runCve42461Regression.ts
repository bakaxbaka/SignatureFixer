/**
 * scripts/runCve42461Regression.ts
 * Run CVE-2024-42461 regression tests to ensure library implementations handle BER variants safely
 */
import { runCve42461Suite } from "../server/engines/cve42461";
import { makeEllipticVerifyAdapter } from "../server/integrations/ellipticAdapter";
import { ec as EC } from "elliptic";

interface TestVector {
  name: string;
  msgHashHex: string;
  canonicalDerHex: string;
  pubkeyHex: string;
  shouldRejectBER: boolean;
}

async function main() {
  console.log("🔐 Running CVE-2024-42461 regression tests...\n");

  const secp = new EC("secp256k1");
  const verifyFn = makeEllipticVerifyAdapter(secp);

  // Sample regression vectors (canonical DER signatures)
  const testVectors: TestVector[] = [
    // In production, load a curated set of real signatures from Bitcoin blockchain
    // Format: canonical signature + variants to ensure library handles them correctly
  ];

  let passed = 0;
  let failed = 0;

  for (const vector of testVectors) {
    try {
      console.log(`Testing: ${vector.name}`);

      const report = await runCve42461Suite({
        libraryName: "elliptic",
        curve: "secp256k1",
        msgHashHex: vector.msgHashHex,
        canonicalDerHex: vector.canonicalDerHex,
        pubkeyHex: vector.pubkeyHex,
        verifyFn,
      });

      if (vector.shouldRejectBER && report.acceptsBERVariants) {
        console.error(`  ❌ FAILED: Should reject BER variants but accepted`);
        failed++;
      } else if (!vector.shouldRejectBER && !report.acceptsBERVariants) {
        console.error(`  ❌ FAILED: Should accept BER variants but rejected`);
        failed++;
      } else {
        console.log(`  ✅ PASSED`);
        passed++;
      }
    } catch (e: any) {
      console.error(`  ❌ ERROR: ${e.message}`);
      failed++;
    }
  }

  console.log(`\n📊 Results: ${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("Fatal error:", e);
  process.exit(1);
});
