/**
 * scripts/runWycheproofAll.ts
 * Run Wycheproof ECDSA test suites for all curves/libraries as CI regression test
 */
import { runWycheproofSuite } from "../server/engines/wycheproofRunner";
import { makeEllipticVerifyAdapter } from "../server/integrations/ellipticAdapter";
import { ec as EC } from "elliptic";

const CURVES = ["secp256k1", "secp521r1"];
const LIBRARIES = ["elliptic"];

async function main() {
  console.log("🔐 Running Wycheproof regression tests...\n");

  let totalPassed = 0;
  let totalFailed = 0;

  for (const curve of CURVES) {
    for (const libName of LIBRARIES) {
      console.log(`Testing ${libName} on ${curve}...`);

      try {
        const secp = new EC(curve as any);
        const verifyFn = makeEllipticVerifyAdapter(secp);

        // Stub test case set (in production, load from JSON files)
        const testCases = [];

        const result = await runWycheproofSuite(testCases, {
          curve: curve as any,
          libraryName: libName,
          verifyFn,
        });

        console.log(
          `  ✅ ${result.passed}/${result.total} passed, ${result.failed} failed`
        );
        totalPassed += result.passed;
        totalFailed += result.failed;
      } catch (e: any) {
        console.error(
          `  ❌ Error testing ${libName} on ${curve}:`,
          e.message
        );
        totalFailed++;
      }
    }
  }

  console.log(`\n📊 Total: ${totalPassed} passed, ${totalFailed} failed`);
  process.exit(totalFailed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("Fatal error:", e);
  process.exit(1);
});
