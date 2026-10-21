import { Router, type Express } from "express";
import { runCve42461Suite } from "../engines/cve42461";
import { makeEllipticVerifyAdapter } from "../integrations/ellipticAdapter";
import { ec as EllipticEC } from "elliptic";
import { z } from "zod";

let secp: InstanceType<typeof EllipticEC> | undefined;

try {
  secp = new EllipticEC("secp256k1");
} catch (e) {
  console.warn("elliptic not available for CVE tests");
}

const router = Router();

const Cve42461RequestSchema = z.object({
  libraryName: z.string(),
  curve: z.string(),
  msgHashHex: z.string(),
  canonicalDerHex: z.string(),
  pubkeyHex: z.string(),
});

router.post("/api/cve42461", async (req, res) => {
  try {
    const parsed = Cve42461RequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid request" });
    }

    const { libraryName, curve, msgHashHex, canonicalDerHex, pubkeyHex } = parsed.data;
    if (!secp) {
      return res.status(503).json({ error: "elliptic library not available" });
    }
    const verifyFn = makeEllipticVerifyAdapter(secp);

    const report = await runCve42461Suite({
      libraryName,
      curve,
      msgHashHex,
      canonicalDerHex,
      pubkeyHex,
      verifyFn,
    });

    res.json(report);
  } catch (err: any) {
    res.status(500).json({ error: err.message || "CVE test failed" });
  }
});

export default router;
