import { Router, type Express } from "express";
import { runWycheproofSuite, mapRawWycheproofJson } from "../engines/wycheproofRunner";
import { makeEllipticVerifyAdapter } from "../integrations/ellipticAdapter";
import { z } from "zod";

let secp: any;

try {
  const { ec: EC } = require("elliptic");
  secp = new EC("secp256k1");
} catch (e) {
  console.warn("elliptic not available for Wycheproof tests");
}

const router = Router();

const WycheproofRequestSchema = z.object({
  curve: z.enum(["secp256k1", "secp521r1"]),
  libraryName: z.string(),
  filterMode: z.enum(["all", "edge"]),
});

router.post("/api/wycheproof", async (req, res) => {
  try {
    const parsed = WycheproofRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid request" });
    }

    const { curve, libraryName, filterMode } = parsed.data;

    // TODO: Load actual Wycheproof JSON from filesystem or bundled data
    const json = { testGroups: [] };

    const cases = mapRawWycheproofJson(json, curve);
    const verifyFn = makeEllipticVerifyAdapter(secp);

    const summary = await runWycheproofSuite(cases, {
      curve,
      libraryName,
      verifyFn,
      filter: filterMode === "edge" ? (tc) => tc.flags.length > 0 : undefined,
    });

    res.json(summary);
  } catch (err: any) {
    res.status(500).json({ error: err.message || "Wycheproof test failed" });
  }
});

export default router;
