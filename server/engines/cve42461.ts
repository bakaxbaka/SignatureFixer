import { generateCveStyleVariants, type CveEncodingType } from "./malleabilityPlayground";
import type { LibraryVerifyFn } from "../integrations/ellipticAdapter";

export interface Cve42461TestCase {
  id: string;
  encodingType: CveEncodingType;
  derHex: string;
  shouldVerify: boolean;
  didVerify?: boolean;
  error?: string;
}

export interface Cve42461Report {
  libraryName: string;
  curve: string;
  acceptsCanonicalDER: boolean;
  acceptsBERVariants: boolean;
  vulnerable: boolean;
  testCases: Cve42461TestCase[];
}

export async function runCve42461Suite(params: {
  libraryName: string;
  curve: string;
  msgHashHex: string;
  canonicalDerHex: string;
  pubkeyHex: string;
  verifyFn: LibraryVerifyFn;
}): Promise<Cve42461Report> {
  const { libraryName, curve, msgHashHex, canonicalDerHex, pubkeyHex, verifyFn } = params;

  const variants = generateCveStyleVariants(canonicalDerHex);
  const testCases: Cve42461TestCase[] = [];

  for (const v of variants) {
    const tc: Cve42461TestCase = {
      id: v.id,
      encodingType: v.encodingType,
      derHex: v.derHex,
      shouldVerify: v.encodingType === "canonical",
    };

    try {
      const didVerify = await verifyFn({
        curve,
        msgHashHex,
        derHex: v.derHex,
        pubkeyHex,
      });
      tc.didVerify = didVerify;
    } catch (e: any) {
      tc.didVerify = false;
      tc.error = e.message || String(e);
    }

    testCases.push(tc);
  }

  const acceptsCanonicalDER = testCases.find((t) => t.encodingType === "canonical")?.didVerify ?? false;
  const acceptsBERVariants = testCases.some((t) => t.encodingType !== "canonical" && t.didVerify);

  return {
    libraryName,
    curve,
    acceptsCanonicalDER,
    acceptsBERVariants,
    vulnerable: acceptsBERVariants,
    testCases,
  };
}
