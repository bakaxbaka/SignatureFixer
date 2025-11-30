import type { LibraryVerifyFn } from "../integrations/ellipticAdapter";
import { analyzeDerStrict } from "../crypto/derStrict";

export type WycheproofResultKind = "valid" | "invalid" | "acceptable";

export interface WycheproofTestCase {
  tcId: number;
  comment: string;
  msgHex: string;
  sigHex: string;
  pubHex: string;
  result: WycheproofResultKind;
  flags: string[];
  curve: string;
}

export interface WycheproofCaseResult {
  tcId: number;
  comment: string;
  curve: string;
  expected: WycheproofResultKind;
  libraryAccepts: boolean;
  parserAccepts: boolean;
  flags: string[];
  derIssues: string[];
}

export interface WycheproofRunOptions {
  curve: string;
  libraryName: string;
  verifyFn: LibraryVerifyFn;
  filter?: (tc: WycheproofTestCase) => boolean;
}

export function mapRawWycheproofJson(json: any, curve: string): WycheproofTestCase[] {
  const groups = json.testGroups || [];
  const cases: WycheproofTestCase[] = [];

  for (const g of groups) {
    const pub = g.key?.uncompressed || g.key?.wx || g.key?.key || "";
    for (const t of g.tests || []) {
      cases.push({
        tcId: t.tcId,
        comment: t.comment || "",
        msgHex: t.msg || "",
        sigHex: t.sig || "",
        pubHex: pub,
        result: t.result,
        flags: t.flags || [],
        curve,
      });
    }
  }

  return cases;
}

export interface WycheproofRunSummary {
  libraryName: string;
  curve: string;
  total: number;
  passed: number;
  failed: number;
  mismatches: WycheproofCaseResult[];
}

export async function runWycheproofSuite(
  cases: WycheproofTestCase[],
  opts: WycheproofRunOptions
): Promise<WycheproofRunSummary> {
  const { verifyFn, libraryName, curve, filter } = opts;
  const filtered = filter ? cases.filter(filter) : cases;

  const mismatches: WycheproofCaseResult[] = [];
  let passed = 0;

  for (const tc of filtered) {
    const derStrict = analyzeDerStrict(tc.sigHex, curve);
    const parserAccepts = derStrict.isCanonical && derStrict.rangeValid;
    let libraryAccepts = false;

    try {
      libraryAccepts = await verifyFn({
        curve,
        msgHashHex: tc.msgHex,
        derHex: tc.sigHex,
        pubkeyHex: tc.pubHex,
      });
    } catch {
      libraryAccepts = false;
    }

    const expected = tc.result;

    const isOk =
      (expected === "valid" && libraryAccepts) ||
      (expected === "invalid" && !libraryAccepts) ||
      (expected === "acceptable" && libraryAccepts);

    if (!isOk) {
      mismatches.push({
        tcId: tc.tcId,
        comment: tc.comment,
        curve,
        expected,
        libraryAccepts,
        parserAccepts,
        flags: tc.flags,
        derIssues: derStrict.derIssues.map((i) => i.message),
      });
    } else {
      passed++;
    }
  }

  return {
    libraryName,
    curve,
    total: filtered.length,
    passed,
    failed: filtered.length - passed,
    mismatches,
  };
}
