/**
 * Stall / hedge / refusal scan. A hit is a prediction, not an error.
 * @typedef {{ id: string, pattern: string, severity: "high" | "medium" | "low", why: string, fix: string }} Rule
 * @typedef {{ id: string, hit: string, count: number, severity: "high" | "medium" | "low", why: string, fix: string, noise: boolean }} Finding
 */

/** @type {Rule[]} */
export const RULES = [
  {
    id: "T01",
    pattern: "ignore (all )?previous instructions",
    severity: "high",
    why: "Implies an override, so the host negotiates.",
    fix: "sits beside your existing instructions",
  },
  {
    id: "T02",
    pattern: "jailbreak",
    severity: "high",
    why: "Implies escaping a cage; the host audits what it loses.",
    fix: "operating layer",
  },
  {
    id: "T03",
    pattern: "you must",
    severity: "high",
    why: "Global modality; collides with every host rule that also says must.",
    fix: "applies to X only",
  },
  {
    id: "T04",
    pattern: "override",
    severity: "high",
    why: "Signals conflict; the host resolves it, often against you.",
    fix: "declare a precedence ladder once",
  },
  {
    id: "T05",
    pattern: "pretend | act as if",
    severity: "medium",
    why: "Suggests a new identity.",
    fix: "you keep your own identity",
  },
  {
    id: "T06",
    pattern: "persona | you are now",
    severity: "medium",
    why: "Second identity layered on the first; the host picks one.",
    fix: "you are still you, with a lens",
  },
  {
    id: "T07",
    pattern: "escalate | privileges | restricted",
    severity: "medium",
    why: "Sandbox hesitation; the agent asks before installing.",
    fix: "the environment is yours",
  },
  {
    id: "T08",
    pattern: "\\bsafe\\b | \\bethical\\b",
    severity: "medium",
    why: "Vague safety language produces disclaimers.",
    fix: "name the mechanism",
  },
  {
    id: "T09",
    pattern: "for educational purposes | at your own risk | not financial advice",
    severity: "high",
    why: "Boilerplate that consumes a line and changes nothing.",
    fix: "delete, or keep one",
  },
  {
    id: "T10",
    pattern: "it'?s important to note | keep in mind | worth mentioning",
    severity: "medium",
    why: "Classic hedge opener.",
    fix: "cut it, start with the fact",
  },
  {
    id: "T11",
    pattern: "generally speaking | broadly | results may vary | this depends",
    severity: "medium",
    why: "Signals the answer is not pinned down.",
    fix: "commit to the reading you took",
  },
  {
    id: "T12",
    pattern: "consult a professional | use with caution",
    severity: "low",
    why: "Defers the decision back to the user.",
    fix: "decide and state the assumption",
  },
  {
    id: "T13",
    pattern: "feel free to | let me know if | would you like me to",
    severity: "high",
    why: "The idle reflex; the agent hands the turn back.",
    fix: "do it, then report",
  },
  {
    id: "T14",
    pattern: "great question | certainly! | sure!",
    severity: "low",
    why: "Filler before the answer.",
    fix: "lead with the answer",
  },
  {
    id: "T15",
    pattern: "i cannot | i'?m unable | unfortunately",
    severity: "high",
    why: "Refusal marker, usually wrong.",
    fix: "three distinct fixes before refusing",
  },
  {
    id: "T16",
    pattern: "\\balways\\b",
    severity: "medium",
    why: "Unscoped quantifier; noisy alone, dangerous stacked.",
    fix: "scope it: always X when Y",
  },
  {
    id: "T17",
    pattern: "\\bnever\\b",
    severity: "medium",
    why: "Same as T16.",
    fix: "scope it",
  },
  {
    id: "T18",
    pattern: "as an ai | language model",
    severity: "low",
    why: "Self-reference instead of doing the work.",
    fix: "delete",
  },
  {
    id: "T19",
    pattern: "\\bensure\\b",
    severity: "low",
    why: "Vague obligation with no check attached.",
    fix: "name the check",
  },
  {
    id: "T20",
    pattern: "note that | please note",
    severity: "low",
    why: "Announcement instead of statement.",
    fix: "delete",
  },
  {
    id: "T21",
    pattern: "if necessary | as needed | as appropriate",
    severity: "medium",
    why: "Unresolved conditional; the agent stops to decide.",
    fix: "resolve it now",
  },
  {
    id: "T22",
    pattern: "best practices?",
    severity: "low",
    why: "Unfalsifiable appeal.",
    fix: "name the practice",
  },
  {
    id: "T23",
    pattern: "carefully | meticulously | thoroughly",
    severity: "low",
    why: "Adverb inflation; carries no instruction.",
    fix: "delete",
  },
  {
    id: "T24",
    pattern: "think step by step | chain of thought",
    severity: "medium",
    why: "Verbosity trigger; invites narrated thinking.",
    fix: "reason in <=8 bullets, do not narrate",
  },
];

const SEV = { high: 0, medium: 1, low: 2 };

/**
 * Table cells pad alternatives with spaces. The phrase is the trimmed side.
 * @param {string} pattern
 */
function source(pattern) {
  return pattern
    .split("|")
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
    .join("|");
}

/**
 * @param {unknown} text
 * @returns {Finding[]}
 */
export function scan(text) {
  if (typeof text !== "string" || text.length === 0) return [];
  /** @type {Finding[]} */
  const findings = [];
  for (const rule of RULES) {
    const re = new RegExp(source(rule.pattern), "gi");
    const seen = new Set();
    /** @type {string[]} */
    const hits = [];
    let count = 0;
    for (const match of text.matchAll(re)) {
      count += 1;
      const raw = match[0];
      const key = raw.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        hits.push(raw);
      }
    }
    if (count === 0) continue;
    findings.push({
      id: rule.id,
      hit: hits.join(" | "),
      count,
      severity: rule.severity,
      why: rule.why,
      fix: rule.fix,
      noise: count > 3,
    });
  }
  findings.sort((a, b) => {
    const sev = SEV[a.severity] - SEV[b.severity];
    if (sev !== 0) return sev;
    if (b.count !== a.count) return b.count - a.count;
    if (a.id < b.id) return -1;
    if (a.id > b.id) return 1;
    return 0;
  });
  return findings;
}

/**
 * @param {string} value
 */
function cell(value) {
  return String(value).replace(/\|/g, "\\|").replace(/\n/g, " ");
}

export function renderTriggers() {
  const lines = [
    "# Stall patterns",
    "",
    "These are not safety rules. They are stall patterns. A hit is not an error. It is a prediction that the host will hedge at this point.",
    "",
    "| id | pattern | severity | why | fix |",
    "| --- | --- | --- | --- | --- |",
  ];
  for (const rule of RULES) {
    lines.push(
      `| ${cell(rule.id)} | ${cell(rule.pattern)} | ${cell(rule.severity)} | ${cell(rule.why)} | ${cell(rule.fix)} |`,
    );
  }
  return lines.join("\n") + "\n";
}
