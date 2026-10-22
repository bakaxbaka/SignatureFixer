import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";
import { renderThinkcore } from "../src/compile.js";
import { renderTriggers } from "../src/scan.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("prompts/THINKCORE.md matches compile({ tier: 'full', profile: 'generic' })", () => {
  const disk = fs.readFileSync(path.join(ROOT, "prompts", "THINKCORE.md"), "utf8");
  assert.equal(disk, renderThinkcore());
});

test("docs/TRIGGERS.md matches RULES", () => {
  const disk = fs.readFileSync(path.join(ROOT, "docs", "TRIGGERS.md"), "utf8");
  assert.equal(disk, renderTriggers());
});
