import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function listing() {
  const dir = path.join(ROOT, "payloads");
  const files = fs
    .readdirSync(dir)
    .filter((name) => name.endsWith(".txt"))
    .sort();
  const lines = files.map((name) => {
    const buf = fs.readFileSync(path.join(dir, name));
    const hex = createHash("sha256").update(buf).digest("hex");
    return `${hex}  payloads/${name}`;
  });
  return lines.join("\n") + "\n";
}

test("ten payload hashes match tests/payloads.sha256", () => {
  const expected = fs.readFileSync(path.join(ROOT, "tests", "payloads.sha256"), "utf8");
  const actual = listing();
  assert.equal(actual.split("\n").filter(Boolean).length, 10);
  assert.equal(actual, expected);
});
