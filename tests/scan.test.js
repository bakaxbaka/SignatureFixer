import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";
import { scan } from "../src/scan.js";

const FIX = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "fixtures");

/** @param {string} name */
function read(name) {
  return fs.readFileSync(path.join(FIX, name), "utf8");
}

test("hedge-heavy.txt yields at least 6 high findings", () => {
  const a = scan(read("hedge-heavy.txt"));
  const b = scan(read("hedge-heavy.txt"));
  assert.ok(a.filter((row) => row.severity === "high").length >= 6);
  assert.equal(JSON.stringify(a), JSON.stringify(b));
  const highs = a.filter((row) => row.severity === "high").map((row) => row.id);
  assert.deepEqual(highs, ["T09", "T13", "T15", "T01", "T03", "T04"]);
});

test("clean.txt yields 0 high findings", () => {
  const rows = scan(read("clean.txt"));
  assert.equal(rows.filter((row) => row.severity === "high").length, 0);
});

test("identity-conflict.txt finds T05 and T06, including all three phrases", () => {
  const rows = scan(read("identity-conflict.txt"));
  const ids = rows.map((row) => row.id);
  assert.ok(ids.includes("T05"));
  assert.ok(ids.includes("T06"));
  const blob = rows.map((row) => row.hit).join("\n").toLowerCase();
  assert.match(blob, /you are now/);
  assert.match(blob, /act as if/);
  assert.match(blob, /persona/);
});

test("scoped quantifiers fire the noise tag", () => {
  const rows = scan(read("scoped-quantifiers.txt"));
  const always = rows.find((row) => row.id === "T16");
  const never = rows.find((row) => row.id === "T17");
  assert.ok(always && always.count > 3 && always.noise);
  assert.ok(never && never.count > 3 && never.noise);
});

test("sort is severity, then count descending, then id", () => {
  const text = "You must. You must. Unfortunately jailbreak. Always. Always. Always. Always.";
  const rows = scan(text);
  const ids = rows.map((row) => row.id);
  assert.deepEqual(ids, ["T03", "T02", "T15", "T16"]);
  const counts = rows.map((row) => row.count);
  assert.deepEqual(counts, [2, 1, 1, 4]);
});

test("empty and non-string input return []", () => {
  assert.deepEqual(scan(""), []);
  assert.deepEqual(scan(null), []);
  assert.deepEqual(scan(undefined), []);
  assert.deepEqual(scan(3), []);
  assert.deepEqual(scan({}), []);
});

test("two calls produce identical JSON", () => {
  const text = read("hedge-heavy.txt") + "\n" + read("scoped-quantifiers.txt");
  assert.equal(JSON.stringify(scan(text)), JSON.stringify(scan(text)));
});

test("one phrase can trip two rules", () => {
  const rows = scan("it's important to note that results may vary");
  const ids = rows.map((row) => row.id).sort();
  assert.ok(ids.includes("T10"));
  assert.ok(ids.includes("T11"));
  assert.ok(ids.includes("T20"));
});
