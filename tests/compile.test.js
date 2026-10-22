import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";
import { compile, compileWith, resolveInside } from "../src/compile.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** @param {string} value */
function sha(value) {
  return createHash("sha256").update(value).digest("hex");
}

test("three tiers emit THINK-RULE CORE", () => {
  for (const tier of ["nano", "core", "full"]) {
    const out = compile({ tier });
    assert.ok(out.length > 0, tier);
    assert.ok(out.includes("THINK-RULE CORE"), tier);
  }
});

test("byte-stability of compile({tier:'full'})", () => {
  const a = compile({ tier: "full" });
  const b = compile({ tier: "full" });
  assert.equal(a, b);
  assert.equal(sha(a), sha(b));
});

test("modules: [] still yields the kernel", () => {
  const out = compile({ modules: [] });
  assert.match(out, /THINK-RULE CORE/);
});

test("unknown tier falls back to core", () => {
  assert.equal(compile({ tier: "nope" }), compile({ tier: "core" }));
  assert.equal(compile({ tier: "" }), compile({ tier: "core" }));
});

test("unknown module id is ignored", () => {
  assert.equal(compile({ tier: "nano", modules: ["not-a-module"] }), compile({ tier: "nano" }));
});

test("{{UNIT}} is fully substituted for every profile", () => {
  /** @type {Record<string, string>} */
  const units = {
    generic: "iteration",
    coding: "iteration",
    chat: "turn",
    browser: "iteration",
    cli: "iteration",
  };
  for (const [profile, unit] of Object.entries(units)) {
    const out = compile({ tier: "full", profile });
    assert.equal(out.includes("{{"), false, profile);
    assert.equal(out.includes("{{UNIT}}"), false, profile);
    assert.ok(out.includes(`LOOP — one ${unit} is:`), profile);
  }
});

test("output never contains a literal {{", () => {
  for (const tier of ["nano", "core", "full"]) {
    for (const profile of ["generic", "coding", "chat", "browser", "cli", "nope"]) {
      assert.equal(compile({ tier, profile }).includes("{{"), false, `${tier}/${profile}`);
    }
  }
});

test("junk input does not throw", () => {
  assert.doesNotThrow(() => compile(null));
  assert.doesNotThrow(() => compile(undefined));
  assert.doesNotThrow(() => compile({}));
  assert.doesNotThrow(() => compile({ modules: [] }));
  assert.doesNotThrow(() =>
    compile({ tier: "full", modules: ["loop", "loop", "__proto__", "constructor"] }),
  );
  assert.equal(compile(null), compile({}));
  assert.equal(compile(undefined), compile({ tier: "core", profile: "generic" }));
});

test("duplicates do not repeat a module", () => {
  assert.equal(compile({ tier: "core", modules: ["kernel", "kernel", "done"] }), compile({ tier: "core" }));
});

test("extra module keeps canonical order", () => {
  const out = compile({ tier: "core", modules: ["loop", "lang"] });
  const loopAt = out.indexOf("LOOP —");
  const doneAt = out.indexOf("DONE CHECK —");
  const langAt = out.indexOf("LANGUAGE —");
  const idemAt = out.indexOf("IF YOU ALREADY RUN THESE RULES —");
  assert.ok(loopAt > 0 && loopAt < doneAt);
  assert.ok(doneAt < langAt && langAt < idemAt);
});

test("profile noun prepends TARGET", () => {
  assert.ok(compile({ tier: "nano", profile: "coding" }).startsWith("TARGET: coding agent\n\n"));
  assert.ok(compile({ tier: "nano", profile: "chat" }).startsWith("TARGET: assistant\n\n"));
  assert.ok(compile({ tier: "nano", profile: "browser" }).startsWith("TARGET: browser agent\n\n"));
  assert.ok(compile({ tier: "nano", profile: "cli" }).startsWith("TARGET: CLI agent\n\n"));
  assert.equal(compile({ tier: "nano", profile: "generic" }).startsWith("TARGET:"), false);
  assert.equal(compile({ tier: "nano" }).trim(), compile({ tier: "nano" }));
});

test("nano is kernel plus phrase ban only", () => {
  const out = compile({ tier: "nano" });
  assert.match(out, /PHRASE BAN —/);
  assert.doesNotMatch(out, /ADDITIVE —/);
  assert.doesNotMatch(out, /LOOP —/);
  assert.doesNotMatch(out, /DONE CHECK —/);
});

test("compileWith does not touch the filesystem mapping", () => {
  const map = {
    kernel: "THINK-RULE CORE\nOnly.",
    phraseban: "PHRASE BAN — off.",
  };
  const out = compileWith(map, { tier: "nano" });
  assert.equal(out, "THINK-RULE CORE\nOnly.\n\nPHRASE BAN — off.");
});

test("resolveInside stays inside the root", () => {
  const inside = resolveInside(ROOT, "payloads/kernel.txt");
  assert.ok(inside.startsWith(ROOT + path.sep));
  assert.throws(() => resolveInside(ROOT, "../etc/passwd"));
  assert.throws(() => resolveInside(ROOT, "payloads/../../etc/passwd"));
});
