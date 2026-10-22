import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";
import { chromium } from "playwright";
import { compile } from "../src/compile.js";
import { scan } from "../src/scan.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PAGE = path.join(ROOT, "index.html");
const SAMPLE = fs.readFileSync(path.join(ROOT, "tests", "fixtures", "hedge-heavy.txt"), "utf8");

test("index.html is offline, self-contained, and has no banned markup", () => {
  const html = fs.readFileSync(PAGE, "utf8");
  assert.equal(/<form[\s>]/i.test(html), false);
  assert.equal(/position\s*:\s*fixed/i.test(html), false);
  assert.equal(html.includes("http://"), false);
  assert.equal(html.includes("https://"), false);
  assert.equal(html.includes("thinkcore_state"), true);

  const payloadStart = html.indexOf("const PAYLOADS = ");
  const payloadEnd = html.indexOf(";\n  const RULES");
  const payloads = JSON.parse(html.slice(payloadStart + "const PAYLOADS = ".length, payloadEnd));
  for (const name of fs.readdirSync(path.join(ROOT, "payloads"))) {
    const id = name.replace(/\.txt$/, "");
    const body = fs.readFileSync(path.join(ROOT, "payloads", name), "utf8");
    assert.equal(payloads[id], body, name);
  }

  const sampleStart = html.indexOf("const SAMPLE = ");
  const sampleEnd = html.indexOf(";\n\n  const ORDER");
  const sample = JSON.parse(html.slice(sampleStart + "const SAMPLE = ".length, sampleEnd));
  assert.equal(sample, SAMPLE);
});

test("bench matches node compile and scan, copy confirms, state restores", async () => {
  const browser = await chromium.launch({
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
  const context = await browser.newContext({ offline: true });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (err) => errors.push(String(err)));
  page.on("console", (msg) => {
    if (msg.type() === "error") errors.push(msg.text());
  });
  const requests = [];
  page.on("request", (req) => requests.push(req.url()));

  await page.goto(pathToFileURL(PAGE).href, { waitUntil: "load" });
  await page.waitForFunction(() => document.getElementById("out")?.textContent?.includes("THINK-RULE CORE"));

  const net = requests.filter((url) => url.startsWith("http:") || url.startsWith("https:"));
  assert.deepEqual(net, []);
  assert.deepEqual(errors, []);

  for (const tier of ["nano", "core", "full"]) {
    for (const profile of ["generic", "coding", "chat", "browser", "cli"]) {
      const fromNode = compile({ tier, profile });
      const fromPage = await page.evaluate(
        ([t, p]) => window.__tc.compile({ tier: t, profile: p }),
        [tier, profile],
      );
      assert.equal(fromPage, fromNode, `${tier}/${profile}`);
    }
  }

  const scanned = await page.evaluate((text) => window.__tc.scan(text), SAMPLE);
  assert.equal(JSON.stringify(scanned), JSON.stringify(scan(SAMPLE)));

  await page.click("#tier-full");
  await page.click("#profile-generic");
  const shown = await page.locator("#out").innerText();
  assert.equal(shown, compile({ tier: "full", profile: "generic" }));
  const lines = shown.split("\n").length;
  assert.match(await page.locator("#count-lines").innerText(), new RegExp(`^${lines} lines$`));
  assert.match(await page.locator("#count-chars").innerText(), new RegExp(`^${shown.length} characters$`));
  assert.match(
    await page.locator("#count-tokens").innerText(),
    new RegExp(`^${Math.round(shown.length / 3.9)} tokens$`),
  );

  await page.click("#copy-btn");
  await page.waitForFunction(() => document.getElementById("copy-note")?.textContent === "Copied");

  await page.evaluate(() => {
    navigator.clipboard.writeText = () => Promise.reject(new Error("blocked"));
  });
  await page.click("#copy-btn");
  await page.waitForFunction(() => document.getElementById("copy-note")?.textContent === "Copied");

  await page.click("#tier-nano");
  await page.click("#profile-chat");
  await page.fill("#scan-text", "draft stays");
  await page.reload({ waitUntil: "load" });
  await page.waitForFunction(() => document.getElementById("out")?.textContent?.includes("THINK-RULE CORE"));
  assert.equal(await page.getAttribute("#tier-nano", "aria-pressed"), "true");
  assert.equal(await page.getAttribute("#profile-chat", "aria-pressed"), "true");
  assert.equal(await page.locator("#scan-text").inputValue(), "draft stays");
  assert.match(await page.locator("#out").innerText(), /TARGET: assistant/);
  assert.doesNotMatch(await page.locator("#out").innerText(), /LOOP —/);

  await page.evaluate(() => localStorage.removeItem("thinkcore_state"));
  await page.click("#tier-core");
  assert.equal(await page.locator("#preset").innerText(), "preset: core");
  assert.deepEqual(errors, []);

  await page.evaluate(() => {
    localStorage.setItem = () => {
      throw new Error("full");
    };
    localStorage.getItem = () => {
      throw new Error("full");
    };
  });
  await page.click("#mod-loop");
  assert.equal(await page.locator("#preset").innerText(), "preset: custom");

  const fresh = await context.newPage();
  const freshErrors = [];
  fresh.on("pageerror", (err) => freshErrors.push(String(err)));
  await fresh.addInitScript(() => {
    Storage.prototype.getItem = () => {
      throw new Error("blocked");
    };
  });
  await fresh.goto(pathToFileURL(PAGE).href, { waitUntil: "load" });
  await fresh.waitForFunction(() => document.getElementById("preset")?.textContent === "preset: full");
  assert.deepEqual(freshErrors, []);

  await browser.close();
});
