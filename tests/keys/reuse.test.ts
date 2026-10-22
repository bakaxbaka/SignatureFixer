/**
 * reuse.ts known-answer + negative control (R10). Synthetic pair: same k, same d.
 */
import { describe, it, expect } from "vitest";
import { reuseCandidates, findReusePairs } from "../../shared/keys/reuse";
import { CURVE, mod, invMod, pointMul } from "../../shared/keys/secp256k1";
import { G, pointMulG, bigToHex32 } from "../../shared/keys/recover";
import { pubkeyFromD } from "../../shared/keys/derive";

const n = CURVE.n;

function sign(d: bigint, k: bigint, z: bigint) {
  const R = pointMul(k, G)!;
  const r = mod(R.x, n);
  const s = mod(invMod(k, n) * (z + r * d), n);
  return { r, s };
}

describe("reuse attack (positive fixture)", () => {
  it("recovers d from two signatures with the same nonce", () => {
    const d = 0xdeadbeefn;
    const k = 0x1337n;
    const a = sign(d, k, 0xaaaa1111n);
    const b = sign(d, k, 0xbbbb2222n);
    const cands = reuseCandidates(
      { record_id: "r1", r: a.r, s: a.s, z: 0xaaaa1111n },
      { record_id: "r2", r: b.r, s: b.s, z: 0xbbbb2222n },
    );
    expect(cands).toContain(d);
    // every candidate must satisfy d·G == Q for one of the group's pubkeys
    const Q = pubkeyFromD(d).compressed;
    const ok = cands.some((c) => {
      const p = pointMulG(c);
      return p && ((p.y & 1n) === 1n ? "03" : "02") + bigToHex32(p.x) === Q;
    });
    expect(ok).toBe(true);
  });

  it("low-S normalized second signature still recovers (nonce is -k, R7)", () => {
    const d = 4242n;
    const k = 999n;
    const a = sign(d, k, 11n);
    let b = sign(d, k, 22n);
    if (b.s > n / 2n) b = { r: b.r, s: mod(-b.s, n) }; // BIP66 normalize
    const cands = reuseCandidates(
      { record_id: "r1", r: a.r, s: a.s, z: 11n },
      { record_id: "r2", r: b.r, s: b.s, z: 22n },
    );
    expect(cands.map((c) => mod(c, n))).toContain(mod(d, n));
  });
});

describe("reuse attack (negative controls)", () => {
  it("different nonces yield no candidates", () => {
    const d = 7n;
    const a = sign(d, 100n, 11n);
    const b = sign(d, 101n, 22n);
    expect(reuseCandidates(
      { record_id: "r1", r: a.r, s: a.s, z: 11n },
      { record_id: "r2", r: b.r, s: b.s, z: 22n },
    )).toEqual([]);
  });

  it("same r across DIFFERENT pubkeys is not paired (W1.5a grouping fix)", () => {
    const recA = { record_id: "r1", r: 5n, s: 6n, z: 1n, pubkey: pubkeyFromD(1n).compressed };
    const recB = { record_id: "r2", r: 5n, s: 7n, z: 2n, pubkey: pubkeyFromD(2n).compressed };
    expect(findReusePairs([recA, recB])).toEqual([]);
  });

  it("same r AND same pubkey AND different z IS paired", () => {
    const q = pubkeyFromD(1n).compressed;
    const recA = { record_id: "r1", r: 5n, s: 6n, z: 1n, pubkey: q };
    const recB = { record_id: "r2", r: 5n, s: 7n, z: 2n, pubkey: q };
    expect(findReusePairs([recA, recB]).length).toBe(1);
  });

  it("identical z is not reuse of two messages", () => {
    const q = pubkeyFromD(1n).compressed;
    const recA = { record_id: "r1", r: 5n, s: 6n, z: 9n, pubkey: q };
    const recB = { record_id: "r2", r: 5n, s: 7n, z: 9n, pubkey: q };
    expect(findReusePairs([recA, recB])).toEqual([]);
  });
});
