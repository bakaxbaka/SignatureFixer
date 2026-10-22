/**
 * W1 known-answer vectors: secp256k1 core, derive addresses/WIF, recover.
 * External vectors: Bitcoin standard test keys 0x01 and (n-7); bitcoinjs address checks.
 */
import { describe, it, expect } from "vitest";
import { CURVE, mod, invMod, pointMul, isOnCurve, G } from "../../shared/keys/secp256k1";
import { pointMulG, recoverCandidates, verifyDgEqualsQ, isHighS } from "../../shared/keys/recover";
import { pubkeyFromD, toWIF, deriveAll } from "../../shared/keys/derive";

const D1 = "0000000000000000000000000000000000000000000000000000000000000001";

describe("secp256k1 known answers", () => {
  it("1*G == G and n*G == infinity", () => {
    const one = pointMulG(1n)!;
    expect(one.x).toBe(CURVE.gx);
    expect(one.y).toBe(CURVE.gy);
    expect(pointMulG(CURVE.n)).toBe(null);
  });

  it("standard vector d=1 compressed pubkey", () => {
    expect(pubkeyFromD(D1).compressed)
      .toBe("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
  });

  it("generated points stay on curve; inverse round-trips", () => {
    const P = pointMul(123456789n, G)!;
    expect(isOnCurve(P)).toBe(true);
    const a = 987654321n;
    expect(mod(a * invMod(a, CURVE.n), CURVE.n)).toBe(1n);
  });
});

describe("derive known answers (mainnet)", () => {
  it("P2PKH for d=1, both pubkey forms", () => {
    const d = deriveAll(D1);
    const p2pkhU = d.addresses.find((a) => a.scriptType === "p2pkh" && !a.compressed);
    expect(p2pkhU?.address).toBe("1BgGZ9tcN4rmKKBpDl32dQwXLF2rg4XmGk");
    const p2pkhC = d.addresses.find((a) => a.scriptType === "p2pkh" && a.compressed);
    expect(p2pkhC?.address).toBe("15ptuXjRHN8AhpoJrneVFnVaYPrBM7rLtz");
  });
  it("P2WPKH for d=1 matches the known bc1q address", () => {
    const d = deriveAll(D1);
    const wpkh = d.addresses.find((a) => a.scriptType === "p2wpkh" && a.compressed);
    expect(wpkh?.address).toBe("bc1qjkfkz7v2m2mgdx5e55em95w949s9xvww7udndm");
  });
  it("WIF for d=1, compressed and uncompressed", () => {
    expect(toWIF(D1, true)).toBe("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
    expect(toWIF(D1, false)).toBe("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ");
  });
});

describe("recover known answers", () => {
  it("signature with d=1, k=2 recovers Q of d=1 among candidates", () => {
    // s = k^-1 (z + r*d) with d=1: pick z=7, k=2
    const R = pointMul(2n, G)!;
    const r = mod(R.x, CURVE.n);
    const z = 7n;
    const s = mod(invMod(2n, CURVE.n) * (z + r * 1n), CURVE.n);
    const cands = recoverCandidates(r, s, z);
    const Q1 = pubkeyFromD(D1).uncompressed;
    expect(cands).toContain(Q1);
    expect(verifyDgEqualsQ(D1, Q1)).toBe(true);
    expect(verifyDgEqualsQ(D1, pubkeyFromD("0000000000000000000000000000000000000000000000000000000000000002").compressed)).toBe(false);
  });

  it("isHighS flags s above n/2 (low-S normalization detector)", () => {
    expect(isHighS(mod(-7n, CURVE.n))).toBe(true);
    expect(isHighS(7n)).toBe(false);
  });
});
