/**
 * shared/keys/recover.ts — S4/S5:
 *  - recover_pubkey(r, s, z, recid): up to 2 candidates per recid, 4 recids total.
 *    Ethereum-style signatures carry no pubkey; never assume you have Q (R8).
 *  - verify(d, Q): d·G == Q — the only accepted proof of correctness (S5),
 *    computed with pure-BigInt math so it is independent of elliptic/bitcoinjs/noble.
 */
import {
  CURVE,
  G,
  bigToHex32,
  invMod,
  mod,
  parsePubkey,
  pointAdd,
  pointMul,
  sqrtMod,
  type Point,
} from "./secp256k1";

export interface SigRecord {
  r: string; // hex or decimal
  s: string;
  z: string; // message digest as scalar, hex or decimal
  recid?: number;
  pubkey?: string;
}

function toScalar(v: string | bigint): bigint {
  if (typeof v === "bigint") return v;
  const t = v.trim();
  return t.startsWith("0x") || /^[0-9a-fA-F]+$/.test(t) && t.length > 8
    ? BigInt("0x" + t.replace(/^0x/, ""))
    : BigInt(t);
}

/** True if (x, y) reconstructed from r and recid parity lies on the curve. */
function pointFromX(x: bigint, oddY: boolean): Point {
  if (x >= CURVE.p) return null;
  const y2 = mod(x * x % CURVE.p * x + CURVE.b, CURVE.p);
  const y0 = sqrtMod(y2);
  if (y0 === null) return null;
  let y = y0;
  if (((y & 1n) === 1n) !== oddY) y = CURVE.p - y;
  return { x, y };
}

/**
 * S4: recover candidate R points and public keys from (r, s, z).
 * For each recid in 0..3: R = (r + j·n) with parity from bit(recid), then
 * Q = r⁻¹(s·R − z·G). Returns every valid distinct candidate ("up to 2, try both").
 */
export function recoverCandidates(rIn: string | bigint, sIn: string | bigint, zIn: string | bigint): string[] {
  const r = toScalar(rIn), s = toScalar(sIn), z = toScalar(zIn);
  if (r <= 0n || r >= CURVE.n || s <= 0n || s >= CURVE.n) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (let recid = 0; recid < 4; recid++) {
    const j = recid >= 2 ? 1n : 0n;
    const x = r + j * CURVE.n;
    if (x >= CURVE.p) continue;
    const oddY = (recid & 1) === 1;
    const R = pointFromX(x, oddY);
    if (!R) continue;
    const rInv = invMod(r, CURVE.n);
    const sR = pointMul(s, R);
    const zG = pointMul(z, G);
    const Q = pointMul(rInv, pointAdd(sR, zG === null ? null : { x: zG.x, y: CURVE.p - zG.y }));
    if (!Q) continue;
    const hex = bigToHex32(Q.x) + bigToHex32(Q.y);
    if (!seen.has(hex)) {
      seen.add(hex);
      out.push("04" + hex);
    }
  }
  return out;
}

/** Convenience: single candidate for a declared recid, or null. */
export function recoverPubkey(r: string | bigint, s: string | bigint, z: string | bigint, recid: number): string | null {
  const all = recoverCandidates(r, s, z);
  // candidates come out ordered by recid group; map recid→parity/x-order deterministically
  const cands = recoverCandidatesWithRecid(r, s, z);
  return cands.find((c) => c.recid === recid)?.pubkey ?? all[0] ?? null;
}

export function recoverCandidatesWithRecid(rIn: string | bigint, sIn: string | bigint, zIn: string | bigint): { recid: number; pubkey: string }[] {
  const r = toScalar(rIn), s = toScalar(sIn), z = toScalar(zIn);
  const out: { recid: number; pubkey: string }[] = [];
  if (r <= 0n || r >= CURVE.n || s <= 0n || s >= CURVE.n) return out;
  for (let recid = 0; recid < 4; recid++) {
    const j = recid >= 2 ? 1n : 0n;
    const x = r + j * CURVE.n;
    if (x >= CURVE.p) continue;
    const R = pointFromX(x, (recid & 1) === 1);
    if (!R) continue;
    const rInv = invMod(r, CURVE.n);
    const sR = pointMul(s, R);
    const zG = pointMul(z, G);
    const negZG: Point = zG === null ? null : { x: zG.x, y: CURVE.p - zG.y };
    const Q = pointMul(rInv, pointAdd(sR, negZG));
    if (!Q) continue;
    out.push({ recid, pubkey: "04" + bigToHex32(Q.x) + bigToHex32(Q.y) });
  }
  return out;
}

/**
 * S5: verify(d, Q) → d·G == Q. Accepts compressed/uncompressed Q hex or bigint privkey.
 * This is the gate's first condition (§9 D_TIMES_G check) — implemented here with
 * our own field math so it cross-checks elliptic/bitcoinjs-derived candidates.
 */
export function verifyDgEqualsQ(dHex: string | bigint, qHex: string): boolean {
  try {
    const d = typeof dHex === "bigint" ? dHex : BigInt("0x" + dHex.trim());
    if (d < 1n || d >= CURVE.n) return false;
    const Q = parsePubkey(qHex);
    if (!Q) return false;
    const calc = pointMul(d, G);
    if (!calc) return false;
    // compare in both forms: Q may be given compressed or uncompressed
    const calcComp = ((calc.y & 1n) === 1n ? "03" : "02") + bigToHex32(calc.x);
    const calcUnc = "04" + bigToHex32(calc.x) + bigToHex32(calc.y);
    const norm = qHex.trim().toLowerCase();
    return norm === calcComp || norm === calcUnc || norm === calcComp.slice(2) || norm === bigToHex32(calc.x);
  } catch {
    return false;
  }
}

/** Low-S check (R7): if s > n/2 the signature was normalized and the nonce is −k. */
export function isHighS(s: string | bigint): boolean {
  const v = toScalar(s);
  return v > CURVE.n / 2n;
}
