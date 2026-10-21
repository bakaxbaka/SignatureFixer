/**
 * shared/keys/secp256k1.ts — pure-BigInt secp256k1 field/group math.
 * Runtime: inproc (R2). No external deps; used by derive/verify/recover.
 */

export const CURVE = {
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  n: 0xffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  a: 0n,
  b: 7n,
  gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
} as const;

export type Point = { x: bigint; y: bigint } | null; // null = point at infinity

export function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

export function invMod(a: bigint, m: bigint): bigint {
  a = mod(a, m);
  if (a === 0n) throw new Error("invMod: zero has no inverse");
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return mod(old_s, m);
}

export function powMod(base: bigint, exp: bigint, m: bigint): bigint {
  base = mod(base, m);
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % m;
    base = (base * base) % m;
    exp >>= 1n;
  }
  return result;
}

// p ≡ 3 (mod 4), so sqrt is a simple exponentiation.
export function sqrtMod(a: bigint, p: bigint = CURVE.p): bigint | null {
  const r = powMod(a, (p + 1n) / 4n, p);
  if ((r * r) % p === mod(a, p)) return r;
  return null;
}

export const G: Point = { x: CURVE.gx, y: CURVE.gy };

export function pointAdd(p1: Point, p2: Point): Point {
  if (p1 === null) return p2;
  if (p2 === null) return p1;
  const p = CURVE.p;
  if (p1.x === p2.x) {
    if (mod(p1.y + p2.y, p) === 0n) return null; // P + (-P)
    const lam = mod(3n * p1.x * p1.x * invMod(2n * p1.y, p), p);
    const x = mod(lam * lam - 2n * p1.x, p);
    const y = mod(lam * (p1.x - x) - p1.y, p);
    return { x, y };
  }
  const lam = mod((p2.y - p1.y) * invMod(p2.x - p1.x, p), p);
  const x = mod(lam * lam - p1.x - p2.x, p);
  const y = mod(lam * (p1.x - x) - p1.y, p);
  return { x, y };
}

export function pointMul(k: bigint, pt: Point): Point {
  k = mod(k, CURVE.n);
  let result: Point = null;
  let addend = pt;
  while (k > 0n) {
    if (k & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    k >>= 1n;
  }
  return result;
}

export function isOnCurve(pt: Point): boolean {
  if (pt === null) return false;
  const { p, a, b } = CURVE;
  return mod(pt.y * pt.y - (powMod(pt.x, 3n, p) + a * pt.x + b), p) === 0n;
}

export function isValidPrivateKey(dHex: string | bigint): boolean {
  const d = typeof dHex === "bigint" ? dHex : BigInt("0x" + dHex.trim());
  return d >= 1n && d < CURVE.n;
}

/** Decompress a 33-byte SEC1 compressed pubkey hex to a curve point (or null if invalid). */
export function decompressPoint(pubkeyHex: string): Point {
  const h = pubkeyHex.trim();
  const prefix = h.slice(0, 2);
  const x = BigInt("0x" + h.slice(2));
  if (x >= CURVE.p) return null;
  const y2 = mod(powMod(x, 3n, CURVE.p) + CURVE.b, CURVE.p);
  const y0 = sqrtMod(y2);
  if (y0 === null) return null;
  const wantOdd = prefix === "03";
  let y = (y0 & 1n) === 1n !== wantOdd ? CURVE.p - y0 : y0;
  const pt: Point = { x, y };
  return isOnCurve(pt) ? pt : null;
}

/** Parse an uncompressed (04…) or compressed (02/03…) pubkey hex into a point. */
export function parsePubkey(pubkeyHex: string): Point {
  const h = pubkeyHex.trim();
  if (h.length === 66 && (h.startsWith("02") || h.startsWith("03"))) {
    return decompressPoint(h);
  }
  if (h.length === 130 && h.startsWith("04")) {
    const x = BigInt("0x" + h.slice(2, 66));
    const y = BigInt("0x" + h.slice(66, 130));
    const pt: Point = { x, y };
    return isOnCurve(pt) ? pt : null;
  }
  return null;
}

export function bigToHex32(v: bigint): string {
  return v.toString(16).padStart(64, "0");
}
