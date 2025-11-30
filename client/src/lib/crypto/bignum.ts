/**
 * BigInt utilities for cryptographic operations
 * Ported from Willem Hengeveld's bitcoinexplainer
 * https://github.com/nlitsme/bitcoinexplainer
 */

export function numzero(x: number | bigint): number | bigint {
  if (typeof x === 'number') return 0;
  if (typeof x === 'bigint') return 0n;
  throw new Error('unsupported number type');
}

export function numone(x: number | bigint): number | bigint {
  if (typeof x === 'number') return 1;
  if (typeof x === 'bigint') return 1n;
  throw new Error('unsupported number type');
}

export function numshr(x: bigint): [bigint, bigint] {
  return [x & 1n, x >> 1n];
}

export function numiszero(x: bigint): boolean {
  return x === 0n;
}

export function numequals(a: bigint, b: bigint): boolean {
  return a === b;
}

export function cvnum(a: number | bigint, b: bigint): bigint {
  if (typeof a === 'bigint') return a;
  return BigInt(a);
}

export function GCD(a: bigint, b: bigint): [bigint, bigint, bigint] {
  let [prevx, x] = [1n, 0n];
  let [prevy, y] = [0n, 1n];
  while (b !== 0n) {
    const r = a % b;
    const q = (a - r) / b;
    [x, prevx] = [prevx - q * x, x];
    [y, prevy] = [prevy - q * y, y];
    [a, b] = [b, r];
  }
  return [a, prevx, prevy];
}

export function gcd(a: bigint, b: bigint): bigint {
  const [g] = GCD(a, b);
  return g;
}

export function lcm(a: bigint, b: bigint): bigint {
  return (a * b) / gcd(a, b);
}

export function modinv(x: bigint, m: bigint): bigint {
  const [, a] = GCD(x, m);
  if (a < 0n) return a + m;
  return a;
}

export function modexp(a: bigint, b: bigint, m: bigint): bigint {
  a = ((a % m) + m) % m;
  
  if (b < 0n) {
    return modexp(modinv(a, m), -b, m);
  }

  let r = 1n;
  while (b > 0n) {
    const [bit, newB] = numshr(b);
    b = newB;
    if (bit) {
      r = (r * a) % m;
    }
    a = (a * a) % m;
  }
  return r % m;
}

export function modSub(a: bigint, b: bigint, n: bigint): bigint {
  return ((a - b) % n + n) % n;
}

export function modAdd(a: bigint, b: bigint, n: bigint): bigint {
  return ((a + b) % n + n) % n;
}

export function modMul(a: bigint, b: bigint, n: bigint): bigint {
  return ((a * b) % n + n) % n;
}

export function modDiv(a: bigint, b: bigint, n: bigint): bigint {
  return modMul(a, modinv(b, n), n);
}
