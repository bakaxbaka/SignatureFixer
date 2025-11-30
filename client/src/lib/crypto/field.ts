/**
 * Galois Field arithmetic for elliptic curve operations
 * Ported from Willem Hengeveld's bitcoinexplainer
 */

import { modinv, modexp, numshr, numiszero, cvnum } from './bignum';

export class Value {
  field: GaloisField;
  num: bigint;

  constructor(field: GaloisField, num: bigint) {
    this.field = field;
    this.num = num;
  }

  add(rhs: Value | bigint): Value {
    return this.field.add(this, rhs);
  }

  double(): Value {
    return this.field.add(this, this);
  }

  thrice(): Value {
    return this.field.add(this.double(), this);
  }

  sub(rhs: Value | bigint): Value {
    return this.field.sub(this, rhs);
  }

  mul(rhs: Value | bigint): Value {
    return this.field.mul(this, rhs);
  }

  square(): Value {
    return this.field.mul(this, this);
  }

  cube(): Value {
    return this.field.mul(this.square(), this);
  }

  div(rhs: Value | bigint): Value {
    return this.field.div(this, rhs);
  }

  pow(rhs: bigint): Value {
    return this.field.pow(this, rhs);
  }

  sqrt(n: number = 0): Value | undefined {
    return this.field.sqrt(this, n);
  }

  neg(): Value {
    return this.field.neg(this);
  }

  inverse(): Value {
    return this.field.inverse(this);
  }

  iszero(): boolean {
    return this.field.iszero(this);
  }

  equals(rhs: Value | bigint): boolean {
    return this.field.equals(this, rhs);
  }

  shr(): [bigint, Value] {
    return this.field.shr(this);
  }

  int(): bigint {
    return this.num;
  }

  uint(): bigint {
    return this.num < 0n ? this.num + this.field.p : this.num;
  }

  toString(): string {
    return `${this.field.fieldtag || 'FIELD'}:0x${this.num.toString(16)}`;
  }
}

export class GaloisField {
  p: bigint;
  fieldtag?: string;

  constructor(p: bigint) {
    this.p = p;
  }

  toString(): string {
    if (this.fieldtag) {
      return this.fieldtag;
    }
    return `FIELD(0x${this.p.toString(16)})`;
  }

  value(x: bigint | Value | number): Value {
    if (x instanceof Value) {
      return new Value(this, x.uint() % this.p);
    }
    const val = typeof x === 'number' ? BigInt(x) : x;
    return new Value(this, ((val % this.p) + this.p) % this.p);
  }

  private getNum(x: Value | bigint): bigint {
    if (x instanceof Value) {
      return x.uint();
    }
    return x;
  }

  add(lhs: Value, rhs: Value | bigint): Value {
    return this.value(this.getNum(lhs) + this.getNum(rhs));
  }

  sub(lhs: Value, rhs: Value | bigint): Value {
    return this.value(this.getNum(lhs) - this.getNum(rhs));
  }

  neg(a: Value): Value {
    return this.value(-this.getNum(a));
  }

  mul(lhs: Value, rhs: Value | bigint): Value {
    return this.value(this.getNum(lhs) * this.getNum(rhs));
  }

  inverse(a: Value): Value {
    return this.value(modinv(this.getNum(a), this.p));
  }

  div(lhs: Value, rhs: Value | bigint): Value {
    const rhsVal = rhs instanceof Value ? rhs : this.value(rhs);
    return this.mul(lhs, rhsVal.inverse());
  }

  pow(lhs: Value, rhs: bigint): Value {
    return this.value(modexp(this.getNum(lhs), rhs, this.p));
  }

  legendre(a: Value): number {
    const [, exp] = numshr(this.p - 1n);
    const ls = a.pow(exp);
    return ls.equals(this.value(-1n)) ? -1 : 1;
  }

  sqrt(a: Value, n: number = 0): Value | undefined {
    if (a.iszero()) return a;
    if (this.p === 2n) return a;
    if (this.legendre(a) !== 1) return undefined;

    const sw = Number(this.p % 4n);
    if (sw === 3) {
      let [, exp] = numshr(this.p + 1n);
      [, exp] = numshr(exp);
      const res = a.pow(exp);
      const [bit] = numshr(res.uint());
      return Number(bit) === n ? res : res.neg();
    }

    let s = this.p - 1n;
    let e = 0;
    while (true) {
      const [bit, res] = numshr(s);
      if (bit) break;
      s = res;
      e++;
    }

    let k = this.value(2n);
    while (this.legendre(k) !== -1) {
      k = k.add(1n);
    }

    const [, ss] = numshr(s + 1n);
    let x = a.pow(ss);
    let b = a.pow(s);
    let g = k.pow(s);
    let r = e;

    while (true) {
      let t = b;
      let m = 0;
      while (m < r) {
        if (t.equals(1n)) break;
        t = t.square();
        m++;
      }
      if (m === 0) {
        const [bit] = numshr(x.uint());
        return Number(bit) === n ? x : x.neg();
      }
      if (m === r) m = r - 1;

      const gs = g.pow(BigInt(2 ** (r - m - 1)));
      g = gs.square();
      x = x.mul(gs);
      b = b.mul(g);
      r = m;
    }
  }

  zero(): bigint {
    return 0n;
  }

  iszero(x: Value): boolean {
    return this.getNum(x) === 0n;
  }

  equals(lhs: Value, rhs: Value | bigint): boolean {
    const rhsVal = rhs instanceof Value ? rhs : this.value(rhs);
    return lhs.sub(rhsVal).iszero();
  }

  shr(x: Value): [bigint, Value] {
    const [bit, res] = numshr(this.getNum(x));
    return [bit, this.value(res)];
  }

  equalsfield(f: GaloisField): boolean {
    return this.p === f.p;
  }
}
