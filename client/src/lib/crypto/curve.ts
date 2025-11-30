/**
 * Elliptic Curve operations (Weierstrass form: y^2 = x^3 + ax + b)
 * Ported from Willem Hengeveld's bitcoinexplainer
 */

import { GaloisField, Value } from './field';
import { numiszero, numshr } from './bignum';

export class Point {
  curve: EllipticCurve;
  x: Value | undefined;
  y: Value | undefined;

  constructor(curve: EllipticCurve, x?: Value, y?: Value) {
    this.curve = curve;
    this.x = x;
    this.y = y;
  }

  add(rhs: Point): Point {
    return this.curve.add(this, rhs);
  }

  double(): Point {
    return this.curve.add(this, this);
  }

  sub(rhs: Point): Point {
    return this.curve.sub(this, rhs);
  }

  mul(rhs: bigint | Value): Point {
    return this.curve.mul(this, rhs);
  }

  div(rhs: Value): Point {
    return this.curve.div(this, rhs);
  }

  neg(): Point {
    return this.curve.neg(this);
  }

  isinf(): boolean {
    return this.x === undefined;
  }

  equals(rhs: Point): boolean {
    return this.curve.equals(this, rhs);
  }

  isoncurve(): boolean {
    return this.curve.isoncurve(this);
  }

  toString(): string {
    if (this.isinf()) return 'Point(infinity)';
    return `Point(${this.x?.toString()}, ${this.y?.toString()})`;
  }

  toHex(): { x: string; y: string } | null {
    if (this.isinf()) return null;
    return {
      x: this.x!.uint().toString(16).padStart(64, '0'),
      y: this.y!.uint().toString(16).padStart(64, '0'),
    };
  }

  toCompressed(): string {
    if (this.isinf()) return '';
    const prefix = this.y!.uint() % 2n === 0n ? '02' : '03';
    return prefix + this.x!.uint().toString(16).padStart(64, '0');
  }

  toUncompressed(): string {
    if (this.isinf()) return '';
    return (
      '04' +
      this.x!.uint().toString(16).padStart(64, '0') +
      this.y!.uint().toString(16).padStart(64, '0')
    );
  }
}

export class EllipticCurve {
  field: GaloisField;
  a: bigint;
  b: bigint;
  order?: GaloisField;

  constructor(field: GaloisField, a: bigint, b: bigint) {
    this.field = field;
    this.a = a;
    this.b = b;
  }

  point(x?: bigint | Value, y?: bigint | Value): Point {
    if (x instanceof Point) return x;
    if (x === undefined) return new Point(this, undefined, undefined);
    const xVal = x instanceof Value ? x : this.coord(x);
    const yVal = y instanceof Value ? y : this.coord(y as bigint);
    return new Point(this, xVal, yVal);
  }

  decompress(x: Value, flag: number): Point {
    const y2 = x.cube().add(x.mul(this.a)).add(this.b);
    const y = y2.sqrt(flag);
    if (!y) throw new Error('no sqrt for x - point not on curve');
    return this.point(x, y);
  }

  coord(x: bigint): Value {
    return this.field.value(x);
  }

  add(lhs: Point, rhs: Point): Point {
    if (lhs.isinf()) return rhs;
    if (rhs.isinf()) return lhs;

    let l: Value;
    if (lhs.equals(rhs)) {
      if (lhs.y!.iszero()) return this.infinity();
      l = lhs.x!.square().thrice().add(this.a).div(lhs.y!.double());
    } else if (lhs.x!.equals(rhs.x!)) {
      return this.infinity();
    } else {
      l = lhs.y!.sub(rhs.y!).div(lhs.x!.sub(rhs.x!));
    }

    const x = l.square().sub(lhs.x!.add(rhs.x!));
    const y = l.mul(lhs.x!.sub(x)).sub(lhs.y!);

    return this.point(x, y);
  }

  sub(lhs: Point, rhs: Point): Point {
    return this.add(lhs, this.neg(rhs));
  }

  neg(p: Point): Point {
    if (p.isinf()) return p;
    return this.point(p.x!, p.y!.neg());
  }

  mul(lhs: Point, rhs: bigint | Value): Point {
    let accu = this.infinity();
    let shifter = lhs;
    let scalar = rhs instanceof Value ? rhs.uint() : rhs;

    while (!numiszero(scalar)) {
      const [bit, newScalar] = numshr(scalar);
      scalar = newScalar;
      if (bit) {
        accu = accu.add(shifter);
      }
      shifter = shifter.add(shifter);
    }

    return accu;
  }

  equals(lhs: Point, rhs: Point): boolean {
    if (lhs.isinf() && rhs.isinf()) return true;
    if (lhs.isinf() || rhs.isinf()) return false;
    return lhs.x!.equals(rhs.x!) && lhs.y!.equals(rhs.y!);
  }

  div(lhs: Point, rhs: Value): Point {
    return this.mul(lhs, rhs.inverse());
  }

  infinity(): Point {
    return this.point(undefined, undefined);
  }

  isoncurve(p: Point): boolean {
    if (p.isinf()) return true;
    const left = p.y!.square();
    const right = p.x!.cube().add(p.x!.mul(this.a)).add(this.b);
    return left.equals(right);
  }
}
