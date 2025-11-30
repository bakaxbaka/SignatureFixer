/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA)
 * Ported from Willem Hengeveld's bitcoinexplainer
 * 
 * Functions:
 * - calcpub(x): Calculate public key from private key
 * - sign(m, x, k): Sign message with private key and signing secret
 * - verify(m, Y, r, s): Verify signature
 * - crack2(r, m1, m2, s1, s2): Recover private key from nonce reuse
 * - crack1r(k, m, r, s): Recover private key from known nonce
 * - crack1(k, m, s): Recover private key from known nonce (calculates r)
 * - findk(m, x, r, s): Calculate nonce from known private key
 * - findpk(m, r, s, flag): Recover public key from signature
 */

import { EllipticCurve, Point } from './curve';
import { Value } from './field';

export interface SignatureResult {
  r: Value;
  s: Value;
}

export interface CrackResult {
  k: Value;
  x: Value;
}

export class ECDSA {
  ec: EllipticCurve;
  G: Point;

  constructor(ec: EllipticCurve, G: Point) {
    this.ec = ec;
    this.G = G;
  }

  scalar(x: bigint | Value): Value {
    if (!this.ec.order) throw new Error('Curve order not set');
    return this.ec.order.value(x);
  }

  calcpub(x: bigint | Value): Point {
    return this.G.mul(x);
  }

  sign(m: Value, x: Value, k: Value): SignatureResult {
    const R = this.G.mul(k);
    const s = m.add(x.mul(this.scalar(R.x!.uint()))).div(k);
    return { r: this.scalar(R.x!.uint()), s };
  }

  verify(m: Value, Y: Point, r: Value, s: Value): boolean {
    const R = this.G.mul(m).add(Y.mul(r)).div(s);
    if (R.isinf()) return false;
    return r.equals(this.scalar(R.x!.uint()));
  }

  crack2(r: Value, m1: Value, m2: Value, s1: Value, s2: Value): CrackResult {
    const k = m1.sub(m2).div(s1.sub(s2));
    const x1 = this.crack1r(k, m1, r, s1);
    const x2 = this.crack1r(k, m2, r, s2);
    
    if (!x1.equals(x2)) {
      console.warn('Warning: x1 != x2, using x1');
    }
    
    return { k, x: x1 };
  }

  crack1r(k: Value, m: Value, r: Value, s: Value): Value {
    return s.mul(k).sub(m).div(r);
  }

  crack1(k: Value, m: Value, s: Value): Value {
    const R = this.G.mul(k);
    return this.crack1r(k, m, this.scalar(R.x!.uint()), s);
  }

  findk(m: Value, x: Value, r: Value, s: Value): Value {
    return m.add(x.mul(r)).div(s);
  }

  findpk(m: Value, r: Value, s: Value, flag: number): Point {
    const R = this.ec.decompress(this.ec.coord(r.uint()), flag);
    return R.mul(s.div(r)).sub(this.G.mul(m.div(r)));
  }
}

export interface NonceReuseRecoveryInput {
  r: string;
  s1: string;
  s2: string;
  m1: string;
  m2: string;
}

export interface KnownNonceRecoveryInput {
  r: string;
  s: string;
  m: string;
  k: string;
}

export interface RecoveryResult {
  privateKey: string;
  nonce?: string;
  publicKeyX?: string;
  publicKeyY?: string;
  compressedPubKey?: string;
  success: boolean;
  error?: string;
}

export function recoverFromNonceReuse(
  ecdsa: ECDSA,
  input: NonceReuseRecoveryInput
): RecoveryResult {
  try {
    const r = ecdsa.scalar(BigInt('0x' + input.r.replace(/^0x/, '')));
    const s1 = ecdsa.scalar(BigInt('0x' + input.s1.replace(/^0x/, '')));
    const s2 = ecdsa.scalar(BigInt('0x' + input.s2.replace(/^0x/, '')));
    const m1 = ecdsa.scalar(BigInt('0x' + input.m1.replace(/^0x/, '')));
    const m2 = ecdsa.scalar(BigInt('0x' + input.m2.replace(/^0x/, '')));

    if (s1.equals(s2)) {
      return { success: false, error: 'S values are identical', privateKey: '' };
    }

    const { k, x } = ecdsa.crack2(r, m1, m2, s1, s2);
    const pubKey = ecdsa.calcpub(x);
    const coords = pubKey.toHex();

    return {
      success: true,
      privateKey: x.uint().toString(16).padStart(64, '0'),
      nonce: k.uint().toString(16).padStart(64, '0'),
      publicKeyX: coords?.x,
      publicKeyY: coords?.y,
      compressedPubKey: pubKey.toCompressed(),
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      privateKey: '',
    };
  }
}

export function recoverFromKnownNonce(
  ecdsa: ECDSA,
  input: KnownNonceRecoveryInput
): RecoveryResult {
  try {
    const r = ecdsa.scalar(BigInt('0x' + input.r.replace(/^0x/, '')));
    const s = ecdsa.scalar(BigInt('0x' + input.s.replace(/^0x/, '')));
    const m = ecdsa.scalar(BigInt('0x' + input.m.replace(/^0x/, '')));
    const k = ecdsa.scalar(BigInt('0x' + input.k.replace(/^0x/, '')));

    const x = ecdsa.crack1r(k, m, r, s);
    const pubKey = ecdsa.calcpub(x);
    const coords = pubKey.toHex();

    return {
      success: true,
      privateKey: x.uint().toString(16).padStart(64, '0'),
      nonce: k.uint().toString(16).padStart(64, '0'),
      publicKeyX: coords?.x,
      publicKeyY: coords?.y,
      compressedPubKey: pubKey.toCompressed(),
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      privateKey: '',
    };
  }
}

export function calculatePublicKey(ecdsa: ECDSA, privateKeyHex: string): {
  x: string;
  y: string;
  compressed: string;
  uncompressed: string;
  isValid: boolean;
} | null {
  try {
    const privateKey = BigInt('0x' + privateKeyHex.replace(/^0x/, ''));
    const pubKey = ecdsa.calcpub(privateKey);
    const coords = pubKey.toHex();

    if (!coords) return null;

    return {
      x: coords.x,
      y: coords.y,
      compressed: pubKey.toCompressed(),
      uncompressed: pubKey.toUncompressed(),
      isValid: pubKey.isoncurve(),
    };
  } catch {
    return null;
  }
}

export function signMessage(
  ecdsa: ECDSA,
  messageHashHex: string,
  privateKeyHex: string,
  nonceHex: string
): { r: string; s: string } | null {
  try {
    const m = ecdsa.scalar(BigInt('0x' + messageHashHex.replace(/^0x/, '')));
    const x = ecdsa.scalar(BigInt('0x' + privateKeyHex.replace(/^0x/, '')));
    const k = ecdsa.scalar(BigInt('0x' + nonceHex.replace(/^0x/, '')));

    const { r, s } = ecdsa.sign(m, x, k);

    return {
      r: r.uint().toString(16).padStart(64, '0'),
      s: s.uint().toString(16).padStart(64, '0'),
    };
  } catch {
    return null;
  }
}

export function verifySignature(
  ecdsa: ECDSA,
  messageHashHex: string,
  pubKeyXHex: string,
  pubKeyYHex: string,
  rHex: string,
  sHex: string
): boolean {
  try {
    const m = ecdsa.scalar(BigInt('0x' + messageHashHex.replace(/^0x/, '')));
    const r = ecdsa.scalar(BigInt('0x' + rHex.replace(/^0x/, '')));
    const s = ecdsa.scalar(BigInt('0x' + sHex.replace(/^0x/, '')));
    const Y = ecdsa.ec.point(
      BigInt('0x' + pubKeyXHex.replace(/^0x/, '')),
      BigInt('0x' + pubKeyYHex.replace(/^0x/, ''))
    );

    return ecdsa.verify(m, Y, r, s);
  } catch {
    return false;
  }
}

export function findSigningSecret(
  ecdsa: ECDSA,
  messageHashHex: string,
  privateKeyHex: string,
  rHex: string,
  sHex: string
): string | null {
  try {
    const m = ecdsa.scalar(BigInt('0x' + messageHashHex.replace(/^0x/, '')));
    const x = ecdsa.scalar(BigInt('0x' + privateKeyHex.replace(/^0x/, '')));
    const r = ecdsa.scalar(BigInt('0x' + rHex.replace(/^0x/, '')));
    const s = ecdsa.scalar(BigInt('0x' + sHex.replace(/^0x/, '')));

    const k = ecdsa.findk(m, x, r, s);
    return k.uint().toString(16).padStart(64, '0');
  } catch {
    return null;
  }
}

export function recoverPublicKey(
  ecdsa: ECDSA,
  messageHashHex: string,
  rHex: string,
  sHex: string,
  flag: number = 0
): { x: string; y: string; compressed: string } | null {
  try {
    const m = ecdsa.scalar(BigInt('0x' + messageHashHex.replace(/^0x/, '')));
    const r = ecdsa.scalar(BigInt('0x' + rHex.replace(/^0x/, '')));
    const s = ecdsa.scalar(BigInt('0x' + sHex.replace(/^0x/, '')));

    const Y = ecdsa.findpk(m, r, s, flag);
    const coords = Y.toHex();

    if (!coords) return null;

    return {
      x: coords.x,
      y: coords.y,
      compressed: Y.toCompressed(),
    };
  } catch {
    return null;
  }
}

export function validatePoint(
  ecdsa: ECDSA,
  xHex: string,
  yHex: string
): boolean {
  try {
    const point = ecdsa.ec.point(
      BigInt('0x' + xHex.replace(/^0x/, '')),
      BigInt('0x' + yHex.replace(/^0x/, ''))
    );
    return point.isoncurve();
  } catch {
    return false;
  }
}
