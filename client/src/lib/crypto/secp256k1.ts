/**
 * Bitcoin secp256k1 curve implementation
 * Ported from Willem Hengeveld's bitcoinexplainer
 */

import { GaloisField } from './field';
import { EllipticCurve } from './curve';
import { ECDSA } from './ecdsa';

export const SECP256K1_PARAMS = {
  p: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn,
  n: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n,
  a: 0n,
  b: 7n,
  Gx: 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,
  Gy: 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n,
};

export function createSecp256k1(): ECDSA {
  const field = new GaloisField(SECP256K1_PARAMS.p);
  field.fieldtag = 'coord';

  const curve = new EllipticCurve(field, SECP256K1_PARAMS.a, SECP256K1_PARAMS.b);
  const generator = curve.point(SECP256K1_PARAMS.Gx, SECP256K1_PARAMS.Gy);

  curve.order = new GaloisField(SECP256K1_PARAMS.n);
  curve.order.fieldtag = 'scalar';

  return new ECDSA(curve, generator);
}

export const bitcoin = createSecp256k1();

export function getSecp256k1Params(): {
  fieldOrder: string;
  curveOrder: string;
  generatorX: string;
  generatorY: string;
  a: string;
  b: string;
} {
  return {
    fieldOrder: SECP256K1_PARAMS.p.toString(16).toUpperCase(),
    curveOrder: SECP256K1_PARAMS.n.toString(16).toUpperCase(),
    generatorX: SECP256K1_PARAMS.Gx.toString(16).toUpperCase(),
    generatorY: SECP256K1_PARAMS.Gy.toString(16).toUpperCase(),
    a: SECP256K1_PARAMS.a.toString(16),
    b: SECP256K1_PARAMS.b.toString(16),
  };
}
