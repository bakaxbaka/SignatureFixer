export const curveOrders: Record<string, bigint> = {
  secp256k1: BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
  secp521r1: BigInt(
    "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  ),
};

export function getCurveOrder(curve: string): bigint {
  return curveOrders[curve] || curveOrders.secp256k1;
}
