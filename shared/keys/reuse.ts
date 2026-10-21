/**
 * shared/keys/reuse.ts — Wave 1 flagship algebra attack (§8, kill order #2).
 * Runtime: inproc. Nonce reuse: same k on two messages ⇒
 *   k = (z1 - z2) / (s1 - s2) mod n ; d = (k*s1 - z1)/r mod n
 * R7: s may be low-S normalized ⇒ effective nonce is -k ⇒ brute-force the sign.
 * Never emits a key directly — candidates go through evidenceGate (§9).
 */
import { CURVE } from "./secp256k1";
import { invMod, mod } from "./secp256k1";

export interface SigPairRec {
  record_id: string;
  r: bigint;
  s: bigint;
  z: bigint;
}

/** Recover candidate private keys from two signatures sharing nonce r. */
export function reuseCandidates(a: SigPairRec, b: SigPairRec): bigint[] {
  if (a.r !== b.r) return []; // no reuse — nothing to do
  const n = CURVE.n;
  const dz = mod(a.z - b.z, n);
  const out: bigint[] = [];
  for (const sb of [b.s, mod(-b.s, n)]) {
    const ds = mod(a.s - sb, n);
    if (ds === 0n) continue;
    const k = mod(dz * invMod(ds, n), n);
    for (const sa of [a.s, mod(-a.s, n)]) {
      const d = mod((k * sa - a.z) * invMod(a.r, n), n);
      if (d >= 1n && d < n && !out.includes(d)) out.push(d);
    }
  }
  return out;
}

/** Scan a group's records for duplicate r values and yield all reuse pairs. */
export function findReusePairs(records: SigPairRec[]): Array<[SigPairRec, SigPairRec]> {
  const byR = new Map<string, SigPairRec[]>();
  for (const rec of records) {
    const key = rec.r.toString(16);
    const list = byR.get(key);
    if (list) list.push(rec);
    else byR.set(key, [rec]);
  }
  const pairs: Array<[SigPairRec, SigPairRec]> = [];
  for (const list of byR.values()) {
    for (let i = 0; i < list.length; i++) {
      for (let j = i + 1; j < list.length; j++) {
        if (list[i].z !== list[j].z) pairs.push([list[i], list[j]]);
      }
    }
  }
  return pairs;
}
