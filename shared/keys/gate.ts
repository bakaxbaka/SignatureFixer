/**
 * shared/keys/gate.ts — §9 evidence gate. The only path to a KEY_VERIFIED event.
 * Enforced once, nowhere else (R12). A lattice short vector is never a key;
 * it sits at CANDIDATE until all three checks pass.
 */
import { deriveAll, type Network } from "./derive";
import { pointToCompressed } from "./derive";
import { verifyDgEqualsQ, pointMulG } from "./recover";
import { CURVE, bigToHex32, parsePubkey } from "./secp256k1";

export type GateReject = "D_TIMES_G_MISMATCH" | "ADDRESS_MISMATCH" | "SECOND_IMPL_DISAGREE";

/**
 * W1.5c: default third check — @bitcoinerlab/secp256k1 via bitcoinjs-lib v7.
 * Independent of the pure-BigInt producer (secp256k1.ts): different codebase,
 * different field math (tiny-secp256k1 WASM). Binds gate condition 3 so no
 * caller can run the ladder with an unwired reverify.
 */
export async function defaultReverify(dHex: string, qHex: string): Promise<boolean> {
  try {
    const ecc = (await import("@bitcoinerlab/secp256k1")).default;
    const d = BigInt("0x" + dHex.trim());
    if (d < 1n || d >= CURVE.n) return false;
    const dBuf = Buffer.from(bigToHex32(d), "hex");
    if (!ecc.isPrivate(dBuf)) return false;
    // external library's view of d·G must equal our pure-BigInt view
    const extPub = ecc.pointFromScalar(dBuf, true);
    if (!extPub) return false;
    const Q = pointMulG(d);
    if (!Q) return false;
    const comp = ((Q.y & 1n) === 1n ? "03" : "02") + bigToHex32(Q.x);
    if (Buffer.from(extPub).toString("hex") !== comp) return false;
    // declared Q must be the point d actually controls
    const q = qHex.trim().toLowerCase();
    let declared: Buffer;
    if (q.length === 128) declared = Buffer.from("04" + q, "hex");
    else if (q.length === 130 || q.length === 66) declared = Buffer.from(q, "hex");
    else if (q.length === 64) declared = Buffer.from("04" + q, "hex");
    else return false; // malformed or empty Q — cannot verify against it
    const dparsed = parsePubkey(declared.toString("hex"));
    if (!dparsed) return false;
    const normComp = Buffer.from(pointToCompressed(dparsed), "hex");
    if (normComp.toString("hex") !== comp) return false;
    // and a live sign/verify round-trip under the declared pubkey
    const msg = Buffer.alloc(32, 7);
    const sig = ecc.sign(msg, dBuf);
    return ecc.verify(msg, new Uint8Array(normComp), new Uint8Array(sig));
  } catch {
    return false;
  }
}

export interface GateInput {
  dHex: string;
  /** the pubkey the signatures came from (compressed or uncompressed hex) */
  qHex: string;
  /** address the group's records were observed at (§3 W2 corpus) */
  expectedAddress?: string;
  /** independent re-verification: a library that is NOT the one that produced d.
   *  Defaults to defaultReverify (@bitcoinerlab/secp256k1) — never unbound (W1.5c). */
  reverify?: (dHex: string, qHex: string) => Promise<boolean>;
  network?: Network;
}

export type GateResult = { ok: true; addresses: string[] } | { ok: false; reason: GateReject };

export async function evidenceGate(input: GateInput): Promise<GateResult> {
  // 1. d·G == Q
  if (!verifyDgEqualsQ(input.dHex, input.qHex)) {
    return { ok: false, reason: "D_TIMES_G_MISMATCH" };
  }
  // 2. derived addresses must include the address the sigs came from (both pubkey forms — S6)
  const d = deriveAll(input.dHex, input.network);
  if (input.expectedAddress && !d.addresses.some((a) => a.address === input.expectedAddress)) {
    return { ok: false, reason: "ADDRESS_MISMATCH" };
  }
  // 3. second implementation must agree before any {"type":"key"} event fires
  const reverify = input.reverify ?? defaultReverify;
  if (!(await reverify(input.dHex, input.qHex))) {
    return { ok: false, reason: "SECOND_IMPL_DISAGREE" };
  }
  return { ok: true, addresses: d.addresses.map((a) => a.address) };
}
