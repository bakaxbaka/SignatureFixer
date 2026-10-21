/**
 * shared/keys/gate.ts — §9 evidence gate. The only path to a KEY_VERIFIED event.
 * Enforced once, nowhere else (R12). A lattice short vector is never a key;
 * it sits at CANDIDATE until all three checks pass.
 */
import { deriveAll, type Network } from "./derive";
import { verifyDgEqualsQ } from "./recover";

export type GateReject = "D_TIMES_G_MISMATCH" | "ADDRESS_MISMATCH" | "SECOND_IMPL_DISAGREE";

export interface GateInput {
  dHex: string;
  /** the pubkey the signatures came from (compressed or uncompressed hex) */
  qHex: string;
  /** address the group's records were observed at (§3 W2 corpus) */
  expectedAddress?: string;
  /** independent re-verification: a library that is NOT the one that produced d */
  reverify: (dHex: string, qHex: string) => Promise<boolean>;
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
  if (!(await input.reverify(input.dHex, input.qHex))) {
    return { ok: false, reason: "SECOND_IMPL_DISAGREE" };
  }
  return { ok: true, addresses: d.addresses.map((a) => a.address) };
}
