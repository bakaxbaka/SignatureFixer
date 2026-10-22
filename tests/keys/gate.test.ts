/**
 * W1.5c gate test: a WRONG d must fail with SECOND_IMPL_DISAGREE, never pass.
 * Uses an injected reverify stub so the test is deterministic and offline.
 */
import { describe, it, expect } from "vitest";
import { evidenceGate } from "../../shared/keys/gate";
import { pubkeyFromD } from "../../shared/keys/derive";

const D = "0000000000000000000000000000000000000000000000000000000000000001"; // d=1 (known vector)
const Q = pubkeyFromD(D).compressed;
const WRONG_D = "0000000000000000000000000000000000000000000000000000000000000002";

describe("evidenceGate (§9)", () => {
  it("rejects a wrong d at condition 1 before any reverify runs", async () => {
    let reverifyCalled = false;
    const res = await evidenceGate({
      dHex: WRONG_D,
      qHex: Q,
      reverify: async () => { reverifyCalled = true; return true; },
    });
    expect(res).toEqual({ ok: false, reason: "D_TIMES_G_MISMATCH" });
    expect(reverifyCalled).toBe(false); // gate short-circuits: never wastes check 3
  });

  it("a d that passes d*G==Q but fails the second implementation yields SECOND_IMPL_DISAGREE", async () => {
    const res = await evidenceGate({
      dHex: D,
      qHex: Q,
      reverify: async () => false,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("SECOND_IMPL_DISAGREE");
  });

  it("full pass with honest reverify — key event is permitted only here", async () => {
    const res = await evidenceGate({
      dHex: D,
      qHex: Q,
      reverify: async () => true,
    });
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.addresses.length).toBeGreaterThan(0);
  });

  it("address mismatch caught when expectedAddress is not derived", async () => {
    const res = await evidenceGate({
      dHex: D,
      qHex: Q,
      expectedAddress: "1BackstopNotReal000000000000000000",
      reverify: async () => true,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("ADDRESS_MISMATCH");
  });

  it("default reverify (@bitcoinerlab/secp256k1) agrees with pure-BigInt producer for d=1", async () => {
    const res = await evidenceGate({ dHex: D, qHex: Q }); // no injected reverify -> defaultReverify
    expect(res.ok).toBe(true);
  }, 30000);

  it("default reverify rejects a malformed Q instead of throwing", async () => {
    const res = await evidenceGate({ dHex: D, qHex: "not-a-pubkey" });
    expect(res.ok).toBe(false); // D_TIMES_G_MISMATCH (parsePubkey fails) — never a throw
  });
});
