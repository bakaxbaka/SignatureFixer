# Paper-to-App Implementation Workflow

Source: the 16 PDFs in `types/` (SignatureFixer repo). Each paper is mapped to a
stage, an attack module, and a gate. Ordered by the kill order in
`docs/runtimes.md`. One workflow per paper — do them in this sequence.

Global rules for every workflow (from docs/protocol.md §4 + gate §9):
- Worker reads one JSON job spec on stdin, emits JSONL events on stdout.
- `{"type":"key"}` only after gate.ts passes (d·G==Q → address → reverify).
- s may be low-S normalized ⇒ effective nonce is −k ⇒ brute-force both signs.
- No pubkey ⇒ recover it first (2 candidates, try both).
- Every attack ships with a positive fixture + a negative control.
- Conformance test (§10): Sage/paper reference vs production module, same
  fixture, same key event, or CI fails.

---

## W-A. Heninger et al. — "Mining Your Ps and Qs" (weakkeys12.extended.pdf)
Stage: W3 (normalize/verify/group) + W5 corpus signals.
1. Implement shared/attack/normalize.ts: hex→int, reject r/s ∉ [1,n−1],
   reject non-curve points, flag low-S (set s_normalized, reason codes).
2. Add gcd pairwise-modulus check hook for RSA keys found by tx-leak scan
   (this paper's core technique; ECDSA part is the bias detector seed).
3. Group by (curve_id, pubkey_fp); record group size distribution.
Acceptance: mutated-s fixture rejected with REASON code; real corpus groups
match data/all_signatures.csv counts.

## W-B. Bos et al. — "ECC in Practice" (2013-734.pdf)
Stage: W3 + classification vocabulary.
1. Encode the failure taxonomy as finding classifications: invalid curve,
   small subgroup, repeated nonce, biased nonce, faulted signature.
2. Add invalid-curve-check to recover.ts (point must satisfy y²=x³+7).
3. Use its dual-ecdsa/reuse cases as negative controls for reuse.ts.
Acceptance: each taxonomy class has one fixture that produces exactly it.

## W-C. Courtois et al. — "Private Key Recovery Combination Attacks" (2014-848.pdf)
Stage: W5 (key-space tier seeds).
1. brainwallet.ts (inproc): dictionary → sha256 → derive → compare Q.
2. randstorm reproduction (native, benchmark-gated): 2011–2015 Android
   seeded-PRNG table lookup — this paper defines the weakness class.
3. Weak-entropy candidate list feeds the ladder AFTER algebra waves.
Acceptance: known weak-key fixture recovers via brainwallet; randstorm gated
on attached benchmark else stays unregistered.

## W-D. Breitner & Heninger — "Biased Nonce Sense" (2019-023.pdf; 104-preproceedings.pdf = earlier version, use 2019-023 as normative)
Stage: W9 wave 3 core. THE lattice template for everything after.
1. research/refs/biased.sage: reproduce §3 lattice L = [[nA_i B_i],[...]]
   per paper eq.; sweep kb × m success rates (Sage stays bench-only).
2. engine/sfx_engine/hnp.py (runtime: python, fpylll): build basis from
   group records {r,s,z}; assume k_i = 2^(256−kb)·h_i + e_i, |e_i| < 2^t;
   centering trick (subtract expected value), LLL then BKZ(25), scan all
   rows for candidate d, gate every output.
3. server attack registration: id=bias_hnp, needs={records≥m, kb_estimate}.
4. TS side: bias_detect (python too, per runtimes.md) — rank groups by
   leading-bit entropy before hnp runs.
Acceptance: synthetic 20 signatures at kb=8 recovered ≥99% on 100 trials;
negative control (uniform k) yields NO_SIGNAL, never a wrong key event.

## W-E. Rowe/Breitner/Heninger — "half-half nonces" (2023-841.pdf)
Stage: W8 wave 2 — first Python lattice attack, easiest win.
1. Detection filter over whole corpus (inproc, cheap): does r match the
   half-half pattern? Paper gives: k = 2^128·a + b with a,b ≈ 128 bits ⇒
   test via single-signature lattice below.
2. research/refs/half_half.sage: A = 2^128 − s·r⁻¹; b = (h − 2^128·s·h_msb)·r⁻¹;
   L = [[n,0,0],[A,1,0],[b,0,2^128]]; recenter to 2^127; LLL; 4-bit brute
   force; 32 sign combos ⇒ ~99.99%.
3. engine/sfx_engine/half_half.py (python): port of step 2; emit candidate,
   gate verifies.
4. Register attack id=half_half, cost=seconds, needs={record}.
Acceptance: ≥99% on 100 synthetic single-signature keys (W8 gate); run on
every corpus signature once (paper observed real drained wallets).

## W-F. Albrecht & Heninger — "BDD with Predicate / kb=1" (2020-1540.pdf)
Stage: W10 wave 4.
1. engine/sfx_engine/hnp_pred.py: Kannan embedding + linear predicate check
   during enumeration instead of pure shortest-vector trust.
2. Subsample rule: take ~350 shortest estimated nonces per group — never
   feed full 1,055-row history to BKZ.
3. Predicate form: verify t·z ≡ ... mod n linear constraint (paper §3.2
   variant used by 2024/296; see W-H).
Acceptance: synthetic kb=1 dataset (m≈100 sigs) recovers; conformance vs
paper Table numbers logged in research/params/.

## W-G. Gilchrist/Buchanan/Finlow-Bates — "Two Affinely Related Nonces" (2025-705.pdf)
Stage: W7 wave 1 (affine) — closed form, no lattice.
1. shared/keys/affine.ts: k2 = a·k1 + b known ⇒
   d = (a·s2·h1 + b·s1·s2 − s1·h2) · (s1·r2 − a·s2·r1)⁻¹ mod n.
2. If a,b unknown: scan a,b ≤ 1000 — BLOCKED on defect S3 (pointMul perf).
   First add cached base-point table / wNAF to secp256k1.ts, measure
   10^6-candidate scan time, only then enable the scan mode.
3. Works even when both signatures are over the SAME message (paper §4) —
   add that fixture.
Acceptance: known-(a,b) fixture recovers instantly; scan mode ships only
with a recorded timing benchmark; negative control rejects random pairs.

## W-H. Gao et al. — "Nonce Leakage by Lattice Sieving" (2024-296.pdf)
Stage: W10 refinement + improved hnp_pred.
1. Adopt interval-reduction algorithm + pre-screening from §3 before sieving.
2. Linear predicate (their improvement over Albrecht-Heninger's EC-based
   one): use 2 log2(q) HNP samples' linear constraints — replace W-F's
   predicate inside hnp_pred.py.
3. Error-resilience extension for noisy z/provenance-mixed groups.
Acceptance: reproduces paper's 1-bit leakage record on simulated 160-bit
curve params; beats W-F baseline on same fixtures (success-rate table in
research/params/).

## W-I. Sun & Chang — "Sieving HNP with Built-in Modulo Arithmetic" (2023-1137.pdf)
Stage: W10 alternative path (kb=1).
1. Port their mod-arithmetic-embedded lattice construction into
    engine/sfx_engine/hnp_decomp.py companion (x = 2^15..2^25 decomposition
    already planned in runtimes.md).
2. Compare against W-H on identical fixtures; keep the winner as default,
    register the other behind a param.
Acceptance: conformance test equal-or-better sample count vs 2024/296.

## W-J. Jančár et al. — "Minerva" (2020-728.pdf)
Stage: W9 bit_length runtime (leakage estimator).
1. engine/sfx_engine/bit_length.py: from timing-derived bit-length leaks
   (or corpus nonce-length statistics where available) estimate
   kb = 256 − observed_bit_length; noise profile per paper §5.
2. Feed estimates into bias_detect ranking; hnp consumes per-group kb.
3. Their two new methods (elimination + recentering variants) become flags
   on hnp.py: --recenter, --eliminate.
Acceptance: TPM-FAIL-style synthetic trace set recovers with ≤900 sigs
(paper's headline number) at simulated leakage.

## W-K. Aranha et al. — "LadderLeak" (2020-615.pdf)
Stage: W12 wave 6 (trace tier). DECLINE-CLEANLY rule applies.
1. engine/sfx_engine/ladderleak.py: FFT branch for constant-time double-and-
   add ladders; needs trace input format {side_channel_bits per signing}.
2. Without trace files the attack returns {"type":"done","status":"no_input"}
   — never guesses (anti-pattern table).
Acceptance: paper's synthetic ladder traces recover; absent-trace call
declines cleanly with zero findings.

## W-L. De Micheli/Piau/Pierrot — "wNAF / EHNP" (2019-861.pdf)
Stage: W12 ehcp_w2naf.
1. engine/sfx_engine/ehcp_w2naf.py: EHNP lattice, dimension mh+1, condition
   K^mh < n^(m−1); preprocessing trick (their 7× speedup) as default pass.
2. Input = partial-double bits from cache traces; same decline rule as W-K.
Acceptance: 3-trace recovery matching paper's bound on synthetic set.

## W-M. Ryan — "Return of HNP / ROHNP" (Paper1_CHES_ROHNP.pdf)
Stage: W12 rohnp.
1. engine/sfx_engine/rohnp.py: from side-channel observation of the modular
   ADDITION inside s = k⁻¹(m + r·x): wrap flag ⇒ inequalities
   m+r·x < q ⇒ 0 < q−m−r·x ; m+r·x ≥ q ⇒ r·x mod q ∈ (q−m−1 ...].
   System of HNP inequalities → lattice/CVP.
2. Black-box detection mode (paper's statistical timing test) as a corpus
   screening tool, not an attack.
Acceptance: synthetic wrap-bit oracle recovers; detection screen reports
plausible rate on uniform control.

## W-N. Couteau & Makriyannis — "ECDSA with Presignatures or Biased Nonces" (2026-2545.pdf)
Stage: W13 hardening + scope guard.
1. Read as policy, not code: document which corpus provenance classes
   (RECONSTRUCTED_VERIFIED etc.) can carry presignature-mode bias risk.
2. Add the paper's caveats to SECURITY.md/CRYPTO_NOTES.md: some modes don't
   reduce to standard ECDSA — affects claim wording, not gate logic.
Acceptance: docs updated; no new attack module (deliberate).

## W-O. Buchanan et al. — "ECDSA Cracking Methods" (2025-654.pdf)
Stage: survey cross-check only.
1. Verify every attack in our registry appears in their taxonomy; note any
   we miss (they include kangaroo/brainwallet classes already in W5).
2. Use their worked examples as extra KAT vectors for reveal/reuse.
Acceptance: registry ⊇ relevant subset of paper taxonomy; KATs added.

## W-P. De Micheli & Heninger — "Recovering keys from partial information, by example" (2020-1506.pdf)
Stage: reference manual for W9–W12.
1. Not a new attack — the tutorial for constructing HNP lattices under many
   leak shapes. Keep open while implementing W-D/F/J/L/M.
2. Extract its checklist (scaling, centering, target-vector norm bounds)
   into engine/sfx_engine/lattice_common.py utilities used by all .py attacks.
Acceptance: all lattice attacks import lattice_common (no copy-paste bases).

---

Execution order (matches kill order, respects dependencies):
W-O (survey/KATs) → W-A/W-B (finish W3) → W-G (affine, after S3 fix) →
W-E (half_half, first Python) → W-D (biased HNP) → W-J (Minerva estimators) →
W-F → W-H → W-I (kb=1 line) → W-C (key-space) → W-K → W-L → W-M (trace) →
W-N (policy).

Blocking prerequisites before any lattice work starts:
1. S3 pointMul perf fix (needed by W-G scan mode).
2. Green tests/keys suite (current session's remaining steps).
3. fpylll installable in engine venv (uv sync --extra lattice).
