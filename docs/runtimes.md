# Runtime assignment — every attack, decided up front (W0)

Rule: each attack declares exactly ONE runtime. No dual implementations. The
conformance test (§10) is the only bridge between a research reference and a
production module. Adding an attack = one file + one registration; the runtime
field in the job spec (docs/protocol.md §1) routes it.

| Attack | Wave | Runtime | Rationale |
|---|---|---|---|
| reveal | 1 | inproc | d = r⁻¹(k·s − h) mod n — pure BigInt algebra, TS |
| reuse | 1 | inproc | implemented: shared/keys/reuse.ts → evidenceGate |
| fault | 1 | inproc | ten lines of modular algebra, TS |
| two_key | 1 | inproc | closed-form rational expression, TS |
| affine | 1 | inproc* | scan a,b ≤ 1000; *needs cached base-point table or wNAF first (perf defect S3) — measure before shipping |
| half_half | 2 | python | 3-D lattice, LLL + 4-bit brute force — fpylll only |
| short_nonce | 2 | python | k < 2^b is HNP at m=1; 2-D lattice for b ≤ 130 |
| bias_detect | 3 | python | statistical scan across groups |
| bit_length | 3 | python | Minerva: kb = 256 − observed_bit_length |
| hnp (kb=3,5,8) | 3 | python | dimension m+1, LLL→BKZ(20–40), fpylll |
| hnp_pred (kb=1) | 4 | python | linear predicate per eprint 2024/296 §3.2; subsample ~350 shortest nonces — never feed 1,055 rows to BKZ whole |
| hnp_decomp | 4 | python | x = 2^15..2^25 decomposition |
| kangaroo | 5 | native | Pollard lambda, d < 2^b — benchmark attached before adoption |
| brainwallet | 5 | inproc | dictionary → sha256 → derive → compare |
| randstorm | 5 | native | 2011–2015 seeded PRNG reproduction |
| tx-leak scan | 5 | inproc | script scan: OP_RETURN, pushdata for base58/WIF/hex |
| ehcp_w2naf | 6 | python | trace-based, mh+1 dim, K^{mh} < n^{m−1}; declines cleanly without trace input |
| rohnp | 6 | python | addition-wrap inequalities; same decline rule |
| LadderLeak FFT | 6 | python | requires trace; no guessing |

Kill order (runtime order, not build order):
reveal → reuse → fault → two_key → affine → half_half → short_nonce → bias_detect
→ hnp(kb=3,5,8) → hnp_pred(kb=1) → kangaroo / brainwallet / randstorm
→ ehcp_w2naf / rohnp / bleichenbacher

Sage stays in research/ as refs + bench only (parameter sweeps for W9). It is
never a production runtime. Native is gated on an attached benchmark.
