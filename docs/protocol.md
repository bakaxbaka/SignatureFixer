# SignatureFixer worker protocol — v1 (FROZEN)

Two schemas, versioned, append-only. `protocol` field carries the major version;
the host rejects a spec whose major differs from its own, loudly, before running anything.

## 1. Job spec (host → worker, one JSON object on stdin)

```json
{ "protocol": 1, "run_id": "r_01H...", "attack_id": "reuse", "attack_version": "1.0.0",
  "runtime": "inproc", "params": { "bruteforce_sign": true },
  "limits": { "wall_ms": 600000, "rss_mb": 4096 },
  "group": { "group_key": "q_ab12...", "curve_id": "secp256k1", "network": "bitcoin-mainnet",
    "records": [ { "record_id": "rec_1", "txid": "..", "input_index": 0, "r": "..", "s": "..",
      "z": "..", "pubkey": "..", "s_normalized": false, "recid": 1,
      "digest_provenance": "RECONSTRUCTED_VERIFIED" } ] } }
```

## 2. Events (worker → host, one JSON per line on stdout)

```json
{"type":"progress","pct":0.4,"msg":"scanning a,b"}
{"type":"candidate","d_hex":"..","confidence":0.6,"evidence":{}}
{"type":"finding","classification":"CANDIDATE","rule":"..","source_record_ids":["rec_1"]}
{"type":"key","privkey_hex":"..","wif":"..","address":"..","method":"reuse","d_times_G":true}
{"type":"error","code":"OOM","msg":".."}
{"type":"done","elapsed_ms":1234,"status":"ok"}
```

## 3. Rules

- `type` is the discriminator. Unknown types are ignored, never fatal — event kinds
  can be added later without touching the host (append-only evolution).
- `{"type":"key"}` is the only event that means success, and it may fire **only after
  §9 of the stage map is fully satisfied**: d·G == Q, address match, second
  implementation agrees. A lattice short vector is never a key; it sits at CANDIDATE.
- stdout is protocol JSONL only. Logs go to stderr. The host pipes stderr to a logfile.
- Workers honour `limits.wall_ms` and `limits.rss_mb`; the host enforces them too
  (process-group kill on breach). Typed failures via `{"type":"error"}` then `done`.
- `runtime` is present from day one (`inproc | python | native`) so no migration is
  needed when tiers are added. Each attack declares exactly one runtime; no dual
  implementations (conformance tests keep ports honest).
- All hex fields are lowercase, unprefixed, fixed-width where the type has a width
  (r, s, z, d: 64 chars). Big-endian.
- Idempotency: re-running a run with the same `run_id` must produce byte-identical
  events.jsonl (run_id = sha256(inputs + git_sha + params)).

## 4. Versioning

Major version in `protocol`. Minor additions (new event types, new optional spec
fields) do not bump it. Breaking changes bump it and require both sides updated.
This document is frozen at v1; edits are append-only deprecation notes below.

---
Baseline SHA at freeze: cd428bd2e174393f19528ae5e89b49728d9216c8
