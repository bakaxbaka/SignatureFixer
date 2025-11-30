# Cryptography Assumptions & Limits

- The platform is strictly for research and education. It must not be used to target wallets without explicit permission.
- Analyses focus on public data (transactions, signatures) and never collect or store private keys, seeds, or wallet secrets.
- Signature parsing enforces canonical ranges (r, s) and rejects malformed hex payloads above reasonable limits to avoid DoS.
- Detection heuristics (nonce reuse, high-S malleability, DER/BER anomalies) are best-effort and should be confirmed with independent tooling.
- External blockchain explorers are treated as untrusted; failures are surfaced as friendly errors while details are logged server-side.
- Any recovery demonstrations should rely on openly published test vectors or user-supplied lab data only.
