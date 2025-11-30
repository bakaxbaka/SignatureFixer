🔐 SignatureFixer  
_Comprehensive Bitcoin Signature Analyzer · Vulnerability Scanner · DER Malleability Lab_

SignatureFixer is a full-stack Bitcoin signature-forensics platform designed to audit
Bitcoin transactions for vulnerabilities, signature malleability, key-reuse dangers,
wallet implementation flaws, and malformed DER encodings.

                                                                   
                        ⸜(｡˃ ᵕ ˂ )⸝ Buy me a coffee : 1PmAFZaBpokiMZ8TxhwMBW78s4Y1U9mEwK ⸜(｡˃ ᵕ ˂ )⸝
                                   ┌──────────────────────────────────────────┐
                                   │                FRONTEND                  │
                                   │        React / Vite / TypeScript         │
                                   ├──────────────────────────────────────────┤
                                   │  RawTX Inspector UI                      │
                                   │  DER Malleability Playground             │
                                   │  CVE‑2024‑42461 Test Panel               │
                                   │  Wycheproof Lab                          │
                                   │  Signature Analysis Dashboard            │
                                   │  Alerts & Vulnerability Visualizer       │
                                   └───────────────▲──────────────────────────┘
                                                   │ REST API Calls
                                                   │ /api/* (JSON)
                                                   ▼
        ┌──────────────────────────────────────────────────────────────────────────────┐
        │                              EXPRESS BACKEND                                 │
        │                           Node.js + TypeScript                                │
        ├──────────────────────────────────────────────────────────────────────────────┤
        │ Routes:                                                                        │
        │   /api/inspect-tx → InspectTxRoute                                             │
        │   /api/parse-der → DerParseRoute                                               │
        │   /api/cve-test → CveTestRoute                                                 │
        │   /api/wycheproof → WycheproofRoute                                            │
        │   /api/fetch → MultiEndpointFetcherRoute                                       │
        └───────────────────────▲────────────────────────────────────────────────────────┘
                                │ Uses Services
                                ▼

┌────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    BACKEND SERVICES                                         │
│  Modular, testable, cryptography‑grade analysis pipeline                                     │
├────────────────────────────────────────────────────────────────────────────────────────────┤

│ 1. Multi‑Endpoint + Tor‑Aware Fetching Layer (fetchers/)                                     │
│    ├ multiEndpointFetcher.ts                                                                 │
│    │   → blockchain.info                                                                     │
│    │   → blockstream.info                                                                    │
│    │   → mempool.space                                                                       │
│    │   → blockcypher.com                                                                     │
│    ├ torFetcher.ts                                                                           │
│    ├ cache.ts (memory + disk)                                                                │
│    └ rateLimiter.ts                                                                          │
│       → Provides normalized transaction + UTXO data                                          │

│ 2. Transaction Inspector (inspectTx/)                                                        │
│    ├ decodeRawTx.ts       → parse hex into structured tx                                     │
│    ├ enrichUtxos.ts       → match previous outputs                                           │
│    ├ extractSignatures.ts → grab DER, pubkey, sighash, witness                              │
│    ├ computeSighash.ts    → legacy + BIP143 reconstruction                                   │
│    ├ summarize.ts         → high‑S, r‑reuse, sighash flags                                   │
│    └ index.ts             → unified inspection pipeline                                      │

│ 3. DER / ASN.1 Engine (der/)                                                                 │
│    ├ derStrict.ts       → Bitcoin‑Core canonical rules                                       │
│    ├ derLoose.ts        → Elliptic.js pre‑patch behavior                                    │
│    ├ canonicalRules.ts  → r/s bounds, zero‑padding rules                                     │
│    ├ derMutations.ts    → generate malleability variants                                     │
│    └ berVariants.ts     → CVE‑2024‑42461 mutation suite                                      │

│ 4. CVE‑2024‑42461 Engine (cve42461/)                                                         │
│    ├ cveGenerator.ts  → Create BER/ASN.1 malformed signatures                                │
│    ├ cveTester.ts     → Test signature variants against libraries                            │
│    └ cveReport.ts     → Consolidate results into vulnerability matrix                       │

│ 5. Wycheproof Engine (wycheproof/)                                                           │
│    ├ loader.ts        → load JSON test vectors                                               │
│    ├ runner.ts        → execute test cases                                                   │
│    ├ compare.ts       → evaluate expected vs actual                                          │
│    └ resultTypes.ts   → structured output                                                    │

│ 6. Library Adapters (libraries/)                                                             │
│    ├ ellipticWrapper.ts                                                                      │
│    ├ nobleWrapper.ts                                                                         │
│    ├ bitcoinjsWrapper.ts                                                                     │
│    └ hwWrapper.ts (optional)                                                                 │
│       → Provides a unified verify(msg, sig, pubkey) API                                      │

│ 7. Bitcoin Internals (bitcoin/)                                                              │
│    ├ script.ts     → script parsing, ASM, decoding                                           │
│    ├ addresses.ts  → base58/bech32 detection                                                 │
│    ├ sighash.ts    → legacy, BIP143, Taproot upcoming                                        │
│    ├ secp256k1.ts  → curve constants + n (for r/s checks)                                    │
│    └ network.ts    → mainnet/testnet                                                         │

│ 8. Utils (utils/)                                                                            │
│    ├ hex.ts      → conversion helpers                                                        │
│    ├ bigint.ts   → safe bigint arithmetic                                                    │
│    ├ asn1.ts     → ASN.1 elements                                                            │
│    ├ logger.ts                                                                            │
│    └ types.ts    → global TypeScript interfaces                                              │
└────────────────────────────────────────────────────────────────────────────────────────────┘

                            ▲
                            │
                            ▼

┌───────────────────────────────────────────────────────┐
│                    CI WORKFLOWS                       │
│                (.github/workflows/)                   │
├───────────────────────────────────────────────────────┤
│ run-tests.yml          → backend unit tests           │
│ run-wycheproof.yml     → verify across all vectors    │
│ cve-regression.yml     → detect malleability regressions│
└───────────────────────────────────────────────────────┘

🚀 Installation & Run
Install
npm install
npm run build
Dev mode
npm run dev
Run Backend Only
npm run server
Run Tests
npm test
🔥 What This System Provides
Feature	Status	Description
Raw TX Inspector	✅	Decode, analyze, extract sigs
DER/BER Parser	✅	Strict + Loose modes
CVE‑2024‑42461 Detector	✅	Auto‑test libraries for ASN.1 bug
Wycheproof Integration	✅	Full compliance testing
Multi‑Curve	✅	secp256k1 + secp521r1
Malleability Engine	✅	High‑S, BER padding, garbage bytes
Sighash Visualizer	✅	BIP143 + legacy
Hardened DER Rules	✅	Bitcoin‑Core canonicality
CI Security Tests	✅	Prevent regression 
SignatureFixer/
│
├── README.md
├── package.json
├── tsconfig.json
├── vite.config.ts (or Next.js config)
│
├── src/
│   ├── frontend/
│   │   ├── components/
│   │   │   ├── RawTxInspector/
│   │   │   ├── DerPlayground/
│   │   │   ├── Cve42461Panel/
│   │   │   ├── WycheproofLab/
│   │   │   ├── SigAnalysisTable/
│   │   │   └── Alerts/
│   │   ├── pages/
│   │   │   ├── index.tsx
│   │   │   ├── tx-inspector.tsx
│   │   │   ├── cve-test.tsx
│   │   │   ├── wycheproof.tsx
│   │   │   └── api-docs.tsx
│   │   └── styles/
│   │
│   ├── backend/
│   │   ├── routes/
│   │   │   ├── inspectTxRoute.ts
│   │   │   ├── derParseRoute.ts
│   │   │   ├── cveTestRoute.ts
│   │   │   └── wycheproofRoute.ts
│   │   │
│   │   ├── services/
│   │   │   ├── inspectTx/
│   │   │   │   ├── decodeRawTx.ts
│   │   │   │   ├── enrichUtxos.ts
│   │   │   │   ├── extractSignatures.ts
│   │   │   │   ├── computeSighash.ts
│   │   │   │   ├── summarize.ts
│   │   │   │   └── index.ts
│   │   │   │
│   │   │   ├── der/
│   │   │   │   ├── derStrict.ts
│   │   │   │   ├── derLoose.ts
│   │   │   │   ├── derMutations.ts
│   │   │   │   ├── canonicalRules.ts
│   │   │   │   └── berVariants.ts
│   │   │   │
│   │   │   ├── cve42461/
│   │   │   │   ├── cveGenerator.ts      # Create CVE-style malformed signatures
│   │   │   │   ├── cveTester.ts         # Runs mutated signatures through libraries
│   │   │   │   └── cveReport.ts         # Produces vulnerability reports
│   │   │   │
│   │   │   ├── wycheproof/
│   │   │   │   ├── loader.ts
│   │   │   │   ├── runner.ts
│   │   │   │   ├── compare.ts
│   │   │   │   └── resultTypes.ts
│   │   │   │
│   │   │   ├── libraries/
│   │   │   │   ├── ellipticWrapper.ts
│   │   │   │   ├── nobleWrapper.ts
│   │   │   │   ├── bitcoinjsWrapper.ts
│   │   │   │   └── hwWrapper.ts (optional)
│   │   │   │
│   │   │   ├── bitcoin/
│   │   │   │   ├── script.ts
│   │   │   │   ├── addresses.ts
│   │   │   │   ├── sighash.ts
│   │   │   │   ├── secp256k1.ts
│   │   │   │   └── network.ts
│   │   │   │
│   │   │   └── fetchers/
│   │   │       ├── multiEndpointFetcher.ts
│   │   │       ├── torFetcher.ts
│   │   │       ├── cache.ts
│   │   │       └── rateLimiter.ts
│   │   │
│   │   └── utils/
│   │       ├── hex.ts
│   │       ├── bigint.ts
│   │       ├── asn1.ts
│   │       ├── logger.ts
│   │       └── types.ts
│   │
│   └── tests/
│       ├── cve42461.spec.ts
│       ├── derStrict.spec.ts
│       ├── wycheproof.spec.ts
│       ├── malleability.spec.ts
│       └── transaction.spec.ts
│
└── .github/workflows/
    ├── run-tests.yml
    ├── run-wycheproof.yml
    └── cve-regression.yml
<img width="1455" height="911" alt="image" src="https://github.com/user-attachments/assets/aefaa474-f016-46f1-a24f-baf67a610205" />
<img width="1038" height="639" alt="image" src="https://github.com/user-attachments/assets/397ae46b-35b6-4fad-be1b-8259689f701c" />


# 📌 Features Overview

## 🟦 1. Multi-Endpoint Blockchain Fetcher
SignatureFixer uses **four blockchain explorers**, automatically switching on rate limits:

1. `blockchain.info`
2. `blockstream.info`
3. `mempool.space`
4. `blockcypher.com`

Features:
- Automatic fallback on errors or HTTP 429  
- Tor-proxy support  
- Normalization into a single unified format  
- Full transaction fetching including inputs, outputs, scripts, witness, etc.  
- Optional TX hex fetching from multiple providers  
<img width="983" height="669" alt="image" src="https://github.com/user-attachments/assets/2ccc7ac8-8ee0-48ca-b8e5-2f22ff578d88" />


## 🟩 2. Tor Rotating Fetcher (Optional)
A custom HTTP client routed through Tor SOCKS5 proxy:

- `socks5h://127.0.0.1:9050`  
- Infinite retry  
- Exponential backoff  
- Global request throttle  
- Disk + memory cache  
- **429-proof** data fetching  

---

## 🟧 3. Caching Layer
All external calls pass through the internal caching mechanism:

- Memory cache (5–10 min TTL)
- Disk cache (`/data/http_cache.json`)
- Reduces API calls by 70–90%
- Instant retries from cache on API blackout

---

## 🟨 4. Transaction Hex Retrieval (Multi-Source)
`getTxHex(txid)` tries:

1. Blockchain.info (`?format=hex`)
2. Blockstream (`/tx/:id/hex`)
3. Mempool.space (`/tx/:id/hex`)
4. BlockCypher (`includeHex=true`)

Always returns canonical raw hexadecimal transaction.

<img width="957" height="913" alt="image" src="https://github.com/user-attachments/assets/3134d84b-1bda-46bd-923e-95945391eb88" />


## 🟪 5. DER Signature Extraction

Supports:

### ✔ P2PKH (scriptSig)  
### ✔ P2WPKH (witness stack)  
### ✔ P2SH-wrapped SegWit  
### ✔ Multisig (m-of-n, multi-signatures)  

Extracts:

- `r`  
- `s`  
- `sighash`  
- public key  
- input index  
- script type  
- corresponding UTXO  

<img width="694" height="597" alt="image" src="https://github.com/user-attachments/assets/831b83e2-5afc-480b-862a-c8efc3fb75d7" />
<img width="649" height="442" alt="image" src="https://github.com/user-attachments/assets/ed8c7f53-99a9-47ca-81f8-20604704c5bf" />
<img width="665" height="470" alt="image" src="https://github.com/user-attachments/assets/36996ffc-2b81-4046-a59b-aa66a8d1ca7b" />




## 🟥 6. DER Parser
Strict ASN.1 DER decoding:
Detects:

- Incorrect SEQUENCE length  
- Overlong encodings  
- Short encodings  
- Negative INTEGERs  
- Non-canonical DER  
- Zero-padding errors  

<img width="682" height="905" alt="image" src="https://github.com/user-attachments/assets/4ac9edb2-a79e-4ff7-a5ff-317323565a56" />


## 🟦 7. DER Malleability Playground
SignatureFixer includes a **live interactive DER signature mutation lab**:

### Generate:
- High-S variant  
- Extra leading zero in `r`  
- Extra leading zero in `s`  
- Wrong SEQUENCE length  
- Structural corruption  
- Trailing garbage bytes  

### And test:
**Does the ECDSA library incorrectly accept malformed signatures?**

Includes:

- Elliptic.js verification backend  
- Expected vs. actual acceptance  
- Automatic bug detection

---

## 🟫 8. Z-Hash Reconstruction (Signature Message Hash)

Supports all hashing modes:

- Legacy P2PKH  
- SegWit P2WPKH (BIP143)  
- Nested SegWit  
- Taproot (coming soon)

Rebuilds:

- Serialized transaction  
- Preimage  
- Double SHA256  
- `z` digest used in ECDSA  

---

## 🟩 9. UTXO Reconstruction Engine

Builds full UTXO set for any address:

- Finds all outputs associated with the address  
- Tracks spending transactions  
- Marks spent/unspent  
- Detects self-spends  
- Required for vulnerability testing  

---

## 🟫 10. Vulnerability Detection

SignatureFixer checks for:

### 🔥 1. Nonce reuse
Identical `r` value across two signatures → PRIVATE KEY RECOVERABLE

### 🔥 2. High-S / Low-S anomalies  
Detects poor signing library behavior

### 🔥 3. Script type detection  
(P2PKH vs P2WPKH vs P2SH)

### 🔥 4. Bad sighash bytes  
Flags anything non-`01`

### 🔥 5. Weak `r` patterns  
Entropy tests, repeating prefixes

### 🔥 6. Multi-input same-pubkey signature correlation  
Same pubkey signing multiple inputs → local nonce correlation analysis

---

## 🟥 11. Wycheproof Integration
Allows:

- Running Google's Wycheproof ECDSA test vectors  
- Checking whether your ECDSA implementation accepts invalid signatures  
- Detecting broken or malleable crypto libraries  
- Running malformed DER corpora  

Supports:
- `ecdsa_secp256k1_sha256_test.json`
- `ed25519_test.json`
- and more

---

## 🟦 12. Parallel Scanning Engine
Scan hundreds of Bitcoin addresses safely:

- Concurrency-limited queue  
- Tor-aware global throttling  
- Memory/disk caching  
- Per-address UTXO reconstruction  
- Per-transaction signature analysis  
# 📥 Installation

### 1. Clone
```bash
git clone https://github.com/bakaxbaka/SignatureFixer
cd SignatureFixer
2. Install dependencies
bash
npm install
3. (Optional) Install + run Tor
bash
sudo apt install tor
tor &
4. Run development server
bash
npm run dev
Backend runs on Express, frontend on React/Vite.

🔄 System Architecture
 ┌──────────────┐
 │   Frontend   │  React + TS
 └───────▲──────┘
         │
         ▼
 ┌──────────────┐
 │  Express API │  /api/vulnerability-test
 └──────▲───────┘
        │
        ▼
 ┌──────────────────────────────┐
 │    Analysis Pipeline         │
 │ - Multi-endpoint fetcher     │
 │ - Tor + caching layer        │
 │ - TX hex downloader          │
 │ - DER parser / malleator     │
 │ - z-hash builder             │
 │ - UTXO engine                │
 │ - Wycheproof runner          │
 │ - Vulnerability scoring      │
 └──────────────────────────────┘
