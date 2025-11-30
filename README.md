🔐 SignatureFixer  
_Comprehensive Bitcoin Signature Analyzer · Vulnerability Scanner · DER Malleability Lab_

SignatureFixer is a full-stack Bitcoin signature-forensics platform designed to audit
Bitcoin transactions for vulnerabilities, signature malleability, key-reuse dangers,
wallet implementation flaws, and malformed DER encodings.

⸜(｡˃ ᵕ ˂ )⸝ Buy me a coffee : 1PmAFZaBpokiMZ8TxhwMBW78s4Y1U9mEwK ⸜(｡˃ ᵕ ˂ )⸝

 Core Modules Explained
1. Raw Transaction Inspector (src/backend/services/inspectTx)
Responsible for turning raw Bitcoin transaction hex into a complete enriched dataset:
parse version, inputs, outputs
compute size, vsize, weight
fetch previous outputs
resolve addresses
extract signatures (scriptSig + witness)
compute sighash preimages
run DER validator
produce vulnerability flags
output analysis in structured form
Output example;
interface InspectTxResponse {
  txid: string;
  version: number;
  sizeBytes: number;
  vsizeBytes: number;
  inputs: InputAnalysis[];
  outputs: OutputAnalysis[];
  summaryFlags: {
    hasHighS: boolean;
    hasNonCanonicalDer: boolean;
    hasWeirdSighash: boolean;
    hasRReuseWithinTx: boolean;
    hasMultiInputSameKey: boolean;
  };
}
2. DER & BER Engine (src/backend/services/der)
Includes:
derStrict.ts
Implements Bitcoin Core’s strict DER rules, ensuring:
no padding
correct length fields
no trailing garbage
r/s in range
canonical S
derLoose.ts
Emulates pre‑fix elliptic library behavior:
accepts BER encodings
accepts wrong length fields
may accept garbage padding
derMutations.ts
Used for:
CVE testing
signature malleability playground
Produces variants:
leading‑zero padding
shortened integers
wrong sequence length
wrong integer length
bad type tags
appended garbage (deadbeef)
3. CVE‑2024‑42461 Detector (src/backend/services/cve42461)
Powered by the above DER engine.
Pipeline:
Input signature → generate 15+ CVE‑style BER variants → verify with target library → produce vulnerability matrix
Output example
interface Cve42461Report {
  libraryName: string;
  vulnerable: boolean;
  acceptsCanonicalDER: boolean;
  acceptsBERVariants: boolean;
  testCases: TestCaseResult[];
}
4. Wycheproof Engine (src/backend/services/wycheproof)
Provides:

load Google Wycheproof vectors

test library verification correctness

test your own strict and loose parsers

compare against expected verdict

You get:

valid → rejected?   → bug  
invalid → accepted? → vulnerability  
5. Multi‑Library Verification (src/backend/services/libraries)
Wrappers unify:

elliptic

noble-secp256k1

bitcoinjs-lib

optional hardware wallets

Each wrapper exposes:

verify(msgHash, signature, pubkey): boolean
Allows cross‑lib comparison.

6. Malleability Playground (src/frontend/components/DerPlayground)
decode/parse DER

forge variants

re‑encode

test with chosen library

visual diff of R/S values

Perfect for debugging or demonstrating exploitation.

⚡ CI / Regression Workflows
Under .github/workflows/:

1. run-tests.yml
Runs Jest/Mocha/uvu tests.

2. run-wycheproof.yml
loads Wycheproof vectors

runs full suite

generates compliance score

3. cve-regression.yml
takes a bundle of BER malformed signatures

verifies expected behavior

fails if any library accepts malformed DER

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
