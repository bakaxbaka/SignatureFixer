🔐 SignatureFixer  
_Comprehensive Bitcoin Signature Analyzer · Vulnerability Scanner · DER Malleability Lab_

SignatureFixer is a full-stack Bitcoin signature-forensics platform designed to audit
Bitcoin transactions for vulnerabilities, signature malleability, key-reuse dangers,
wallet implementation flaws, and malformed DER encodings.

> **Safety first:** this project is for educational auditing only. It never handles private keys, enforces size-limited hex parsing, and now logs requests and errors via structured Pino logging so operational teams can spot abuse.

                                                                   
         ⸜(｡˃ ᵕ ˂ )⸝ Buy me a coffee : 1PmAFZaBpokiMZ8TxhwMBW78s4Y1U9mEwK ⸜(｡˃ ᵕ ˂ )⸝
                         ┌────────────────────────────┐
                         │        Frontend UI         │
                         │  React / Vite / TypeScript │
                         └──────────────▲─────────────┘
                                        │
                         User Input     │     JSON Responses
                                        │
                         ┌──────────────┴─────────────┐
                         │         Express API         │
                         │       /api/* Endpoints      │
                         └──────────────▲─────────────┘
                                        │
                                        │  Calls Services
                                        ▼
     ┌──────────────────────────────────────────────────────────────────┐
     │                        BACKEND SERVICE LAYER                     │
     │                                                                  │
     │  ┌───────────────────────┐   ┌───────────────────────────────┐   │
     │  │  Multi-Endpoint       │   │   Tor + Cache Layer           │   │
     │  │  Blockchain Fetcher   │   │ - Rate limit smoothing        │   │ 
     │  │ - blockstream.info    │   │ - Memory + Disk cache         │   │
     │  │ - mempool.space       │   │ - Tor SOCKS5 optional         │   │
     │  │ - blockchain.info     │   │ - Retry + backoff             │   │
     │  └─────────────▲─────────┘   └───────────────▲───────────────┘   │
     │                │                           │                     │
     │                │ TX Hex + JSON Data        │ Cached / Tor-Fixed  │
     │                ▼                           ▼                     │
     │  ┌─────────────────────────────┐  ┌──────────────────────────┐   │
     │  │   Raw Transaction Decoder   │   │   UTXO Reconstruction   │   │
     │  │ - version / locktime        │   │ - find inputs/outputs   │   │
     │  │ - inputs / outputs          │   │ - mark spent/unspent    │   │
     │  │ - script extraction         │   │ - change detection      │   │
     │  └─────────────▲───────────────┘   └──────────────▲──────────┘   │
     │                │                                 │               │
     │                │ Signatures / Scripts            │ UTXO Context  │
     │                ▼                                 ▼               │
     │  ┌──────────────────────────────┐   ┌──────────────────────────┐ │
     │  │  Signature Extraction Engine │   │      Sighash Builder     │ │
     │  │ - r / s / sighash byte       │   │ - Legacy (P2PKH)         │ │
     │  │ - pubkey parsing             │   │ - SegWit (BIP143)        │ │
     │  │ - script type detection      │   │ - Nested SW              │ │
     │  └─────────────▲───────────────┘   └──────────────▲────────────┘ │
     │                │                                 │               │
     │                │ Parsed Signature Data           │ Preimages     │
     │                ▼                                 ▼               │
     │  ┌─────────────────────────────┐   ┌───────────────────────────┐ │
     │  │        DER/BER Engine       │   │    Malleability Engine    │ │
     │  │ - Strict DER (Bitcoin Core) │   │ - High‑S transform        │ │
     │  │ - Loose DER (elliptic bug)  │   │ - BER padding             │ │
     │  │ - Range validation          │   │ - Bad length fields       │ │
     │  └─────────────▲───────────────┘   └──────────────▲────────────┘ │
     │                │                                 │               │
     │                │ Valid / Invalid DER             │ Malleated Sig │
     │                ▼                                 ▼               │
     │   ┌────────────────────────────┐  ┌───────────────────────────┐  │
     │   │   Library Verification     │  │    CVE‑2024‑42461 Tester  │  │
     │   │ - elliptic                 │  │- Generate 15+ BER variants│  │
     │   │ - noble-secp256k1          │  │- Cross‑library verify     │  │
     │   │ - bitcoinjs-lib            │  │- Produce vulnerability map│  │
     │   └─────────────▲──────────────┘  └──────────────▲────────────┘  │
     │                 │                                  │             │
     │                 │ Verification Matrix               │ CVE Report │
     │                 ▼                                  ▼             │
     │   ┌────────────────────────────┐   ┌───────────────────────────┐ │
     │   │     Wycheproof Runner      │   │ Vulnerability Scoring     │ │
     │   │ - load vectors             │   │ - r reuse                 │ │
     │   │ - run full suite           │   │ - high-S detection        │ │
     │   │ - detect invalid accepted  │   │ - sighash anomalies       │ │
     │   └─────────────▲──────────────┘   └──────────────▲────────────┘ │
     │                 │                                  │             │
     └─────────────────┼──────────────────────────────────┼─────────────┘
                       │                                  │
                       ▼                                  ▼
              ┌──────────────────┐             ┌────────────────────────┐
              │ Structured JSON  │             │  UI Visualization      │
              │ (Analysis Result)│             │ (Tables, Charts, Flags)│
              └──────────────────┘             └────────────────────────┘


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
