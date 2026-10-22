#!/usr/bin/env python3
"""
ECDSA nonce (k) reuse recovery for Bitcoin legacy (P2SH-P2WPKH-style) signatures.

Pipeline:
  1. Load signatures.csv (txid, vout, r, s, pubkey columns).
  2. Group all signatures by `r` -> find a nonce k that was reused across two
     different transactions (same r == same k, given the same curve).
  3. Pull the raw transaction hex for both txids from mempool.space, falling
     back to blockstream.info if the first fails.
  4. Rebuild the legacy SIGHASH_ALL sighash preimage for each signed input:
        scriptCode = 76 a9 14 <hash160(pubkey)> 88 ac   (P2SH redeemScript)
     with every *other* input's scriptSig emptied, then double-SHA256 the whole
     serialization -> the real message hashes z1 and z2.
  5. Solve over secp256k1 order n:
        k  = (z1 - z2) / (s1 - s2)   mod n
        d  = (s1*k - z1) / r         mod n
  6. Verify: d*G must equal the pubkey recorded in the CSV, then print d (hex),
     both WIF encodings (uncompressed/compressed) and the derived addresses.
"""

import csv
import hashlib
import sys
from collections import defaultdict

import requests
from ecdsa.ellipticcurve import Point, INFINITY
from ecdsa.curves import SECP256k1
from ecdsa.numbertheory import inverse_mod

# ---------------------------------------------------------------------------
# secp256k1 parameters
# ---------------------------------------------------------------------------
CURVE = SECP256k1.curve
N = SECP256k1.order          # group order
G = SECP256k1.generator      # generator point (verified against SEC2 constants)
P = CURVE.p()

assert G.x() == 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
assert G.y() == 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
assert N == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# ---------------------------------------------------------------------------
# tiny bitcoin primitives
# ---------------------------------------------------------------------------
def dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def ripemd160(b: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(b)
    return h.digest()


def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))


def b58encode(data: bytes) -> str:
    ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = ALPHA[rem] + out
    for byte in data:                      # leading zero bytes -> '1's
        if byte == 0:
            out = "1" + out
        else:
            break
    return out


def wif(priv_int: int, compressed: bool) -> str:
    """Wallet Import Format for mainnet."""
    body = b"\x80" + priv_int.to_bytes(32, "big")
    if compressed:
        body += b"\x01"
    checksum = dsha(body)[:4]
    return b58encode(body + checksum)


def p2pkh_address(pubkey_bytes: bytes, testnet: bool = False) -> str:
    version = b"\x6f" if testnet else b"\x00"
    payload = version + hash160(pubkey_bytes)
    return b58encode(payload + dsha(payload)[:4])


def p2sh_address(redeem_script: bytes, testnet: bool = False) -> str:
    version = b"\xc4" if testnet else b"\x05"
    payload = version + hash160(redeem_script)
    return b58encode(payload + dsha(payload)[:4])


# ---------------------------------------------------------------------------
# compact-size / var-int helpers
# ---------------------------------------------------------------------------
class Reader:
    def __init__(self, data: bytes):
        self.d, self.i = data, 0

    def take(self, n: int) -> bytes:
        chunk = self.d[self.i:self.i + n]
        if len(chunk) != n:
            raise ValueError("truncated transaction data")
        self.i += n
        return chunk

    def read_varint(self) -> int:
        b = self.take(1)[0]
        if b < 0xFD:
            return b
        if b == 0xFD:
            return int.from_bytes(self.take(2), "little")
        if b == 0xFE:
            return int.from_bytes(self.take(4), "little")
        return int.from_bytes(self.take(8), "little")


def varint_bytes(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


# ---------------------------------------------------------------------------
# raw transaction parsing
# ---------------------------------------------------------------------------
class TxIn:
    __slots__ = ("prev_hash", "prev_n", "script_sig", "sequence")


class Tx:
    __slots__ = ("version", "vin", "vout", "locktime", "raw", "is_segwit", "txid", "wtxid")


def parse_tx(raw_hex: str) -> Tx:
    data = bytes.fromhex(raw_hex)
    r = Reader(data)
    tx = Tx.__new__(Tx)
    tx.raw = data
    tx.version = r.take(4)

    marker = r.d[r.i]
    flag = r.d[r.i + 1] if r.i + 1 < len(r.d) else None
    tx.is_segwit = (marker == 0x00 and flag == 0x01)
    if tx.is_segwit:
        r.take(2)                                   # consume marker+flag

    n_in = r.read_varint()
    tx.vin = []
    for _ in range(n_in):
        ti = TxIn.__new__(TxIn)
        ti.prev_hash = r.take(32)                   # internal byte order
        ti.prev_n = r.take(4)
        sl = r.read_varint()
        ti.script_sig = r.take(sl)
        ti.sequence = r.take(4)
        tx.vin.append(ti)

    n_out = r.read_varint()
    tx.vout = []
    for _ in range(n_out):
        amount = r.take(8)
        pl = r.read_varint()
        script = r.take(pl)
        tx.vout.append((amount, script))

    tx.locktime = r.take(4)

    if tx.is_segwit:                                # skip witness data
        for _ in range(n_in):
            items = r.read_varint()
            for _ in range(items):
                wl = r.read_varint()
                r.take(wl)

    # txid = dsha of the non-segwit serialization
    legacy = bytearray(tx.version)
    legacy += varint_bytes(len(tx.vin))
    for ti in tx.vin:
        legacy += ti.prev_hash + ti.prev_n + varint_bytes(len(ti.script_sig)) \
                  + ti.script_sig + ti.sequence
    legacy += varint_bytes(len(tx.vout))
    for amount, script in tx.vout:
        legacy += amount + varint_bytes(len(script)) + script
    legacy += tx.locktime
    tx.txid = dsha(bytes(legacy))[::-1].hex()
    tx.wtxid = dsha(data)[::-1].hex()
    return tx


def prev_out_to_internal(prev_hash_hex_be: str) -> bytes:
    """Display-order (big-endian) outpoint hash -> internal little-endian bytes."""
    return bytes.fromhex(prev_hash_hex_be)[::-1]


# ---------------------------------------------------------------------------
# legacy SIGHASH_ALL preimage
# ---------------------------------------------------------------------------
def legacy_sighash_all(tx: Tx, input_index: int, script_code: bytes) -> bytes:
    """
    Double-SHA256 of the legacy signing serialization for `input_index`:
      - everything after the outpoint of the signing input is replaced by
        script_code, sequence kept
      - every other input gets an EMPTY scriptSig
      - SIGHASH_ALL (0x00000001) appended as 4-byte LE
    """
    buf = bytearray(tx.version)
    buf += varint_bytes(len(tx.vin))
    for idx, ti in enumerate(tx.vin):
        buf += ti.prev_hash + ti.prev_n
        if idx == input_index:
            buf += varint_bytes(len(script_code)) + script_code
        else:
            buf += b"\x00"                          # empty scriptSig
        buf += ti.sequence
    buf += varint_bytes(len(tx.vout))
    for amount, script in tx.vout:
        buf += amount + varint_bytes(len(script)) + script
    buf += tx.locktime
    buf += b"\x01\x00\x00\x00"                      # SIGHASH_ALL
    return dsha(bytes(buf))


# ---------------------------------------------------------------------------
# fetch raw tx hex (mempool.space first, blockstream.info fallback)
# ---------------------------------------------------------------------------
import os

ENDPOINTS = [
    ("mempool.space", "https://mempool.space/api/tx/{txid}/hex"),
    ("blockstream.info", "https://blockstream.info/api/tx/{txid}/hex"),
]
# Optional override for offline/testing use: TX_ENDPOINTS="name|url_template,name|url_template"
if os.environ.get("TX_ENDPOINTS"):
    ENDPOINTS = []
    for item in os.environ["TX_ENDPOINTS"].split(","):
        nm, tpl = item.split("|", 1)
        ENDPOINTS.append((nm.strip(), tpl.strip()))


def fetch_raw_tx(txid: str) -> tuple[str, str]:
    """Try each endpoint in order (mempool.space first, blockstream.info fallback)."""
    last_err = None
    for name, tmpl in ENDPOINTS:
        try:
            resp = requests.get(tmpl.format(txid=txid), timeout=20)
            if resp.status_code == 200:
                hexstr = resp.text.strip()
                if len(hexstr) >= 10 and all(c in "0123456789abcdefABCDEF" for c in hexstr):
                    return hexstr, name
                last_err = f"{name}: response is not valid hex ({hexstr[:80]!r})"
            else:
                last_err = f"{name}: HTTP {resp.status_code}"
        except Exception as exc:                     # noqa: BLE001
            last_err = f"{name}: {exc}"
    raise RuntimeError(f"could not fetch raw tx {txid} ({last_err})")


# ---------------------------------------------------------------------------
# signature loading / grouping
# ---------------------------------------------------------------------------
def load_signatures(path: str) -> list[dict]:
    rows = []
    with open(path, newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise SystemExit(f"{path}: empty file")
        norm = [f.strip().lower() for f in reader.fieldnames]
        for raw in reader:
            rec = dict(zip(norm, (v.strip() if isinstance(v, str) else v for v in raw.values())))
            for key in ("r", "s"):
                val = rec[key].replace("0x", "").replace("0X", "")
                try:
                    rec[key] = int(val, 16)          # r/s are 256-bit hex scalars
                except ValueError:
                    rec[key] = int(val)              # also accept decimal input
            rows.append(rec)
    if not rows:
        raise SystemExit(f"{path}: no rows parsed")
    return rows


def find_reused_r(rows: list[dict]) -> tuple[int, list[dict]]:
    groups: dict[int, list[dict]] = defaultdict(list)
    for row in rows:
        groups[row["r"]].append(row)
    # A reused nonce means the same r appears in two DIFFERENT transactions.
    for r_val, grp in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        txids = {g["txid"] for g in grp}
        if len(grp) >= 2 and len(txids) >= 2:
            return r_val, grp
    return None, []


def locate_input(tx: Tx, vout: int, prev_hash_field: str | None, script_code: bytes) -> int:
    """Find which input index of `tx` corresponds to this signature row."""
    candidates = []
    for idx, ti in enumerate(tx.vin):
        if int.from_bytes(ti.prev_n, "little") != vout:
            continue
        if prev_hash_field and ti.prev_hash != prev_out_to_internal(prev_hash_field):
            continue
        candidates.append(idx)
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:                         # ambiguous outpoint -> match script
        for idx in candidates:
            if script_code in tx.vin[idx].script_sig:
                return idx
        raise RuntimeError("ambiguous input: multiple inputs spend the same outpoint")
    # last resort: any input whose scriptSig contains the redeem script
    for idx, ti in enumerate(tx.vin):
        if script_code in ti.script_sig:
            return idx
    raise RuntimeError("could not locate the signed input inside the transaction")


# ---------------------------------------------------------------------------
# core recovery
# ---------------------------------------------------------------------------
def recover(r: int, sigs: list[dict]) -> dict:
    assert len(sigs) == 2, "exactly two signatures sharing r are required"
    s1, s2 = sigs[0]["s"], sigs[1]["s"]
    z1, z2 = sigs[0]["z"], sigs[1]["z"]
    if s1 == s2:
        raise RuntimeError("identical s values -> degenerate case (same message)")

    k = (z1 - z2) * inverse_mod(s1 - s2, N) % N
    d = (s1 * k - z1) * inverse_mod(r, N) % N

    pub = d * G
    return {"k": k, "d": d, "pub_point": pub}


def encode_pub(point, compressed: bool) -> bytes:
    x, y = point.x(), point.y()
    if compressed:
        return bytes([0x02 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> int:
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "signatures.csv"
    testnet = "--testnet" in sys.argv

    print(f"[1] Loading signatures from {csv_path} ...")
    rows = load_signatures(csv_path)
    print(f"    loaded {len(rows)} signature rows")

    print("[2] Grouping by r to find a reused nonce ...")
    r_shared, group = find_reused_r(rows)
    if r_shared is None:
        print("    No reused r found among different transactions.")
        return 1
    print(f"    reused r = {r_shared:064x}  ({len(group)} signatures)")
    for g in group:
        print(f"      txid={g['txid']} vout={g.get('vout')}")

    # Take the first two signatures of the group (distinct txids guaranteed above).
    pair = []
    seen_tx = set()
    for g in group:
        if g["txid"] not in seen_tx:
            pair.append(g)
            seen_tx.add(g["txid"])
        if len(pair) == 2:
            break
    sig1, sig2 = pair

    print("[3] Fetching raw transactions (mempool.space -> blockstream.info fallback) ...")
    srcs = {}
    for i, sig in enumerate((sig1, sig2), start=1):
        try:
            raw_hex, src = fetch_raw_tx(sig["txid"])
        except RuntimeError as exc:
            # Network failed -> fall back to a raw_hex column if the CSV carries one.
            if sig.get("raw_hex"):
                raw_hex, src = sig["raw_hex"].strip(), "CSV raw_hex column"
                print(f"    WARNING: {exc}")
                print(f"    using raw_hex from signatures.csv instead")
            else:
                raise
        tx = parse_tx(raw_hex)
        if tx.txid != sig["txid"]:
            print(f"    WARNING: recomputed txid {tx.txid} != csv txid {sig['txid']}")
        srcs[i] = (tx, src)
        print(f"    tx{i}: {sig['txid']} ({len(raw_hex)//2} bytes, segwit={tx.is_segwit}) via {src}")

    print("[4] Building legacy sighash preimages (scriptCode = 76 a9 14 <h160> 88 ac, SIGHASH_ALL) ...")
    for i, sig in enumerate((sig1, sig2), start=1):
        tx, _ = srcs[i]
        pub_bytes = bytes.fromhex(sig["pubkey"]) if "pubkey" in sig and sig["pubkey"] else None
        if pub_bytes is None:
            raise SystemExit("CSV must contain a 'pubkey' column to build the P2SH scriptCode")
        h160 = hash160(pub_bytes)
        script_code = b"\x76\xa9\x14" + h160 + b"\x88\xac"
        vin_idx = locate_input(tx, int(sig["vout"]), sig.get("prev_hash"), script_code)
        z = legacy_sighash_all(tx, vin_idx, script_code)
        sig["z"] = int.from_bytes(z, "big")
        sig["z_hex"] = z.hex()
        sig["script_code"] = script_code
        sig["vin_idx"] = vin_idx
        sig["hash160"] = h160
        print(f"    tx{i} input[{vin_idx}]  z{i} = {z.hex()}")

    print("[5] Solving k = (z1-z2)/(s1-s2) and d = (s1*k - z1)/r  (mod n) ...")
    res = recover(r_shared, [sig1, sig2])
    k, d, pub_point = res["k"], res["d"], res["pub_point"]
    print(f"    k = {k:064x}")
    print(f"    d = {d:064x}")

    print("[6] Verifying d*G == pubkey from CSV ...")
    ok = False
    for i, sig in enumerate((sig1, sig2), start=1):
        want = bytes.fromhex(sig["pubkey"])
        got_c = encode_pub(pub_point, True)
        got_u = encode_pub(pub_point, False)
        match = want in (got_c, got_u)
        ok = ok or match
        print(f"    tx{i} pubkey : {want.hex()}")
        print(f"      compressed  : {got_c.hex()} {'== MATCH' if want == got_c else ''}")
        print(f"      uncompressed: {got_u.hex()} {'== MATCH' if want == got_u else ''}")
    if not ok:
        print("    VERIFICATION FAILED: d*G does not match the recorded pubkey.")
        print("    (check that both signatures really share k and that the sighashes were built right)")
        return 2
    print("    VERIFIED: d*G equals the file's pubkey.")

    # ---- output -------------------------------------------------------------
    print("\n==================== RESULT ====================")
    print(f"d  (private key) : {d:064x}")
    print(f"k  (nonce)       : {k:064x}")
    print(f"WIF (uncompressed): {wif(d, False)}")
    print(f"WIF (compressed)  : {wif(d, True)}")

    pub_c = encode_pub(pub_point, True)
    pub_u = encode_pub(pub_point, False)
    print(f"P2PKH (uncompressed): {p2pkh_address(pub_u, testnet)}")
    print(f"P2PKH (compressed)  : {p2pkh_address(pub_c, testnet)}")
    for i, sig in enumerate((sig1, sig2), start=1):
        sc = sig["script_code"]
        print(f"P2SH   (tx{i} redeem): {p2sh_address(sc, testnet)}")
    print("================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
