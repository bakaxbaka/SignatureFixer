/**
 * shared/keys/derive.ts — S1/S6: derive_all(d) → pubkeys (compressed + uncompressed)
 * and every address form the key controls: P2PKH, P2SH-P2WPKH, P2WPKH, P2WSH, P2TR.
 * Runtime: inproc. Uses bitcoinjs-lib v7 payments for encoding correctness,
 * pure-BigInt math (secp256k1.ts) for point derivation.
 */
import { createHash } from "node:crypto";
import base58 from "bs58";
import * as bitcoin from "bitcoinjs-lib";
import { CURVE, G, bigToHex32, pointMul, type Point } from "./secp256k1";

export interface Network {
  name: string;
  /** bitcoinjs network params */
  params: bitcoin.Network;
  /** WIF version byte (0x80 mainnet, 0xef testnet) */
  wifPrefix: number;
  bech32Prefix: string;
}

export const MAINNET: Network = {
  name: "bitcoin-mainnet",
  params: bitcoin.networks.bitcoin,
  wifPrefix: 0x80,
  bech32Prefix: "bc",
};

export const TESTNET: Network = {
  name: "bitcoin-testnet",
  params: bitcoin.networks.testnet,
  wifPrefix: 0xef,
  bech32Prefix: "tb",
};

export type ScriptType = "p2pkh" | "p2sh-p2wpkh" | "p2wpkh" | "p2wsh" | "p2tr";

export interface DerivedAddress {
  scriptType: ScriptType;
  address: string;
  compressed: boolean;
  pubkeyHex: string;
}

export interface DerivedKey {
  privkeyHex: string;
  wif: string;
  pubkeys: { compressed: string; uncompressed: string };
  addresses: DerivedAddress[];
  network: string;
}

export function sha256(buf: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(buf).digest());
}

export function hash160(buf: Uint8Array): Uint8Array {
  const s = createHash("sha256").update(buf).digest();
  return new Uint8Array(createHash("ripemd160").update(s).digest());
}

export function dToBigint(d: string | bigint): bigint {
  const v = typeof d === "bigint" ? d : BigInt("0x" + d.trim());
  if (v < 1n || v >= CURVE.n) throw new Error("derive: private key out of range [1, n-1]");
  return v;
}

export function pointToCompressed(pt: Point): string {
  if (!pt) throw new Error("derive: point at infinity has no encoding");
  const prefix = (pt.y & 1n) === 1n ? "03" : "02";
  return prefix + bigToHex32(pt.x);
}

export function pointToUncompressed(pt: Point): string {
  if (!pt) throw new Error("derive: point at infinity has no encoding");
  return "04" + bigToHex32(pt.x) + bigToHex32(pt.y);
}

export function pubkeyFromD(d: string | bigint): { compressed: string; uncompressed: string } {
  const Q = pointMul(dToBigint(d), G);
  return { compressed: pointToCompressed(Q), uncompressed: pointToUncompressed(Q) };
}

export function toWIF(privkeyHex: string, compressed: boolean, net: Network = MAINNET): string {
  const payload = Buffer.alloc(38);
  payload[0] = net.wifPrefix;
  Buffer.from(bigToHex32(dToBigint(privkeyHex)), "hex").copy(payload, 1);
  if (compressed) payload[37] = 0x01;
  // double-sha256 checksum
  const h = sha256(sha256(new Uint8Array(payload)));
  const withChecksum = Buffer.concat([payload, Buffer.from(h.slice(0, 4))]);
  return base58.encode(withChecksum);
}

/**
 * S1: full sweep. Both pubkey forms × all five script types.
 * Pre-2012 keys are uncompressed — missing this is how you "recover" a key
 * with zero balance. P2WSH/P2TR use the compressed key per BIP141/BIP341 policy.
 */
export function deriveAll(privkeyHex: string, net: Network = MAINNET): DerivedKey {
  const { compressed, uncompressed } = pubkeyFromD(privkeyHex);
  const addresses: DerivedAddress[] = [];

  for (const [pub, isComp] of [
    [compressed, true],
    [uncompressed, false],
  ] as const) {
    const pubBuf = Buffer.from(pub, "hex");

    const p2pkh = bitcoin.payments.p2pkh({ pubkey: pubBuf, network: net.params });
    if (p2pkh.address) {
      addresses.push({ scriptType: "p2pkh", address: p2pkh.address, compressed: isComp, pubkeyHex: pub });
    }

    const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: pubBuf, network: net.params });
    if (p2wpkh.address) {
      addresses.push({ scriptType: "p2wpkh", address: p2wpkh.address, compressed: isComp, pubkeyHex: pub });
      const p2sh = bitcoin.payments.p2sh({
        redeem: p2wpkh,
        network: net.params,
      });
      if (p2sh.address) {
        addresses.push({ scriptType: "p2sh-p2wpkh", address: p2sh.address, compressed: isComp, pubkeyHex: pub });
      }
    }

    // P2WSH over a bare 2-of-1-ish witness script embedding this key (single-key CHECKSIG)
    const witnessScript = Buffer.concat([
      Buffer.from([0x21]), pubBuf, Buffer.from([0xac]), // PUSHDATA33 <pub> CHECKSIG
    ]);
    const p2wsh = bitcoin.payments.p2wsh({ redeem: { output: witnessScript }, network: net.params });
    if (p2wsh.address) {
      addresses.push({ scriptType: "p2wsh", address: p2wsh.address, compressed: isComp, pubkeyHex: pub });
    }
  }

  // P2TR (BIP341 key-path, un-tweaked output key = x-only of Q).
  // NOTE (S7): a key recovered from an ECDSA signature may correspond to the
  // *tweaked* output key, not the internal key. Spend via key path needs the
  // internal key t = d + H_TapRoot(P) mod n, or the tweak itself.
  const xOnly = Buffer.from(compressed.slice(2), "hex");
  try {
    const p2tr = bitcoin.payments.p2tr({ pubkey: xOnly, network: net.params });
    if (p2tr.address) {
      addresses.push({ scriptType: "p2tr", address: p2tr.address, compressed: true, pubkeyHex: compressed });
    }
  } catch {
    /* x-only parse failure — skip */
  }

  return {
    privkeyHex: bigToHex32(dToBigint(privkeyHex)),
    wif: toWIF(privkeyHex, true, net),
    pubkeys: { compressed, uncompressed },
    addresses,
    network: net.name,
  };
}
