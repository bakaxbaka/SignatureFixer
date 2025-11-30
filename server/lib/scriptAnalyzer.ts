/**
 * Script Analyzer
 * Classifies script types and decodes addresses
 */

import * as bitcoin from "bitcoinjs-lib";
import type { ScriptType } from "../../client/src/types/txInspector";

const network = bitcoin.networks.bitcoin;

export function classifyScriptPubKey(scriptHex: string): ScriptType {
  try {
    const script = Buffer.from(scriptHex, "hex");

    // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if (script.length === 25 && script[0] === 0x76 && script[1] === 0xa9 && script[2] === 0x14 && script[23] === 0x88 && script[24] === 0xac) {
      return "p2pkh";
    }

    // P2WPKH: OP_0 <20 bytes>
    if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) {
      return "p2wpkh";
    }

    // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    if (script.length === 23 && script[0] === 0xa9 && script[1] === 0x14 && script[22] === 0x87) {
      return "p2sh";
    }

    // P2WSH: OP_0 <32 bytes>
    if (script.length === 34 && script[0] === 0x00 && script[1] === 0x20) {
      return "p2tr";
    }

    // P2TR: OP_1 <32 bytes>
    if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) {
      return "p2tr";
    }

    // Null data: OP_RETURN
    if (script.length > 0 && script[0] === 0x6a) {
      return "nulldata";
    }

    return "unknown";
  } catch {
    return "unknown";
  }
}

export function decodeAddressFromScript(scriptHex: string, network?: bitcoin.Network): string | undefined {
  try {
    const script = Buffer.from(scriptHex, "hex");
    const net = network || bitcoin.networks.bitcoin;

    // Try to decode as address
    const address = bitcoin.address.fromOutputScript(script, net);
    return address;
  } catch {
    return undefined;
  }
}
