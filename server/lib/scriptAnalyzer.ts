import { payments } from "bitcoinjs-lib";
import type { ScriptType } from "../../client/src/types/txInspector";
import { getBitcoinJsNetwork } from "../config/network";

export function classifyScriptPubKey(scriptHex: string): ScriptType {
  const buf = Buffer.from(scriptHex, "hex");

  if (
    buf.length === 25 &&
    buf[0] === 0x76 &&
    buf[1] === 0xa9 &&
    buf[2] === 0x14 &&
    buf[23] === 0x88 &&
    buf[24] === 0xac
  ) {
    return "p2pkh";
  }

  if (buf.length === 22 && buf[0] === 0x00 && buf[1] === 0x14) {
    return "p2wpkh";
  }

  if (buf.length === 23 && buf[0] === 0xa9 && buf[1] === 0x14 && buf[22] === 0x87) {
    return "p2sh";
  }

  if (buf.length > 0 && buf[0] === 0x6a) {
    return "nulldata";
  }

  return "unknown";
}

export function decodeAddressFromScript(
  scriptHex: string
): string | undefined {
  const network = getBitcoinJsNetwork();
  const buf = Buffer.from(scriptHex, "hex");

  try {
    if (classifyScriptPubKey(scriptHex) === "p2pkh") {
      const payment = payments.p2pkh({ output: buf, network });
      return payment.address;
    }
    if (classifyScriptPubKey(scriptHex) === "p2wpkh") {
      const payment = payments.p2wpkh({ output: buf, network });
      return payment.address;
    }
    if (classifyScriptPubKey(scriptHex) === "p2sh") {
      const payment = payments.p2sh({ output: buf, network });
      return payment.address;
    }
  } catch (e) {
    console.warn("decodeAddressFromScript error", e);
  }

  return undefined;
}
