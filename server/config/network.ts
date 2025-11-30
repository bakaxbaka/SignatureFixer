import type { NetworkName } from "../../client/src/types/txInspector";
import { networks, Network } from "bitcoinjs-lib";

export const NETWORK: NetworkName = "mainnet";

export function getBitcoinJsNetwork(): Network {
  switch (NETWORK) {
    case "testnet":
      return networks.testnet;
    case "regtest":
      return networks.regtest;
    case "signet":
      return networks.testnet;
    case "mainnet":
    default:
      return networks.bitcoin;
  }
}
