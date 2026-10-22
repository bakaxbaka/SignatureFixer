/**
 * bjl.ts — single typed entry point for bitcoinjs-lib v7.
 * The package's "exports" map mis-resolves under TS bundler resolution, so we
 * load the authoritative CJS build via createRequire and re-export it with a
 * minimal structural typing surface (TxInput/TxOutput mirror
 * client/src/types/txInspector shapes consumed downstream).
 */
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-var-requires
const bjp = require("bitcoinjs-lib");

export interface TxInput {
  hash: Buffer | Uint8Array;
  index: number;
  script: Buffer;
  sequence: number;
  witness: Buffer[];
}

export interface TxOutput {
  value: bigint | number;
  script: Buffer;
}

export interface BjlTransaction {
  version: number;
  locktime: number;
  ins: TxInput[];
  outs: TxOutput[];
  getId(): string;
  virtualSize(): number;
  weight(): number;
  toBuffer(): Buffer;
  toHex(): string;
  hasWitnesses(): boolean;
  hashForSignature(vinIndex: number, prevOutScript: Buffer, hashType: number): Buffer;
}

interface TransactionCtor {
  fromBuffer(buffer: Buffer | Uint8Array): BjlTransaction;
  new (): BjlTransaction;
}

export const Transaction: TransactionCtor = bjp.Transaction as TransactionCtor;
export type TransactionInstance = BjlTransaction;
