/**
 * bjl.ts — single typed entry point for bitcoinjs-lib v7.
 * The package's "exports" map points TS at ESM JS without colocated .d.ts, so
 * bundler resolution mis-declares class statics (e.g. Transaction.fromBuffer).
 * types/bitcoinjs-lib.d.ts re-exports the authoritative CJS declarations;
 * import through the bare specifier so both runtime and tsc resolve cleanly.
 */
import { Transaction as _Transaction, TxInput, TxOutput } from "bitcoinjs-lib";

export const Transaction: typeof _Transaction = _Transaction;
export type TransactionInstance = _Transaction;
export type { TxInput, TxOutput };

/** v7 ships plain Uint8Array (no Buffer polyfill) for script/hash/witness fields.
 *  Single conversion point so callers keep Buffer ergonomics without `any`. */
export const toBuffer = (u: Uint8Array): Buffer => Buffer.from(u);
