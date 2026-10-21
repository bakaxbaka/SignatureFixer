/**
 * bjl.ts — single typed entry point for bitcoinjs-lib v7.
 * The package's "exports" map points TS at ESM JS without colocated .d.ts, so
 * bundler resolution mis-declares class statics (e.g. Transaction.fromBuffer).
 * We import the authoritative CJS declarations directly and re-export typed.
 */
import { Transaction as _Transaction } from "bitcoinjs-lib/src/cjs/transaction.js";

export const Transaction: typeof _Transaction = _Transaction;
export type TransactionInstance = _Transaction;
