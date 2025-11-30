/**
 * Transaction Inspector API Types
 * Unified types for /api/inspect-tx backend pipeline
 */

export type NetworkName = "mainnet" | "testnet" | "signet" | "regtest";

export type ScriptType =
  | "p2pkh"
  | "p2wpkh"
  | "p2sh"
  | "p2sh-p2wpkh"
  | "p2tr"
  | "nulldata"
  | "unknown";

export type SighashTypeName =
  | "SIGHASH_ALL"
  | "SIGHASH_NONE"
  | "SIGHASH_SINGLE"
  | "SIGHASH_ALL|ANYONECANPAY"
  | "SIGHASH_NONE|ANYONECANPAY"
  | "SIGHASH_SINGLE|ANYONECANPAY"
  | "UNKNOWN";

export interface SignatureDerIssue {
  code:
    | "NON_CANONICAL"
    | "EXTRA_PADDING_R"
    | "EXTRA_PADDING_S"
    | "BAD_SEQ_TAG"
    | "BAD_LENGTH"
    | "TRAILING_GARBAGE"
    | "OUT_OF_RANGE_R"
    | "OUT_OF_RANGE_S";
  message: string;
}

export interface SignatureAnalysis {
  derHex: string;
  rHex: string;
  sHex: string;
  zHex: string; // sighash preimage hash
  sighashType: number;
  sighashName: SighashTypeName;
  pubkeyHex?: string;
  isHighS: boolean;
  isCanonicalDer: boolean;
  rangeValid: boolean;
  derIssues: SignatureDerIssue[];
  warnings: string[];
}

export interface TxInputAnalysis {
  index: number;
  prevTxid: string; // big-endian
  prevVout: number;
  sequence: number;
  scriptSigHex?: string;
  scriptSigAsm?: string;
  witness?: string[]; // raw witness stack entries
  scriptType: ScriptType;
  valueSats?: number; // if previous tx fetched
  address?: string;
  isCoinbase: boolean;
  pubkeyHex?: string;
  signature?: SignatureAnalysis | null;
  samePubkeyAsInputs?: number[]; // indices of other inputs using same pubkey
}

export interface TxOutputAnalysis {
  index: number;
  valueSats: number;
  scriptPubKeyHex: string;
  scriptPubKeyAsm?: string;
  scriptType: ScriptType;
  address?: string;
  isChangeGuess: boolean;
}

export interface SummaryFlags {
  hasHighS: boolean;
  hasNonCanonicalDer: boolean;
  hasWeirdSighash: boolean;
  hasRangeViolations: boolean;
  hasMultiInputSameKey: boolean;
  hasRReuseWithinTx: boolean;
}

export interface InspectTxResponse {
  ok: boolean;
  error?: string;

  network?: NetworkName;
  txid?: string;
  rawTxHex?: string;

  version?: number;
  locktime?: number;
  sizeBytes?: number;
  vsizeBytes?: number;
  weight?: number;

  totalInputSats?: number;
  totalOutputSats?: number;
  feeSats?: number;
  feeRateSatPerVbyte?: number;

  inputs?: TxInputAnalysis[];
  outputs?: TxOutputAnalysis[];
  summaryFlags?: SummaryFlags;
}

export interface InspectTxRequest {
  rawTxHex?: string;
  txid?: string;
}
