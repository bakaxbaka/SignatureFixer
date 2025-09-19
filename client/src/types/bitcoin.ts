export interface BitcoinAddress {
  address: string;
  networkType: 'mainnet' | 'testnet';
  addressType: 'P2PKH' | 'P2SH' | 'P2WPKH' | 'P2WSH' | 'unknown';
}

export interface UTXO {
  txid: string;
  vout: number;
  value: number; // in satoshis
  confirmations: number;
  script: string;
  address?: string;
}

export interface UTXOData {
  utxos: UTXO[];
  totalValue: number;
  totalUTXOs: number;
  source: 'blockchain.com' | 'blockstream.info' | 'sochain.com' | 'multiple';
}

export interface TransactionInput {
  txid: string;
  vout: number;
  script: string;
  sequence: number;
  signature?: ECDSASignature;
  witness?: string[];
}

export interface TransactionOutput {
  value: number;
  script: string;
  address?: string;
  scriptType?: 'P2PKH' | 'P2SH' | 'P2WPKH' | 'P2WSH' | 'OP_RETURN' | 'unknown';
}

export interface Transaction {
  txid: string;
  version: number;
  inputs: TransactionInput[];
  outputs: TransactionOutput[];
  locktime: number;
  size: number;
  weight?: number;
  fee?: number;
  confirmations?: number;
  blockHash?: string;
  blockHeight?: number;
  timestamp?: number;
}

export interface ECDSASignature {
  r: string;
  s: string;
  sighashType: number;
  publicKey: string;
  derEncoded: string;
  messageHash?: string;
  inputIndex?: number;
}

export interface VulnerabilityType {
  type: 'nonce_reuse' | 'biased_nonce' | 'sighash_single' | 'weak_entropy' | 'poor_randomness' | 'sequential_nonce';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  affectedSignatures: ECDSASignature[];
  affectedTransactions: string[];
  recoveredData?: {
    privateKey?: string;
    confidence?: number;
    method?: string;
    entropyScore?: number;
    patterns?: string[];
    rValue?: string;
  };
  educational: boolean;
  cveId?: string;
  references?: string[];
}

export interface NonceReuseResult {
  isVulnerable: boolean;
  rValue: string;
  affectedSignatures: ECDSASignature[];
  recoveredPrivateKey?: string;
  confidence: number;
  method: 'nonce_reuse_attack' | 'lattice_attack' | 'polynonce_attack';
  mathematical_proof?: {
    s1: string;
    s2: string;
    m1: string;
    m2: string;
    k: string;
    private_key: string;
  };
}

export interface SignatureAnalysis {
  totalSignatures: number;
  uniqueRValues: number;
  uniqueSValues: number;
  averageEntropyScore: number;
  weakPatterns: Array<{
    type: string;
    description: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    count: number;
    signatures: ECDSASignature[];
  }>;
  sighashDistribution: Record<string, number>;
  recommendedActions: string[];
}

export interface AnalysisResult {
  id: string;
  bitcoinAddress: string;
  networkType: 'mainnet' | 'testnet';
  utxoData?: UTXOData;
  vulnerabilities: VulnerabilityType[];
  signatureAnalysis: SignatureAnalysis;
  nonceReuse: NonceReuseResult[];
  recoveredKeys: Array<{
    privateKey: string;
    format: 'hex' | 'wif' | 'base58';
    method: string;
    confidence: number;
    educational: true;
  }>;
  analysisTimestamp: string;
  responseTime?: number;
}

export interface APIConnection {
  provider: 'blockchain_com' | 'blockstream' | 'sochain' | 'multiple';
  status: 'online' | 'error' | 'timeout' | 'rate_limited';
  responseTime: number;
  lastChecked: string;
  errorMessage?: string;
  requestCount: number;
  errorCount: number;
}

export interface BatchAnalysisJob {
  id: string;
  name: string;
  addresses: string[];
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress: number; // 0-100
  totalAddresses: number;
  processedAddresses: number;
  vulnerabilitiesFound: number;
  startedAt?: string;
  completedAt?: string;
  estimatedTimeRemaining?: number;
  results?: AnalysisResult[];
}

export interface SystemStatistics {
  totalScanned: number;
  nonceReuseFound: number;
  keysRecovered: number;
  criticalVulns: number;
  highVulns: number;
  mediumVulns: number;
  lowVulns: number;
  averageAnalysisTime: number;
  successRate: number;
  apiUptime: Record<string, number>;
}

export interface EducationalTopic {
  id: string;
  title: string;
  category: 'vulnerability' | 'prevention' | 'mathematics' | 'history' | 'tools';
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  description: string;
  content: string;
  codeExamples?: Array<{
    language: string;
    code: string;
    description: string;
  }>;
  references: Array<{
    title: string;
    url: string;
    type: 'paper' | 'article' | 'documentation' | 'tool';
  }>;
  tags: string[];
  viewCount: number;
  lastUpdated: string;
}

export interface WebSocketMessage {
  type: 'utxo_analysis' | 'vulnerability_analysis' | 'batch_progress' | 'batch_completed' | 'batch_error' | 'system_status';
  timestamp: string;
  data: any;
}

export interface BlockchainAPIResponse<T> {
  success: boolean;
  data: T;
  source: string;
  responseTime: number;
  cached?: boolean;
  error?: string;
}

export interface ErrorResponse {
  error: string;
  details?: string;
  code?: string;
  timestamp: string;
  requestId?: string;
}
