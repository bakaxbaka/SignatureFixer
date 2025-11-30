import { bitcoinService } from "./bitcoin";
import { cryptoAnalysis } from "./crypto";

interface ScanResult {
  blockHeight?: number;
  txid: string;
  address: string;
  signatures: Array<{
    r: string;
    s: string;
    messageHash: string;
    publicKey: string;
  }>;
  vulnerabilityType?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: number;
}

interface BlockScanProgress {
  currentBlock: number;
  totalBlocks: number;
  vulnerabilitiesFound: number;
  startTime: number;
}

interface MempoolScanResult {
  txid: string;
  size: number;
  fee: number;
  signatures: Array<{
    r: string;
    s: string;
    scriptPubKey?: string;
  }>;
  potentialVulnerability?: string;
}

export class BlockScanner {
  private isScanning = false;
  private scanProgress: BlockScanProgress | null = null;
  private rValueMap = new Map<string, Array<{ txid: string; signature: any }>>();

  async scanBlockRange(
    startBlock: number,
    endBlock: number,
    networkType: string = 'mainnet',
    onProgress?: (progress: BlockScanProgress) => void,
    onVulnerabilityFound?: (result: ScanResult) => void
  ): Promise<ScanResult[]> {
    if (this.isScanning) {
      throw new Error('Scan already in progress');
    }

    this.isScanning = true;
    const results: ScanResult[] = [];
    this.rValueMap.clear();

    try {
      this.scanProgress = {
        currentBlock: startBlock,
        totalBlocks: endBlock - startBlock + 1,
        vulnerabilitiesFound: 0,
        startTime: Date.now()
      };

      for (let height = startBlock; height <= endBlock; height++) {
        if (!this.isScanning) break;

        this.scanProgress.currentBlock = height;
        if (onProgress) {
          onProgress({ ...this.scanProgress });
        }

        try {
          const blockResults = await this.scanBlock(height, networkType);
          
          for (const result of blockResults) {
            results.push(result);
            this.scanProgress.vulnerabilitiesFound++;
            if (onVulnerabilityFound) {
              onVulnerabilityFound(result);
            }
          }
        } catch (error) {
          console.error(`Error scanning block ${height}:`, error);
        }

        await this.delay(100);
      }

      return results;
    } finally {
      this.isScanning = false;
      this.scanProgress = null;
    }
  }

  async scanBlock(blockHeight: number, networkType: string = 'mainnet'): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    try {
      const blockHash = await bitcoinService.getBlockHash(blockHeight, networkType);
      if (!blockHash) return results;

      const block = await bitcoinService.getBlock(blockHash, networkType);
      if (!block || !block.tx) return results;

      for (const txid of block.tx.slice(0, 50)) {
        try {
          const txResult = await this.analyzeTxSignatures(txid, networkType, blockHeight);
          if (txResult) {
            results.push(txResult);
          }
        } catch (error) {
          continue;
        }
      }
    } catch (error) {
      console.error(`Error scanning block ${blockHeight}:`, error);
    }

    return results;
  }

  async analyzeTxSignatures(
    txid: string,
    networkType: string = 'mainnet',
    blockHeight?: number
  ): Promise<ScanResult | null> {
    try {
      const tx = await bitcoinService.getTransactionDetails(txid, networkType);
      if (!tx || !tx.vin) return null;

      const signatures: ScanResult['signatures'] = [];

      for (const input of tx.vin) {
        if (!input.scriptSig) continue;

        const sigData = this.extractSignatureFromScript(input.scriptSig.hex || '');
        if (sigData) {
          signatures.push(sigData);

          const existingSignatures = this.rValueMap.get(sigData.r) || [];
          existingSignatures.push({ txid, signature: sigData });
          this.rValueMap.set(sigData.r, existingSignatures);

          if (existingSignatures.length >= 2) {
            return {
              blockHeight,
              txid,
              address: input.prevout?.scriptpubkey_address || 'unknown',
              signatures,
              vulnerabilityType: 'nonce_reuse',
              severity: 'critical',
              timestamp: Date.now()
            };
          }
        }
      }

      if (signatures.length > 0) {
        const patterns = cryptoAnalysis.analyzeSignaturePatterns(
          signatures.map(s => ({
            r: s.r,
            s: s.s,
            sighashType: 1,
            publicKey: s.publicKey,
            messageHash: s.messageHash
          }))
        );

        if (patterns.weakPatterns.length > 0) {
          const mostSevere = patterns.weakPatterns.reduce((a, b) => {
            const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
            return severityOrder[a.severity] > severityOrder[b.severity] ? a : b;
          });

          return {
            blockHeight,
            txid,
            address: 'unknown',
            signatures,
            vulnerabilityType: mostSevere.type,
            severity: mostSevere.severity,
            timestamp: Date.now()
          };
        }
      }

      return null;
    } catch (error) {
      return null;
    }
  }

  private extractSignatureFromScript(scriptHex: string): {
    r: string;
    s: string;
    messageHash: string;
    publicKey: string;
  } | null {
    try {
      if (scriptHex.length < 140) return null;

      let offset = 0;
      const sigLenHex = scriptHex.slice(offset, offset + 2);
      const sigLen = parseInt(sigLenHex, 16);
      offset += 2;

      if (sigLen < 68 || sigLen > 73) return null;

      const derSignature = scriptHex.slice(offset, offset + sigLen * 2);
      offset += sigLen * 2;

      const parsedSig = this.parseDERSignature(derSignature);
      if (!parsedSig) return null;

      const pubKeyLenHex = scriptHex.slice(offset, offset + 2);
      const pubKeyLen = parseInt(pubKeyLenHex, 16);
      offset += 2;

      let publicKey = '';
      if (pubKeyLen === 33 || pubKeyLen === 65) {
        publicKey = scriptHex.slice(offset, offset + pubKeyLen * 2);
      }

      return {
        r: parsedSig.r,
        s: parsedSig.s,
        messageHash: '',
        publicKey
      };
    } catch (error) {
      return null;
    }
  }

  private parseDERSignature(derHex: string): { r: string; s: string } | null {
    try {
      let offset = 0;

      if (derHex.slice(offset, offset + 2) !== '30') return null;
      offset += 2;

      const totalLen = parseInt(derHex.slice(offset, offset + 2), 16);
      offset += 2;

      if (derHex.slice(offset, offset + 2) !== '02') return null;
      offset += 2;

      const rLen = parseInt(derHex.slice(offset, offset + 2), 16);
      offset += 2;

      let r = derHex.slice(offset, offset + rLen * 2);
      offset += rLen * 2;

      if (r.startsWith('00')) {
        r = r.slice(2);
      }
      r = r.padStart(64, '0');

      if (derHex.slice(offset, offset + 2) !== '02') return null;
      offset += 2;

      const sLen = parseInt(derHex.slice(offset, offset + 2), 16);
      offset += 2;

      let s = derHex.slice(offset, offset + sLen * 2);

      if (s.startsWith('00')) {
        s = s.slice(2);
      }
      s = s.padStart(64, '0');

      return { r, s };
    } catch (error) {
      return null;
    }
  }

  async scanMempool(
    networkType: string = 'mainnet',
    onTxFound?: (result: MempoolScanResult) => void
  ): Promise<MempoolScanResult[]> {
    const results: MempoolScanResult[] = [];

    try {
      const mempoolTxs = await bitcoinService.getMempoolTxids(networkType);
      
      for (const txid of mempoolTxs.slice(0, 100)) {
        try {
          const tx = await bitcoinService.getTransactionDetails(txid, networkType);
          if (!tx) continue;

          const signatures: MempoolScanResult['signatures'] = [];

          for (const input of tx.vin || []) {
            if (input.scriptsig) {
              const sigData = this.extractSignatureFromScript(input.scriptsig || '');
              if (sigData) {
                signatures.push({
                  r: sigData.r,
                  s: sigData.s
                });
              }
            }
          }

          const result: MempoolScanResult = {
            txid,
            size: tx.size || tx.weight / 4 || 0,
            fee: tx.fee || 0,
            signatures,
            potentialVulnerability: undefined
          };

          const existingR = signatures.some(s => this.rValueMap.has(s.r));
          if (existingR) {
            result.potentialVulnerability = 'possible_nonce_reuse';
          }

          results.push(result);
          if (onTxFound) {
            onTxFound(result);
          }

          await this.delay(50);
        } catch (error) {
          continue;
        }
      }
    } catch (error) {
      console.error('Error scanning mempool:', error);
    }

    return results;
  }

  getScanProgress(): BlockScanProgress | null {
    return this.scanProgress ? { ...this.scanProgress } : null;
  }

  stopScan(): void {
    this.isScanning = false;
  }

  getRValueStatistics(): {
    totalUniqueR: number;
    reusedR: number;
    rValueDistribution: Array<{ r: string; count: number }>;
  } {
    const stats = {
      totalUniqueR: this.rValueMap.size,
      reusedR: 0,
      rValueDistribution: [] as Array<{ r: string; count: number }>
    };

    for (const [r, signatures] of this.rValueMap) {
      if (signatures.length > 1) {
        stats.reusedR++;
        stats.rValueDistribution.push({
          r: r.slice(0, 16) + '...',
          count: signatures.length
        });
      }
    }

    stats.rValueDistribution.sort((a, b) => b.count - a.count);
    stats.rValueDistribution = stats.rValueDistribution.slice(0, 10);

    return stats;
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

export const blockScanner = new BlockScanner();
