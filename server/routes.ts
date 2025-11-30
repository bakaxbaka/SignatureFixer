import type { Express } from "express";
import { createServer, type Server } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { storage } from "./storage";
import { bitcoinService } from "./services/bitcoin";
import { vulnerabilityService } from "./services/vulnerability";
import { ecdsaRecovery, cryptoAnalysis } from "./services/crypto";
import { blockScanner } from "./services/scanner";
import { insertAnalysisResultSchema, insertBatchAnalysisSchema } from "@shared/schema";
import { z } from "zod";

export async function registerRoutes(app: Express): Promise<Server> {
  const httpServer = createServer(app);

  // WebSocket server for real-time updates
  const wss = new WebSocketServer({ server: httpServer, path: '/ws' });

  wss.on('connection', (ws) => {
    console.log('WebSocket client connected');

    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message.toString());
        console.log('WebSocket message received:', data);
      } catch (error) {
        console.error('Invalid WebSocket message:', error);
      }
    });

    ws.on('close', () => {
      console.log('WebSocket client disconnected');
    });
  });

  // Broadcast function for real-time updates
  const broadcast = (data: any) => {
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(data));
      }
    });
  };

  // UTXO Analysis endpoint
  app.post('/api/utxos', async (req, res) => {
    try {
      const { address, networkType = 'mainnet' } = req.body;

      if (!address) {
        return res.status(400).json({ error: 'Bitcoin address is required' });
      }

      const startTime = Date.now();
      const utxoData = await bitcoinService.fetchUTXOs(address, networkType);
      const responseTime = Date.now() - startTime;

      // Record API metrics
      await storage.recordApiMetric({
        apiProvider: 'multiple',
        endpoint: '/api/utxos',
        responseTime,
        statusCode: 200,
        requestCount: 1,
        errorCount: 0,
      });

      // Save analysis result
      const analysisResult = await storage.saveAnalysisResult({
        bitcoinAddress: address,
        networkType,
        utxoData,
        vulnerabilities: null,
        signatureAnalysis: null,
        nonceReuse: null,
        recoveredKeys: null,
      });

      // Broadcast update
      broadcast({
        type: 'utxo_analysis',
        address,
        utxoCount: utxoData?.utxos?.length || 0,
      });

      res.json({
        success: true,
        data: utxoData,
        analysisId: analysisResult.id,
        responseTime,
      });
    } catch (error) {
      console.error('UTXO analysis error:', error);

      // Record error metric
      await storage.recordApiMetric({
        apiProvider: 'multiple',
        endpoint: '/api/utxos',
        responseTime: 0,
        statusCode: 500,
        requestCount: 1,
        errorCount: 1,
      });

      res.status(500).json({ 
        error: 'Failed to analyze UTXOs',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // Get Raw Transaction endpoint
  app.post('/api/get-raw-transaction', async (req, res) => {
    try {
      const { txid, networkType = 'mainnet' } = req.body;

      if (!txid) {
        return res.status(400).json({ error: 'Transaction ID is required' });
      }

      const startTime = Date.now();
      const rawTransaction = await bitcoinService.getRawTransaction(txid, networkType);
      const responseTime = Date.now() - startTime;

      res.json({
        success: true,
        data: {
          txid,
          rawTransaction,
          networkType,
        },
        responseTime,
      });
    } catch (error) {
      console.error('Get raw transaction error:', error);
      res.status(500).json({ 
        error: 'Failed to get raw transaction',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // Transaction Decoder endpoint
  app.post('/api/decode-transaction', async (req, res) => {
    try {
      const { rawTransaction } = req.body;

      if (!rawTransaction) {
        return res.status(400).json({ error: 'Raw transaction hex is required' });
      }

      const startTime = Date.now();
      const decodedData = await bitcoinService.decodeTransaction(rawTransaction);
      const responseTime = Date.now() - startTime;

      // Analyze signatures for vulnerabilities
      const vulnerabilityAnalysis = await vulnerabilityService.analyzeSignatures(decodedData.signatures || []);

      res.json({
        success: true,
        data: {
          ...decodedData,
          vulnerabilityAnalysis,
        },
        responseTime,
      });
    } catch (error) {
      console.error('Transaction decode error:', error);
      res.status(500).json({ 
        error: 'Failed to decode transaction',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // Vulnerability testing endpoint - uses same blockchain.info approach as analyze-address
  app.post('/api/vulnerability-test', async (req, res) => {
    try {
      const { address, limit = 1000 } = req.body;

      if (!address) {
        return res.status(400).json({
          error: 'Bitcoin address is required'
        });
      }

      console.log(`\n========== COMPREHENSIVE VULNERABILITY ANALYSIS ==========`);
      console.log(`Address: ${address}`);
      
      // Fetch ALL transactions from blockchain.info in a single API call (no per-transaction calls!)
      const addressData = await bitcoinService.fetchAddressDataComplete(address, limit);
      const transactions = addressData.txs || [];
      
      console.log(`✓ Fetched ${transactions.length} transactions from blockchain.info/rawaddr\n`);

      if (transactions.length === 0) {
        return res.json({
          success: true,
          data: {
            address,
            totalTransactions: 0,
            vulnerabilities: [],
            signatureAnalysis: {
              totalSignatures: 0,
              uniqueRValues: 0,
              weakPatterns: [],
              entropyAnalysis: { entropyScore: 0, patterns: [], recommendation: 'No data to analyze' }
            },
            nonceReuse: [],
            recoveredKeys: [],
            addressInfo: { tx_count: 0, total_received: 0, total_sent: 0 }
          }
        });
      }

      // Analyze transactions directly from blockchain.info response (NO individual API calls!)
      const rValueMap = new Map<string, Array<{ txid: string; inputIndex: number; r: string; s: string }>>();
      const allSignatures: any[] = [];
      const weakSignatures: any[] = [];
      let totalExtracted = 0;

      console.log(`========== ANALYZING ${transactions.length} TRANSACTIONS ==========`);
      
      for (let txIndex = 0; txIndex < transactions.length; txIndex++) {
        const tx = transactions[txIndex];
        console.log(`[${txIndex + 1}/${transactions.length}] TX: ${tx.hash}`);
        
        try {
          if (!tx.inputs || tx.inputs.length === 0) {
            console.log(`  └─ No inputs`);
            continue;
          }

          console.log(`  └─ Found ${tx.inputs.length} input(s)`);

          for (let inputIdx = 0; inputIdx < tx.inputs.length; inputIdx++) {
            const input = tx.inputs[inputIdx];
            const script = input.script || input.scriptSig || '';
            
            if (!script) continue;

            try {
              const sig = cryptoAnalysis.parseBitcoinSignature(script);
              
              if (sig.isValid && sig.r && sig.s) {
                totalExtracted++;
                console.log(`    ✓ Input ${inputIdx}: R=${sig.r.substring(0, 16)}... PubKey=${sig.publicKey?.substring(0, 16)}...`);
                
                allSignatures.push({
                  txid: tx.hash,
                  inputIndex: inputIdx,
                  r: sig.r,
                  s: sig.s,
                  messageHash: tx.hash,
                  publicKey: sig.publicKey,
                  sighashType: sig.sighashType
                });

                // Check malleability
                const malleability = cryptoAnalysis.detectSignatureMalleability([{
                  r: sig.r,
                  s: sig.s,
                  publicKey: input.prev_out?.addr || '',
                  messageHash: '',
                  sighashType: 1
                }]);

                if (malleability.hasMalleability) {
                  console.log(`      ⚠ BIP62 Malleability`);
                  weakSignatures.push({
                    txid: tx.hash,
                    inputIndex: inputIdx,
                    type: 'malleability_violation',
                    severity: 'high',
                    s: sig.s,
                    details: 'BIP62 violation: S > n/2'
                  });
                }

                // Index by R value for nonce reuse
                const rValue = sig.r;
                const existing = rValueMap.get(rValue) || [];
                existing.push({
                  txid: tx.hash,
                  inputIndex: inputIdx,
                  r: sig.r,
                  s: sig.s
                });
                rValueMap.set(rValue, existing);
              }
            } catch (sigErr) {
              continue;
            }
          }
        } catch (txErr) {
          continue;
        }
      }
      
      console.log(`\n========== SIGNATURE EXTRACTION COMPLETE ==========`);
      console.log(`Total signatures: ${totalExtracted}`);
      console.log(`Unique R values: ${rValueMap.size}`);

      // Detect nonce reuse
      console.log(`\n========== ANALYZING NONCE REUSE ==========`);
      const nonceReuseDetails: any[] = [];
      let nonceReuseCount = 0;
      
      for (const [rValue, signatures] of rValueMap.entries()) {
        if (signatures.length >= 2) {
          nonceReuseCount++;
          console.log(`[NONCE REUSE #${nonceReuseCount}] R=${rValue.substring(0, 32)}... appears in ${signatures.length} transactions`);
          
          nonceReuseDetails.push({
            rValue: rValue.substring(0, 16) + '...',
            count: signatures.length,
            severity: 'critical',
            transactions: signatures.map(s => ({ txid: s.txid, inputIndex: s.inputIndex })),
            privateKeyRecoveryPossible: true
          });

          for (const sig of signatures) {
            weakSignatures.push({
              txid: sig.txid,
              inputIndex: sig.inputIndex,
              type: 'nonce_reuse',
              severity: 'critical',
              r: sig.r,
              s: sig.s
            });
          }
        }
      }
      
      console.log(`✓ Nonce reuse groups found: ${nonceReuseCount}\n`);

      // Build response
      const vulnerabilities: any[] = [];
      
      if (nonceReuseCount > 0) {
        vulnerabilities.push({
          type: 'nonce_reuse',
          severity: 'critical',
          description: `${nonceReuseCount} nonce reuse group(s) detected. Private key recovery possible.`,
          affectedTransactions: nonceReuseDetails.length,
          educational: true
        });
      }

      if (weakSignatures.filter(s => s.severity === 'high').length > 0) {
        vulnerabilities.push({
          type: 'signature_malleability',
          severity: 'high',
          description: `${weakSignatures.filter(s => s.severity === 'high').length} malleability violations detected`,
          educational: true
        });
      }

      res.json({
        success: true,
        data: {
          address,
          totalTransactions: transactions.length,
          vulnerabilities,
          signatureAnalysis: {
            totalSignatures: totalExtracted,
            uniqueRValues: rValueMap.size,
            weakPatterns: weakSignatures,
            entropyAnalysis: { entropyScore: totalExtracted > 0 ? 75 : 0, patterns: [], recommendation: 'Analysis complete' }
          },
          nonceReuse: nonceReuseDetails,
          recoveredKeys: [],
          addressInfo: {
            tx_count: addressData.n_tx,
            total_received: addressData.total_received,
            total_sent: addressData.total_sent,
            final_balance: addressData.final_balance
          }
        }
      });

    } catch (error) {
      console.error('Vulnerability test error:', error);
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      });
    }
  });

  // Signature forgery demonstration endpoint
  app.post('/api/forge-signature', async (req, res) => {
    try {
      const { signature, type = 'malleability' } = req.body;

      if (!signature || !signature.r || !signature.s) {
        return res.status(400).json({
          error: 'Valid signature with r and s values is required'
        });
      }

      let result;

      switch (type) {
        case 'malleability':
          result = bitcoinService.demonstrateSignatureForgery(signature);
          break;

        case 'deserialize':
          result = {
            original: signature,
            deserialized: {
              derEncoded: signature.derEncoded,
              rHex: signature.r,
              sHex: signature.s,
              rDecimal: BigInt('0x' + signature.r).toString(),
              sDecimal: BigInt('0x' + signature.s).toString(),
              sighashType: signature.sighashType,
              sighashName: getSighashTypeName(signature.sighashType)
            },
            educational: true
          };
          break;

        default:
          return res.status(400).json({
            error: 'Invalid forgery type. Use "malleability" or "deserialize"'
          });
      }

      res.json({
        success: true,
        data: result
      });

    } catch (error) {
      console.error('Signature forgery error:', error);
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      });
    }
  });

  // Transaction creation endpoint
  app.post('/api/create-transaction', async (req, res) => {
    try {
      const { fromAddress, toAddress, amount, privateKey } = req.body;

      if (!fromAddress || !toAddress || !amount || !privateKey) {
        return res.status(400).json({
          error: 'All fields are required: fromAddress, toAddress, amount, privateKey'
        });
      }

      // Create a mock transaction for educational purposes
      const result = await bitcoinService.createEducationalTransaction({
        fromAddress,
        toAddress,
        amount: parseInt(amount),
        privateKey
      });

      res.json({
        success: true,
        data: result
      });

    } catch (error) {
      console.error('Transaction creation error:', error);
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      });
    }
  });

  // Create unsigned raw transaction
  app.post('/api/create-raw-transaction', async (req, res) => {
    try {
      const { version, inputs, outputs, locktime } = req.body;

      if (!inputs || !Array.isArray(inputs) || inputs.length === 0) {
        return res.status(400).json({
          error: 'At least one input is required'
        });
      }

      if (!outputs || !Array.isArray(outputs) || outputs.length === 0) {
        return res.status(400).json({
          error: 'At least one output is required'
        });
      }

      // Create unsigned raw transaction
      const result = await bitcoinService.createUnsignedRawTransaction({
        version: parseInt(version) || 1,
        inputs,
        outputs,
        locktime: parseInt(locktime) || 0
      });

      res.json({
        success: true,
        data: result
      });

    } catch (error) {
      console.error('Raw transaction creation error:', error);
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      });
    }
  });

  // Sign raw transaction with DER R and S values
  app.post('/api/sign-transaction-der', async (req, res) => {
    try {
      const { rawTransaction, rValue, sValue, sighashType, publicKey } = req.body;

      if (!rawTransaction || !rValue || !sValue) {
        return res.status(400).json({
          error: 'rawTransaction, rValue, and sValue are required'
        });
      }

      // Sign transaction using parsed R and S values
      const result = await bitcoinService.signRawTransactionWithDER({
        rawTransaction,
        rValue,
        sValue,
        sighashType: sighashType || 0x01,
        publicKey
      });

      res.json({
        success: true,
        data: result
      });

    } catch (error) {
      console.error('DER signing error:', error);
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      });
    }
  });

  // Signature malleability detection endpoint - REAL formulas, no mock data
  app.post('/api/signature-malleability', async (req, res) => {
    try {
      const { signatures } = req.body;

      if (!signatures || !Array.isArray(signatures)) {
        return res.status(400).json({
          error: 'Array of signatures required with r, s, publicKey fields'
        });
      }

      // Use real ECDSA crypto analysis with proper formulas
      const result = cryptoAnalysis.detectSignatureMalleability(signatures);

      res.json({
        success: true,
        data: result
      });

    } catch (error) {
      console.error('Signature malleability check error:', error);
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Invalid signature format'
      });
    }
  });

  // DER signature crafting endpoint - real DER encoding, no mock data
  app.post('/api/der-signature', async (req, res) => {
    try {
      const { r, s, makeNonCanonical = false } = req.body;

      if (!r || !s) {
        return res.status(400).json({
          error: 'R and S values required as hex strings'
        });
      }

      // Use real DER encoding with proper byte construction
      const result = cryptoAnalysis.craftDERSignature(r, s, makeNonCanonical);

      res.json({
        success: true,
        data: result
      });

    } catch (error) {
      console.error('DER crafting error:', error);
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Invalid R/S values'
      });
    }
  });

  // DER signature validation endpoint - real parsing, no mock data
  app.post('/api/validate-der', async (req, res) => {
    try {
      const { derHex } = req.body;

      if (!derHex) {
        return res.status(400).json({
          error: 'DER encoded signature hex string required'
        });
      }

      // Use real DER parsing with proper byte-level validation
      const result = cryptoAnalysis.validateDERSignature(derHex);

      res.json({
        success: true,
        data: result
      });

    } catch (error) {
      console.error('DER validation error:', error);
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Invalid DER signature'
      });
    }
  });

  // Signature forgery endpoint for malleability demonstration
  app.post('/api/forge-signature', async (req, res) => {
    try {
      const { rawTransaction, malleabilityType } = req.body;

      if (!rawTransaction) {
        return res.status(400).json({
          error: 'Raw transaction is required'
        });
      }

      // Create malleable signature for educational purposes
      const result = await bitcoinService.createMalleableSignature({
        rawTransaction,
        malleabilityType: malleabilityType || 'sighash_single'
      });

      res.json({
        success: true,
        data: result
      });

    } catch (error) {
      console.error('Signature forgery error:', error);
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      });
    }
  });

  // Helper method for SIGHASH type names
  function getSighashTypeName(type: number): string {
    const baseType = type & 0x1f;
    let name = "";

    switch (baseType) {
      case 0x01: name = "SIGHASH_ALL"; break;
      case 0x02: name = "SIGHASH_NONE"; break;
      case 0x03: name = "SIGHASH_SINGLE"; break;
      default: name = "UNKNOWN";
    }

    if (type & 0x80) {
      name += " | SIGHASH_ANYONECANPAY";
    }

    return `${name} (0x${type.toString(16).padStart(2, '0')})`;
  }

  // API Status endpoint
  app.get('/api/status', async (req, res) => {
    try {
      const apiStatus = await storage.getApiStatus();
      const stats = await storage.getVulnerabilityStats();

      res.json({
        success: true,
        data: {
          apiConnections: apiStatus,
          statistics: stats,
          timestamp: new Date().toISOString(),
        },
      });
    } catch (error) {
      console.error('Status check error:', error);
      res.status(500).json({ 
        error: 'Failed to get system status',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // Batch Analysis endpoints
  app.post('/api/batch-analysis', async (req, res) => {
    try {
      const batchData = insertBatchAnalysisSchema.parse(req.body);

      const batchAnalysis = await storage.createBatchAnalysis(batchData);

      // Start batch processing (this would be done in background)
      vulnerabilityService.processBatchAnalysis(batchAnalysis.id, broadcast);

      res.json({
        success: true,
        data: batchAnalysis,
      });
    } catch (error) {
      console.error('Batch analysis error:', error);
      res.status(500).json({ 
        error: 'Failed to start batch analysis',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  app.get('/api/batch-analysis/:id', async (req, res) => {
    try {
      const { id } = req.params;
      const batchAnalysis = await storage.getBatchAnalysis(id);

      if (!batchAnalysis) {
        return res.status(404).json({ error: 'Batch analysis not found' });
      }

      res.json({
        success: true,
        data: batchAnalysis,
      });
    } catch (error) {
      console.error('Get batch analysis error:', error);
      res.status(500).json({ 
        error: 'Failed to get batch analysis',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // Educational Content endpoints
  app.get('/api/educational-content', async (req, res) => {
    try {
      const { category } = req.query;

      let content;
      if (category && typeof category === 'string') {
        content = await storage.getEducationalContentByCategory(category);
      } else {
        content = await storage.getEducationalContent();
      }

      res.json({
        success: true,
        data: content,
      });
    } catch (error) {
      console.error('Educational content error:', error);
      res.status(500).json({ 
        error: 'Failed to get educational content',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  app.post('/api/educational-content/:id/view', async (req, res) => {
    try {
      const { id } = req.params;
      await storage.incrementContentView(id);

      res.json({
        success: true,
        message: 'View count incremented',
      });
    } catch (error) {
      console.error('View increment error:', error);
      res.status(500).json({ 
        error: 'Failed to increment view count',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // Analysis History endpoint
  app.get('/api/analysis-history', async (req, res) => {
    try {
      const { address, limit = 50 } = req.query;

      let results;
      if (address && typeof address === 'string') {
        results = await storage.getAnalysisResultsByAddress(address);
      } else {
        results = await storage.getRecentAnalysisResults(Number(limit));
      }

      res.json({
        success: true,
        data: results,
      });
    } catch (error) {
      console.error('Analysis history error:', error);
      res.status(500).json({ 
        error: 'Failed to get analysis history',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // Vulnerability Patterns endpoint
  app.get('/api/vulnerability-patterns', async (req, res) => {
    try {
      const { type } = req.query;

      let patterns;
      if (type && typeof type === 'string') {
        patterns = await storage.getVulnerabilityPatternsByType(type);
      } else {
        patterns = await storage.getVulnerabilityPatterns();
      }

      res.json({
        success: true,
        data: patterns,
      });
    } catch (error) {
      console.error('Vulnerability patterns error:', error);
      res.status(500).json({ 
        error: 'Failed to get vulnerability patterns',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // ECDSA Nonce Reuse Recovery endpoint
  app.post('/api/ecdsa/recover-nonce-reuse', async (req, res) => {
    try {
      const { r, s1, s2, m1, m2 } = req.body;

      if (!r || !s1 || !s2 || !m1 || !m2) {
        return res.status(400).json({ 
          error: 'Missing required parameters: r, s1, s2, m1, m2' 
        });
      }

      const result = await ecdsaRecovery.recoverFromNonceReuse({ r, s1, s2, m1, m2 });

      if (result.success) {
        broadcast({
          type: 'key_recovered',
          method: 'nonce_reuse',
          address: result.address,
        });
      }

      res.json({
        success: true,
        data: result,
      });
    } catch (error) {
      console.error('ECDSA nonce reuse recovery error:', error);
      res.status(500).json({ 
        error: 'Failed to recover private key',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // ECDSA Known Nonce Recovery endpoint
  app.post('/api/ecdsa/recover-known-nonce', async (req, res) => {
    try {
      const { r, s, m, k } = req.body;

      if (!r || !s || !m || !k) {
        return res.status(400).json({ 
          error: 'Missing required parameters: r, s, m, k' 
        });
      }

      const result = await ecdsaRecovery.recoverFromKnownNonce({ r, s, m, k });

      if (result.success) {
        broadcast({
          type: 'key_recovered',
          method: 'known_nonce',
          address: result.address,
        });
      }

      res.json({
        success: true,
        data: result,
      });
    } catch (error) {
      console.error('ECDSA known nonce recovery error:', error);
      res.status(500).json({ 
        error: 'Failed to recover private key',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // ECDSA Curve Parameters endpoint
  app.get('/api/ecdsa/curve-params', async (req, res) => {
    try {
      res.json({
        success: true,
        data: {
          curve: 'secp256k1',
          p: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F',
          n: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',
          Gx: '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
          Gy: '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8',
          a: '0',
          b: '7',
          equation: 'y² = x³ + 7',
        },
      });
    } catch (error) {
      console.error('Curve params error:', error);
      res.status(500).json({ 
        error: 'Failed to get curve parameters',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // Block Scanner endpoints
  app.post('/api/scanner/scan-blocks', async (req, res) => {
    try {
      const { startBlock, endBlock, networkType = 'mainnet' } = req.body;

      if (!startBlock || !endBlock) {
        return res.status(400).json({ 
          error: 'Missing required parameters: startBlock, endBlock' 
        });
      }

      if (endBlock - startBlock > 100) {
        return res.status(400).json({ 
          error: 'Maximum scan range is 100 blocks' 
        });
      }

      const results = await blockScanner.scanBlockRange(
        startBlock,
        endBlock,
        networkType,
        (progress) => {
          broadcast({
            type: 'scan_progress',
            ...progress,
          });
        },
        (vulnerability) => {
          broadcast({
            type: 'vulnerability_found',
            ...vulnerability,
          });
        }
      );

      res.json({
        success: true,
        data: {
          scannedBlocks: endBlock - startBlock + 1,
          vulnerabilitiesFound: results.length,
          results,
        },
      });
    } catch (error) {
      console.error('Block scan error:', error);
      res.status(500).json({ 
        error: 'Failed to scan blocks',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  app.post('/api/scanner/scan-mempool', async (req, res) => {
    try {
      const { networkType = 'mainnet' } = req.body;

      const results = await blockScanner.scanMempool(
        networkType,
        (tx) => {
          if (tx.potentialVulnerability) {
            broadcast({
              type: 'mempool_vulnerability',
              txid: tx.txid,
              vulnerability: tx.potentialVulnerability,
            });
          }
        }
      );

      res.json({
        success: true,
        data: {
          transactionsScanned: results.length,
          vulnerabilities: results.filter(r => r.potentialVulnerability).length,
          results,
        },
      });
    } catch (error) {
      console.error('Mempool scan error:', error);
      res.status(500).json({ 
        error: 'Failed to scan mempool',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  app.get('/api/scanner/progress', async (req, res) => {
    try {
      const progress = blockScanner.getScanProgress();
      res.json({
        success: true,
        data: progress,
      });
    } catch (error) {
      console.error('Scanner progress error:', error);
      res.status(500).json({ 
        error: 'Failed to get scan progress',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  app.post('/api/scanner/stop', async (req, res) => {
    try {
      blockScanner.stopScan();
      res.json({
        success: true,
        message: 'Scan stopped',
      });
    } catch (error) {
      console.error('Scanner stop error:', error);
      res.status(500).json({ 
        error: 'Failed to stop scan',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  app.get('/api/scanner/statistics', async (req, res) => {
    try {
      const stats = blockScanner.getRValueStatistics();
      res.json({
        success: true,
        data: stats,
      });
    } catch (error) {
      console.error('Scanner statistics error:', error);
      res.status(500).json({ 
        error: 'Failed to get scanner statistics',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  app.get('/api/blockchain/height', async (req, res) => {
    try {
      const { networkType = 'mainnet' } = req.query;
      const height = await bitcoinService.getBlockHeight(networkType as string);
      res.json({
        success: true,
        data: { height },
      });
    } catch (error) {
      console.error('Block height error:', error);
      res.status(500).json({ 
        error: 'Failed to get block height',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // Vulnerability logs endpoints
  app.get('/api/vulnerability-logs', async (req, res) => {
    try {
      const logs = await storage.getAllVulnerabilityLogs(100);
      res.json({ success: true, data: logs });
    } catch (error) {
      res.status(500).json({ error: 'Failed to fetch vulnerability logs' });
    }
  });

  app.get('/api/vulnerability-logs/address/:address', async (req, res) => {
    try {
      const logs = await storage.getVulnerabilityLogsByAddress(req.params.address);
      res.json({ success: true, data: logs });
    } catch (error) {
      res.status(500).json({ error: 'Failed to fetch vulnerability logs' });
    }
  });

  app.get('/api/vulnerability-logs/type/:type', async (req, res) => {
    try {
      const logs = await storage.getVulnerabilityLogsByType(req.params.type);
      res.json({ success: true, data: logs });
    } catch (error) {
      res.status(500).json({ error: 'Failed to fetch vulnerability logs' });
    }
  });

  app.post('/api/vulnerability-logs', async (req, res) => {
    try {
      const log = await storage.saveVulnerabilityLog(req.body);
      broadcast({ type: 'vulnerability_detected', log });
      res.json({ success: true, data: log });
    } catch (error) {
      res.status(500).json({ error: 'Failed to save vulnerability log' });
    }
  });

  // Nonce reuse history endpoints
  app.get('/api/nonce-reuse-history/address/:address', async (req, res) => {
    try {
      const history = await storage.getNonceReuseHistoryByAddress(req.params.address);
      res.json({ success: true, data: history });
    } catch (error) {
      res.status(500).json({ error: 'Failed to fetch nonce reuse history' });
    }
  });

  app.post('/api/nonce-reuse-history', async (req, res) => {
    try {
      const history = await storage.saveNonceReuseHistory(req.body);
      broadcast({ type: 'nonce_reuse_detected', history });
      res.json({ success: true, data: history });
    } catch (error) {
      res.status(500).json({ error: 'Failed to save nonce reuse history' });
    }
  });

  // Individual Address Analysis - WebScrapeHelper pattern
  // Fetches ALL transactions for an address and analyzes each one
  app.post('/api/analyze-address', async (req, res) => {
    try {
      const { address, limit = 1000 } = req.body;

      if (!address) {
        return res.status(400).json({ error: 'Bitcoin address required' });
      }

      // Fetch complete address data with all transactions from blockchain.info
      const addressData = await bitcoinService.fetchAddressDataComplete(address, limit);

      // Extract transaction list
      const transactions = addressData.txs || [];
      if (transactions.length === 0) {
        return res.json({
          success: true,
          data: {
            address,
            totalTransactions: 0,
            analysis: {
              totalSignaturesExtracted: 0,
              nonceReuseGroupsFound: 0,
              criticalVulnerabilities: 0,
              weakSignatures: []
            },
            nonceReuseDetails: [],
            addressInfo: { tx_count: 0, total_received: 0, total_sent: 0 }
          }
        });
      }

      // Analyze each transaction directly from blockchain.info rawaddr response (NO individual API calls!)
      console.log(`\n========== ANALYZING ${transactions.length} TRANSACTIONS FOR ADDRESS: ${address} ==========`);
      console.log(`✓ All transaction data already fetched from blockchain.info/rawaddr (single API call)\n`);
      
      const rValueMap = new Map<string, Array<{ txid: string; inputIndex: number; r: string; s: string; input_index: number }>>();
      const allSignatures: any[] = [];
      const weakSignatures: any[] = [];
      let totalExtracted = 0;

      // Process transactions from the rawaddr response directly (no additional API calls needed!)
      for (let txIndex = 0; txIndex < transactions.length; txIndex++) {
        const tx = transactions[txIndex];
        console.log(`[${txIndex + 1}/${transactions.length}] TX: ${tx.hash}`);
        
        try {
          // Use inputs directly from blockchain.info rawaddr response
          if (!tx.inputs || tx.inputs.length === 0) {
            console.log(`  └─ ✗ No inputs found`);
            continue;
          }

          console.log(`  └─ Found ${tx.inputs.length} input(s) - extracting signatures...`);

          for (let inputIdx = 0; inputIdx < tx.inputs.length; inputIdx++) {
            const input = tx.inputs[inputIdx];
            
            // blockchain.info provides script field
            const script = input.script || input.scriptSig || '';
            if (!script) {
              continue;
            }

            try {
              // Extract signature using Bitcoin-specific parser (extracts r, s, sighash, pubkey)
              const sig = cryptoAnalysis.parseBitcoinSignature(script);
              
              if (sig.isValid && sig.r && sig.s) {
                totalExtracted++;
                console.log(`    ✓ Input ${inputIdx}: R=${sig.r.substring(0, 16)}... S=${sig.s.substring(0, 16)}... PubKey=${sig.publicKey?.substring(0, 16)}...`);
                console.log(`       Sighash: ${sig.sighashType === 1 ? 'SIGHASH_ALL' : 'OTHER'}`);
                
                allSignatures.push({
                  txid: tx.hash,
                  inputIndex: inputIdx,
                  r: sig.r,
                  s: sig.s,
                  publicKey: sig.publicKey,
                  sighashType: sig.sighashType
                });

                // Check for malleability (BIP62 violation)
                const malleability = cryptoAnalysis.detectSignatureMalleability([{
                  r: sig.r,
                  s: sig.s,
                  publicKey: input.prev_out?.addr || '',
                  messageHash: '',
                  sighashType: 1
                }]);

                if (malleability.hasMalleability) {
                  console.log(`      ⚠ BIP62 Malleability detected`);
                  weakSignatures.push({
                    txid: tx.hash,
                    inputIndex: inputIdx,
                    type: 'malleability_violation',
                    severity: 'high',
                    s: sig.s,
                    details: 'BIP62 violation: S > n/2'
                  });
                }

                // Index by R value for nonce reuse
                const rValue = sig.r;
                const existing = rValueMap.get(rValue) || [];
                existing.push({
                  txid: tx.hash,
                  inputIndex: inputIdx,
                  r: sig.r,
                  s: sig.s,
                  input_index: inputIdx
                });
                rValueMap.set(rValue, existing);
              }
            } catch (sigErr) {
              continue;
            }
          }
        } catch (txErr) {
          continue;
        }
      }
      
      console.log(`\n========== SIGNATURE EXTRACTION COMPLETE ==========`);
      console.log(`Total signatures extracted: ${totalExtracted}`);
      console.log(`Unique R values found: ${rValueMap.size}`);

      // Find nonce reuse vulnerabilities
      console.log(`\n========== ANALYZING NONCE REUSE ==========`);
      const nonceReuseDetails: any[] = [];
      let nonceReuseCount = 0;
      
      for (const [rValue, signatures] of rValueMap.entries()) {
        if (signatures.length >= 2) {
          nonceReuseCount++;
          console.log(`\n[NONCE REUSE #${nonceReuseCount}] R value: ${rValue.substring(0, 32)}...`);
          console.log(`  Appears in ${signatures.length} transactions:`);
          
          for (let i = 0; i < signatures.length; i++) {
            const sig = signatures[i];
            console.log(`    ${i + 1}. TxID: ${sig.txid}`);
            console.log(`       Input: ${sig.inputIndex}`);
            console.log(`       S value: ${sig.s.substring(0, 32)}...`);
          }
          
          console.log(`  ✓ CRITICAL: Same nonce k detected - private key recovery possible!`);
          console.log(`  Formula: k = (z1-z2)/(s1-s2) mod n, then x = (s*k - m) * r⁻¹ mod n`);
          
          nonceReuseDetails.push({
            rValue: rValue.substring(0, 16) + '...',
            count: signatures.length,
            severity: 'critical',
            transactions: signatures.map(s => ({
              txid: s.txid,
              inputIndex: s.inputIndex,
              s: s.s
            })),
            privateKeyRecoveryPossible: true,
            formula: 'k = (z1-z2)/(s1-s2) mod n, then x = (s*k - m) * r⁻¹ mod n'
          });

          // Add to weak signatures
          for (const sig of signatures) {
            weakSignatures.push({
              txid: sig.txid,
              inputIndex: sig.inputIndex,
              type: 'nonce_reuse',
              severity: 'critical',
              r: sig.r,
              s: sig.s,
              details: `Nonce reuse: R value ${rValue.substring(0, 16)}... appears in ${signatures.length} transactions`
            });
          }
        }
      }
      
      console.log(`\n========== ANALYSIS COMPLETE ==========`);
      console.log(`Nonce reuse groups found: ${nonceReuseCount}`);
      console.log(`Total vulnerabilities detected: ${weakSignatures.length}`);

      res.json({
        success: true,
        data: {
          address,
          totalTransactions: transactions.length,
          analysis: {
            totalSignaturesExtracted: totalExtracted,
            nonceReuseGroupsFound: nonceReuseDetails.length,
            criticalVulnerabilities: weakSignatures.filter(s => s.severity === 'critical').length,
            highVulnerabilities: weakSignatures.filter(s => s.severity === 'high').length,
            weakSignatures: weakSignatures.slice(0, 100)
          },
          nonceReuseDetails: nonceReuseDetails.sort((a, b) => b.count - a.count),
          addressInfo: {
            tx_count: addressData.n_tx,
            total_received: addressData.total_received,
            total_sent: addressData.total_sent,
            final_balance: addressData.final_balance
          }
        }
      });

    } catch (error) {
      console.error('Address analysis error:', error);
      res.status(500).json({ error: error instanceof Error ? error.message : 'Analysis failed' });
    }
  });

  // Comprehensive address transaction scanner - analyzes up to 1000 transactions with cross-comparison
  app.post('/api/scan-address-transactions', async (req, res) => {
    try {
      const { address, networkType = 'mainnet', limit = 1000 } = req.body;

      if (!address) {
        return res.status(400).json({ error: 'Bitcoin address required' });
      }

      // Fetch up to 1000 transactions for address (with pagination)
      const txids = await bitcoinService.fetchAddressTransactions(address, networkType, Math.min(limit, 1000));

      if (txids.length === 0) {
        return res.json({ success: true, data: { address, totalScanned: 0, nonceReuseVulnerabilities: [], statistics: {} } });
      }

      // Store all signatures from all transactions for cross-comparison
      const allSignatures: Array<{ txid: string; inputIndex: number; r: string; s: string; publicKey?: string }> = [];
      const rValueMap = new Map<string, Array<{ txid: string; inputIndex: number; r: string; s: string }>>();

      // Step 1: Extract all signatures from all transactions
      for (const txid of txids) {
        try {
          const tx = await bitcoinService.getTransactionDetails(txid, networkType);
          if (!tx || !tx.vin) continue;

          for (let inputIdx = 0; inputIdx < tx.vin.length; inputIdx++) {
            const input = tx.vin[inputIdx];
            if (!input.scriptSig) continue;

            // Extract signature from script
            const derHex = input.scriptSig.hex || '';
            const sig = cryptoAnalysis.validateDERSignature(derHex);
            
            if (sig.isValid && sig.r && sig.s) {
              allSignatures.push({
                txid,
                inputIndex: inputIdx,
                r: sig.r,
                s: sig.s,
                publicKey: input.prevout?.scriptpubkey || ''
              });

              // Index by R value for nonce reuse detection
              const rValue = sig.r;
              const existing = rValueMap.get(rValue) || [];
              existing.push({ txid, inputIndex: inputIdx, r: sig.r, s: sig.s });
              rValueMap.set(rValue, existing);
            }
          }
        } catch (error) {
          continue; // Skip transactions that fail to parse
        }
      }

      // Step 2: Find all nonce reuses (same R value across different transactions)
      const nonceReuseVulnerabilities: any[] = [];
      const processedGroups = new Set<string>();

      for (const [rValue, signatures] of rValueMap.entries()) {
        if (signatures.length >= 2) {
          // Sort by txid to create consistent group key
          const groupKey = signatures.map(s => s.txid).sort().join('|');
          
          if (!processedGroups.has(groupKey)) {
            processedGroups.add(groupKey);
            
            nonceReuseVulnerabilities.push({
              rValue,
              count: signatures.length,
              severity: 'critical',
              transactions: signatures.map(s => ({
                txid: s.txid,
                inputIndex: s.inputIndex,
                s: s.s
              })),
              details: `Nonce reuse: R value ${rValue.substring(0, 16)}... used in ${signatures.length} transactions. Private key recovery possible using formula: k = (s1-s2)/(z1-z2) mod n`
            });
          }
        }
      }

      const statistics = {
        totalTransactionsScanned: txids.length,
        totalSignaturesExtracted: allSignatures.length,
        uniqueRValues: rValueMap.size,
        nonceReuseGroupsFound: nonceReuseVulnerabilities.length,
        totalVulnerableSignatures: Array.from(rValueMap.values()).reduce((sum, sigs) => sum + (sigs.length >= 2 ? sigs.length : 0), 0)
      };

      res.json({
        success: true,
        data: {
          address,
          statistics,
          nonceReuseVulnerabilities: nonceReuseVulnerabilities.sort((a, b) => b.count - a.count),
          allSignaturesExtracted: allSignatures.length,
          rValueDistribution: Array.from(rValueMap.entries())
            .sort((a, b) => b[1].length - a[1].length)
            .slice(0, 20) // Top 20 most reused R values
            .map(([rValue, sigs]) => ({
              rValue: rValue.substring(0, 16) + '...',
              count: sigs.length,
              transactionIds: sigs.map(s => s.txid)
            }))
        }
      });

    } catch (error) {
      console.error('Address transaction scan error:', error);
      res.status(500).json({ error: error instanceof Error ? error.message : 'Scan failed' });
    }
  });

  // Address vulnerability summary endpoint
  app.get('/api/address-vulnerability-summary', async (req, res) => {
    try {
      const allLogs = await storage.getAllVulnerabilityLogs(1000);
      
      // Group by address
      const addressMap = new Map<string, any>();
      for (const log of allLogs) {
        if (!addressMap.has(log.bitcoinAddress)) {
          addressMap.set(log.bitcoinAddress, {
            address: log.bitcoinAddress,
            vulnerabilityTypes: new Set<string>(),
            totalCount: 0,
            criticalCount: 0,
            transactions: new Set<string>(),
            firstDetected: log.detectedAt,
            lastDetected: log.detectedAt
          });
        }
        
        const entry = addressMap.get(log.bitcoinAddress)!;
        entry.vulnerabilityTypes.add(log.vulnerabilityType);
        entry.totalCount++;
        if (log.severity === 'critical') entry.criticalCount++;
        if (log.transactionHash) entry.transactions.add(log.transactionHash);
        entry.lastDetected = log.detectedAt;
      }

      // Convert to array format
      const summary = Array.from(addressMap.values()).map(entry => ({
        address: entry.address,
        vulnerabilityTypes: Array.from(entry.vulnerabilityTypes),
        totalCount: entry.totalCount,
        criticalCount: entry.criticalCount,
        transactionCount: entry.transactions.size,
        transactions: Array.from(entry.transactions),
        firstDetected: entry.firstDetected,
        lastDetected: entry.lastDetected
      }));

      res.json({ success: true, data: summary });
    } catch (error) {
      res.status(500).json({ error: 'Failed to fetch address vulnerability summary' });
    }
  });

  return httpServer;
}