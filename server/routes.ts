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

  // Vulnerability testing endpoint
  app.post('/api/vulnerability-test', async (req, res) => {
    try {
      const { address, analysisId } = req.body;

      if (!address) {
        return res.status(400).json({
          error: 'Bitcoin address is required'
        });
      }

      // Get analysis result or fetch new data
      let utxoData;
      if (analysisId) {
        const existingResult = await storage.getAnalysisResult(analysisId);
        if (existingResult) {
          utxoData = existingResult.utxoData;
        }
      }

      if (!utxoData) {
        const networkType = address.startsWith('bc1') || address.startsWith('1') || address.startsWith('3') ? 'mainnet' : 'testnet';
        utxoData = await bitcoinService.fetchUTXOs(address, networkType);
      }

      // Perform comprehensive vulnerability analysis
      const vulnerabilityResult = await vulnerabilityService.comprehensiveAnalysis(address, utxoData);

      res.json({
        success: true,
        data: vulnerabilityResult
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