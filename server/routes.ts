import type { Express } from "express";
import { createServer, type Server } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { storage } from "./storage";
import { bitcoinService } from "./services/bitcoin";
import { vulnerabilityService } from "./services/vulnerability";
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

  return httpServer;
}