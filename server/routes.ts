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

  // Vulnerability Test endpoint
  app.post('/api/vulnerability-test', async (req, res) => {
    try {
      const { address, analysisId } = req.body;
      
      if (!address) {
        return res.status(400).json({ error: 'Address is required for vulnerability testing' });
      }

      const startTime = Date.now();
      
      // Get existing analysis or create new one
      let analysisResult;
      if (analysisId) {
        analysisResult = await storage.getAnalysisResult(analysisId);
      }

      if (!analysisResult) {
        return res.status(404).json({ error: 'Analysis result not found' });
      }

      // Perform comprehensive vulnerability analysis
      const vulnerabilities = await vulnerabilityService.comprehensiveAnalysis(
        address,
        analysisResult.utxoData
      );

      // Update analysis result with vulnerability data
      const updatedResult = await storage.saveAnalysisResult({
        bitcoinAddress: address,
        networkType: analysisResult.networkType,
        utxoData: analysisResult.utxoData,
        vulnerabilities: JSON.parse(JSON.stringify(vulnerabilities.vulnerabilities)),
        signatureAnalysis: vulnerabilities.signatureAnalysis,
        nonceReuse: vulnerabilities.nonceReuse,
        recoveredKeys: vulnerabilities.recoveredKeys,
      });

      const responseTime = Date.now() - startTime;

      // Broadcast vulnerability update
      broadcast({
        type: 'vulnerability_analysis',
        address,
        vulnerabilityCount: vulnerabilities.vulnerabilities?.length || 0,
        criticalIssues: vulnerabilities.vulnerabilities?.filter((v: any) => v.severity === 'critical').length || 0,
      });

      res.json({
        success: true,
        data: vulnerabilities,
        analysisId: updatedResult.id,
        responseTime,
      });
    } catch (error) {
      console.error('Vulnerability test error:', error);
      res.status(500).json({ 
        error: 'Failed to perform vulnerability analysis',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

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
