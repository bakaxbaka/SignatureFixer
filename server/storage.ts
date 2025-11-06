import { 
  type User, 
  type InsertUser,
  type AnalysisResult,
  type InsertAnalysisResult,
  type VulnerabilityPattern,
  type InsertVulnerabilityPattern,
  type ApiMetric,
  type BatchAnalysis,
  type InsertBatchAnalysis,
  type EducationalContent,
  type InsertEducationalContent
} from "@shared/schema";

export interface IStorage {
  // User methods
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;

  // Analysis results methods
  saveAnalysisResult(result: InsertAnalysisResult): Promise<AnalysisResult>;
  getAnalysisResult(id: string): Promise<AnalysisResult | undefined>;
  getAnalysisResultsByAddress(address: string): Promise<AnalysisResult[]>;
  getRecentAnalysisResults(limit?: number): Promise<AnalysisResult[]>;

  // Vulnerability patterns methods
  saveVulnerabilityPattern(pattern: InsertVulnerabilityPattern): Promise<VulnerabilityPattern>;
  getVulnerabilityPatterns(): Promise<VulnerabilityPattern[]>;
  getVulnerabilityPatternsByType(type: string): Promise<VulnerabilityPattern[]>;

  // API metrics methods
  recordApiMetric(metric: Omit<ApiMetric, 'id' | 'timestamp'>): Promise<void>;
  getApiMetrics(provider?: string, hours?: number): Promise<ApiMetric[]>;
  getApiStatus(): Promise<{ provider: string; status: string; responseTime: number; }[]>;

  // Batch analysis methods
  createBatchAnalysis(batch: InsertBatchAnalysis): Promise<BatchAnalysis>;
  updateBatchAnalysis(id: string, updates: Partial<BatchAnalysis>): Promise<BatchAnalysis>;
  getBatchAnalysis(id: string): Promise<BatchAnalysis | undefined>;
  getActiveBatchAnalyses(): Promise<BatchAnalysis[]>;

  // Educational content methods
  getEducationalContent(): Promise<EducationalContent[]>;
  getEducationalContentByCategory(category: string): Promise<EducationalContent[]>;
  incrementContentView(id: string): Promise<void>;

  // Analytics methods
  getVulnerabilityStats(): Promise<{
    totalScanned: number;
    nonceReuseFound: number;
    keysRecovered: number;
    criticalVulns: number;
    highVulns: number;
    mediumVulns: number;
  }>;
}

export class MemStorage implements IStorage {
  private users: Map<string, User> = new Map();
  private analysisResults: Map<string, AnalysisResult> = new Map();
  private vulnerabilityPatterns: Map<string, VulnerabilityPattern> = new Map();
  private apiMetrics: ApiMetric[] = [];
  private batchAnalyses: Map<string, BatchAnalysis> = new Map();
  private educationalContents: Map<string, EducationalContent> = new Map();

  private generateId(): string {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
  }

  async getUser(id: string): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(u => u.username === username);
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const user: User = {
      id: this.generateId(),
      ...insertUser,
      createdAt: new Date(),
    };
    this.users.set(user.id, user);
    return user;
  }

  async saveAnalysisResult(result: InsertAnalysisResult): Promise<AnalysisResult> {
    const analysisResult: AnalysisResult = {
      id: this.generateId(),
      networkType: result.networkType || "mainnet",
      bitcoinAddress: result.bitcoinAddress,
      utxoData: result.utxoData || null,
      vulnerabilities: result.vulnerabilities || null,
      signatureAnalysis: result.signatureAnalysis || null,
      nonceReuse: result.nonceReuse || null,
      recoveredKeys: result.recoveredKeys || null,
      analysisTimestamp: new Date(),
      isEducational: true,
    };
    this.analysisResults.set(analysisResult.id, analysisResult);
    return analysisResult;
  }

  async getAnalysisResult(id: string): Promise<AnalysisResult | undefined> {
    return this.analysisResults.get(id);
  }

  async getAnalysisResultsByAddress(address: string): Promise<AnalysisResult[]> {
    return Array.from(this.analysisResults.values())
      .filter(r => r.bitcoinAddress === address)
      .sort((a, b) => (b.analysisTimestamp?.getTime() || 0) - (a.analysisTimestamp?.getTime() || 0));
  }

  async getRecentAnalysisResults(limit: number = 50): Promise<AnalysisResult[]> {
    return Array.from(this.analysisResults.values())
      .sort((a, b) => (b.analysisTimestamp?.getTime() || 0) - (a.analysisTimestamp?.getTime() || 0))
      .slice(0, limit);
  }

  async saveVulnerabilityPattern(pattern: InsertVulnerabilityPattern): Promise<VulnerabilityPattern> {
    const vulnPattern: VulnerabilityPattern = {
      id: this.generateId(),
      patternType: pattern.patternType,
      severity: pattern.severity,
      description: pattern.description,
      detectionCriteria: pattern.detectionCriteria || null,
      exampleTransactions: pattern.exampleTransactions || null,
      educationalContent: pattern.educationalContent || null,
      discoveredAt: new Date(),
    };
    this.vulnerabilityPatterns.set(vulnPattern.id, vulnPattern);
    return vulnPattern;
  }

  async getVulnerabilityPatterns(): Promise<VulnerabilityPattern[]> {
    return Array.from(this.vulnerabilityPatterns.values())
      .sort((a, b) => (b.discoveredAt?.getTime() || 0) - (a.discoveredAt?.getTime() || 0));
  }

  async getVulnerabilityPatternsByType(type: string): Promise<VulnerabilityPattern[]> {
    return Array.from(this.vulnerabilityPatterns.values())
      .filter(p => p.patternType === type)
      .sort((a, b) => (b.discoveredAt?.getTime() || 0) - (a.discoveredAt?.getTime() || 0));
  }

  async recordApiMetric(metric: Omit<ApiMetric, 'id' | 'timestamp'>): Promise<void> {
    const apiMetric: ApiMetric = {
      id: this.generateId(),
      ...metric,
      timestamp: new Date(),
    };
    this.apiMetrics.push(apiMetric);
  }

  async getApiMetrics(provider?: string, hours: number = 24): Promise<ApiMetric[]> {
    const hoursAgo = new Date(Date.now() - hours * 60 * 60 * 1000);
    let metrics = this.apiMetrics.filter(m => (m.timestamp?.getTime() || 0) >= hoursAgo.getTime());
    
    if (provider) {
      metrics = metrics.filter(m => m.apiProvider === provider);
    }
    
    return metrics.sort((a, b) => (b.timestamp?.getTime() || 0) - (a.timestamp?.getTime() || 0));
  }

  async getApiStatus(): Promise<{ provider: string; status: string; responseTime: number; }[]> {
    const providers = ['blockchain_com', 'blockstream', 'sochain'];
    const results = [];

    for (const provider of providers) {
      const providerMetrics = this.apiMetrics
        .filter(m => m.apiProvider === provider)
        .sort((a, b) => (b.timestamp?.getTime() || 0) - (a.timestamp?.getTime() || 0));
      
      const metric = providerMetrics[0];
      
      if (metric) {
        results.push({
          provider,
          status: metric.statusCode === 200 ? 'online' : 'error',
          responseTime: metric.responseTime || 0,
        });
      } else {
        results.push({
          provider,
          status: 'unknown',
          responseTime: 0,
        });
      }
    }

    return results;
  }

  async createBatchAnalysis(batch: InsertBatchAnalysis): Promise<BatchAnalysis> {
    const batchResult: BatchAnalysis = {
      id: this.generateId(),
      ...batch,
      status: 'pending',
      progress: 0,
      processedAddresses: 0,
      vulnerabilitiesFound: 0,
      startedAt: null,
      completedAt: null,
      createdAt: new Date(),
    };
    this.batchAnalyses.set(batchResult.id, batchResult);
    return batchResult;
  }

  async updateBatchAnalysis(id: string, updates: Partial<BatchAnalysis>): Promise<BatchAnalysis> {
    const existing = this.batchAnalyses.get(id);
    if (!existing) {
      throw new Error('Batch analysis not found');
    }
    const updated = { ...existing, ...updates };
    this.batchAnalyses.set(id, updated);
    return updated;
  }

  async getBatchAnalysis(id: string): Promise<BatchAnalysis | undefined> {
    return this.batchAnalyses.get(id);
  }

  async getActiveBatchAnalyses(): Promise<BatchAnalysis[]> {
    return Array.from(this.batchAnalyses.values())
      .filter(b => b.status === 'pending' || b.status === 'running')
      .sort((a, b) => (b.createdAt?.getTime() || 0) - (a.createdAt?.getTime() || 0));
  }

  async getEducationalContent(): Promise<EducationalContent[]> {
    return Array.from(this.educationalContents.values())
      .sort((a, b) => (b.viewCount || 0) - (a.viewCount || 0));
  }

  async getEducationalContentByCategory(category: string): Promise<EducationalContent[]> {
    return Array.from(this.educationalContents.values())
      .filter(c => c.category === category)
      .sort((a, b) => (b.viewCount || 0) - (a.viewCount || 0));
  }

  async incrementContentView(id: string): Promise<void> {
    const content = this.educationalContents.get(id);
    if (content) {
      content.viewCount = (content.viewCount || 0) + 1;
      this.educationalContents.set(id, content);
    }
  }

  async getVulnerabilityStats(): Promise<{
    totalScanned: number;
    nonceReuseFound: number;
    keysRecovered: number;
    criticalVulns: number;
    highVulns: number;
    mediumVulns: number;
  }> {
    const totalScanned = this.analysisResults.size;
    
    const criticalVulns = Array.from(this.vulnerabilityPatterns.values())
      .filter(p => p.severity === 'critical').length;
    
    const highVulns = Array.from(this.vulnerabilityPatterns.values())
      .filter(p => p.severity === 'high').length;
    
    const mediumVulns = Array.from(this.vulnerabilityPatterns.values())
      .filter(p => p.severity === 'medium').length;

    let nonceReuseFound = 0;
    let keysRecovered = 0;

    for (const result of this.analysisResults.values()) {
      if (result.nonceReuse && Array.isArray(result.nonceReuse)) {
        nonceReuseFound += result.nonceReuse.length;
      }
      if (result.recoveredKeys && Array.isArray(result.recoveredKeys)) {
        keysRecovered += result.recoveredKeys.length;
      }
    }

    return {
      totalScanned,
      nonceReuseFound,
      keysRecovered,
      criticalVulns,
      highVulns,
      mediumVulns,
    };
  }
}

export const storage = new MemStorage();
