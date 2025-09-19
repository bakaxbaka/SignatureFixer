import { 
  users, 
  analysisResults, 
  vulnerabilityPatterns, 
  apiMetrics, 
  batchAnalysis, 
  educationalContent,
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
import { db } from "./db";
import { eq, desc, and, gte, count, sql } from "drizzle-orm";

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

export class DatabaseStorage implements IStorage {
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user || undefined;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(insertUser)
      .returning();
    return user;
  }

  async saveAnalysisResult(result: InsertAnalysisResult): Promise<AnalysisResult> {
    const [analysisResult] = await db
      .insert(analysisResults)
      .values(result)
      .returning();
    return analysisResult;
  }

  async getAnalysisResult(id: string): Promise<AnalysisResult | undefined> {
    const [result] = await db
      .select()
      .from(analysisResults)
      .where(eq(analysisResults.id, id));
    return result || undefined;
  }

  async getAnalysisResultsByAddress(address: string): Promise<AnalysisResult[]> {
    return await db
      .select()
      .from(analysisResults)
      .where(eq(analysisResults.bitcoinAddress, address))
      .orderBy(desc(analysisResults.analysisTimestamp));
  }

  async getRecentAnalysisResults(limit: number = 50): Promise<AnalysisResult[]> {
    return await db
      .select()
      .from(analysisResults)
      .orderBy(desc(analysisResults.analysisTimestamp))
      .limit(limit);
  }

  async saveVulnerabilityPattern(pattern: InsertVulnerabilityPattern): Promise<VulnerabilityPattern> {
    const [vulnPattern] = await db
      .insert(vulnerabilityPatterns)
      .values(pattern)
      .returning();
    return vulnPattern;
  }

  async getVulnerabilityPatterns(): Promise<VulnerabilityPattern[]> {
    return await db
      .select()
      .from(vulnerabilityPatterns)
      .orderBy(desc(vulnerabilityPatterns.discoveredAt));
  }

  async getVulnerabilityPatternsByType(type: string): Promise<VulnerabilityPattern[]> {
    return await db
      .select()
      .from(vulnerabilityPatterns)
      .where(eq(vulnerabilityPatterns.patternType, type))
      .orderBy(desc(vulnerabilityPatterns.discoveredAt));
  }

  async recordApiMetric(metric: Omit<ApiMetric, 'id' | 'timestamp'>): Promise<void> {
    await db.insert(apiMetrics).values({
      ...metric,
      timestamp: new Date(),
    });
  }

  async getApiMetrics(provider?: string, hours: number = 24): Promise<ApiMetric[]> {
    const hoursAgo = new Date(Date.now() - hours * 60 * 60 * 1000);
    
    let query = db
      .select()
      .from(apiMetrics)
      .where(gte(apiMetrics.timestamp, hoursAgo));

    if (provider) {
      return await db
        .select()
        .from(apiMetrics)
        .where(and(
          gte(apiMetrics.timestamp, hoursAgo),
          eq(apiMetrics.apiProvider, provider)
        ))
        .orderBy(desc(apiMetrics.timestamp));
    }

    return await query.orderBy(desc(apiMetrics.timestamp));
  }

  async getApiStatus(): Promise<{ provider: string; status: string; responseTime: number; }[]> {
    const providers = ['blockchain_com', 'blockstream', 'sochain'];
    const results = [];

    for (const provider of providers) {
      const [metric] = await db
        .select()
        .from(apiMetrics)
        .where(eq(apiMetrics.apiProvider, provider))
        .orderBy(desc(apiMetrics.timestamp))
        .limit(1);

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
    const [batchResult] = await db
      .insert(batchAnalysis)
      .values(batch)
      .returning();
    return batchResult;
  }

  async updateBatchAnalysis(id: string, updates: Partial<BatchAnalysis>): Promise<BatchAnalysis> {
    const [updated] = await db
      .update(batchAnalysis)
      .set(updates)
      .where(eq(batchAnalysis.id, id))
      .returning();
    return updated;
  }

  async getBatchAnalysis(id: string): Promise<BatchAnalysis | undefined> {
    const [batch] = await db
      .select()
      .from(batchAnalysis)
      .where(eq(batchAnalysis.id, id));
    return batch || undefined;
  }

  async getActiveBatchAnalyses(): Promise<BatchAnalysis[]> {
    return await db
      .select()
      .from(batchAnalysis)
      .where(
        sql`${batchAnalysis.status} IN ('pending', 'running')`
      )
      .orderBy(desc(batchAnalysis.createdAt));
  }

  async getEducationalContent(): Promise<EducationalContent[]> {
    return await db
      .select()
      .from(educationalContent)
      .orderBy(desc(educationalContent.viewCount));
  }

  async getEducationalContentByCategory(category: string): Promise<EducationalContent[]> {
    return await db
      .select()
      .from(educationalContent)
      .where(eq(educationalContent.category, category))
      .orderBy(desc(educationalContent.viewCount));
  }

  async incrementContentView(id: string): Promise<void> {
    await db
      .update(educationalContent)
      .set({
        viewCount: sql`${educationalContent.viewCount} + 1`,
      })
      .where(eq(educationalContent.id, id));
  }

  async getVulnerabilityStats(): Promise<{
    totalScanned: number;
    nonceReuseFound: number;
    keysRecovered: number;
    criticalVulns: number;
    highVulns: number;
    mediumVulns: number;
  }> {
    const [totalScanned] = await db
      .select({ count: count() })
      .from(analysisResults);

    const [criticalVulns] = await db
      .select({ count: count() })
      .from(vulnerabilityPatterns)
      .where(eq(vulnerabilityPatterns.severity, 'critical'));

    const [highVulns] = await db
      .select({ count: count() })
      .from(vulnerabilityPatterns)
      .where(eq(vulnerabilityPatterns.severity, 'high'));

    const [mediumVulns] = await db
      .select({ count: count() })
      .from(vulnerabilityPatterns)
      .where(eq(vulnerabilityPatterns.severity, 'medium'));

    // Count nonce reuse and recovered keys from analysis results
    const analysisData = await db
      .select({
        nonceReuse: analysisResults.nonceReuse,
        recoveredKeys: analysisResults.recoveredKeys,
      })
      .from(analysisResults);

    let nonceReuseFound = 0;
    let keysRecovered = 0;

    for (const result of analysisData) {
      if (result.nonceReuse && Array.isArray(result.nonceReuse)) {
        nonceReuseFound += result.nonceReuse.length;
      }
      if (result.recoveredKeys && Array.isArray(result.recoveredKeys)) {
        keysRecovered += result.recoveredKeys.length;
      }
    }

    return {
      totalScanned: totalScanned.count,
      nonceReuseFound,
      keysRecovered,
      criticalVulns: criticalVulns.count,
      highVulns: highVulns.count,
      mediumVulns: mediumVulns.count,
    };
  }
}

export const storage = new DatabaseStorage();
