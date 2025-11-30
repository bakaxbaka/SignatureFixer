import { sql } from "drizzle-orm";
import { pgTable, text, varchar, timestamp, jsonb, boolean, integer, decimal, index } from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  createdAt: timestamp("created_at").default(sql`now()`),
});

export const analysisResults = pgTable("analysis_results", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  bitcoinAddress: text("bitcoin_address").notNull(),
  networkType: text("network_type").notNull().default("mainnet"),
  utxoData: jsonb("utxo_data"),
  vulnerabilities: jsonb("vulnerabilities"),
  signatureAnalysis: jsonb("signature_analysis"),
  nonceReuse: jsonb("nonce_reuse"),
  recoveredKeys: jsonb("recovered_keys"),
  analysisTimestamp: timestamp("analysis_timestamp").default(sql`now()`),
  isEducational: boolean("is_educational").default(true),
}, (table) => ({
  addressIdx: index("address_idx").on(table.bitcoinAddress),
  timestampIdx: index("timestamp_idx").on(table.analysisTimestamp),
}));

export const vulnerabilityPatterns = pgTable("vulnerability_patterns", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  patternType: text("pattern_type").notNull(), // 'nonce_reuse', 'sighash_single', 'weak_randomness'
  severity: text("severity").notNull(), // 'critical', 'high', 'medium', 'low'
  description: text("description").notNull(),
  detectionCriteria: jsonb("detection_criteria"),
  exampleTransactions: jsonb("example_transactions"),
  educationalContent: text("educational_content"),
  discoveredAt: timestamp("discovered_at").default(sql`now()`),
});

export const apiMetrics = pgTable("api_metrics", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  apiProvider: text("api_provider").notNull(), // 'blockchain_com', 'blockstream', 'sochain'
  endpoint: text("endpoint").notNull(),
  responseTime: integer("response_time"), // milliseconds
  statusCode: integer("status_code"),
  requestCount: integer("request_count").default(0),
  errorCount: integer("error_count").default(0),
  timestamp: timestamp("timestamp").default(sql`now()`),
}, (table) => ({
  providerIdx: index("provider_idx").on(table.apiProvider),
  timestampIdx: index("metrics_timestamp_idx").on(table.timestamp),
}));

export const batchAnalysis = pgTable("batch_analysis", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  addresses: jsonb("addresses").notNull(), // array of Bitcoin addresses
  status: text("status").notNull().default("pending"), // 'pending', 'running', 'completed', 'failed'
  progress: integer("progress").default(0), // percentage
  totalAddresses: integer("total_addresses").notNull(),
  processedAddresses: integer("processed_addresses").default(0),
  vulnerabilitiesFound: integer("vulnerabilities_found").default(0),
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
  createdAt: timestamp("created_at").default(sql`now()`),
});

export const educationalContent = pgTable("educational_content", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  title: text("title").notNull(),
  category: text("category").notNull(), // 'vulnerability', 'prevention', 'mathematics', 'history'
  content: text("content").notNull(),
  difficulty: text("difficulty").notNull(), // 'beginner', 'intermediate', 'advanced'
  tags: jsonb("tags"), // array of tags
  examples: jsonb("examples"), // code examples, transaction examples
  references: jsonb("references"), // research papers, links
  viewCount: integer("view_count").default(0),
  createdAt: timestamp("created_at").default(sql`now()`),
});

export const vulnerabilityLogs = pgTable("vulnerability_logs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  bitcoinAddress: text("bitcoin_address").notNull(),
  vulnerabilityType: text("vulnerability_type").notNull(), // 'nonce_reuse', 'signature_malleability', 'weak_randomness', etc.
  severity: text("severity").notNull(), // 'critical', 'high', 'medium', 'low'
  transactionHash: text("transaction_hash"),
  signatureDetails: jsonb("signature_details"), // r, s, m, k values
  analysisDetails: jsonb("analysis_details"), // full calculation steps
  recoveredPrivateKey: text("recovered_private_key"),
  recoveredWIF: text("recovered_wif"),
  nonce: text("nonce"),
  detectionMethod: text("detection_method"),
  confidence: integer("confidence").default(0),
  detectedAt: timestamp("detected_at").default(sql`now()`),
  networkType: text("network_type").default("mainnet"),
}, (table) => ({
  addressIdx: index("vuln_log_address_idx").on(table.bitcoinAddress),
  typeIdx: index("vuln_log_type_idx").on(table.vulnerabilityType),
  timestampIdx: index("vuln_log_timestamp_idx").on(table.detectedAt),
}));

export const nonceReuseHistory = pgTable("nonce_reuse_history", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  bitcoinAddress: text("bitcoin_address").notNull(),
  rValue: text("r_value").notNull(),
  signatures: jsonb("signatures").notNull(), // array of signature hashes
  transactionHashes: jsonb("transaction_hashes"), // array of txids
  recoveredPrivateKey: text("recovered_private_key"),
  recoveredWIF: text("recovered_wif"),
  nonce: text("nonce"),
  analysisDetails: jsonb("analysis_details"),
  detectedAt: timestamp("detected_at").default(sql`now()`),
}, (table) => ({
  addressIdx: index("nonce_reuse_address_idx").on(table.bitcoinAddress),
  rValueIdx: index("nonce_reuse_r_value_idx").on(table.rValue),
}));

// Relations
export const analysisResultsRelations = relations(analysisResults, ({ many }) => ({
  vulnerabilityInstances: many(vulnerabilityPatterns),
}));

export const batchAnalysisRelations = relations(batchAnalysis, ({ many }) => ({
  results: many(analysisResults),
}));

// Zod schemas
export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export const insertAnalysisResultSchema = createInsertSchema(analysisResults).pick({
  bitcoinAddress: true,
  networkType: true,
  utxoData: true,
  vulnerabilities: true,
  signatureAnalysis: true,
  nonceReuse: true,
  recoveredKeys: true,
});

export const insertVulnerabilityPatternSchema = createInsertSchema(vulnerabilityPatterns).pick({
  patternType: true,
  severity: true,
  description: true,
  detectionCriteria: true,
  exampleTransactions: true,
  educationalContent: true,
});

export const insertBatchAnalysisSchema = createInsertSchema(batchAnalysis).pick({
  name: true,
  addresses: true,
  totalAddresses: true,
});

export const insertEducationalContentSchema = createInsertSchema(educationalContent).pick({
  title: true,
  category: true,
  content: true,
  difficulty: true,
  tags: true,
  examples: true,
  references: true,
});

// Types
export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

export type InsertAnalysisResult = z.infer<typeof insertAnalysisResultSchema>;
export type AnalysisResult = typeof analysisResults.$inferSelect;

export type InsertVulnerabilityPattern = z.infer<typeof insertVulnerabilityPatternSchema>;
export type VulnerabilityPattern = typeof vulnerabilityPatterns.$inferSelect;

export type InsertBatchAnalysis = z.infer<typeof insertBatchAnalysisSchema>;
export type BatchAnalysis = typeof batchAnalysis.$inferSelect;

export type InsertEducationalContent = z.infer<typeof insertEducationalContentSchema>;
export type EducationalContent = typeof educationalContent.$inferSelect;

export type ApiMetric = typeof apiMetrics.$inferSelect;
export type VulnerabilityLog = typeof vulnerabilityLogs.$inferSelect;
export type NonceReuseHistory = typeof nonceReuseHistory.$inferSelect;
