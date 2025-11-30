/**
 * Markdown report generator for Bitcoin transaction vulnerability analysis
 */

import { performVulnerabilityScan, VulnerabilityScanResult } from './vulnerability-scanner';
import { TransactionInput } from '@/lib/transaction-analyzer';

export interface TransactionReport {
  markdown: string;
  filename: string;
}

export function generateReport(
  txid: string | undefined,
  txInfo: {
    version: number;
    inputCount: number;
    outputCount: number;
    locktime: number;
    totalInput: number;
    totalOutput: number;
  },
  inputs: TransactionInput[],
  outputs: Array<{ address: string; amount: number; isChange?: boolean }>,
  vsize?: number,
  weight?: number
): TransactionReport {
  const scan = performVulnerabilityScan(inputs, txid);
  
  let md = '';

  // Header
  md += '# Bitcoin Transaction Vulnerability Report\n\n';
  md += `**Generated:** ${new Date().toLocaleString()}\n\n`;
  
  if (txid) {
    md += `**TXID:** \`${txid}\`\n\n`;
  }

  // Summary
  md += '## Executive Summary\n\n';
  md += `**Risk Level:** \`${scan.summary.riskLevel}\`\n\n`;
  md += `**Issues Found:**\n`;
  md += `- 🔴 Critical: ${scan.summary.criticalCount}\n`;
  md += `- 🟠 High: ${scan.summary.highCount}\n`;
  md += `- 🟡 Medium: ${scan.summary.mediumCount}\n`;
  md += `- 🔵 Low: ${scan.summary.lowCount}\n\n`;

  // Transaction Structure
  md += '## Transaction Structure\n\n';
  md += `| Property | Value |\n`;
  md += `|---|---|\n`;
  md += `| Version | \`${txInfo.version}\` |\n`;
  md += `| Inputs | ${txInfo.inputCount} |\n`;
  md += `| Outputs | ${txInfo.outputCount} |\n`;
  md += `| Locktime | \`${txInfo.locktime}\` |\n`;
  if (vsize) md += `| vsize | ${vsize} bytes |\n`;
  if (weight) md += `| weight | ${weight} WU |\n`;
  md += `| Total Input Value | ${txInfo.totalInput} sats |\n`;
  md += `| Total Output Value | ${txInfo.totalOutput} sats |\n\n`;

  // Signature Analysis
  md += '## Signature Analysis\n\n';
  
  const canonicalCount = inputs.filter(i => i.signature?.isCanonical).length;
  const nonCanonicalCount = inputs.filter(i => !i.signature?.isCanonical).length;
  const highSCount = inputs.filter(i => i.signature?.isHighS).length;
  const lowSCount = inputs.filter(i => i.signature && !i.signature.isHighS).length;

  md += `| Metric | Count |\n`;
  md += `|---|---|\n`;
  md += `| Canonical DER | ${canonicalCount} |\n`;
  md += `| Non-canonical DER | ${nonCanonicalCount} |\n`;
  md += `| High-S Values | ${highSCount} |\n`;
  md += `| Low-S Values | ${lowSCount} |\n\n`;

  // Detailed Issues
  if (scan.issues.length > 0) {
    md += '## Vulnerability Details\n\n';
    
    scan.issues.forEach((issue, idx) => {
      const severityEmoji = {
        CRITICAL: '🔴',
        HIGH: '🟠',
        MEDIUM: '🟡',
        LOW: '🔵',
      }[issue.severity];

      md += `### ${severityEmoji} ${issue.severity}: ${issue.title}\n\n`;
      md += `**Category:** \`${issue.category}\`\n\n`;
      md += `**Description:** ${issue.description}\n\n`;
      
      if (issue.inputs && issue.inputs.length > 0) {
        md += `**Affected Inputs:** ${issue.inputs.join(', ')}\n\n`;
      }

      if (issue.details && Object.keys(issue.details).length > 0) {
        md += '**Details:**\n';
        Object.entries(issue.details).forEach(([key, value]) => {
          md += `- ${key}: ${value}\n`;
        });
        md += '\n';
      }
    });
  } else {
    md += '## Vulnerability Details\n\n';
    md += '✅ No critical vulnerabilities detected.\n\n';
  }

  // Input Details
  md += '## Input Details\n\n';
  inputs.forEach((input, idx) => {
    md += `### Input #${input.index}\n\n`;
    md += `| Property | Value |\n`;
    md += `|---|---|\n`;
    md += `| Previous TXID | \`${input.prevTxid.substring(0, 16)}...\` |\n`;
    md += `| Previous Output | ${input.vout} |\n`;
    md += `| Script Length | ${input.scriptSig.length / 2} bytes |\n`;
    if (input.pubkey) {
      md += `| Pubkey | \`${input.pubkey.substring(0, 16)}...\` |\n`;
    }
    md += `| Signature r | \`${input.signature?.r.substring(0, 16) || '—'}...\` |\n`;
    md += `| Signature s | \`${input.signature?.s.substring(0, 16) || '—'}...\` |\n`;
    md += `| Canonical | ${input.signature?.isCanonical ? '✓' : '✗'} |\n`;
    md += `| High-S | ${input.signature?.isHighS ? '⚠' : '✓'} |\n\n`;
  });

  // Output Details
  md += '## Output Details\n\n';
  outputs.forEach((output, idx) => {
    md += `### Output #${idx}\n\n`;
    md += `| Property | Value |\n`;
    md += `|---|---|\n`;
    md += `| Address | \`${output.address}\` |\n`;
    md += `| Amount | ${output.amount} sats |\n`;
    md += `| Type | ${output.isChange ? 'Change' : 'Payment'} |\n\n`;
  });

  // Recommendations
  md += '## Recommendations\n\n';
  
  if (scan.summary.riskLevel === 'CRITICAL') {
    md += '⚠️ **CRITICAL RISK** - Do not broadcast this transaction without investigation.\n\n';
  }

  if (nonCanonicalCount > 0) {
    md += `- **Non-canonical DER:** Use BIP66 strict DER encoding. See [BIP66](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki)\n`;
  }

  if (highSCount > 0) {
    md += `- **High-S Values:** Normalize to low-S per [BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki)\n`;
  }

  const nonceReuses = Array.from(
    new Map(
      inputs
        .filter(i => i.signature?.r)
        .map(i => [i.signature!.r, i.index])
    ).entries()
  ).filter(([_, indices]) => Array.isArray(indices) || true);

  if (nonceReuses.length > 0) {
    md += `- **Nonce Reuse:** Private key recovery possible. Use CVE-42461 tester to verify library behavior.\n`;
  }

  md += `- **Test Against Libraries:** Use the CVE-42461 testing feature to verify target library acceptance.\n`;
  md += `- **Export Signatures:** Export r,s,z values for external analysis and lattice reduction tools.\n\n`;

  // Footer
  md += '---\n\n';
  md += `**Report Version:** 1.0\n`;
  md += `**Analysis Tool:** Bitcoin ECDSA Signature Vulnerability Analyzer\n`;

  const filename = txid 
    ? `vulnerability-report-${txid.substring(0, 8)}.md`
    : `vulnerability-report-${Date.now()}.md`;

  return {
    markdown: md,
    filename,
  };
}

/**
 * Download report as markdown file
 */
export function downloadReport(markdown: string, filename: string): void {
  const blob = new Blob([markdown], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
