/**
 * Export signature data to CSV/JSON formats
 */

export interface ExportableSignature {
  txid?: string;
  index: number;
  r: string;
  s: string;
  zHash: string;
  pubkey?: string;
  sighash: string;
  sighashByte?: number;
  isHighS: boolean;
  isCanonical: boolean;
}

/**
 * Convert signatures to CSV format
 */
export function toCSV(signatures: ExportableSignature[]): string {
  const headers = ['txid', 'index', 'r', 's', 'z_hash', 'pubkey', 'sighash', 'sighash_byte', 'high_s', 'canonical'];
  const rows = signatures.map(sig => [
    sig.txid || '',
    sig.index,
    sig.r,
    sig.s,
    sig.zHash,
    sig.pubkey || '',
    sig.sighash,
    sig.sighashByte || '',
    sig.isHighS ? '1' : '0',
    sig.isCanonical ? '1' : '0',
  ]);

  return [headers, ...rows].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
}

/**
 * Convert signatures to JSON format
 */
export function toJSON(signatures: ExportableSignature[]): string {
  return JSON.stringify(
    {
      exportDate: new Date().toISOString(),
      count: signatures.length,
      signatures,
    },
    null,
    2
  );
}

/**
 * Download data as file
 */
export function downloadFile(data: string, filename: string, mimeType: string): void {
  const blob = new Blob([data], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Export signatures for lattice/HNP tools
 */
export function toLatticeFormat(signatures: ExportableSignature[]): string {
  // Format for lattice basis reduction tools
  const lines = signatures.map((sig, idx) => {
    return `${idx}\t${sig.r}\t${sig.s}\t${sig.zHash}\t${sig.pubkey || ''}`;
  });
  return lines.join('\n');
}
