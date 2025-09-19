import { z } from "zod";

/**
 * Bitcoin address validation
 */
export function isValidBitcoinAddress(address: string): boolean {
  if (!address || typeof address !== 'string') {
    return false;
  }

  // Remove any whitespace
  address = address.trim();

  // Check length constraints
  if (address.length < 26 || address.length > 62) {
    return false;
  }

  // Legacy address (starts with 1 or 3)
  const legacyAddressRegex = /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/;
  
  // Bech32 address (starts with bc1)
  const bech32AddressRegex = /^bc1[a-z0-9]{39,59}$/;
  
  // Testnet addresses
  const testnetLegacyRegex = /^[mn2][a-km-zA-HJ-NP-Z1-9]{25,34}$/;
  const testnetBech32Regex = /^tb1[a-z0-9]{39,59}$/;

  return (
    legacyAddressRegex.test(address) ||
    bech32AddressRegex.test(address) ||
    testnetLegacyRegex.test(address) ||
    testnetBech32Regex.test(address)
  );
}

/**
 * Determine the network type from a Bitcoin address
 */
export function getNetworkFromAddress(address: string): 'mainnet' | 'testnet' | 'unknown' {
  if (!isValidBitcoinAddress(address)) {
    return 'unknown';
  }

  // Mainnet addresses
  if (address.startsWith('1') || address.startsWith('3') || address.startsWith('bc1')) {
    return 'mainnet';
  }

  // Testnet addresses
  if (address.startsWith('m') || address.startsWith('n') || address.startsWith('2') || address.startsWith('tb1')) {
    return 'testnet';
  }

  return 'unknown';
}

/**
 * Format satoshis to BTC with proper precision
 */
export function formatBTC(satoshis: number, precision: number = 8): string {
  const btc = satoshis / 100000000;
  return btc.toFixed(precision).replace(/\.?0+$/, '');
}

/**
 * Format large numbers with appropriate units
 */
export function formatNumber(num: number): string {
  if (num >= 1000000000) {
    return (num / 1000000000).toFixed(1) + 'B';
  }
  if (num >= 1000000) {
    return (num / 1000000).toFixed(1) + 'M';
  }
  if (num >= 1000) {
    return (num / 1000).toFixed(1) + 'K';
  }
  return num.toString();
}

/**
 * Convert hex string to bytes
 */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Convert bytes to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Validate transaction hex
 */
export function isValidTransactionHex(hex: string): boolean {
  if (!hex || typeof hex !== 'string') {
    return false;
  }

  // Remove any whitespace
  hex = hex.replace(/\s/g, '');

  // Must be valid hex
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    return false;
  }

  // Must have even length
  if (hex.length % 2 !== 0) {
    return false;
  }

  // Minimum transaction size (roughly 60 bytes for a minimal transaction)
  if (hex.length < 120) {
    return false;
  }

  return true;
}

/**
 * Extract the address type for display purposes
 */
export function getAddressType(address: string): string {
  if (!isValidBitcoinAddress(address)) {
    return 'Invalid';
  }

  if (address.startsWith('1') || address.startsWith('m') || address.startsWith('n')) {
    return 'P2PKH (Legacy)';
  }
  
  if (address.startsWith('3') || address.startsWith('2')) {
    return 'P2SH (Script Hash)';
  }
  
  if (address.startsWith('bc1') || address.startsWith('tb1')) {
    if (address.length === 42 || address.length === 62) {
      return 'P2WPKH/P2WSH (Bech32)';
    }
  }

  return 'Unknown';
}

/**
 * Truncate long strings for display
 */
export function truncateString(str: string, startLen: number = 8, endLen: number = 8): string {
  if (str.length <= startLen + endLen) {
    return str;
  }
  return `${str.slice(0, startLen)}...${str.slice(-endLen)}`;
}

/**
 * Calculate confirmation status
 */
export function getConfirmationStatus(confirmations: number): {
  status: 'unconfirmed' | 'low' | 'medium' | 'high';
  color: string;
  description: string;
} {
  if (confirmations === 0) {
    return {
      status: 'unconfirmed',
      color: 'text-yellow-500',
      description: 'Unconfirmed'
    };
  } else if (confirmations < 3) {
    return {
      status: 'low',
      color: 'text-orange-500',
      description: 'Low security'
    };
  } else if (confirmations < 6) {
    return {
      status: 'medium',
      color: 'text-blue-500',
      description: 'Medium security'
    };
  } else {
    return {
      status: 'high',
      color: 'text-green-500',
      description: 'High security'
    };
  }
}

/**
 * Validate and format SIGHASH type
 */
export function formatSighashType(type: number): string {
  const baseType = type & 0x1f;
  let name = '';
  
  switch (baseType) {
    case 0x01: name = 'SIGHASH_ALL'; break;
    case 0x02: name = 'SIGHASH_NONE'; break;
    case 0x03: name = 'SIGHASH_SINGLE'; break;
    default: name = 'UNKNOWN';
  }
  
  if (type & 0x80) {
    name += ' | SIGHASH_ANYONECANPAY';
  }
  
  return `${name} (0x${type.toString(16).padStart(2, '0')})`;
}

/**
 * Time formatting utilities
 */
export function formatRelativeTime(timestamp: string | Date): string {
  const date = typeof timestamp === 'string' ? new Date(timestamp) : timestamp;
  const now = new Date();
  const diff = now.getTime() - date.getTime();
  
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  
  if (days > 0) return `${days} day${days > 1 ? 's' : ''} ago`;
  if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
  if (minutes > 0) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
  return `${seconds} second${seconds > 1 ? 's' : ''} ago`;
}
