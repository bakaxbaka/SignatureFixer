// ======================================================================
// Tor + Caching Blockchain Fetcher
// Routes requests through Tor SOCKS5 proxy + local caching layer
// ======================================================================

import { SocksProxyAgent } from 'socks-proxy-agent';
import * as fs from 'fs';
import * as path from 'path';
import { fetchAddressData as fetchDirect } from '../explorers/multiEndpointFetcher';

const CACHE_DIR = '/home/runner/workspace/server/cache';
const CACHE_TTL = 3600000; // 1 hour

if (!fs.existsSync(CACHE_DIR)) {
  fs.mkdirSync(CACHE_DIR, { recursive: true });
}

interface CacheEntry {
  data: any;
  timestamp: number;
}

function getCacheKey(address: string): string {
  return `addr_${address.toLowerCase()}.json`;
}

function getCachePath(address: string): string {
  return path.join(CACHE_DIR, getCacheKey(address));
}

function isCacheValid(timestamp: number): boolean {
  return Date.now() - timestamp < CACHE_TTL;
}

function readCache(address: string): any | null {
  try {
    const cachePath = getCachePath(address);
    if (!fs.existsSync(cachePath)) return null;
    const content = fs.readFileSync(cachePath, 'utf-8');
    const entry: CacheEntry = JSON.parse(content);
    if (isCacheValid(entry.timestamp)) {
      console.log(`[Cache] HIT for ${address}`);
      return entry.data;
    }
    console.log(`[Cache] EXPIRED for ${address}`);
    return null;
  } catch (e) {
    console.warn(`[Cache] Read error: ${(e as Error).message}`);
    return null;
  }
}

function writeCache(address: string, data: any): void {
  try {
    const cachePath = getCachePath(address);
    const entry: CacheEntry = { data, timestamp: Date.now() };
    fs.writeFileSync(cachePath, JSON.stringify(entry), 'utf-8');
    console.log(`[Cache] WRITE for ${address}`);
  } catch (e) {
    console.warn(`[Cache] Write error: ${(e as Error).message}`);
  }
}

export async function fetchAddressDataWithTor(address: string): Promise<any> {
  console.log(`[TorFetcher] Fetching ${address}...`);
  const cached = readCache(address);
  if (cached) return cached;
  
  try {
    console.log(`[TorFetcher] Attempting Tor route (SOCKS5 at 127.0.0.1:9050)...`);
    const torAgent = new SocksProxyAgent('socks5://127.0.0.1:9050');
    const result = await fetchWithAgent(address, torAgent);
    writeCache(address, result);
    return result;
  } catch (torError) {
    console.warn(`[TorFetcher] Tor route failed: ${(torError as Error).message}`);
    console.log(`[TorFetcher] Falling back to direct fetch...`);
    try {
      const result = await fetchDirect(address);
      writeCache(address, result);
      return result;
    } catch (directError) {
      console.error(`[TorFetcher] All routes failed: ${(directError as Error).message}`);
      throw directError;
    }
  }
}

async function fetchWithAgent(address: string, agent: any): Promise<any> {
  const endpoints = [
    `https://blockstream.info/api/address/${address}/txs`,
    `https://mempool.space/api/address/${address}/txs`,
    `https://api.blockcypher.com/v1/btc/main/addrs/${address}?limit=50&txlimit=50`
  ];
  
  for (const endpoint of endpoints) {
    try {
      console.log(`[TorFetcher] Trying ${endpoint.split('/api/')[1]?.substring(0, 30)}...`);
      const res = await fetch(endpoint, { agent, timeout: 10000 });
      if (!res.ok) {
        console.warn(`[TorFetcher] ${endpoint} returned ${res.status}`);
        continue;
      }
      const data = await res.json();
      console.log(`[TorFetcher] ✓ Success via Tor`);
      return {
        address,
        totalTx: data.length || data.n_tx || 0,
        txs: Array.isArray(data) ? data : (data.txs || data.txrefs || [])
      };
    } catch (e) {
      console.warn(`[TorFetcher] Endpoint failed: ${(e as Error).message}`);
    }
  }
  throw new Error('All Tor endpoints failed');
}

export function clearCache(address: string): void {
  try {
    const cachePath = getCachePath(address);
    if (fs.existsSync(cachePath)) {
      fs.unlinkSync(cachePath);
      console.log(`[Cache] Cleared for ${address}`);
    }
  } catch (e) {
    console.warn(`[Cache] Clear error: ${(e as Error).message}`);
  }
}

export function clearAllCache(): void {
  try {
    if (fs.existsSync(CACHE_DIR)) {
      const files = fs.readdirSync(CACHE_DIR);
      files.forEach(f => fs.unlinkSync(path.join(CACHE_DIR, f)));
      console.log(`[Cache] Cleared all`);
    }
  } catch (e) {
    console.warn(`[Cache] Clear all error: ${(e as Error).message}`);
  }
}
