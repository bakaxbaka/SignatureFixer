import fetch from 'node-fetch';
import { SocksProxyAgent } from 'socks-proxy-agent';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const TOR_SOCKS = "socks5h://127.0.0.1:9050";
const torAgent = new SocksProxyAgent(TOR_SOCKS);

type CacheEntry = { url: string; json: any; createdAt: number };
const memoryCache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 5 * 60 * 1000;
const CACHE_FILE = path.join(__dirname, "../../data/http_cache.json");

function loadDiskCache() {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      const raw = fs.readFileSync(CACHE_FILE, "utf8");
      const parsed = JSON.parse(raw);
      Object.entries(parsed).forEach(([k, v]: any) => memoryCache.set(k, v));
      console.log(`[Cache] Loaded ${memoryCache.size} entries`);
    }
  } catch (e) {
    console.warn("Cache load error:", (e as Error).message);
  }
}

function saveDiskCache() {
  try {
    const obj: any = {};
    memoryCache.forEach((v, k) => obj[k] = v);
    fs.mkdirSync(path.dirname(CACHE_FILE), { recursive: true });
    fs.writeFileSync(CACHE_FILE, JSON.stringify(obj), "utf8");
  } catch (e) {
    console.warn("Cache save error");
  }
}

loadDiskCache();

let lastRequest = 0;
const MIN_DELAY = 1200;

async function globalThrottle() {
  const diff = Date.now() - lastRequest;
  if (diff < MIN_DELAY) await new Promise(r => setTimeout(r, MIN_DELAY - diff));
  lastRequest = Date.now();
}

export async function torJson(url: string, options: any = {}, useCache = true, attempt = 1): Promise<any> {
  const cached = memoryCache.get(url);
  if (cached && useCache && Date.now() - cached.createdAt < CACHE_TTL_MS) return cached.json;

  await globalThrottle();

  try {
    const res = await fetch(url, { ...options, agent: torAgent }) as any;
    if (res.status === 429) {
      const wait = Math.min(60000, attempt * 2000);
      await new Promise(r => setTimeout(r, wait));
      return torJson(url, options, useCache, attempt + 1);
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const json = await res.json();
    if (useCache) {
      memoryCache.set(url, { url, json, createdAt: Date.now() });
      if (Math.random() < 0.05) saveDiskCache();
    }
    return json;
  } catch (e) {
    const wait = Math.min(60000, attempt * 2000);
    await new Promise(r => setTimeout(r, wait));
    return torJson(url, options, useCache, attempt + 1);
  }
}

export async function fetchAddressDataWithTor(address: string): Promise<any> {
  const endpoints = [
    `https://blockstream.info/api/address/${address}/txs`,
    `https://mempool.space/api/address/${address}/txs`,
    `https://api.blockcypher.com/v1/btc/main/addrs/${address}?limit=50&txlimit=50`
  ];

  for (const endpoint of endpoints) {
    try {
      const data = await torJson(endpoint);
      return {
        address,
        totalTx: data.length || data.n_tx || 0,
        txs: Array.isArray(data) ? data : (data.txs || data.txrefs || [])
      };
    } catch (e) {
      // Try next endpoint
    }
  }
  throw new Error("All endpoints failed");
}

export function clearCache(address: string): void {
  memoryCache.forEach((_, k) => k.includes(address) && memoryCache.delete(k));
}

export function clearAllCache(): void {
  memoryCache.clear();
  try { fs.existsSync(CACHE_FILE) && fs.unlinkSync(CACHE_FILE); } catch (e) {}
}
