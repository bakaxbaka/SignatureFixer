/**
 * Wallet Import Format (WIF) conversion utilities
 * For converting private keys to Bitcoin WIF format
 */

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hashBuffer);
}

async function doubleSha256(data: Uint8Array): Promise<Uint8Array> {
  const first = await sha256(data);
  return sha256(first);
}

async function ripemd160(data: Uint8Array): Promise<Uint8Array> {
  const K = [
    0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E,
    0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000
  ];
  const KK = [
    0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000,
    0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E
  ];
  const r = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13];
  const rr = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11];
  const s = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6];
  const ss = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11];

  const padded = new Uint8Array(((data.length + 72) >> 6) << 6);
  padded.set(data);
  padded[data.length] = 0x80;
  const bitLength = data.length * 8;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, bitLength, true);

  let h0 = 0x67452301;
  let h1 = 0xEFCDAB89;
  let h2 = 0x98BADCFE;
  let h3 = 0x10325476;
  let h4 = 0xC3D2E1F0;

  function rotl(x: number, n: number) {
    return ((x << n) | (x >>> (32 - n))) >>> 0;
  }

  function f(j: number, x: number, y: number, z: number) {
    if (j < 16) return x ^ y ^ z;
    if (j < 32) return (x & y) | (~x & z);
    if (j < 48) return (x | ~y) ^ z;
    if (j < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
  }

  for (let i = 0; i < padded.length; i += 64) {
    const X = new Uint32Array(16);
    for (let j = 0; j < 16; j++) {
      X[j] = view.getUint32(i + j * 4, true);
    }

    let A = h0, B = h1, C = h2, D = h3, E = h4;
    let AA = h0, BB = h1, CC = h2, DD = h3, EE = h4;

    for (let j = 0; j < 80; j++) {
      const T = (A + f(j, B, C, D) + X[r[j]] + K[j >> 4]) >>> 0;
      const TT = rotl(T, s[j]);
      A = E; E = D; D = rotl(C, 10); C = B; B = (TT + E) >>> 0;

      const T2 = (AA + f(79 - j, BB, CC, DD) + X[rr[j]] + KK[j >> 4]) >>> 0;
      const TT2 = rotl(T2, ss[j]);
      AA = EE; EE = DD; DD = rotl(CC, 10); CC = BB; BB = (TT2 + EE) >>> 0;
    }

    const T = (h1 + C + DD) >>> 0;
    h1 = (h2 + D + EE) >>> 0;
    h2 = (h3 + E + AA) >>> 0;
    h3 = (h4 + A + BB) >>> 0;
    h4 = (h0 + B + CC) >>> 0;
    h0 = T;
  }

  const result = new Uint8Array(20);
  const resultView = new DataView(result.buffer);
  resultView.setUint32(0, h0, true);
  resultView.setUint32(4, h1, true);
  resultView.setUint32(8, h2, true);
  resultView.setUint32(12, h3, true);
  resultView.setUint32(16, h4, true);
  return result;
}

async function hash160(data: Uint8Array): Promise<Uint8Array> {
  const sha = await sha256(data);
  return ripemd160(sha);
}

function encodeBase58(data: Uint8Array): string {
  let num = 0n;
  for (const byte of data) {
    num = num * 256n + BigInt(byte);
  }

  let result = '';
  while (num > 0n) {
    const remainder = Number(num % 58n);
    num = num / 58n;
    result = BASE58_ALPHABET[remainder] + result;
  }

  for (const byte of data) {
    if (byte === 0) {
      result = '1' + result;
    } else {
      break;
    }
  }

  return result;
}

function decodeBase58(str: string): Uint8Array {
  let num = 0n;
  for (const char of str) {
    const index = BASE58_ALPHABET.indexOf(char);
    if (index === -1) throw new Error('Invalid Base58 character');
    num = num * 58n + BigInt(index);
  }

  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num = num / 256n;
  }

  for (const char of str) {
    if (char === '1') {
      bytes.unshift(0);
    } else {
      break;
    }
  }

  return new Uint8Array(bytes);
}

export async function privateKeyToWIF(
  privateKeyHex: string,
  compressed: boolean = true,
  mainnet: boolean = true
): Promise<string> {
  const privateKey = privateKeyHex.replace(/^0x/, '').padStart(64, '0');
  const prefix = mainnet ? 0x80 : 0xef;
  
  const keyBytes = new Uint8Array(privateKey.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
  
  let extendedKey: Uint8Array;
  if (compressed) {
    extendedKey = new Uint8Array(34);
    extendedKey[0] = prefix;
    extendedKey.set(keyBytes, 1);
    extendedKey[33] = 0x01;
  } else {
    extendedKey = new Uint8Array(33);
    extendedKey[0] = prefix;
    extendedKey.set(keyBytes, 1);
  }

  const checksum = await doubleSha256(extendedKey);
  const finalKey = new Uint8Array(extendedKey.length + 4);
  finalKey.set(extendedKey);
  finalKey.set(checksum.slice(0, 4), extendedKey.length);

  return encodeBase58(finalKey);
}

export async function wifToPrivateKey(wif: string): Promise<{
  privateKey: string;
  compressed: boolean;
  mainnet: boolean;
}> {
  const decoded = decodeBase58(wif);
  
  const checksum = decoded.slice(-4);
  const payload = decoded.slice(0, -4);
  
  const calculatedChecksum = await doubleSha256(payload);
  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== calculatedChecksum[i]) {
      throw new Error('Invalid WIF checksum');
    }
  }

  const prefix = payload[0];
  const mainnet = prefix === 0x80;
  const compressed = payload.length === 34 && payload[33] === 0x01;
  
  const keyBytes = payload.slice(1, 33);
  const privateKey = Array.from(keyBytes)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');

  return { privateKey, compressed, mainnet };
}

export async function privateKeyToAddress(
  privateKeyHex: string,
  compressed: boolean = true,
  mainnet: boolean = true
): Promise<string> {
  const { bitcoin } = await import('./secp256k1');
  
  const privateKey = BigInt('0x' + privateKeyHex.replace(/^0x/, ''));
  const pubKey = bitcoin.calcpub(privateKey);
  
  let pubKeyBytes: Uint8Array;
  if (compressed) {
    const prefix = pubKey.y!.uint() % 2n === 0n ? 0x02 : 0x03;
    const xHex = pubKey.x!.uint().toString(16).padStart(64, '0');
    pubKeyBytes = new Uint8Array([prefix, ...xHex.match(/.{1,2}/g)!.map(b => parseInt(b, 16))]);
  } else {
    const xHex = pubKey.x!.uint().toString(16).padStart(64, '0');
    const yHex = pubKey.y!.uint().toString(16).padStart(64, '0');
    pubKeyBytes = new Uint8Array([0x04, 
      ...xHex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)),
      ...yHex.match(/.{1,2}/g)!.map(b => parseInt(b, 16))
    ]);
  }

  const hash = await hash160(pubKeyBytes);
  const prefix = mainnet ? 0x00 : 0x6f;
  
  const prefixedHash = new Uint8Array(21);
  prefixedHash[0] = prefix;
  prefixedHash.set(hash, 1);

  const checksum = await doubleSha256(prefixedHash);
  const finalAddress = new Uint8Array(25);
  finalAddress.set(prefixedHash);
  finalAddress.set(checksum.slice(0, 4), 21);

  return encodeBase58(finalAddress);
}

export function formatHex(value: string | bigint, length: number = 64): string {
  const hex = typeof value === 'bigint' ? value.toString(16) : value.replace(/^0x/, '');
  return hex.padStart(length, '0').toLowerCase();
}
