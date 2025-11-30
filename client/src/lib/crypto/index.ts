/**
 * Bitcoin ECDSA Cryptographic Library
 * 
 * A complete TypeScript implementation of secp256k1 elliptic curve operations
 * for Bitcoin signature analysis and vulnerability research.
 * 
 * Based on Willem Hengeveld's bitcoinexplainer
 * https://github.com/nlitsme/bitcoinexplainer
 */

export * from './bignum';
export * from './field';
export * from './curve';
export * from './ecdsa';
export * from './secp256k1';
export * from './wif';

import { bitcoin, getSecp256k1Params, SECP256K1_PARAMS } from './secp256k1';
import {
  recoverFromNonceReuse,
  recoverFromKnownNonce,
  calculatePublicKey,
  signMessage,
  verifySignature,
  findSigningSecret,
  recoverPublicKey,
  validatePoint,
} from './ecdsa';
import { privateKeyToWIF, wifToPrivateKey, privateKeyToAddress, formatHex } from './wif';

export const BitcoinCrypto = {
  curve: bitcoin,
  params: SECP256K1_PARAMS,
  getParams: getSecp256k1Params,

  recoverFromNonceReuse: (input: {
    r: string;
    s1: string;
    s2: string;
    m1: string;
    m2: string;
  }) => recoverFromNonceReuse(bitcoin, input),

  recoverFromKnownNonce: (input: {
    r: string;
    s: string;
    m: string;
    k: string;
  }) => recoverFromKnownNonce(bitcoin, input),

  calculatePublicKey: (privateKeyHex: string) =>
    calculatePublicKey(bitcoin, privateKeyHex),

  signMessage: (messageHash: string, privateKey: string, nonce: string) =>
    signMessage(bitcoin, messageHash, privateKey, nonce),

  verifySignature: (
    messageHash: string,
    pubKeyX: string,
    pubKeyY: string,
    r: string,
    s: string
  ) => verifySignature(bitcoin, messageHash, pubKeyX, pubKeyY, r, s),

  findSigningSecret: (
    messageHash: string,
    privateKey: string,
    r: string,
    s: string
  ) => findSigningSecret(bitcoin, messageHash, privateKey, r, s),

  recoverPublicKey: (
    messageHash: string,
    r: string,
    s: string,
    flag?: number
  ) => recoverPublicKey(bitcoin, messageHash, r, s, flag),

  validatePoint: (x: string, y: string) => validatePoint(bitcoin, x, y),

  privateKeyToWIF,
  wifToPrivateKey,
  privateKeyToAddress,
  formatHex,
};

export default BitcoinCrypto;
