import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";

// Uses the Web Crypto API (`globalThis.crypto`) instead of node:crypto's
// `randomBytes`/`timingSafeEqual`. `globalThis.crypto` is available natively
// in Node 20+ (this package's minimum supported version), every modern
// browser, and other modern JS runtimes — so this file has no environment-
// specific import at all and is safe to evaluate in a browser bundle.
const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function bytesToBase64Url(bytes) {
  let result = "";
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    result += BASE64URL_ALPHABET[(chunk >> 18) & 63];
    result += BASE64URL_ALPHABET[(chunk >> 12) & 63];
    result += BASE64URL_ALPHABET[(chunk >> 6) & 63];
    result += BASE64URL_ALPHABET[chunk & 63];
  }
  const remaining = bytes.length - i;
  if (remaining === 1) {
    const chunk = bytes[i] << 16;
    result += BASE64URL_ALPHABET[(chunk >> 18) & 63] + BASE64URL_ALPHABET[(chunk >> 12) & 63];
  } else if (remaining === 2) {
    const chunk = (bytes[i] << 16) | (bytes[i + 1] << 8);
    result +=
      BASE64URL_ALPHABET[(chunk >> 18) & 63] +
      BASE64URL_ALPHABET[(chunk >> 12) & 63] +
      BASE64URL_ALPHABET[(chunk >> 6) & 63];
  }
  return result;
}

function secureRandomBytes(size) {
  const cryptoObj = globalThis.crypto;
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== "function") {
    throw new SecurityError(SecurityErrorCode.CRYPTO_ERROR, "No secure random source available in this runtime");
  }
  const bytes = new Uint8Array(size);
  cryptoObj.getRandomValues(bytes);
  return bytes;
}

// CSRF tokens are always ASCII (base64url, generated below), so a simple
// per-character byte mapping is sufficient here — this avoids depending on
// `TextEncoder`, which (unlike `crypto.getRandomValues`) some browser-like
// test environments such as jsdom don't provide as a global.
function stringToBytes(str) {
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    bytes[i] = str.charCodeAt(i) & 0xff;
  }
  return bytes;
}

// Constant-time comparison — a length check runs first (an O(1) integer
// compare that doesn't depend on secret content, so it doesn't leak timing
// proportional to a matching prefix), then every byte is compared via XOR
// accumulation so a mismatch anywhere doesn't short-circuit the loop early.
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

function defaultStorage() {
  let value = null;
  return {
    get: () => value,
    set: (v) => {
      value = v;
    }
  };
}

export class CSRFTokenManager {
  /**
   * @param {{storage?: {get:()=>string|null,set:(value:string)=>void}, tokenLength?: number}} [options]
   */
  constructor(options = {}) {
    this.storage = options.storage || defaultStorage();
    this.tokenLength = options.tokenLength || 32;
  }

  generateToken() {
    return bytesToBase64Url(secureRandomBytes(this.tokenLength));
  }

  getToken() {
    return this.storage.get();
  }

  rotateToken() {
    const token = this.generateToken();
    this.storage.set(token);
    return token;
  }

  attach(headers = {}) {
    const token = this.getToken();
    if (!token) return headers;
    return { ...headers, "X-CSRF-Token": token };
  }

  validate(token) {
    const expected = this.getToken();
    const expectedBytes = typeof expected === "string" ? stringToBytes(expected) : null;
    const tokenBytes = typeof token === "string" ? stringToBytes(token) : null;
    const valid = Boolean(expectedBytes && tokenBytes && constantTimeEqual(expectedBytes, tokenBytes));
    if (!valid) {
      throw new SecurityError(SecurityErrorCode.CSRF_INVALID, "CSRF token validation failed");
    }
    return true;
  }
}
