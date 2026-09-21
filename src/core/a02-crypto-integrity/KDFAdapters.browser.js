import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";

// Browser build of KDFAdapters (see package.json's "browser" export condition).
// `Argon2Adapter` never touched node:crypto (callers inject their own `deriveFn`) —
// duplicated here verbatim rather than re-exported from KDFAdapters.js, since that
// file's top-level node:crypto import (for PBKDF2Adapter) would otherwise still be
// evaluated. `generateSalt` only needs random bytes, which the Web Crypto API
// provides natively, so it's reimplemented portably instead of stubbed. Only
// `PBKDF2Adapter` (Node's synchronous `pbkdf2Sync`) has no browser equivalent.
export class Argon2Adapter {
  /**
   * @param {{deriveFn: (password: string, salt: Buffer, options?: Record<string, unknown>) => Buffer}} options
   */
  constructor(options = {}) {
    this.deriveFn = options.deriveFn || null;
  }

  deriveKey(password, salt, options = {}) {
    if (!this.deriveFn) {
      throw new SecurityError(
        SecurityErrorCode.CRYPTO_ERROR,
        "Argon2 deriveFn is required. Provide a plugin implementation."
      );
    }
    return this.deriveFn(password, salt, options);
  }
}

export class PBKDF2Adapter {
  constructor() {}

  deriveKey() {
    throw new SecurityError(
      SecurityErrorCode.CRYPTO_ERROR,
      "PBKDF2Adapter requires Node's crypto module (pbkdf2Sync has no synchronous, " +
        "browser-portable equivalent). Use @owasp-webshield/core in a Node/SSR context, or " +
        "provide an Argon2Adapter with your own Web Crypto-based deriveFn instead."
    );
  }
}

export function generateSalt(size = 16) {
  const cryptoObj = globalThis.crypto;
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== "function") {
    throw new SecurityError(SecurityErrorCode.CRYPTO_ERROR, "No secure random source available in this runtime");
  }
  return cryptoObj.getRandomValues(new Uint8Array(size));
}
