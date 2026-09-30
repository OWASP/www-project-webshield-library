import { pbkdf2Sync, randomBytes } from "node:crypto";
import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";

/**
 * @typedef {{
 *  deriveKey: (password: string, salt: Buffer, options?: Record<string, unknown>) => Buffer
 * }} KDFAdapter
 */

// OWASP Password Storage Cheat Sheet: PBKDF2-HMAC-SHA256 needs 600,000 iterations
// (210,000 is the figure for SHA-512). Keys derived with the 1.0.x default of
// 210,000 need `iterations: 210000` passed explicitly to be reproduced.
export const DEFAULT_PBKDF2_ITERATIONS = 600000;

export class PBKDF2Adapter {
  constructor({ iterations = DEFAULT_PBKDF2_ITERATIONS, keyLength = 32, digest = "sha256" } = {}) {
    this.iterations = iterations;
    this.keyLength = keyLength;
    this.digest = digest;
  }

  deriveKey(password, salt) {
    return pbkdf2Sync(password, salt, this.iterations, this.keyLength, this.digest);
  }
}

/**
 * Argon2 adapter pattern.
 * Consumers can pass any Argon2 implementation via deriveFn.
 */
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

export function generateSalt(size = 16) {
  return randomBytes(size);
}
