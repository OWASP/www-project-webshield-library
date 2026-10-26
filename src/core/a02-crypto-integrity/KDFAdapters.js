import { pbkdf2Sync, randomBytes } from "node:crypto";
import { DEFAULT_PBKDF2_ITERATIONS } from "./KDFAdapters.shared.js";

export { Argon2Adapter, DEFAULT_PBKDF2_ITERATIONS } from "./KDFAdapters.shared.js";

/**
 * @typedef {{
 *  deriveKey: (password: string, salt: Buffer, options?: Record<string, unknown>) => Buffer
 * }} KDFAdapter
 */

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

export function generateSalt(size = 16) {
  return randomBytes(size);
}
