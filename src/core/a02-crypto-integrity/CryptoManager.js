import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";
import { PBKDF2Adapter } from "./KDFAdapters.js";

function toBase64(buffer) {
  return Buffer.from(buffer).toString("base64");
}

function fromBase64(value) {
  return Buffer.from(value, "base64");
}

export class CryptoManager {
  constructor(options = {}) {
    this.kdfAdapter =
      options.kdfAdapter ||
      new PBKDF2Adapter({
        iterations: options.iterations || 210000,
        keyLength: options.keyLength || 32,
        digest: options.digest || "sha256"
      });
  }

  random(size = 32) {
    return randomBytes(size);
  }

  deriveKey(password, salt = this.random(16)) {
    const normalizedSalt = Buffer.isBuffer(salt) ? salt : Buffer.from(String(salt));
    const key = this.kdfAdapter.deriveKey(password, normalizedSalt, {});
    return { key, salt: normalizedSalt };
  }

  encrypt(plaintext, key) {
    try {
      const iv = this.random(12);
      const cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
      const encrypted = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
      const tag = cipher.getAuthTag();
      return {
        ciphertext: toBase64(encrypted),
        iv: toBase64(iv),
        tag: toBase64(tag),
        alg: "aes-256-gcm"
      };
    } catch (error) {
      throw new SecurityError(SecurityErrorCode.CRYPTO_ERROR, "Encryption failed", { cause: String(error) });
    }
  }

  decrypt(payload, key) {
    try {
      const decipher = createDecipheriv("aes-256-gcm", key, fromBase64(payload.iv), { authTagLength: 16 });
      decipher.setAuthTag(fromBase64(payload.tag));
      const output = Buffer.concat([
        decipher.update(fromBase64(payload.ciphertext)),
        decipher.final()
      ]);
      return output.toString("utf8");
    } catch (error) {
      throw new SecurityError(SecurityErrorCode.CRYPTO_ERROR, "Decryption failed", { cause: String(error) });
    }
  }
}