import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";

const UNAVAILABLE_MESSAGE =
  "CryptoManager requires Node's crypto module (AES-256-GCM/PBKDF2 have no synchronous, " +
  "browser-portable equivalent — Web Crypto's subtle.encrypt/deriveBits are async-only). " +
  "Use @owasp-webshield/core in a Node/SSR context for real encryption, or provide your own " +
  "Web Crypto-based implementation. See the FAQ: " +
  "https://owasp.org/www-project-webshield-library/faq#can-i-use-owl-in-a-browser-bundle";

// Browser build of CryptoManager (see package.json's "browser" export condition).
// Same class shape as the real, Node-only implementation, so `new CryptoManager()`
// and `instanceof` checks keep working — but every method throws a clear, actionable
// error instead of the whole bundle failing to build. Selected automatically by
// bundlers (Vite, webpack, Rollup with @rollup/plugin-node-resolve browser:true) that
// respect the "browser" exports condition; the real implementation is still used for
// Node/CJS/SSR builds.
export class CryptoManager {
  constructor() {
    this.kdfAdapter = null;
  }

  random() {
    throw new SecurityError(SecurityErrorCode.CRYPTO_ERROR, UNAVAILABLE_MESSAGE);
  }

  deriveKey() {
    throw new SecurityError(SecurityErrorCode.CRYPTO_ERROR, UNAVAILABLE_MESSAGE);
  }

  encrypt() {
    throw new SecurityError(SecurityErrorCode.CRYPTO_ERROR, UNAVAILABLE_MESSAGE);
  }

  decrypt() {
    throw new SecurityError(SecurityErrorCode.CRYPTO_ERROR, UNAVAILABLE_MESSAGE);
  }
}
