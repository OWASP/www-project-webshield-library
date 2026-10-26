import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";

// Browser build of KDFAdapters (see package.json's "browser" export condition).
// `Argon2Adapter` and `DEFAULT_PBKDF2_ITERATIONS` come from KDFAdapters.shared.js,
// like in the Node build, so both builds export the same ones. `generateSalt` only
// needs random bytes, which the Web Crypto API provides natively, so it's
// reimplemented portably instead of stubbed. Only `PBKDF2Adapter` (Node's
// synchronous `pbkdf2Sync`) has no browser equivalent.
export { Argon2Adapter, DEFAULT_PBKDF2_ITERATIONS } from "./KDFAdapters.shared.js";

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
