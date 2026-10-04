// Browser build entry (selected via package.json's "browser" exports condition).
// The same exports as index.js, except that A02 resolves to its browser-safe
// variant: see a02-crypto-integrity/index.browser.js and the FAQ for why
// CryptoManager can't be made fully portable. A08 needs no swap:
// CSRFTokenManager is Web Crypto-based.
export * from "./index.shared.js";

export { useCryptoManager } from "./a02-crypto-integrity/index.browser.js";
export * as A02CryptoIntegrity from "./a02-crypto-integrity/index.browser.js";
