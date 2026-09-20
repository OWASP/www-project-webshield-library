// Browser build entry (selected via package.json's "browser" exports condition).
// Identical to index.js except a02 resolves to its browser-safe variant — see
// a02-crypto-integrity/index.browser.js and the FAQ for why CryptoManager can't be
// made fully portable.
export * from "./a01-access-control/index.js";
export * from "./a02-crypto-integrity/index.browser.js";
export * from "./a03-injection-defense/index.js";
export * from "./a04-insecure-design-guard/index.js";
export * from "./a05-security-misconfiguration/index.js";
export * from "./a06-vulnerable-components/index.js";
export * from "./a07-auth-session/index.js";
export * from "./a08-data-integrity/index.js";
export * from "./a09-logging-monitoring/index.js";
export * from "./a10-ssrf-defense/index.js";
export * from "./error/index.js";
