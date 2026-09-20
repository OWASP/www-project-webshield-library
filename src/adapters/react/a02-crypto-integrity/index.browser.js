import React from "react";
import { CryptoManager } from "@owasp-core/owl/core/a02-crypto-integrity/CryptoManager.browser.js";

/**
 * Browser build of the A02 crypto adapter (see package.json's "browser" export
 * condition). Returns the same throwing-stub `CryptoManager` used by the core
 * package's browser build — see the FAQ for why AES-256-GCM/PBKDF2 have no
 * browser-portable equivalent.
 */
export function useCryptoManager(options = {}) {
  return React.useMemo(() => new CryptoManager(options), [options]);
}
