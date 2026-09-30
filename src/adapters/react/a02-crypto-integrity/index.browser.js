import React from "react";
import { CryptoManager } from "@owasp-webshield/core/modules/a02-crypto-integrity/CryptoManager.browser.js";
import { useStableValue } from "../useStableValue.js";

/**
 * Browser build of the A02 crypto adapter (see package.json's "browser" export
 * condition). Returns the same throwing-stub `CryptoManager` used by the core
 * package's browser build — see the FAQ for why AES-256-GCM/PBKDF2 have no
 * browser-portable equivalent.
 */
export function useCryptoManager(options = {}) {
  const stableOptions = useStableValue(options);
  return React.useMemo(() => new CryptoManager(stableOptions), [stableOptions]);
}
