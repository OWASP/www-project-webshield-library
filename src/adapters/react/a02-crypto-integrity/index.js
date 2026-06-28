import React from "react";
import { CryptoManager } from "../../../core/a02-crypto-integrity/CryptoManager.js";

/**
 * React hook wrapper around core CryptoManager.
 */
export function useCryptoManager(options = {}) {
  return React.useMemo(() => new CryptoManager(options), [options]);
}