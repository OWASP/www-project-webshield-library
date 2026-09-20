import React from "react";
import { CryptoManager } from "../../../core/a02-crypto-integrity/CryptoManager.js";

const EMPTY_OPTIONS = Object.freeze({});

/**
 * React hook wrapper around core CryptoManager.
 */
export function useCryptoManager(options = EMPTY_OPTIONS) {
  return React.useMemo(() => new CryptoManager(options), [options]);
}