import React from "react";
import { CryptoManager } from "@owasp-webshield/core/modules/a02-crypto-integrity/CryptoManager.js";

// A literal `= {}` default is re-created on every call, so useMemo's
// dependency reference (and thus the memoization) breaks on every render
// for the common no-argument case. A hoisted, frozen constant stays
// referentially stable across renders.
const EMPTY_OPTIONS = Object.freeze({});

/**
 * React hook wrapper around core CryptoManager.
 */
export function useCryptoManager(options = EMPTY_OPTIONS) {
  return React.useMemo(() => new CryptoManager(options), [options]);
}