import React from "react";
import { CryptoManager } from "@owasp-webshield/core";
import { useStableValue } from "../useStableValue.js";

/**
 * React hook wrapper around core CryptoManager.
 */
export function useCryptoManager(options = {}) {
  const stableOptions = useStableValue(options);
  return React.useMemo(() => new CryptoManager(stableOptions), [stableOptions]);
}
