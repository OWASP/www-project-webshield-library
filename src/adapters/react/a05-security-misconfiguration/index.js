import React from "react";
import { HardeningReporter } from "@owasp-webshield/core/modules/a05-security-misconfiguration/HardeningReporter.js";
import { SecurityConfigManager } from "@owasp-webshield/core/modules/a05-security-misconfiguration/SecurityConfigManager.js";

// See a02-crypto-integrity/index.js for why this needs to be hoisted: a
// literal `= {}` default is re-created on every call, which breaks
// useMemo's memoization for the common no-argument case.
const EMPTY_CONFIG = Object.freeze({});

/**
 * Hook that evaluates configuration and returns findings report.
 */
export function useHardeningReport(config = EMPTY_CONFIG) {
  return React.useMemo(() => {
    const manager = new SecurityConfigManager(config);
    return new HardeningReporter(manager).generate();
  }, [config]);
}