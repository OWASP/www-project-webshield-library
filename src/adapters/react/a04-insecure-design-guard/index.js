import React from "react";
import { ThreatModelGuard } from "@owasp-webshield/core/modules/a04-insecure-design-guard/ThreatModelGuard.js";

// See a02-crypto-integrity/index.js for why this needs to be hoisted: a
// literal `= {}` default is re-created on every call, which breaks
// useMemo's memoization for the common no-argument case.
const EMPTY_CONFIG = Object.freeze({});

/**
 * React hook wrapper around core ThreatModelGuard.
 */
export function useThreatModelGuard(config = EMPTY_CONFIG) {
  return React.useMemo(() => new ThreatModelGuard(config), [config]);
}