import React from "react";
import { ThreatModelGuard } from "@owasp-webshield/core";

const EMPTY_CONFIG = Object.freeze({});

/**
 * React hook wrapper around core ThreatModelGuard.
 */
export function useThreatModelGuard(config = EMPTY_CONFIG) {
  return React.useMemo(() => new ThreatModelGuard(config), [config]);
}