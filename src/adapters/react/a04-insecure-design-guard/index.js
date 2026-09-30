import React from "react";
import { ThreatModelGuard } from "@owasp-webshield/core";

/**
 * React hook wrapper around core ThreatModelGuard.
 */
export function useThreatModelGuard(config = {}) {
  return React.useMemo(() => new ThreatModelGuard(config), [config]);
}