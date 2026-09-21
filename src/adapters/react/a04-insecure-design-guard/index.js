import React from "react";
import { ThreatModelGuard } from "@owasp-js/owl/core/a04-insecure-design-guard/ThreatModelGuard.js";

/**
 * React hook wrapper around core ThreatModelGuard.
 */
export function useThreatModelGuard(config = {}) {
  return React.useMemo(() => new ThreatModelGuard(config), [config]);
}