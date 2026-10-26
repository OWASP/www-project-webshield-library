import React from "react";
import { ThreatModelGuard } from "@owasp-webshield/core";
import { useStableValue } from "../useStableValue.js";

/**
 * React hook wrapper around core ThreatModelGuard.
 */
export function useThreatModelGuard(config = {}) {
  const stableConfig = useStableValue(config);
  return React.useMemo(() => new ThreatModelGuard(stableConfig), [stableConfig]);
}
