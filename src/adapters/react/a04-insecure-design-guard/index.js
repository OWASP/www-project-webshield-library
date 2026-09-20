import React from "react";
import { ThreatModelGuard } from "../../../core/a04-insecure-design-guard/ThreatModelGuard.js";

const EMPTY_CONFIG = Object.freeze({});

/**
 * React hook wrapper around core ThreatModelGuard.
 */
export function useThreatModelGuard(config = EMPTY_CONFIG) {
  return React.useMemo(() => new ThreatModelGuard(config), [config]);
}