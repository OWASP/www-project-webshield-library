import React from "react";
import { HardeningReporter } from "../../../core/a05-security-misconfiguration/HardeningReporter.js";
import { SecurityConfigManager } from "../../../core/a05-security-misconfiguration/SecurityConfigManager.js";

/**
 * Hook that evaluates configuration and returns findings report.
 */
export function useHardeningReport(config = {}) {
  return React.useMemo(() => {
    const manager = new SecurityConfigManager(config);
    return new HardeningReporter(manager).generate();
  }, [config]);
}