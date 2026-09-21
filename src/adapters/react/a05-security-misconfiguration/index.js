import React from "react";
import { HardeningReporter } from "@owasp-webshield/core/modules/a05-security-misconfiguration/HardeningReporter.js";
import { SecurityConfigManager } from "@owasp-webshield/core/modules/a05-security-misconfiguration/SecurityConfigManager.js";

/**
 * Hook that evaluates configuration and returns findings report.
 */
export function useHardeningReport(config = {}) {
  return React.useMemo(() => {
    const manager = new SecurityConfigManager(config);
    return new HardeningReporter(manager).generate();
  }, [config]);
}