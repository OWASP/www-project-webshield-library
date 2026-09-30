import React from "react";
import { HardeningReporter } from "@owasp-webshield/core/modules/a05-security-misconfiguration/HardeningReporter.js";
import { SecurityConfigManager } from "@owasp-webshield/core/modules/a05-security-misconfiguration/SecurityConfigManager.js";
import { useStableValue } from "../useStableValue.js";

/**
 * Hook that evaluates configuration and returns findings report.
 */
export function useHardeningReport(config = {}) {
  const stableConfig = useStableValue(config);
  return React.useMemo(() => {
    const manager = new SecurityConfigManager(stableConfig);
    return new HardeningReporter(manager).generate();
  }, [stableConfig]);
}
