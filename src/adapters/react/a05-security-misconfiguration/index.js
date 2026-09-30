import React from "react";
import { HardeningReporter, SecurityConfigManager } from "@owasp-webshield/core";
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
