import React from "react";
import { SSRFGuard } from "../../../core/a10-ssrf-defense/SSRFGuard.js";
import { SafeFetcher } from "../../../core/a10-ssrf-defense/SafeFetcher.js";

/**
 * Hook that returns a SafeFetcher enforcing SSRF policy.
 */
export function useSafeFetcher(config = {}, fetchImpl) {
  const guard = React.useMemo(() => new SSRFGuard(config), [config]);
  return React.useMemo(() => new SafeFetcher({ guard, fetchImpl }), [guard, fetchImpl]);
}