import React from "react";
import { SafeFetcher, SSRFGuard } from "@owasp-webshield/core";
import { useStableValue } from "../useStableValue.js";

/**
 * Hook that returns a SafeFetcher enforcing SSRF policy. The instance is kept
 * across renders while `config` is structurally equal (functions inside it, such
 * as `resolveHost`, are compared by identity).
 */
export function useSafeFetcher(config = {}, fetchImpl) {
  const stableConfig = useStableValue(config);
  const guard = React.useMemo(() => new SSRFGuard(stableConfig), [stableConfig]);
  return React.useMemo(() => new SafeFetcher({ guard, fetchImpl }), [guard, fetchImpl]);
}
