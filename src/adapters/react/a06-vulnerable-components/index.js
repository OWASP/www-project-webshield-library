import React from "react";
import { DependencyRiskScanner } from "../../../core/a06-vulnerable-components/DependencyRiskScanner.js";

/**
 * Hook to run dependency risk scans in React components.
 */
export function useDependencyRiskScanner(provider) {
  const scanner = React.useMemo(() => new DependencyRiskScanner(provider), [provider]);
  const [state, setState] = React.useState({ loading: false, results: [], error: null });

  const runScan = React.useCallback(async () => {
    setState((prev) => ({ ...prev, loading: true, error: null }));
    try {
      const results = await scanner.scan();
      setState({ loading: false, results, error: null });
      return results;
    } catch (error) {
      setState({ loading: false, results: [], error });
      throw error;
    }
  }, [scanner]);

  return { ...state, runScan, scanner };
}