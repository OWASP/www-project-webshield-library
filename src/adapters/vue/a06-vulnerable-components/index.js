import { computed, readonly, shallowRef, toValue } from "vue";
import { DependencyRiskScanner } from "@owasp-webshield/core";

/**
 * Runs `DependencyRiskScanner` scans with reactive `loading`/`results`/`error`.
 * When scans overlap, only the latest one updates the state.
 * @param {import("vue").MaybeRefOrGetter<{scan: () => Promise<Array<{name: string, severity: string}>>}>} provider
 */
export function useDependencyRiskScanner(provider) {
  const scanner = computed(() => new DependencyRiskScanner(toValue(provider)));
  const loading = shallowRef(false);
  const results = shallowRef([]);
  const error = shallowRef(null);
  let latestRun = 0;

  async function runScan() {
    const run = ++latestRun;
    loading.value = true;
    error.value = null;
    try {
      const scanResults = await scanner.value.scan();
      if (run === latestRun) {
        results.value = scanResults;
        loading.value = false;
      }
      return scanResults;
    } catch (caught) {
      if (run === latestRun) {
        results.value = [];
        error.value = caught;
        loading.value = false;
      }
      throw caught;
    }
  }

  return { loading: readonly(loading), results: readonly(results), error: readonly(error), runScan, scanner };
}
