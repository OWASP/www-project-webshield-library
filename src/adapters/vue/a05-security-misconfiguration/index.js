import { computed, toValue } from "vue";
import { HardeningReporter, SecurityConfigManager } from "@owasp-webshield/core";

/**
 * The `HardeningReporter` findings for `config`; recomputed when a ref/getter
 * `config` changes.
 * @param {import("vue").MaybeRefOrGetter<object>} [config]
 * @returns {import("vue").ComputedRef<Array<{id: string, severity: string, recommendation: string}>>}
 */
export function useHardeningReport(config = {}) {
  return computed(() => new HardeningReporter(new SecurityConfigManager({ ...toValue(config) })).generate());
}
