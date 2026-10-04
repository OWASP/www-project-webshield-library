import { computed, toValue } from "vue";
import { ThreatModelGuard } from "@owasp-webshield/core";

/**
 * A `ThreatModelGuard`; rebuilt when a ref/getter `config` changes.
 * @param {import("vue").MaybeRefOrGetter<object>} [config]
 * @returns {import("vue").ComputedRef<ThreatModelGuard>}
 */
export function useThreatModelGuard(config = {}) {
  return computed(() => new ThreatModelGuard({ ...toValue(config) }));
}
