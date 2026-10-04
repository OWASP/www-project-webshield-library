import { computed, toValue, unref } from "vue";
import { SafeFetcher, SSRFGuard } from "@owasp-webshield/core";

/**
 * A `SafeFetcher` enforcing the SSRF policy in `config`; rebuilt when a
 * ref/getter argument changes.
 * @param {import("vue").MaybeRefOrGetter<object>} [config]
 * @param {typeof fetch | import("vue").Ref<typeof fetch>} [fetchImpl] a function or a ref to one (a function is never called as a getter)
 * @returns {import("vue").ComputedRef<SafeFetcher>}
 */
export function useSafeFetcher(config = {}, fetchImpl) {
  const guard = computed(() => new SSRFGuard({ ...toValue(config) }));
  return computed(() => new SafeFetcher({ guard: guard.value, fetchImpl: unref(fetchImpl) }));
}
