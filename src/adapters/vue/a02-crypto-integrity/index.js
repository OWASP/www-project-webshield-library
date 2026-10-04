import { computed, toValue } from "vue";
import { CryptoManager } from "@owasp-webshield/core";

/**
 * A `CryptoManager`; rebuilt when a ref/getter `options` changes.
 *
 * Real encryption needs Node. In a browser bundle `@owasp-webshield/core`
 * resolves to its browser build, where `CryptoManager` is a stub whose
 * methods throw (see the FAQ).
 * @param {import("vue").MaybeRefOrGetter<object>} [options]
 * @returns {import("vue").ComputedRef<CryptoManager>}
 */
export function useCryptoManager(options = {}) {
  return computed(() => new CryptoManager({ ...toValue(options) }));
}
