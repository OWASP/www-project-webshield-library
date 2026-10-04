/**
 * A `SafeFetcher` enforcing the SSRF policy in `config`; rebuilt when a
 * ref/getter argument changes.
 * @param {import("vue").MaybeRefOrGetter<object>} [config]
 * @param {typeof fetch | import("vue").Ref<typeof fetch>} [fetchImpl] a function or a ref to one (a function is never called as a getter)
 * @returns {import("vue").ComputedRef<SafeFetcher>}
 */
export function useSafeFetcher(config?: import("vue").MaybeRefOrGetter<object>, fetchImpl?: typeof fetch | import("vue").Ref<typeof fetch>): import("vue").ComputedRef<SafeFetcher>;
import { SafeFetcher } from "@owasp-webshield/core";
