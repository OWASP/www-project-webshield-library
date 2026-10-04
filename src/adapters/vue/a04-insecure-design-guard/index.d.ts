/**
 * A `ThreatModelGuard`; rebuilt when a ref/getter `config` changes.
 * @param {import("vue").MaybeRefOrGetter<object>} [config]
 * @returns {import("vue").ComputedRef<ThreatModelGuard>}
 */
export function useThreatModelGuard(config?: import("vue").MaybeRefOrGetter<object>): import("vue").ComputedRef<ThreatModelGuard>;
import { ThreatModelGuard } from "@owasp-webshield/core";
