/**
 * The `HardeningReporter` findings for `config`; recomputed when a ref/getter
 * `config` changes.
 * @param {import("vue").MaybeRefOrGetter<object>} [config]
 * @returns {import("vue").ComputedRef<Array<{id: string, severity: string, recommendation: string}>>}
 */
export function useHardeningReport(config?: import("vue").MaybeRefOrGetter<object>): import("vue").ComputedRef<Array<{
    id: string;
    severity: string;
    recommendation: string;
}>>;
