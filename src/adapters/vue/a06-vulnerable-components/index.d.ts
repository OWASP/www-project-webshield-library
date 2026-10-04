/**
 * Runs `DependencyRiskScanner` scans with reactive `loading`/`results`/`error`.
 * When scans overlap, only the latest one updates the state.
 * @param {import("vue").MaybeRefOrGetter<{scan: () => Promise<Array<{name: string, severity: string}>>}>} provider
 */
export function useDependencyRiskScanner(provider: import("vue").MaybeRefOrGetter<{
    scan: () => Promise<Array<{
        name: string;
        severity: string;
    }>>;
}>): {
    loading: Readonly<import("vue").Ref<boolean, boolean>>;
    results: Readonly<import("vue").Ref<readonly any[], readonly any[]>>;
    error: Readonly<import("vue").Ref<any, any>>;
    runScan: () => Promise<{
        package: string;
        severity: string;
        fixedVersion: string;
        currentVersion: string;
    }[]>;
    scanner: import("vue").ComputedRef<DependencyRiskScanner>;
};
import { DependencyRiskScanner } from "@owasp-webshield/core";
