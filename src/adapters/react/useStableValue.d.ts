/**
 * Returns the previous value while the new one is structurally equal, so hooks
 * can memoize on config objects written inline (`useSafeFetcher({})`) instead of
 * rebuilding their instance on every render. Internal to the React adapter.
 */
export function useStableValue(value: any): any;
