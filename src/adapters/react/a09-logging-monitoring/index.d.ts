export function SecurityProvider({ logger, events, children }: {
    logger: any;
    events: any;
    children: any;
}): any;
/**
 * Hook exposing logger and event emitter from SecurityProvider.
 */
export function useSecurityMonitoring(): any;
export function SecurityAlert({ message, level }: {
    message: any;
    level?: string;
}): any;
export const SecurityContext: any;
