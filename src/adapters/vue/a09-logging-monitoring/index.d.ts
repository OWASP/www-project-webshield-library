/**
 * The provided `SecurityLogger` and `EventEmitter` (either can be null).
 * @returns {{logger: object | null, events: object | null}}
 */
export function useSecurityMonitoring(): {
    logger: object | null;
    events: object | null;
};
/**
 * An accessible alert. Content comes from `message` or the default slot, and
 * is rendered as text, never as HTML.
 */
export const SecurityAlert: import("vue").DefineComponent<import("vue").ExtractPropTypes<{
    message: {
        type: StringConstructor;
        default: string;
    };
    level: {
        type: StringConstructor;
        default: string;
    };
}>, () => import("vue").VNode<import("vue").RendererNode, import("vue").RendererElement, {
    [key: string]: any;
}>, {}, {}, {}, import("vue").ComponentOptionsMixin, import("vue").ComponentOptionsMixin, {}, string, import("vue").PublicProps, Readonly<import("vue").ExtractPropTypes<{
    message: {
        type: StringConstructor;
        default: string;
    };
    level: {
        type: StringConstructor;
        default: string;
    };
}>> & Readonly<{}>, {
    message: string;
    level: string;
}, {}, {}, {}, string, import("vue").ComponentProvideOptions, true, {}, any>;
