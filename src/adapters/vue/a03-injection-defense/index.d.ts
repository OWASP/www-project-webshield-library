/**
 * An `InputSanitizer` for `profile`; rebuilt when a ref/getter argument changes.
 * @param {import("vue").MaybeRefOrGetter<"strict"|"moderate">} [profile]
 * @param {import("vue").MaybeRefOrGetter<{allowedClasses?: string[]}>} [options]
 * @returns {import("vue").ComputedRef<InputSanitizer>}
 */
export function useInputSanitizer(profile?: import("vue").MaybeRefOrGetter<"strict" | "moderate">, options?: import("vue").MaybeRefOrGetter<{
    allowedClasses?: string[];
}>): import("vue").ComputedRef<InputSanitizer>;
/**
 * Renders `html` after sanitizing it. The sanitizer's output is HTML (entities
 * encoded, only allowlisted tags kept), so it is inserted as markup.
 */
export const SanitizedText: import("vue").DefineComponent<import("vue").ExtractPropTypes<{
    html: {
        type: StringConstructor;
        default: string;
    };
    profile: {
        type: StringConstructor;
        default: string;
    };
    allowedClasses: {
        type: ArrayConstructor;
        default: any;
    };
}>, () => import("vue").VNode<import("vue").RendererNode, import("vue").RendererElement, {
    [key: string]: any;
}>, {}, {}, {}, import("vue").ComponentOptionsMixin, import("vue").ComponentOptionsMixin, {}, string, import("vue").PublicProps, Readonly<import("vue").ExtractPropTypes<{
    html: {
        type: StringConstructor;
        default: string;
    };
    profile: {
        type: StringConstructor;
        default: string;
    };
    allowedClasses: {
        type: ArrayConstructor;
        default: any;
    };
}>> & Readonly<{}>, {
    html: string;
    profile: string;
    allowedClasses: unknown[];
}, {}, {}, {}, string, import("vue").ComponentProvideOptions, true, {}, any>;
export namespace vSafeHtml {
    export { render as mounted };
    export { render as updated };
    export function getSSRProps(binding: any): {
        innerHTML: any;
    };
}
import { InputSanitizer } from "@owasp-webshield/core";
declare function render(el: any, binding: any): void;
export {};
