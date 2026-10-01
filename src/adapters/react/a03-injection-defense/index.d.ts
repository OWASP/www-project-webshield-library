/**
 * React hook wrapper around core InputSanitizer.
 * @param {"strict"|"moderate"} [profile]
 * @param {{allowedClasses?: string[]}} [options]
 */
export function useInputSanitizer(profile?: "strict" | "moderate", options?: {
    allowedClasses?: string[];
}): any;
/**
 * Renders `html` after sanitizing it. The sanitizer's output is HTML (entities
 * encoded, only allowlisted tags kept), so it is inserted as markup; passing it
 * as a text child would escape it a second time ("Tom &amp; Jerry").
 */
export function SanitizedText({ html, profile, allowedClasses }: {
    html: any;
    profile?: string;
    allowedClasses: any;
}): any;
