export class InputSanitizer {
    /**
     * @param {"strict"|"moderate"} [profile]
     * @param {{allowedClasses?: string[]}} [options] class names that may survive on
     *   moderate-profile tags; every other class name is removed.
     */
    constructor(profile?: "strict" | "moderate", options?: {
        allowedClasses?: string[];
    });
    profile: string;
    allowedClasses: Set<string>;
    sanitizeHTML(input: any): string;
}
