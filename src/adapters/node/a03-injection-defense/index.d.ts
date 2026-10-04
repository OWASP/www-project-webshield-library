/**
 * Validates request input against an `InputValidator` schema and throws
 * `INVALID_INPUT` (carrying the per-field errors) when it fails. A body that
 * isn't an object, such as a JSON array or string, is validated as `{}`, so its
 * required fields fail instead of being read off the wrong type.
 *
 * @param {unknown} input
 * @param {Record<string, {required?: boolean, type?: string, minLength?: number, maxLength?: number, pattern?: RegExp}>} schema
 * @param {{validator?: InputValidator, allowUnknownFields?: boolean}} [options]
 *   `allowUnknownFields: false` also rejects fields the schema doesn't list,
 *   which stops mass assignment (`{"role": "admin"}`) when the body is passed on
 *   to a model or database call as a whole.
 */
export function assertValidInput(input: unknown, schema: Record<string, {
    required?: boolean;
    type?: string;
    minLength?: number;
    maxLength?: number;
    pattern?: RegExp;
}>, { validator, allowUnknownFields }?: {
    validator?: InputValidator;
    allowUnknownFields?: boolean;
}): unknown;
/**
 * A shallow copy of `input` with the listed string fields run through
 * `InputSanitizer.sanitizeHTML()`. Other fields are copied unchanged.
 *
 * @param {unknown} input
 * @param {string[]} fields
 * @param {{sanitizer?: InputSanitizer}} [options] defaults to the "strict" profile
 */
export function sanitizeFields(input: unknown, fields: string[], { sanitizer }?: {
    sanitizer?: InputSanitizer;
}): any;
import { InputValidator } from "@owasp-webshield/core";
import { InputSanitizer } from "@owasp-webshield/core";
