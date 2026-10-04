import { InputSanitizer, InputValidator, SecurityError, SecurityErrorCode } from "@owasp-webshield/core";

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

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
export function assertValidInput(input, schema, { validator = new InputValidator(), allowUnknownFields = true } = {}) {
  const data = isPlainObject(input) ? input : {};
  const { errors } = validator.validateSchema(data, schema);
  if (!allowUnknownFields) {
    for (const key of Object.keys(data)) {
      if (!Object.hasOwn(schema, key)) errors.push({ field: key, code: "unknown", message: `${key} is not allowed` });
    }
  }
  if (errors.length) {
    throw new SecurityError(SecurityErrorCode.INVALID_INPUT, "Request failed validation", { errors });
  }
  return data;
}

/**
 * A shallow copy of `input` with the listed string fields run through
 * `InputSanitizer.sanitizeHTML()`. Other fields are copied unchanged.
 *
 * @param {unknown} input
 * @param {string[]} fields
 * @param {{sanitizer?: InputSanitizer}} [options] defaults to the "strict" profile
 */
export function sanitizeFields(input, fields, { sanitizer = new InputSanitizer("strict") } = {}) {
  if (!isPlainObject(input)) return input;
  const output = { ...input };
  for (const field of fields) {
    if (typeof output[field] === "string") output[field] = sanitizer.sanitizeHTML(output[field]);
  }
  return output;
}
