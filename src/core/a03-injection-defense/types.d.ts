/**
 * @typedef {Object} ValidationResult
 * @property {boolean} valid
 * @property {Array<{field:string,code:string,message:string}>} errors
 */
export const INJECTION_DEFENSE_TYPES: {};
export type ValidationResult = {
    valid: boolean;
    errors: Array<{
        field: string;
        code: string;
        message: string;
    }>;
};
