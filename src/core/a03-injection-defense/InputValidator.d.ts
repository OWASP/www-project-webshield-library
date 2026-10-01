export class InputValidator {
    validateSchema(input: any, schema: any): {
        valid: boolean;
        errors: {
            field: string;
            code: string;
            message: string;
        }[];
    };
    validateEmail(value: any): boolean;
    validateUrl(value: any): boolean;
    validateLength(value: any, { min, max }?: {
        min?: number;
        max?: number;
    }): boolean;
}
