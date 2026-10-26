export function generateSalt(size?: number): NonSharedBuffer;
/**
 * @typedef {{
 *  deriveKey: (password: string, salt: Buffer, options?: Record<string, unknown>) => Buffer
 * }} KDFAdapter
 */
export class PBKDF2Adapter {
    constructor({ iterations, keyLength, digest }?: {
        iterations?: 600000;
        keyLength?: number;
        digest?: string;
    });
    iterations: 600000;
    keyLength: number;
    digest: string;
    deriveKey(password: any, salt: any): NonSharedBuffer;
}
export type KDFAdapter = {
    deriveKey: (password: string, salt: Buffer, options?: Record<string, unknown>) => Buffer;
};
export { Argon2Adapter, DEFAULT_PBKDF2_ITERATIONS } from "./KDFAdapters.shared.js";
