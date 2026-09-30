export function generateSalt(size?: number): NonSharedBuffer;
/**
 * @typedef {{
 *  deriveKey: (password: string, salt: Buffer, options?: Record<string, unknown>) => Buffer
 * }} KDFAdapter
 */
export const DEFAULT_PBKDF2_ITERATIONS: 600000;
export class PBKDF2Adapter {
    constructor({ iterations, keyLength, digest }?: {
        iterations?: number;
        keyLength?: number;
        digest?: string;
    });
    iterations: number;
    keyLength: number;
    digest: string;
    deriveKey(password: any, salt: any): NonSharedBuffer;
}
/**
 * Argon2 adapter pattern.
 * Consumers can pass any Argon2 implementation via deriveFn.
 */
export class Argon2Adapter {
    /**
     * @param {{deriveFn: (password: string, salt: Buffer, options?: Record<string, unknown>) => Buffer}} options
     */
    constructor(options?: {
        deriveFn: (password: string, salt: Buffer, options?: Record<string, unknown>) => Buffer;
    });
    deriveFn: (password: string, salt: Buffer, options?: Record<string, unknown>) => Buffer;
    deriveKey(password: any, salt: any, options?: {}): Buffer<ArrayBufferLike>;
}
export type KDFAdapter = {
    deriveKey: (password: string, salt: Buffer, options?: Record<string, unknown>) => Buffer;
};
