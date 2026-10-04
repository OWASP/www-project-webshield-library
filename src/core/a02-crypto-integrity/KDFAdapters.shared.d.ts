export const DEFAULT_PBKDF2_ITERATIONS: 600000;
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
