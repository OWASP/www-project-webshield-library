export function generateSalt(size?: number): Uint8Array<ArrayBuffer>;
export class PBKDF2Adapter {
    deriveKey(): void;
}
export { Argon2Adapter, DEFAULT_PBKDF2_ITERATIONS } from "./KDFAdapters.shared.js";
