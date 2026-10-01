export class CryptoManager {
    constructor(options?: {});
    kdfAdapter: any;
    random(size?: number): NonSharedBuffer;
    deriveKey(password: any, salt?: NonSharedBuffer): {
        key: any;
        salt: NonSharedBuffer;
    };
    encrypt(plaintext: any, key: any): {
        ciphertext: string;
        iv: string;
        tag: string;
        alg: string;
    };
    decrypt(payload: any, key: any): string;
}
