export class SecretPolicy {
    static minimumEntropyBits(secret: any): number;
    static isEntropySufficient(secret: any, minimumBits?: number): boolean;
    static isRotationWindowExceeded(issuedAtMs: any, maxAgeMs: any): boolean;
}
