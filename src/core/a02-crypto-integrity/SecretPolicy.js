export class SecretPolicy {
  static minimumEntropyBits(secret) {
    const unique = new Set(String(secret || "").split(""));
    const charsetEstimate = Math.max(unique.size, 1);
    return Math.round(Math.log2(charsetEstimate) * String(secret || "").length);
  }

  static isEntropySufficient(secret, minimumBits = 60) {
    return SecretPolicy.minimumEntropyBits(secret) >= minimumBits;
  }

  static isRotationWindowExceeded(issuedAtMs, maxAgeMs) {
    return Date.now() - issuedAtMs > maxAgeMs;
  }
}