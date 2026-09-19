// Character-class pool sizes used to estimate bits-per-symbol, rather than
// trusting a secret's own literal character count as its "charset size".
const CHARACTER_POOLS = [
  { pattern: /[a-z]/, size: 26 },
  { pattern: /[A-Z]/, size: 26 },
  { pattern: /[0-9]/, size: 10 },
  { pattern: /[^a-zA-Z0-9]/, size: 33 }
];

export class SecretPolicy {
  // Entropy = (count of distinct characters actually used) x (bits per symbol
  // for the character classes present). Unlike raw-length x log2(uniqueCount),
  // this does not reward repeating a short pattern over a long string (e.g.
  // "ab".repeat(32)), since repetition doesn't raise the distinct-character count.
  static minimumEntropyBits(secret) {
    const value = String(secret || "");
    if (!value) return 0;

    const poolSize = CHARACTER_POOLS.reduce(
      (total, { pattern, size }) => (pattern.test(value) ? total + size : total),
      0
    );
    const uniqueChars = new Set(value).size;
    return Math.round(uniqueChars * Math.log2(Math.max(poolSize, 2)));
  }

  static isEntropySufficient(secret, minimumBits = 60) {
    return SecretPolicy.minimumEntropyBits(secret) >= minimumBits;
  }

  static isRotationWindowExceeded(issuedAtMs, maxAgeMs) {
    return Date.now() - issuedAtMs > maxAgeMs;
  }
}