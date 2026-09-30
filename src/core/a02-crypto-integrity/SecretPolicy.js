// Character-class pool sizes used to estimate bits-per-symbol, rather than
// trusting a secret's own literal character count as its "charset size".
const CHARACTER_POOLS = [
  { pattern: /[a-z]/, size: 26 },
  { pattern: /[A-Z]/, size: 26 },
  { pattern: /[0-9]/, size: 10 },
  { pattern: /[^a-zA-Z0-9]/, size: 33 }
];

// Predictable segments an attacker's wordlist or mask tries first. Each match
// contributes a small fixed guess cost instead of full per-character entropy.
const COMMON_WORDS =
  /p[a@4]ss(?:w[o0]rd)?|qwerty|letmein|welcome|admin|login|secret|monkey|dragon|football|baseball|iloveyou|sunshine|princess|master|shadow|summer|winter|spring|autumn|changeme/gi;
const YEARS = /(?:19|20)\d{2}/g;
const KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];
const MIN_RUN = 3;
const WEAK_SEGMENT_BITS = 8;

// Marks every character that belongs to a predictable segment; returns the count of segments.
function markWeakSegments(value, weak) {
  let segments = 0;
  const mark = (start, end) => {
    let added = false;
    for (let i = start; i < end; i++) {
      added = added || !weak[i];
      weak[i] = true;
    }
    if (added) segments++; // overlapping matches (e.g. "qwerty" word + keyboard run) count once
  };

  for (const pattern of [COMMON_WORDS, YEARS]) {
    for (const match of value.matchAll(pattern)) mark(match.index, match.index + match[0].length);
  }

  // Ascending/descending character runs ("abc", "321") and keyboard-row runs ("qwe", "lkj").
  const lower = value.toLowerCase();
  const isStep = (a, b) =>
    Math.abs(lower.charCodeAt(b) - lower.charCodeAt(a)) === 1 ||
    KEYBOARD_ROWS.some((row) => {
      const i = row.indexOf(lower[a]);
      return i !== -1 && (row[i + 1] === lower[b] || row[i - 1] === lower[b]);
    });
  let start = 0;
  for (let i = 1; i <= lower.length; i++) {
    if (i < lower.length && isStep(i - 1, i)) continue;
    if (i - start >= MIN_RUN) mark(start, i);
    start = i;
  }
  return segments;
}

export class SecretPolicy {
  // An estimate, not a guarantee. Entropy = (count of distinct characters outside
  // predictable segments) x (bits per symbol for the character classes present),
  // plus a small fixed cost per predictable segment (dictionary word, year,
  // sequence, keyboard run). Repeating a short pattern ("ab".repeat(32)) doesn't
  // raise the distinct-character count, and "Password123!" scores like a guessable
  // password rather than a 12-character random string.
  static minimumEntropyBits(secret) {
    const value = String(secret || "");
    if (!value) return 0;

    const poolSize = CHARACTER_POOLS.reduce(
      (total, { pattern, size }) => (pattern.test(value) ? total + size : total),
      0
    );
    const weak = new Array(value.length).fill(false);
    const weakSegments = markWeakSegments(value, weak);
    const remaining = new Set();
    for (let i = 0; i < value.length; i++) {
      if (!weak[i]) remaining.add(value[i]);
    }
    const uniqueChars = remaining.size;
    return Math.round(uniqueChars * Math.log2(Math.max(poolSize, 2)) + weakSegments * WEAK_SEGMENT_BITS);
  }

  static isEntropySufficient(secret, minimumBits = 60) {
    return SecretPolicy.minimumEntropyBits(secret) >= minimumBits;
  }

  static isRotationWindowExceeded(issuedAtMs, maxAgeMs) {
    return Date.now() - issuedAtMs > maxAgeMs;
  }
}
