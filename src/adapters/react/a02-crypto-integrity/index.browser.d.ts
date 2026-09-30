/**
 * Browser build of the A02 crypto adapter (see package.json's "browser" export
 * condition). In a browser bundle "@owasp-webshield/core" also resolves to its
 * browser build, whose `CryptoManager` is the throwing stub — see the FAQ for why
 * AES-256-GCM/PBKDF2 have no browser-portable equivalent. Importing the package
 * root (not a `modules/*` path) keeps a single copy of each class per bundle.
 */
export function useCryptoManager(options?: {}): any;
