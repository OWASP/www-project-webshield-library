export default {
  testEnvironment: "jsdom",
  extensionsToTreatAsEsm: [".jsx"],
  roots: ["<rootDir>/src"],
  testMatch: ["**/__tests__/**/*.test.js"],
  moduleNameMapper: {
    "^@owasp-webshield/core$": "<rootDir>/src/index.js",
    "^@owasp-webshield/react$": "<rootDir>/src/adapters/react/index.js",
    "^@owasp-webshield/node$": "<rootDir>/src/adapters/node/index.js",
    "^@owasp-webshield/express$": "<rootDir>/src/adapters/express/index.js",
    "^@owasp-webshield/vue$": "<rootDir>/src/adapters/vue/index.js"
  },
  collectCoverageFrom: [
    "src/core/**/*.js",
    "src/adapters/react/**/*.js",
    "src/adapters/node/**/*.js",
    "src/adapters/express/**/*.js",
    "src/adapters/vue/**/*.js",
    "!src/**/*.test.js",
    // Barrel files only. The adapters keep each category's code in its own
    // index.js (src/adapters/<name>/a0X-*/index.js), so those are measured.
    "!src/index.js",
    "!src/index.browser.js",
    "!src/core/**/index.js",
    "!src/core/**/index.browser.js",
    "!src/adapters/*/index.js",
    "!src/adapters/*/index.browser.js"
  ],
  // Enforced only when coverage is collected (npm run test:coverage, PR review workflow).
  // Set just below the measured baseline (92.0 / 85.8 / 92.1 / 93.5) so coverage can't
  // silently drop; raise these as coverage improves.
  coverageThreshold: {
    global: {
      statements: 91,
      branches: 84,
      functions: 91,
      lines: 92
    }
  }
};