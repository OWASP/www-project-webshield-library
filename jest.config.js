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
    "!src/**/index.js"
  ],
  // Enforced only when coverage is collected (npm run test:coverage, PR review workflow).
  // Set just below the measured baseline (87.6 / 81.8 / 87.1 / 89.9) so coverage can't
  // silently drop; raise these as coverage improves.
  coverageThreshold: {
    global: {
      statements: 86,
      branches: 80,
      functions: 85,
      lines: 88
    }
  }
};