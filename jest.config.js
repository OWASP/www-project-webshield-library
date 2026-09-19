export default {
  testEnvironment: "jsdom",
  extensionsToTreatAsEsm: [".jsx"],
  roots: ["<rootDir>/src"],
  testMatch: ["**/__tests__/**/*.test.js"],
  moduleNameMapper: {
    "^@owasp-core/owl$": "<rootDir>/src/index.js",
    "^@owasp-core/owl-react$": "<rootDir>/src/adapters/react/index.js"
  },
  collectCoverageFrom: [
    "src/core/**/*.js",
    "src/adapters/react/**/*.js",
    "!src/**/*.test.js",
    "!src/**/index.js"
  ]
};