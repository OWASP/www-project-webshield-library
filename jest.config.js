export default {
  testEnvironment: "jsdom",
  extensionsToTreatAsEsm: [".jsx"],
  roots: ["<rootDir>/src"],
  testMatch: ["**/__tests__/**/*.test.js"],
  moduleNameMapper: {
    "^@owasp-js/owl$": "<rootDir>/src/index.js",
    "^@owasp-js/owl-react$": "<rootDir>/src/adapters/react/index.js"
  },
  collectCoverageFrom: [
    "src/core/**/*.js",
    "src/adapters/react/**/*.js",
    "!src/**/*.test.js",
    "!src/**/index.js"
  ]
};