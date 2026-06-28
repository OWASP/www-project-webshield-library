export default {
  testEnvironment: "jsdom",
  extensionsToTreatAsEsm: [".jsx"],
  roots: ["<rootDir>/src"],
  testMatch: ["**/__tests__/**/*.test.js"],
  moduleNameMapper: {
    "^@owl/core$": "<rootDir>/src/index.js",
    "^@owl/react-adapter$": "<rootDir>/src/adapters/react/index.js"
  },
  collectCoverageFrom: [
    "src/core/**/*.js",
    "src/adapters/react/**/*.js",
    "!src/**/*.test.js",
    "!src/**/index.js"
  ]
};