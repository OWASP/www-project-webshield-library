import js from "@eslint/js";
import globals from "globals";

export default [
  {
    ignores: ["**/dist/**", "**/node_modules/**"]
  },
  js.configs.recommended,
  {
    files: ["src/**/*.js", "src/**/*.jsx", "examples/**/*.js", "examples/**/*.jsx", "jest.config.js"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      parserOptions: {
        ecmaFeatures: {
          jsx: true
        }
      },
      globals: {
        ...globals.node,
        ...globals.browser,
        ...globals.jest
      }
    },
    rules: {
      "no-unused-vars": ["error", { "argsIgnorePattern": "^_" }]
    }
  },
  {
    files: ["src/**/*.jsx", "examples/**/*.jsx"],
    rules: {
      "no-unused-vars": "off"
    }
  }
];