import js from "@eslint/js";
import globals from "globals";

export default [
  {
    ignores: ["**/dist/**", "**/node_modules/**", "**/.next/**"]
  },
  js.configs.recommended,
  {
    files: ["src/**/*.js", "src/**/*.jsx", "examples/**/*.js", "examples/**/*.jsx", "scripts/**/*.mjs", "jest.config.js"],
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
    files: ["scripts/**/*.mjs"],
    languageOptions: {
      globals: {
        ...globals.node,
        URL: "readonly"
      }
    }
  },
  {
    // No JSX plugin here, so a component used only in JSX looks unused. Next.js
    // apps write JSX in .js files, hence the example's app/ folder too.
    files: ["src/**/*.jsx", "examples/**/*.jsx", "examples/owl-enabled-nextjs-expense-portal/app/**/*.js"],
    rules: {
      "no-unused-vars": "off"
    }
  }
];