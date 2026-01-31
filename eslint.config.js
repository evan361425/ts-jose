import typescriptEslint from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import prettierConfig from "eslint-config-prettier";
import mochaPlugin from "eslint-plugin-mocha";
import globals from "globals";

export default [
  // 1. Global Ignores (Equivalent to .eslintignore)
  {
    ignores: ["node_modules/", "dist/"],
  },

  // 2. Main Configuration
  {
    files: ["**/*.ts", "**/*.tsx"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 2020,
        sourceType: "module",
        project: "./tsconfig.json",
      },
      globals: {
        ...globals.node,
      },
    },
    plugins: {
      "@typescript-eslint": typescriptEslint,
      "mocha": mochaPlugin,
    },
    rules: {
      // Manually merging recommended rules
      ...typescriptEslint.configs["recommended"].rules,
      ...typescriptEslint.configs["recommended-requiring-type-checking"].rules,
      ...mochaPlugin.configs.recommended.rules,

      // Custom Rules
      "eqeqeq": "warn",
      "@typescript-eslint/no-non-null-assertion": "off",
    },
  },

  // 3. Prettier (Must be last to override other rules)
  prettierConfig,

  {
    files: ["test/**/*.spec.ts"],
    rules: {
      "@typescript-eslint/no-unused-expressions": "off"
    }
  }
];
