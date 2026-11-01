import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "src-tauri"] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // These helpers live beside the component they belong to on purpose (shadcn's *Variants,
      // the severity helpers, the revision hook). The only cost is a full reload instead of a hot
      // swap when one of those files changes in dev, so they are allowed by name — a new
      // non-component export elsewhere still warns.
      "react-refresh/only-export-components": [
        "warn",
        {
          allowConstantExport: true,
          allowExportNames: [
            "badgeVariants",
            "buttonVariants",
            "tabsListVariants",
            "groupFindingsByCategory",
            "ignoreKeyOf",
            "SEVERITY_ORDER",
            "severityLabel",
            "railStyle",
            "useRevision",
          ],
        },
      ],
      // Rules read live host state into typed structs whose exact shape isn't worth
      // re-declaring on the frontend for every unused field — an explicit opt-out here,
      // not a blanket relaxation (unused *variables* still error).
      "@typescript-eslint/no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
    },
  },
);
