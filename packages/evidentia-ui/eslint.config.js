// v0.7.14 P0.3: ESLint 10 flat-config for the Evidentia web UI.
//
// ESLint 10 requires the flat config format (`eslint.config.js`)
// and removed support for the legacy `.eslintrc.*` files. This is
// a minimal config that:
//
// - Lints `src/**/*.{ts,tsx}` (TypeScript + React surfaces)
// - Pulls in `eslint-plugin-react-hooks` recommended rules
// - Pulls in `eslint-plugin-react-refresh` for HMR-correctness
//   when using React Refresh in dev
// - Ignores `dist/` (Vite output) + `node_modules/` (default)
//
// Pre-v0.7.14 there was no ESLint config in this package, so the
// `npm run lint` step was effectively a no-op (it printed the
// migration message + exited). v0.7.14 P0.3 fixes the lint
// pipeline.

import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["dist/**", "node_modules/**", "coverage/**"],
  },
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}", "tests/**/*.{ts,tsx}"],
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": [
        "warn",
        { allowConstantExport: true },
      ],
      // The codebase uses `any` defensively in a few places where
      // SDK types are too narrow; keep as warnings, not errors.
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      // v0.7.15 P0.2: SettingsPage.tsx refactored to a key-based
      // remount pattern (sub-component <SettingsForm/> keyed on
      // configQuery.data.source_path; useState lazy initializers
      // seed from props). Promoted from `warn` (v0.7.14) back to
      // the recommended `error` level — any future regression
      // (setState inside useEffect) now fails CI.
      "react-hooks/set-state-in-effect": "error",
    },
    // v0.7.15 P0.1 cleanup: tailwind.config.ts removed (migrated
    // to CSS-first @theme in src/index.css). The previous override
    // block for `@typescript-eslint/no-require-imports` is no longer
    // needed.
  },
);
