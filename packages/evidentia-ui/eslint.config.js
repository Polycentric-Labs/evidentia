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
      // v0.7.14 P0.3: react-hooks v7 added a new
      // `set-state-in-effect` rule that flags setState calls
      // inside useEffect. SettingsPage.tsx uses this pattern
      // for a config-load workflow that's intentional but
      // needs refactoring to a controlled-form pattern in a
      // follow-up. Keep as warning for v0.7.14; promote to
      // error in v0.7.15 / v0.8.0 once SettingsPage.tsx is
      // refactored.
      "react-hooks/set-state-in-effect": "warn",
    },
  },
  {
    // tailwind.config.ts uses CommonJS require() for the
    // tailwindcss-animate plugin (legacy tailwind v3 plugin
    // surface). v0.7.14 P0.3 keeps this as a warning since
    // the migration to tailwind 4 (P0.1; defer-to-v0.8.0
    // possible) replaces this entire file with CSS-first
    // @theme. After tailwind 4 migration, this scope override
    // becomes obsolete + can be removed.
    files: ["tailwind.config.ts"],
    rules: {
      "@typescript-eslint/no-require-imports": "warn",
    },
  },
);
