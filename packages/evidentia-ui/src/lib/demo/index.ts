/**
 * Demo-mode toggle. `true` only in a `VITE_DEMO=true` build (the static,
 * no-backend bundle deployed to the public demo site). In every normal build
 * `import.meta.env.VITE_DEMO` is undefined, so `IS_DEMO` is `false` and the UI
 * keeps talking to the real API client (`api.ts`).
 */
export const IS_DEMO = import.meta.env.VITE_DEMO === "true";
