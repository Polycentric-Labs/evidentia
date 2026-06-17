/**
 * Demo-mode toggle. `true` only in a `VITE_DEMO=true` build (the static,
 * no-backend bundle deployed to the public demo site). In every normal build
 * `import.meta.env.VITE_DEMO` is undefined, so `IS_DEMO` is `false` and the UI
 * keeps talking to the real API client (`api.ts`).
 */
export const IS_DEMO = import.meta.env.VITE_DEMO === "true";

/**
 * FDA-index build mode. `true` only in a `VITE_DEMO_FDA_INDEX=true` build — the
 * dedicated bundle served at `fdademo.evidentiagrc.com`, where `FdaDemoPage`
 * renders full-bleed as the index (outside `AppLayout`) so the in-repo bundle
 * is the single source of truth for the FDA Section 524B showcase (retiring the
 * decoupled prototype fork). Built alongside `VITE_DEMO=true`, so the static
 * `HashRouter` + the no-backend demo client are active.
 */
export const IS_DEMO_FDA_INDEX = import.meta.env.VITE_DEMO_FDA_INDEX === "true";
