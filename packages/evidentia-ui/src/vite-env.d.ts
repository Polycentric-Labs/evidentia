/// <reference types="vite/client" />

// v0.7.14 P0.2 (TypeScript 5 → 6 migration): TypeScript 6 is
// stricter about unresolved side-effect imports — `import
// "@/index.css"` in main.tsx now requires the *.css module
// declaration that vite/client supplies. Adding this triple-
// slash reference is the canonical Vite + TypeScript 6 fix.
//
// References:
//   https://vitejs.dev/guide/features.html#typescript
//   https://www.typescriptlang.org/docs/handbook/release-notes/typescript-6.html
