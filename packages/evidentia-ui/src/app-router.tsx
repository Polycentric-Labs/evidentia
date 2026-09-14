import { BrowserRouter, HashRouter } from "react-router-dom";

import { IS_DEMO } from "@/lib/demo";

// The demo bundle is served from a static subpath (e.g. a Vercel project root
// or a folder under the site repo) with no server-side rewrite, so `HashRouter`
// keeps every route reachable on a hard refresh. The real console runs under a
// backend that rewrites unknown paths to index.html, so it uses `BrowserRouter`.
export const AppRouter = IS_DEMO ? HashRouter : BrowserRouter;

