import { FlaskConical } from "lucide-react";

import { IS_DEMO } from "@/lib/demo";

/**
 * Persistent demo-mode strip.
 *
 * Rendered only in a `VITE_DEMO=true` build (the static, no-backend bundle on
 * the public demo site). It makes the "synthetic data · no live backend"
 * contract unmissable so an evaluator never mistakes the baked Meridian fixtures
 * for live results. In every normal build `IS_DEMO` is `false` and this returns
 * `null`, so the production console is unaffected.
 */
export function DemoBanner() {
  if (!IS_DEMO) {
    return null;
  }
  return (
    <div
      role="status"
      className="flex items-center justify-center gap-2 border-b border-chrome-border bg-chrome px-4 py-1.5 text-center text-[0.74rem] font-medium tracking-wide text-cream-soft"
    >
      <FlaskConical className="h-3.5 w-3.5 shrink-0 text-cream" aria-hidden />
      <span>
        DEMO · synthetic data · no live backend ·{" "}
        <a
          href="https://github.com/polycentric-labs/evidentia"
          className="underline underline-offset-[3px] hover:text-cream"
          target="_blank"
          rel="noreferrer"
        >
          Source on GitHub
        </a>
      </span>
    </div>
  );
}
