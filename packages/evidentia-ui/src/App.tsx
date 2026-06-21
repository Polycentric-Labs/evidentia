import { lazy, Suspense } from "react";
import { Route, Routes } from "react-router-dom";

import { DemoBanner } from "@/components/common/DemoBanner";
import { AppLayout } from "@/components/layout/AppLayout";
import { IS_DEMO, IS_DEMO_FDA_INDEX } from "@/lib/demo";

// Route pages are code-split with React.lazy so each console ships as its own
// chunk instead of bloating the initial bundle. The page modules use NAMED
// exports, so each loader adapts to the { default } shape lazy() expects. A
// Suspense boundary inside AppLayout (and the FDA-index branch below) renders a
// fallback while a chunk loads.
const AiGovPage = lazy(() =>
  import("@/routes/AiGovPage").then((m) => ({ default: m.AiGovPage })),
);
const CatalogPage = lazy(() =>
  import("@/routes/CatalogPage").then((m) => ({ default: m.CatalogPage })),
);
const CollectPage = lazy(() =>
  import("@/routes/CollectPage").then((m) => ({ default: m.CollectPage })),
);
const ConmonPage = lazy(() =>
  import("@/routes/ConmonPage").then((m) => ({ default: m.ConmonPage })),
);
const DashboardPage = lazy(() =>
  import("@/routes/DashboardPage").then((m) => ({ default: m.DashboardPage })),
);
const DemoPage = lazy(() =>
  import("@/routes/DemoPage").then((m) => ({ default: m.DemoPage })),
);
const EvidencePage = lazy(() =>
  import("@/routes/EvidencePage").then((m) => ({ default: m.EvidencePage })),
);
const ExplainPage = lazy(() =>
  import("@/routes/ExplainPage").then((m) => ({ default: m.ExplainPage })),
);
const FdaDemoPage = lazy(() =>
  import("@/routes/FdaDemoPage").then((m) => ({ default: m.FdaDemoPage })),
);
const FrameworkDetailPage = lazy(() =>
  import("@/routes/FrameworkDetailPage").then((m) => ({
    default: m.FrameworkDetailPage,
  })),
);
const FrameworksPage = lazy(() =>
  import("@/routes/FrameworksPage").then((m) => ({
    default: m.FrameworksPage,
  })),
);
const GapAnalyzePage = lazy(() =>
  import("@/routes/GapAnalyzePage").then((m) => ({
    default: m.GapAnalyzePage,
  })),
);
const GapDiffPage = lazy(() =>
  import("@/routes/GapDiffPage").then((m) => ({ default: m.GapDiffPage })),
);
const GovernancePage = lazy(() =>
  import("@/routes/GovernancePage").then((m) => ({
    default: m.GovernancePage,
  })),
);
const HomePage = lazy(() =>
  import("@/routes/HomePage").then((m) => ({ default: m.HomePage })),
);
const IntegrationsPage = lazy(() =>
  import("@/routes/IntegrationsPage").then((m) => ({
    default: m.IntegrationsPage,
  })),
);
const ModelRiskPage = lazy(() =>
  import("@/routes/ModelRiskPage").then((m) => ({ default: m.ModelRiskPage })),
);
const OscalVerifyPage = lazy(() =>
  import("@/routes/OscalVerifyPage").then((m) => ({
    default: m.OscalVerifyPage,
  })),
);
const PoamPage = lazy(() =>
  import("@/routes/PoamPage").then((m) => ({ default: m.PoamPage })),
);
const RetentionPage = lazy(() =>
  import("@/routes/RetentionPage").then((m) => ({ default: m.RetentionPage })),
);
const RiskGeneratePage = lazy(() =>
  import("@/routes/RiskGeneratePage").then((m) => ({
    default: m.RiskGeneratePage,
  })),
);
const RiskQuantifyPage = lazy(() =>
  import("@/routes/RiskQuantifyPage").then((m) => ({
    default: m.RiskQuantifyPage,
  })),
);
const SettingsPage = lazy(() =>
  import("@/routes/SettingsPage").then((m) => ({ default: m.SettingsPage })),
);
const TprmPage = lazy(() =>
  import("@/routes/TprmPage").then((m) => ({ default: m.TprmPage })),
);
const TraceabilityPage = lazy(() =>
  import("@/routes/TraceabilityPage").then((m) => ({
    default: m.TraceabilityPage,
  })),
);

/** Centered loading fallback shown while a lazily-loaded route chunk resolves. */
function RouteFallback() {
  return (
    <div className="grid place-items-center py-24 text-sm text-muted-foreground">
      Loading…
    </div>
  );
}

/**
 * Evidentia web UI root.
 *
 * v0.4.0-alpha.1: Home / Dashboard / Frameworks (list + detail) / Settings.
 * v0.7.6: alpha.2 routing wired — Onboarding wizard (HomePage step machine),
 *         Gap Analyze, Gap Diff, Risk Generate.
 * v0.10.12: Wave-1 parity — Governance / Retention / Evidence consoles.
 *           Wave-2 parity — Model-risk / Catalog management / Risk-quantify.
 */
export function App() {
  // FDA-index build (fdademo.evidentiagrc.com): the Section 524B showcase
  // renders full-bleed as its own index, outside AppLayout. Every path resolves
  // to it so a hard refresh on any sub-path still lands on the single-page demo.
  // FdaDemoPage self-discloses its synthetic data, so the global DemoBanner is
  // intentionally omitted here.
  if (IS_DEMO_FDA_INDEX) {
    return (
      <Suspense fallback={<RouteFallback />}>
        <Routes>
          <Route path="*" element={<FdaDemoPage />} />
        </Routes>
      </Suspense>
    );
  }

  return (
    <>
      {/* No-op in normal builds; a persistent strip in the VITE_DEMO bundle. */}
      <DemoBanner />
      <Routes>
        <Route element={<AppLayout />}>
          <Route index element={<HomePage />} />
          {/* Tier 0 cast — registered only in the static VITE_DEMO bundle. */}
          {IS_DEMO && <Route path="demo" element={<DemoPage />} />}
          {/*
           * FDA Section 524B medical-device showcase — registered only in the
           * VITE_DEMO bundle, demo-only, and kept inside the normal AppLayout.
           * The landing/index is intentionally untouched.
           */}
          {IS_DEMO && <Route path="demo/fda" element={<FdaDemoPage />} />}
          <Route path="dashboard" element={<DashboardPage />} />
          <Route path="frameworks" element={<FrameworksPage />} />
          <Route path="frameworks/:id" element={<FrameworkDetailPage />} />
          <Route path="catalog" element={<CatalogPage />} />
          <Route path="collect" element={<CollectPage />} />
          <Route path="gap/analyze" element={<GapAnalyzePage />} />
          <Route path="gap/diff" element={<GapDiffPage />} />
          <Route path="risk/generate" element={<RiskGeneratePage />} />
          <Route path="risk/quantify" element={<RiskQuantifyPage />} />
          <Route path="explain" element={<ExplainPage />} />
          <Route path="poam" element={<PoamPage />} />
          <Route path="conmon" element={<ConmonPage />} />
          <Route path="tprm" element={<TprmPage />} />
          <Route path="integrations" element={<IntegrationsPage />} />
          {/* v0.10.12 Wave 1 — local-store CRUD consoles (governance / retention
           * / evidence). Live (non-demo) routes wired through the typed client.
           * Wave 2 adds model-risk. */}
          <Route path="governance" element={<GovernancePage />} />
          <Route path="retention" element={<RetentionPage />} />
          <Route path="evidence" element={<EvidencePage />} />
          <Route path="model-risk" element={<ModelRiskPage />} />
          <Route path="ai-gov" element={<AiGovPage />} />
          {/* v0.10.12 Wave 3 — live read-only OSCAL verify (verify an uploaded
           * Assessment Result) + unsigned traceability emit. Signing stays an
           * air-gap CLI operation; these consoles never sign. */}
          <Route path="oscal" element={<OscalVerifyPage />} />
          <Route path="traceability" element={<TraceabilityPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route
            path="*"
            element={
              <div className="space-y-3">
                <h1 className="text-3xl font-semibold tracking-tight">
                  Page not found
                </h1>
                <p className="text-muted-foreground">
                  That route isn't implemented yet. Check the sidebar for
                  available pages.
                </p>
              </div>
            }
          />
        </Route>
      </Routes>
    </>
  );
}
