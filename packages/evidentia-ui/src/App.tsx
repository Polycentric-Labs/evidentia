import { Route, Routes } from "react-router-dom";

import { DemoBanner } from "@/components/common/DemoBanner";
import { AppLayout } from "@/components/layout/AppLayout";
import { IS_DEMO, IS_DEMO_FDA_INDEX } from "@/lib/demo";
import { CatalogPage } from "@/routes/CatalogPage";
import { ConmonPage } from "@/routes/ConmonPage";
import { DashboardPage } from "@/routes/DashboardPage";
import { DemoPage } from "@/routes/DemoPage";
import { EvidencePage } from "@/routes/EvidencePage";
import { ExplainPage } from "@/routes/ExplainPage";
import { FdaDemoPage } from "@/routes/FdaDemoPage";
import { FrameworkDetailPage } from "@/routes/FrameworkDetailPage";
import { FrameworksPage } from "@/routes/FrameworksPage";
import { GapAnalyzePage } from "@/routes/GapAnalyzePage";
import { GapDiffPage } from "@/routes/GapDiffPage";
import { GovernancePage } from "@/routes/GovernancePage";
import { HomePage } from "@/routes/HomePage";
import { ModelRiskPage } from "@/routes/ModelRiskPage";
import { OscalResultsPage } from "@/routes/OscalResultsPage";
import { PoamPage } from "@/routes/PoamPage";
import { RetentionPage } from "@/routes/RetentionPage";
import { RiskGeneratePage } from "@/routes/RiskGeneratePage";
import { RiskQuantifyPage } from "@/routes/RiskQuantifyPage";
import { SettingsPage } from "@/routes/SettingsPage";
import { TprmPage } from "@/routes/TprmPage";

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
      <Routes>
        <Route path="*" element={<FdaDemoPage />} />
      </Routes>
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
          <Route path="gap/analyze" element={<GapAnalyzePage />} />
          <Route path="gap/diff" element={<GapDiffPage />} />
          <Route path="risk/generate" element={<RiskGeneratePage />} />
          <Route path="risk/quantify" element={<RiskQuantifyPage />} />
          <Route path="explain" element={<ExplainPage />} />
          <Route path="poam" element={<PoamPage />} />
          <Route path="conmon" element={<ConmonPage />} />
          <Route path="tprm" element={<TprmPage />} />
          {/* v0.10.12 Wave 1 — local-store CRUD consoles (governance / retention
           * / evidence). Live (non-demo) routes wired through the typed client.
           * Wave 2 adds model-risk. */}
          <Route path="governance" element={<GovernancePage />} />
          <Route path="retention" element={<RetentionPage />} />
          <Route path="evidence" element={<EvidencePage />} />
          <Route path="model-risk" element={<ModelRiskPage />} />
          {/* OSCAL emit/verify console view — a read-mostly GUI-fill, previewed
           * in the static demo bundle (fixture-backed). Wiring it to a live run
           * is the v0.10.12 parity work. */}
          {IS_DEMO && <Route path="oscal" element={<OscalResultsPage />} />}
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
