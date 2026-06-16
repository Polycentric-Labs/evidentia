import { Route, Routes } from "react-router-dom";

import { DemoBanner } from "@/components/common/DemoBanner";
import { AppLayout } from "@/components/layout/AppLayout";
import { IS_DEMO } from "@/lib/demo";
import { ConmonPage } from "@/routes/ConmonPage";
import { DashboardPage } from "@/routes/DashboardPage";
import { DemoPage } from "@/routes/DemoPage";
import { ExplainPage } from "@/routes/ExplainPage";
import { FdaDemoPage } from "@/routes/FdaDemoPage";
import { FrameworkDetailPage } from "@/routes/FrameworkDetailPage";
import { FrameworksPage } from "@/routes/FrameworksPage";
import { GapAnalyzePage } from "@/routes/GapAnalyzePage";
import { GapDiffPage } from "@/routes/GapDiffPage";
import { HomePage } from "@/routes/HomePage";
import { PoamPage } from "@/routes/PoamPage";
import { RiskGeneratePage } from "@/routes/RiskGeneratePage";
import { SettingsPage } from "@/routes/SettingsPage";
import { TprmPage } from "@/routes/TprmPage";

/**
 * Evidentia web UI root.
 *
 * v0.4.0-alpha.1: Home / Dashboard / Frameworks (list + detail) / Settings.
 * v0.7.6: alpha.2 routing wired — Onboarding wizard (HomePage step machine),
 *         Gap Analyze, Gap Diff, Risk Generate.
 */
export function App() {
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
          <Route path="gap/analyze" element={<GapAnalyzePage />} />
          <Route path="gap/diff" element={<GapDiffPage />} />
          <Route path="risk/generate" element={<RiskGeneratePage />} />
          <Route path="explain" element={<ExplainPage />} />
          <Route path="poam" element={<PoamPage />} />
          <Route path="conmon" element={<ConmonPage />} />
          <Route path="tprm" element={<TprmPage />} />
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
