import { Route, Routes } from "react-router-dom";

import { AppLayout } from "@/components/layout/AppLayout";
import { ConmonPage } from "@/routes/ConmonPage";
import { DashboardPage } from "@/routes/DashboardPage";
import { ExplainPage } from "@/routes/ExplainPage";
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
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<HomePage />} />
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
  );
}
