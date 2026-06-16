import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { PathChooser } from "@/components/onboarding/PathChooser";
import { SampleLoaded } from "@/components/onboarding/SampleLoaded";
import { UploadForm } from "@/components/onboarding/UploadForm";
import { WizardForm } from "@/components/onboarding/WizardForm";
import { WizardPreview } from "@/components/onboarding/WizardPreview";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { api } from "@/lib/api";
import { useWizardStore } from "@/lib/wizard-store";

/**
 * Home / first-run onboarding.
 *
 * v0.4.1 wires the three-path wizard:
 *   - Sample data     -> SampleLoaded (walkthrough)
 *   - Upload          -> UploadForm (drag-drop + proceed)
 *   - Wizard from scratch -> WizardForm -> WizardPreview
 *
 * If the server already has a report in the gap store, the wizard is
 * collapsed and we redirect the user to the Dashboard summary.
 */
export function HomePage() {
  const step = useWizardStore((s) => s.step);

  // Peek at the gap-reports endpoint so we can show the "returning user"
  // variant when the store isn't empty.
  const reportsQuery = useQuery({
    queryKey: ["gap-reports"],
    queryFn: () => api.listGapReports(),
  });
  const hasReports = (reportsQuery.data?.total ?? 0) > 0;

  return (
    <div className="stack-8">
      <header className="stack-2">
        <h1 className="page-title">Welcome to Evidentia</h1>
        <p className="page-sub">
          Open-source GRC tool for gap analysis, risk statements, and
          compliance automation. The web UI is the accessible counterpart
          to the <code className="kbd">evidentia</code> CLI.
        </p>
      </header>

      {step === "path-chooser" && <PathChooser />}
      {step === "wizard-form" && <WizardForm />}
      {step === "wizard-preview" && <WizardPreview />}
      {step === "upload-form" && <UploadForm />}
      {step === "sample-loaded" && <SampleLoaded />}
      {step === "done" && <DonePanel />}

      {hasReports && step === "path-chooser" && (
        <aside className="box muted text-sm">
          You have {reportsQuery.data?.total} saved{" "}
          {reportsQuery.data?.total === 1 ? "report" : "reports"}. Head to
          the{" "}
          <Link to="/dashboard" className="primary-link">
            Dashboard
          </Link>{" "}
          to review, or run a new analysis from the{" "}
          <Link to="/gap/analyze" className="primary-link">
            Gap Analyze
          </Link>{" "}
          page.
        </aside>
      )}
    </div>
  );
}

function DonePanel() {
  const reset = useWizardStore((s) => s.reset);
  return (
    <Card>
      <CardHeader>
        <CardTitle className="lg">Nice. Next steps:</CardTitle>
        <CardDescription>
          Save the YAMLs in your project root, run the analysis, and review
          the results here.
        </CardDescription>
      </CardHeader>
      <CardContent className="stack-3">
        <ul className="reset stack-2 text-sm">
          <li>
            Save the YAMLs in your project root (
            <code className="kbd">evidentia.yaml</code>,{" "}
            <code className="kbd">my-controls.yaml</code>,{" "}
            <code className="kbd">system-context.yaml</code>)
          </li>
          <li>
            Run <code className="kbd">evidentia gap analyze</code>
          </li>
          <li>
            Come back to the{" "}
            <Link className="primary-link" to="/dashboard">
              Dashboard
            </Link>{" "}
            to review gaps, or use the{" "}
            <Link className="primary-link" to="/gap/analyze">
              Gap Analyze
            </Link>{" "}
            page to re-run without leaving the browser.
          </li>
        </ul>
        <div className="row-end">
          <Button variant="outline" size="sm" onClick={reset}>
            Start wizard over
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
