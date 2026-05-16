import { CheckCircle2 } from "lucide-react";
import { Link } from "react-router-dom";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useWizardStore } from "@/lib/wizard-store";

/**
 * "Try sample data" success screen. v0.4.1 renders the Meridian v2
 * sample commands the user should run locally; v0.4.2 will add an
 * "Auto-download + analyze" button that fetches the sample from the
 * GitHub repo and runs gap analyze in one click.
 */
export function SampleLoaded() {
  const reset = useWizardStore((s) => s.reset);
  return (
    <section aria-labelledby="sample-heading" className="space-y-4">
      <Alert variant="success">
        <CheckCircle2 className="h-4 w-4" />
        <AlertTitle>Sample scenario selected</AlertTitle>
        <AlertDescription>
          We'll walk you through the Meridian Financial fintech example.
          Run the two commands below in your terminal to analyze the sample.
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader>
          <CardTitle id="sample-heading" className="text-lg">
            1. Download the sample inventory
          </CardTitle>
          <CardDescription>
            Meridian v2 is a 48-control fintech scenario; the PR-branch
            snapshot exercises every gap-diff classification.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <pre className="overflow-auto rounded bg-muted p-3 text-xs">
            <code>{`curl -o my-controls.yaml \\
  https://raw.githubusercontent.com/polycentric-labs/evidentia/main/examples/meridian-fintech-v2/my-controls.yaml`}</code>
          </pre>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">2. Run gap analysis</CardTitle>
          <CardDescription>
            Analyzes against SOC 2 + NIST 800-53 Moderate + GDPR.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <pre className="overflow-auto rounded bg-muted p-3 text-xs">
            <code>{`evidentia gap analyze \\
  --inventory my-controls.yaml \\
  --frameworks soc2-tsc,nist-800-53-rev5-moderate,eu-gdpr`}</code>
          </pre>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">3. View results here</CardTitle>
          <CardDescription>
            Once the analysis completes, the <strong>Dashboard</strong> page
            will show the new report. From there you can drill into gaps,
            run a Gap Diff, or generate risk statements.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex gap-2">
          <Button asChild>
            <Link to="/dashboard">Open dashboard</Link>
          </Button>
          <Button variant="outline" onClick={reset}>
            Start over
          </Button>
        </CardContent>
      </Card>
    </section>
  );
}
