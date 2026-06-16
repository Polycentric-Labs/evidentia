import { useMutation, useQuery } from "@tanstack/react-query";
import { Layers, ShieldCheck, Sparkles } from "lucide-react";
import { useRef, useState } from "react";
import { Link } from "react-router-dom";

import { MetricCard, SeverityBar } from "@/components/common/console";
import { GapExportControl } from "@/components/gap/GapExportControl";
import { GapTable } from "@/components/gap/GapTable";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, ApiError } from "@/lib/api";
import { IS_DEMO } from "@/lib/demo";
import { cn } from "@/lib/utils";
import { useWizardStore } from "@/lib/wizard-store";
import type { GapAnalysisReport } from "@/types/api";

/**
 * Gap Analyze interactive page.
 *
 * Two inventory sources:
 *   1. A file uploaded from the browser (primary path; the wizard's
 *      upload path also lands here).
 *   2. A server-side path — typing a path the backend can read. Useful
 *      for CI / headless / power-user flows.
 *
 * Results render as a :class:`GapTable` below the form.
 */
export function GapAnalyzePage() {
  const uploadFile = useWizardStore((s) => s.uploadFile);
  const setUploadFile = useWizardStore((s) => s.setUploadFile);
  const [serverPath, setServerPath] = useState("");
  const [frameworks, setFrameworks] = useState<Set<string>>(new Set());
  const [organization, setOrganization] = useState("");
  const [systemName, setSystemName] = useState("");
  const [inventoryText, setInventoryText] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement | null>(null);

  const fwQuery = useQuery({
    queryKey: ["frameworks-picker"],
    queryFn: () => api.listFrameworks(),
  });

  const mutation = useMutation({
    mutationFn: async (): Promise<GapAnalysisReport> => {
      if (IS_DEMO) {
        // Static demo build: resolve the baked Meridian v2 report from
        // fixtures — no backend, no network. Mirrors the SSE pages' demo
        // branch so "Run analysis" tells the same story offline.
        return api.getGapReport("meridian-fintech-v2:baseline");
      }
      const payload: {
        frameworks: string[];
        organization?: string;
        system_name?: string;
        inventory_content?: string;
        inventory_format?: string;
        inventory_path?: string;
      } = {
        frameworks: Array.from(frameworks),
        organization: organization.trim() || undefined,
        system_name: systemName.trim() || undefined,
      };
      if (inventoryText) {
        payload.inventory_content = inventoryText;
        payload.inventory_format = inferFormat(uploadFile?.name);
      } else if (serverPath.trim()) {
        payload.inventory_path = serverPath.trim();
      }
      const res = await fetch("/api/gap/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        let detail: unknown = null;
        try {
          detail = await res.json();
        } catch {
          /* empty */
        }
        throw new ApiError(
          `POST /api/gap/analyze failed (${res.status})`,
          res.status,
          detail,
        );
      }
      return (await res.json()) as GapAnalysisReport;
    },
  });

  const handleFile = async (f: File | null) => {
    if (!f) return;
    setUploadFile(f);
    setInventoryText(await f.text());
  };

  const canSubmit =
    frameworks.size > 0 &&
    (inventoryText !== null || serverPath.trim().length > 0) &&
    !mutation.isPending;

  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">Gap Analyze</h1>
        <p className="page-sub">
          Pick frameworks, provide an inventory, and run{" "}
          <code className="kbd">evidentia gap analyze</code> from the browser.
          Results save to the gap store automatically.
        </p>
      </header>

      <form
        className="stack-5"
        onSubmit={(e) => {
          e.preventDefault();
          if (canSubmit) mutation.mutate();
        }}
      >
        <section className="stack-3">
          <h2 className="section-num">1. Inventory</h2>
          <div className="grid grid-2">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="base">Upload file</CardTitle>
                <CardDescription>YAML / JSON / CSV.</CardDescription>
              </CardHeader>
              <CardContent className="stack-2">
                <input
                  ref={fileInput}
                  type="file"
                  accept=".yaml,.yml,.json,.csv"
                  className="sr-only"
                  id="analyze-upload"
                  onChange={(e) => {
                    handleFile(e.target.files?.[0] ?? null);
                  }}
                />
                <Label
                  htmlFor="analyze-upload"
                  className="inline-block cursor-pointer"
                >
                  <Button asChild variant="outline" size="sm">
                    <span>{uploadFile ? "Change file" : "Choose file"}</span>
                  </Button>
                </Label>
                {uploadFile && (
                  <p className="text-xs muted">
                    Selected: <code className="kbd">{uploadFile.name}</code> (
                    {uploadFile.size} bytes)
                  </p>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="base">Or server path</CardTitle>
                <CardDescription>
                  Absolute path readable by the server process.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Input
                  placeholder="/path/to/my-controls.yaml"
                  value={serverPath}
                  onChange={(e) => setServerPath(e.target.value)}
                />
              </CardContent>
            </Card>
          </div>
        </section>

        <section className="stack-3">
          <h2 className="section-num">2. Frameworks</h2>
          <p className="text-sm muted">
            Pick one or more. Filter by tier in the{" "}
            <Link to="/frameworks" className="primary-link">
              Frameworks browser
            </Link>{" "}
            if you need help picking.
          </p>
          <div className="box scroll-60">
            {fwQuery.isPending && <p className="text-sm">Loading...</p>}
            {fwQuery.isError && (
              <p className="text-sm text-destructive">
                Could not load frameworks.
              </p>
            )}
            <div className="row wrap gap-2">
              {fwQuery.data?.frameworks.map((fw) => {
                const checked = frameworks.has(fw.id);
                return (
                  <button
                    key={fw.id}
                    type="button"
                    role="switch"
                    aria-checked={checked}
                    onClick={() => {
                      const next = new Set(frameworks);
                      if (checked) {
                        next.delete(fw.id);
                      } else {
                        next.add(fw.id);
                      }
                      setFrameworks(next);
                    }}
                    className={cn("pill", checked && "on")}
                  >
                    {fw.id} <span className="dim">(T{fw.tier})</span>
                  </button>
                );
              })}
            </div>
          </div>
          {frameworks.size > 0 && (
            <p className="text-xs muted">
              Selected: {Array.from(frameworks).join(", ")}
            </p>
          )}
        </section>

        <section className="grid grid-2">
          <div className="stack-2">
            <Label htmlFor="org-override">Organization override (optional)</Label>
            <Input
              id="org-override"
              value={organization}
              onChange={(e) => setOrganization(e.target.value)}
              placeholder="Uses inventory's organization if blank"
            />
          </div>
          <div className="stack-2">
            <Label htmlFor="system-override">
              System name override (optional)
            </Label>
            <Input
              id="system-override"
              value={systemName}
              onChange={(e) => setSystemName(e.target.value)}
            />
          </div>
        </section>

        <div className="row-between border-t pt-4">
          <p className="text-xs muted">
            The report will be saved to the local gap store and appear on the
            Dashboard.
          </p>
          <Button type="submit" disabled={!canSubmit}>
            {mutation.isPending ? "Running..." : "Run analysis"}
          </Button>
        </div>
      </form>

      {mutation.isError && (
        <Alert variant="destructive">
          <AlertTitle>Analysis failed</AlertTitle>
          <AlertDescription>
            {mutation.error instanceof ApiError && mutation.error.payload
              ? JSON.stringify(mutation.error.payload)
              : String(mutation.error)}
          </AlertDescription>
        </Alert>
      )}

      {mutation.data && <GapResults report={mutation.data} />}
    </div>
  );
}

function GapResults({ report }: { report: GapAnalysisReport }) {
  const coveragePct = Math.round(report.coverage_percentage);
  // The header counts (total/critical/high) come from the report's roll-up,
  // but the SeverityBar + GapTable render only `report.gaps` — which can be a
  // representative subset of `total_gaps` (e.g. the bundled demo report ships
  // a sample of the full Meridian run). Surface a caption so the visible rows
  // never read as a contradiction of the header totals. General: triggered by
  // the length<total condition, not a demo-only branch.
  const isSubset = report.gaps.length < report.total_gaps;
  return (
    <section className="stack-5" aria-labelledby="results-heading">
      <header
        className="row-between wrap gap-4"
        style={{ alignItems: "flex-start" }}
      >
        <div className="stack-2">
          <h2 id="results-heading" className="h2-lg">
            Results
          </h2>
          <div className="row gap-2 wrap">
            <Badge variant="secondary">{report.total_gaps} total gaps</Badge>
            {report.critical_gaps > 0 && (
              <Badge variant="critical">{report.critical_gaps} critical</Badge>
            )}
            {report.high_gaps > 0 && (
              <Badge variant="high">{report.high_gaps} high</Badge>
            )}
          </div>
        </div>
        <GapExportControl report={report} />
      </header>
      <div className="grid grid-3">
        <MetricCard
          icon={ShieldCheck}
          label="Coverage"
          value={`${coveragePct}%`}
          description={`${report.total_controls_in_inventory} / ${report.total_controls_required} controls satisfied`}
          bar={coveragePct}
        />
        <MetricCard
          icon={Layers}
          label="Frameworks analyzed"
          value={String(report.frameworks_analyzed.length)}
          description={report.frameworks_analyzed.join(", ")}
        />
        <MetricCard
          icon={Sparkles}
          label="Efficiency wins"
          value={String(report.efficiency_opportunities.length)}
          description="controls satisfying 3+ frameworks"
        />
      </div>
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">Severity distribution</CardTitle>
          <CardDescription>
            {report.total_gaps} open gaps across{" "}
            {report.frameworks_analyzed.length} frameworks, by gap severity.
            {isSubset && " The chart below reflects the sampled rows."}
          </CardDescription>
        </CardHeader>
        <CardContent className="pt-0">
          <SeverityBar gaps={report.gaps} />
        </CardContent>
      </Card>
      {isSubset && (
        <p className="text-sm muted" role="note">
          Showing a representative {report.gaps.length} of {report.total_gaps}{" "}
          gaps.
        </p>
      )}
      <GapTable gaps={report.gaps} />
    </section>
  );
}

function inferFormat(filename: string | undefined): string {
  if (!filename) return "yaml";
  const lower = filename.toLowerCase();
  if (lower.endsWith(".csv")) return "csv";
  if (lower.endsWith(".json")) return "json";
  return "yaml";
}
