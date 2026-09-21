import { Download } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  ApiError,
  exportGapReport,
  GAP_EXPORT_FORMATS,
  type GapExportFormat,
  type VexSpecVersion,
} from "@/lib/api";
import { triggerBlobDownload } from "@/lib/download";
import type { GapAnalysisReport } from "@/types/api";

/**
 * Format selector + download control for a gap-analysis report.
 *
 * Posts the in-memory report to `POST /api/gap/export` (which reuses the
 * CLI's `export_report` emitters), reads the returned artifact, and
 * triggers a browser download. The format list mirrors the engine's
 * supported formats: JSON, OSCAL AR, SARIF, OCSF (compliance 2003),
 * OCSF detection (2004), CycloneDX VEX, CSV, Markdown.
 */
export function GapExportControl({ report }: { report: GapAnalysisReport }) {
  const [format, setFormat] = useState<GapExportFormat>("json");
  const [vexSpecVersion, setVexSpecVersion] = useState<VexSpecVersion>("1.6");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onDownload = async () => {
    const selectedFormat = format;
    const selectedVersion =
      selectedFormat === "cyclonedx-vex" ? vexSpecVersion : undefined;
    setBusy(true);
    setError(null);
    try {
      const { blob, filename } = await exportGapReport(
        report,
        selectedFormat,
        selectedVersion,
      );
      triggerBlobDownload(blob, filename);
    } catch (e) {
      if (e instanceof ApiError) {
        setError(e.message);
      } else {
        setError(e instanceof Error ? e.message : String(e));
      }
    } finally {
      setBusy(false);
    }
  };

  const activeHint = GAP_EXPORT_FORMATS.find((f) => f.id === format)?.hint;

  return (
    <div className="stack gap-1">
      <div className="row items-end gap-2">
        <div className="stack gap-1">
          <Label htmlFor="gap-export-format" className="text-xs">
            Export format
          </Label>
          <select
            id="gap-export-format"
            className="select"
            value={format}
            onChange={(e) => setFormat(e.target.value as GapExportFormat)}
            disabled={busy}
          >
            {GAP_EXPORT_FORMATS.map((f) => (
              <option key={f.id} value={f.id}>
                {f.label}
              </option>
            ))}
          </select>
        </div>
        {format === "cyclonedx-vex" && (
          <div className="stack gap-1">
            <Label htmlFor="gap-export-vex-version" className="text-xs">
              CycloneDX version
            </Label>
            <select
              id="gap-export-vex-version"
              className="select"
              value={vexSpecVersion}
              onChange={(e) =>
                setVexSpecVersion(e.target.value as VexSpecVersion)
              }
              disabled={busy}
            >
              <option value="1.6">1.6 (default)</option>
              <option value="1.7">1.7</option>
            </select>
          </div>
        )}
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={onDownload}
          disabled={busy}
        >
          <Download className="h-4 w-4" aria-hidden />
          {busy ? "Exporting..." : "Download"}
        </Button>
      </div>
      {activeHint && <p className="text-xs muted">{activeHint}</p>}
      {error && (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}
