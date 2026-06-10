import { useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";

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
import { Progress } from "@/components/ui/progress";
import { api } from "@/lib/api";
import { readSse } from "@/lib/sse";
import { cn } from "@/lib/utils";

type StreamEvent =
  | { phase: "start"; total: number }
  | {
      phase: "progress";
      gap_id: string;
      control_id: string;
      framework: string;
      index: number;
      total: number;
      status: "generating" | "done";
      risk?: unknown;
    }
  | {
      phase: "error";
      gap_id?: string;
      control_id?: string;
      framework?: string;
      detail: string;
    }
  | { phase: "done"; generated: number; failed: number };

interface GapRow {
  key: string;
  status: "pending" | "generating" | "done" | "error";
  detail?: string;
  control_id?: string;
  framework?: string;
}

/**
 * Risk Generate — SSE-streamed per-gap progress.
 *
 * POSTs to /api/risk/generate using fetch + ReadableStream reader so we
 * can read the SSE body in the browser. (The standard EventSource API
 * doesn't support POST; sse-starlette serves a POST-friendly stream.)
 */
export function RiskGeneratePage() {
  const [reportKey, setReportKey] = useState<string | null>(null);
  const [contextPath, setContextPath] = useState("");
  const [topN, setTopN] = useState(10);
  const [rows, setRows] = useState<Record<string, GapRow>>({});
  const [progress, setProgress] = useState<{
    current: number;
    total: number;
  } | null>(null);
  const [isStreaming, setIsStreaming] = useState(false);
  const [finalSummary, setFinalSummary] = useState<{
    generated: number;
    failed: number;
  } | null>(null);
  const [streamError, setStreamError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const reportsQuery = useQuery({
    queryKey: ["gap-reports"],
    queryFn: () => api.listGapReports(),
  });
  const reports = reportsQuery.data?.reports ?? [];

  const reset = useCallback(() => {
    setRows({});
    setProgress(null);
    setFinalSummary(null);
    setStreamError(null);
  }, []);

  const onStreamEvent = useCallback((evt: StreamEvent) => {
    if (evt.phase === "start") {
      setProgress({ current: 0, total: evt.total });
    } else if (evt.phase === "progress") {
      const gapKey = evt.gap_id;
      setRows((prev) => ({
        ...prev,
        [gapKey]: {
          key: gapKey,
          status: evt.status,
          control_id: evt.control_id,
          framework: evt.framework,
        },
      }));
      if (evt.status === "done") {
        setProgress((p) =>
          p ? { ...p, current: Math.min(p.total, p.current + 1) } : p,
        );
      }
    } else if (evt.phase === "error") {
      if (evt.gap_id) {
        setRows((prev) => ({
          ...prev,
          [evt.gap_id!]: {
            key: evt.gap_id!,
            status: "error",
            detail: evt.detail,
            control_id: evt.control_id,
            framework: evt.framework,
          },
        }));
      } else {
        setStreamError(evt.detail);
      }
    } else if (evt.phase === "done") {
      setFinalSummary({
        generated: evt.generated,
        failed: evt.failed,
      });
      setIsStreaming(false);
    }
  }, []);

  const start = async () => {
    if (!reportKey) return;
    reset();
    setIsStreaming(true);
    abortRef.current = new AbortController();

    try {
      const res = await fetch("/api/risk/generate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "text/event-stream",
        },
        signal: abortRef.current.signal,
        body: JSON.stringify({
          report_key: reportKey,
          top_n: topN,
          context_path: contextPath.trim() || null,
        }),
      });

      if (!res.ok || !res.body) {
        const detail = (await res.text().catch(() => "")) || `HTTP ${res.status}`;
        setStreamError(`Request failed: ${detail.slice(0, 300)}`);
        setIsStreaming(false);
        return;
      }

      await readSse(res.body, onStreamEvent);
    } catch (e) {
      if ((e as { name?: string }).name !== "AbortError") {
        setStreamError(e instanceof Error ? e.message : String(e));
      }
      setIsStreaming(false);
    }
  };

  const cancel = () => {
    abortRef.current?.abort();
    setIsStreaming(false);
  };

  useEffect(() => () => abortRef.current?.abort(), []);

  const rowList = Object.values(rows);

  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">Risk Generate</h1>
        <p className="page-sub">
          AI-generated NIST SP 800-30 risk statements for your top-priority
          gaps. Progress streams live from the server.
        </p>
      </header>

      {reports.length === 0 && (
        <Alert>
          <AlertTitle>No reports in the gap store yet</AlertTitle>
          <AlertDescription>
            Run a gap analysis first (from the{" "}
            <a href="/gap/analyze" className="primary underline">
              Gap Analyze
            </a>{" "}
            page) so there's a report to generate risks for.
          </AlertDescription>
        </Alert>
      )}

      {reports.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="base">Configuration</CardTitle>
            <CardDescription>
              Pick the source report + system context. The generator
              fans out concurrently and streams per-gap progress back.
            </CardDescription>
          </CardHeader>
          <CardContent className="stack-4">
            <div className="stack-2">
              <Label>Source report</Label>
              <div className="box scroll-44 stack-2">
                {reports.map((r) => (
                  <button
                    key={r.key}
                    type="button"
                    onClick={() => setReportKey(r.key)}
                    className={cn("select-row", reportKey === r.key && "on")}
                  >
                    <span className="text-xs">
                      <span className="font-medium">
                        {r.organization || "(unknown)"}
                      </span>{" "}
                      —{" "}
                      <span className="muted">
                        {r.total_gaps} gaps, {r.frameworks_analyzed.join(", ")}
                      </span>
                    </span>
                    <div className="mt-1 text-xs">
                      <code className="kbd">{r.key}</code>{" "}
                      <span className="muted">
                        {new Date(r.mtime_iso).toLocaleString()}
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            </div>
            <div className="grid grid-2">
              <div className="stack-2">
                <Label htmlFor="context-path">
                  system-context.yaml path (required)
                </Label>
                <Input
                  id="context-path"
                  placeholder="/abs/path/to/system-context.yaml"
                  value={contextPath}
                  onChange={(e) => setContextPath(e.target.value)}
                />
              </div>
              <div className="stack-2">
                <Label htmlFor="top-n">Top N gaps</Label>
                <Input
                  id="top-n"
                  type="number"
                  min={1}
                  max={50}
                  value={topN}
                  onChange={(e) =>
                    setTopN(
                      Math.max(1, Math.min(50, Number(e.target.value) || 10)),
                    )
                  }
                />
                <p className="text-xs muted">
                  Picks the highest-priority gaps by priority_score.
                </p>
              </div>
            </div>
            <div className="row-end gap-2">
              {isStreaming ? (
                <Button variant="outline" onClick={cancel}>
                  Cancel
                </Button>
              ) : (
                <Button
                  onClick={start}
                  disabled={!reportKey || !contextPath.trim()}
                >
                  Generate
                </Button>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {progress && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="base">Progress</CardTitle>
            <CardDescription>
              {progress.current} of {progress.total} complete
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Progress
              value={
                progress.total === 0
                  ? 0
                  : (progress.current / progress.total) * 100
              }
            />
          </CardContent>
        </Card>
      )}

      {streamError && (
        <Alert variant="destructive">
          <AlertTitle>Stream error</AlertTitle>
          <AlertDescription>{streamError}</AlertDescription>
        </Alert>
      )}

      {finalSummary && (
        <Alert variant={finalSummary.failed > 0 ? "destructive" : "success"}>
          <AlertTitle>Done</AlertTitle>
          <AlertDescription>
            Generated {finalSummary.generated} risk statement
            {finalSummary.generated === 1 ? "" : "s"}
            {finalSummary.failed > 0 &&
              `; ${finalSummary.failed} failed (see individual rows below).`}
          </AlertDescription>
        </Alert>
      )}

      {rowList.length > 0 && (
        <ul className="reset rounded-lg border">
          {rowList.map((row, i) => (
            <li
              key={row.key}
              className={cn(
                "reset row gap-3 px-4 py-2",
                i > 0 && "border-t",
              )}
            >
              <span
                aria-hidden
                className={cn(
                  "dot-status",
                  row.status === "done" && "dot-done",
                  row.status === "generating" && "dot-gen",
                  row.status === "error" && "dot-err",
                  row.status === "pending" && "dot-pend",
                )}
              />
              <div className="flex-1 text-sm">
                {row.control_id && (
                  <span className="mono text-xs">
                    {row.framework}:{row.control_id}
                  </span>
                )}
                {row.detail && (
                  <span className="ml-2 text-xs text-destructive">
                    {row.detail}
                  </span>
                )}
              </div>
              <Badge variant="outline" className="capitalize">
                {row.status}
              </Badge>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
