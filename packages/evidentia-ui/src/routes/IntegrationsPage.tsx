import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";

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
import { api, ApiError, type GapReportMeta } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * Integrations console (/integrations) — the iTICKETING / BI push surface.
 *
 * HIGH-risk page: the push / publish / sync verbs make credentialed EXTERNAL
 * writes (Jira incidents, ServiceNow records, Tableau / Power BI publishes)
 * using SERVER-SIDE credentials. The forms therefore NEVER ask for secrets —
 * only a report-key (picked from `listGapReports`) plus non-secret options.
 *
 * §4(c) AUTH-GATING: the page reads `GET /api/health` once; when
 * `auth_configured` is false (an anonymous deployment) every write verb is
 * DISABLED with an explanatory note. The read-only status / test / status-map
 * probes stay enabled regardless — they create no records.
 *
 * Every write verb is additionally guarded by a per-action confirmation
 * interstitial ("This writes to <external system>. Continue?") because the
 * write is irreversible. Result objects are rendered as structured text;
 * `ApiError` payloads (503 not-configured, 404 unknown report key) surface in
 * a destructive alert.
 */

const AUTH_NOTE =
  "Integration pushes write to external systems with server-side " +
  "credentials — configure API authentication " +
  "(EVIDENTIA_API_AUTH_TOKEN_FILE) to enable.";

/** Surface an ApiError payload (or any error) as readable text. */
function apiErrorText(error: unknown): string {
  if (error instanceof ApiError && error.payload != null) {
    return JSON.stringify(error.payload);
  }
  return String(error);
}

export function IntegrationsPage() {
  const [reportKey, setReportKey] = useState<string | null>(null);

  const health = useQuery({
    queryKey: ["health"],
    queryFn: () => api.health(),
  });
  const authed = health.data?.auth_configured ?? false;

  const reportsQuery = useQuery({
    queryKey: ["gap-reports"],
    queryFn: () => api.listGapReports(),
  });
  const reports = reportsQuery.data?.reports ?? [];

  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">Integrations</h1>
        <p className="page-sub">
          Push compliance gaps to ticketing and BI systems. Credentials are
          server-side; these forms never ask for secrets — only a saved report
          and non-secret options.
        </p>
      </header>

      {health.isSuccess && !authed && (
        <Alert variant="destructive" aria-label="Authentication notice">
          <AlertTitle>External writes are disabled</AlertTitle>
          <AlertDescription>{AUTH_NOTE}</AlertDescription>
        </Alert>
      )}

      <ReportKeyPicker
        reports={reports}
        loading={reportsQuery.isLoading}
        error={reportsQuery.isError}
        selected={reportKey}
        onSelect={setReportKey}
      />

      <JiraSection authed={authed} reportKey={reportKey} />
      <ServiceNowSection authed={authed} reportKey={reportKey} />
      <TableauSection authed={authed} reportKey={reportKey} />
      <PowerBiSection authed={authed} reportKey={reportKey} />
    </div>
  );
}

// ── Shared report-key picker ──────────────────────────────────────────────

/**
 * Report-key picker — feeds every push / publish / sync verb. A write verb is
 * a no-op without a target report, so the sections disable their write
 * controls until a key is selected here.
 */
function ReportKeyPicker({
  reports,
  loading,
  error,
  selected,
  onSelect,
}: {
  reports: GapReportMeta[];
  loading: boolean;
  error: boolean;
  selected: string | null;
  onSelect: (key: string) => void;
}) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="base">Target report</CardTitle>
        <CardDescription>
          Pick the saved gap report whose open gaps the push / publish / sync
          verbs act on.
        </CardDescription>
      </CardHeader>
      <CardContent className="stack-3">
        {error && (
          <span className="text-sm text-destructive" role="alert">
            Could not fetch reports. Is the backend running?
          </span>
        )}

        {loading && <div className="skel" style={{ height: "4rem" }} />}

        {!loading && !error && reports.length === 0 && (
          <div className="empty-state">
            No saved reports yet. Run{" "}
            <code className="kbd">evidentia gap analyze</code> to populate the
            gap store.
          </div>
        )}

        {reports.length > 0 && (
          <ul
            className="reset stack-2"
            role="radiogroup"
            aria-label="Target report"
          >
            {reports.map((r) => (
              <li key={r.key} className="reset">
                <button
                  type="button"
                  role="radio"
                  aria-checked={selected === r.key}
                  onClick={() => onSelect(r.key)}
                  className={cn("select-row", selected === r.key && "on")}
                  style={{ width: "100%", textAlign: "left" }}
                >
                  <div className="row-between">
                    <span style={{ fontWeight: 500 }} className="text-sm">
                      {r.organization || "(unknown org)"}
                    </span>
                    <Badge variant="outline">{r.total_gaps} gaps</Badge>
                  </div>
                  <div
                    className="row-between text-xs muted"
                    style={{ marginTop: "0.25rem" }}
                  >
                    <span>{r.frameworks_analyzed.join(", ")}</span>
                    <code className="kbd">{r.key}</code>
                  </div>
                </button>
              </li>
            ))}
          </ul>
        )}

        <p className="text-xs muted">
          {selected ? (
            <>
              Selected: <code className="kbd">{selected}</code>
            </>
          ) : (
            "No report selected — write verbs stay disabled until you pick one."
          )}
        </p>
      </CardContent>
    </Card>
  );
}

// ── Shared building blocks ────────────────────────────────────────────────

/** Render a free-form result object as readable JSON (never raw HTML). */
function ResultBlock({ data }: { data: unknown }) {
  return (
    <pre
      className="mono text-xs box"
      style={{ whiteSpace: "pre-wrap", overflowX: "auto" }}
    >
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}

/**
 * A write (push / publish / sync) control with a two-step confirmation
 * interstitial. The first click reveals "This writes to <system>. Continue?";
 * the confirm click fires `onConfirm`. Disabled (with reason text) when the
 * deployment is unauthenticated or no report key is selected.
 */
function ConfirmWriteButton({
  label,
  system,
  disabled,
  disabledReason,
  pending,
  onConfirm,
}: {
  label: string;
  system: string;
  disabled: boolean;
  disabledReason: string | null;
  pending: boolean;
  onConfirm: () => void;
}) {
  const [confirming, setConfirming] = useState(false);

  if (confirming) {
    return (
      <div
        className="row gap-2 wrap"
        role="group"
        aria-label={`Confirm ${label}`}
      >
        <span className="text-xs muted">
          This writes to {system}. Continue?
        </span>
        <Button
          type="button"
          variant="destructive"
          size="sm"
          disabled={pending}
          onClick={() => {
            onConfirm();
            setConfirming(false);
          }}
        >
          {pending ? "Working..." : `Confirm ${label}`}
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => setConfirming(false)}
        >
          Cancel
        </Button>
      </div>
    );
  }

  return (
    <div className="stack-1">
      <Button
        type="button"
        size="sm"
        disabled={disabled || pending}
        onClick={() => setConfirming(true)}
      >
        {label}
      </Button>
      {disabled && disabledReason && (
        <span className="text-xs faint">{disabledReason}</span>
      )}
    </div>
  );
}

/** Compute the disabled-reason for a write verb (auth gate then report gate). */
function writeDisabledReason(
  authed: boolean,
  reportKey: string | null,
): string | null {
  if (!authed) return AUTH_NOTE;
  if (!reportKey) return "Select a target report above to enable this write.";
  return null;
}

// ── Jira ──────────────────────────────────────────────────────────────────

function JiraSection({
  authed,
  reportKey,
}: {
  authed: boolean;
  reportKey: string | null;
}) {
  const status = useMutation({ mutationFn: () => api.jiraStatus() });
  const statusMap = useMutation({ mutationFn: () => api.jiraStatusMap() });
  const push = useMutation({
    mutationFn: () => api.jiraPush(reportKey ?? ""),
  });
  const sync = useMutation({
    mutationFn: () => api.jiraSync(reportKey ?? ""),
  });

  const disabledReason = writeDisabledReason(authed, reportKey);
  const writeDisabled = disabledReason != null;

  return (
    <section className="stack-3" aria-label="Jira integration">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">Jira</CardTitle>
          <CardDescription>
            Push open gaps as Jira issues or sync their status back.
            Credentials come from server-side environment variables — the forms
            never carry an API token.
          </CardDescription>
        </CardHeader>
        <CardContent className="stack-4">
          <div className="row gap-2 wrap" aria-label="Jira actions">
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={status.isPending}
              onClick={() => status.mutate()}
            >
              {status.isPending ? "Testing..." : "Test connection"}
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={statusMap.isPending}
              onClick={() => statusMap.mutate()}
            >
              {statusMap.isPending ? "Loading..." : "Status map"}
            </Button>
            <ConfirmWriteButton
              label="Push gaps"
              system="Jira"
              disabled={writeDisabled}
              disabledReason={disabledReason}
              pending={push.isPending}
              onConfirm={() => push.mutate()}
            />
            <ConfirmWriteButton
              label="Sync status"
              system="Jira"
              disabled={writeDisabled}
              disabledReason={disabledReason}
              pending={sync.isPending}
              onConfirm={() => sync.mutate()}
            />
          </div>

          <ActionOutcome
            title="connection"
            mutation={status}
            errorTitle="Jira connection failed"
          />
          <ActionOutcome
            title="status map"
            mutation={statusMap}
            errorTitle="Could not load status map"
          />
          <ActionOutcome
            title="push"
            mutation={push}
            errorTitle="Jira push failed"
          />
          <ActionOutcome
            title="sync"
            mutation={sync}
            errorTitle="Jira sync failed"
          />
        </CardContent>
      </Card>
    </section>
  );
}

// ── ServiceNow ─────────────────────────────────────────────────────────────

function ServiceNowSection({
  authed,
  reportKey,
}: {
  authed: boolean;
  reportKey: string | null;
}) {
  const status = useMutation({ mutationFn: () => api.servicenowStatus() });
  const push = useMutation({
    mutationFn: () => api.servicenowPush(reportKey ?? ""),
  });

  const disabledReason = writeDisabledReason(authed, reportKey);
  const writeDisabled = disabledReason != null;

  return (
    <section className="stack-3" aria-label="ServiceNow integration">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">ServiceNow</CardTitle>
          <CardDescription>
            Push open gaps as ServiceNow records (idempotent by correlation
            id). Credentials are sourced server-side.
          </CardDescription>
        </CardHeader>
        <CardContent className="stack-4">
          <div className="row gap-2 wrap" aria-label="ServiceNow actions">
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={status.isPending}
              onClick={() => status.mutate()}
            >
              {status.isPending ? "Testing..." : "Test connection"}
            </Button>
            <ConfirmWriteButton
              label="Push gaps"
              system="ServiceNow"
              disabled={writeDisabled}
              disabledReason={disabledReason}
              pending={push.isPending}
              onConfirm={() => push.mutate()}
            />
          </div>

          <ActionOutcome
            title="connection"
            mutation={status}
            errorTitle="ServiceNow connection failed"
          />
          <ActionOutcome
            title="push"
            mutation={push}
            errorTitle="ServiceNow push failed"
          />
        </CardContent>
      </Card>
    </section>
  );
}

// ── Tableau ────────────────────────────────────────────────────────────────

function TableauSection({
  authed,
  reportKey,
}: {
  authed: boolean;
  reportKey: string | null;
}) {
  const publish = useMutation({
    mutationFn: () => api.tableauPublish(reportKey ?? ""),
  });

  const disabledReason = writeDisabledReason(authed, reportKey);
  const writeDisabled = disabledReason != null;

  return (
    <section className="stack-3" aria-label="Tableau integration">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">Tableau</CardTitle>
          <CardDescription>
            Publish the selected report to Tableau as data sources. The PAT name
            and secret are read server-side from env vars; the publish carries
            only non-secret options.
          </CardDescription>
        </CardHeader>
        <CardContent className="stack-4">
          <div className="row gap-2 wrap" aria-label="Tableau actions">
            <ConfirmWriteButton
              label="Publish"
              system="Tableau"
              disabled={writeDisabled}
              disabledReason={disabledReason}
              pending={publish.isPending}
              onConfirm={() => publish.mutate()}
            />
          </div>

          <ActionOutcome
            title="publish"
            mutation={publish}
            errorTitle="Tableau publish failed"
          />
        </CardContent>
      </Card>
    </section>
  );
}

// ── Power BI ───────────────────────────────────────────────────────────────

function PowerBiSection({
  authed,
  reportKey,
}: {
  authed: boolean;
  reportKey: string | null;
}) {
  const publish = useMutation({
    mutationFn: () => api.powerbiPublish(reportKey ?? ""),
  });

  const disabledReason = writeDisabledReason(authed, reportKey);
  const writeDisabled = disabledReason != null;

  return (
    <section className="stack-3" aria-label="Power BI integration">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">Power BI</CardTitle>
          <CardDescription>
            Push the selected report to Power BI as Push Datasets. The client
            secret is read server-side from an env var; the publish carries only
            non-secret options.
          </CardDescription>
        </CardHeader>
        <CardContent className="stack-4">
          <div className="row gap-2 wrap" aria-label="Power BI actions">
            <ConfirmWriteButton
              label="Publish"
              system="Power BI"
              disabled={writeDisabled}
              disabledReason={disabledReason}
              pending={publish.isPending}
              onConfirm={() => publish.mutate()}
            />
          </div>

          <ActionOutcome
            title="publish"
            mutation={publish}
            errorTitle="Power BI publish failed"
          />
        </CardContent>
      </Card>
    </section>
  );
}

// ── Outcome renderer ──────────────────────────────────────────────────────

/**
 * Render the success / error outcome of one integration action. Success
 * renders the result object as structured text; error surfaces the ApiError
 * payload (503 not-configured, 404 unknown report key) in a destructive alert.
 */
function ActionOutcome({
  title,
  mutation,
  errorTitle,
}: {
  title: string;
  mutation: {
    isError: boolean;
    isSuccess: boolean;
    error: unknown;
    data: unknown;
  };
  errorTitle: string;
}) {
  if (mutation.isError) {
    return (
      <Alert variant="destructive">
        <AlertTitle>{errorTitle}</AlertTitle>
        <AlertDescription>{apiErrorText(mutation.error)}</AlertDescription>
      </Alert>
    );
  }
  if (mutation.isSuccess) {
    return (
      <div className="stack-2" aria-label={`${title} result`}>
        <h3 className="text-sm font-medium">Result — {title}</h3>
        <ResultBlock data={mutation.data} />
      </div>
    );
  }
  return null;
}
