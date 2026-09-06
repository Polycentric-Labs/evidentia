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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import {
  api,
  ApiError,
  type GreenboneCollectRequest,
  type NessusCollectRequest,
  type SecurityFinding,
} from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * Collectors console (/collect) — Wave-4 HIGH-risk surface.
 *
 * Every credentialed collector here makes an OUTBOUND, authenticated call to an
 * external system (AWS, GitHub, Okta, the SQL adapters, the SaaS/vendor-risk
 * APIs). Credentials are sourced SERVER-SIDE (env / config) — the forms NEVER
 * ask for a secret; they carry only non-secret params (region / repo / host /
 * options). Per the v0.10.12 threat model §4(c), the credentialed + network-
 * egress "Run" buttons are GATED on `auth_configured`: when the deployment has
 * no AuthProvider, anyone reaching the local API could drive these calls, so
 * they are disabled until `EVIDENTIA_API_AUTH_TOKEN_FILE` is set. This mirrors
 * the always-visible SecurityPostureBanner.
 *
 * Four surfaces are LOCAL-ONLY and therefore NOT auth-gated:
 *   - Convert (`collectConvert`): round-trips findings through the OCSF
 *                                 mapping layer; no network.
 *   - OCSF inline `content` ingest: parses supplied JSON locally.
 *   - Nessus scan ingest (`collectNessus`): parses a supplied .nessus XML
 *                                 export; text upload only, no path, no
 *                                 URL, no credentials.
 *   - Greenbone scan ingest (`collectGreenbone`): parses a supplied GMP
 *                                 report XML export; text upload only,
 *                                 same posture as the Nessus tab.
 * OCSF `url` mode IS networked (and carries the SSRF surface), so the URL leg
 * is auth-gated like the credentialed collectors; its `block_private_ips`
 * guard defaults ON.
 *
 * ApiError payloads (incl. the SSRF-refusal 400 for a private-IP OCSF URL) are
 * surfaced as escaped text — never via a raw-HTML prop.
 */

/** Map a finding's Severity to the matching Badge variant. */
const SEVERITY_BADGE_VARIANT: Record<
  string,
  "critical" | "high" | "medium" | "low" | "informational"
> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  informational: "informational",
};

/** Surface an ApiError payload (or any error) as readable, escaped text. */
function apiErrorText(error: unknown): string {
  if (error instanceof ApiError && error.payload != null) {
    return JSON.stringify(error.payload);
  }
  return String(error);
}

export function CollectPage() {
  const health = useQuery({
    queryKey: ["health"],
    queryFn: () => api.health(),
  });
  // Default CLOSED: until we know auth is ON, treat the deployment as
  // unsecured and keep the credentialed Run buttons disabled.
  const authed = health.data?.auth_configured ?? false;

  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">Collect</h1>
        <p className="page-sub">
          Run evidence collectors against external systems. Each run returns a
          list of security findings.
        </p>
      </header>

      <CredentialsNote authed={authed} />

      <Tabs defaultValue="collectors">
        <TabsList>
          <TabsTrigger value="collectors">Collectors</TabsTrigger>
          <TabsTrigger value="ocsf">OCSF ingest</TabsTrigger>
          <TabsTrigger value="nessus">Nessus scan</TabsTrigger>
          <TabsTrigger value="greenbone">Greenbone report</TabsTrigger>
          <TabsTrigger value="convert">Convert</TabsTrigger>
          <TabsTrigger value="status">Status</TabsTrigger>
        </TabsList>

        <TabsContent value="collectors">
          <CollectorsTab authed={authed} />
        </TabsContent>
        <TabsContent value="ocsf">
          <OcsfTab authed={authed} />
        </TabsContent>
        <TabsContent value="nessus">
          <NessusTab />
        </TabsContent>
        <TabsContent value="greenbone">
          <GreenboneTab />
        </TabsContent>
        <TabsContent value="convert">
          <ConvertTab />
        </TabsContent>
        <TabsContent value="status">
          <StatusTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

/**
 * Two-part credentials notice:
 *   1. Always: secrets are sourced server-side; the forms never ask for them.
 *   2. When unauthenticated: the §4(c) gate explanation (Run buttons disabled).
 */
function CredentialsNote({ authed }: { authed: boolean }) {
  return (
    <div className="stack-3">
      <Alert>
        <AlertTitle>Credentials are server-side</AlertTitle>
        <AlertDescription>
          Collector credentials (API tokens, DB passwords, cloud profiles) are
          sourced SERVER-SIDE from environment / config — never through these
          forms. The forms below carry only non-secret parameters (region, repo,
          host, options).
        </AlertDescription>
      </Alert>

      {!authed && (
        <Alert variant="destructive" role="note">
          <AlertTitle>Collectors disabled</AlertTitle>
          <AlertDescription>
            Collectors make credentialed external calls — configure API
            authentication (
            <code className="kbd">EVIDENTIA_API_AUTH_TOKEN_FILE</code>) to
            enable.
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════
// Findings result (shared)
// ════════════════════════════════════════════════════════════════════════

/** Render the returned `SecurityFinding[]` as a count + per-finding cards. */
function FindingsResult({ findings }: { findings: SecurityFinding[] }) {
  return (
    <div className="stack-3" aria-label="Collector findings">
      <p className="text-sm font-medium">
        {findings.length} finding{findings.length === 1 ? "" : "s"} returned
      </p>
      {findings.length === 0 ? (
        <div className="empty-state">
          The collector ran but returned no findings.
        </div>
      ) : (
        <ul className="reset stack-2">
          {findings.map((finding, idx) => (
            <li key={finding.id ?? `${finding.title}-${idx}`} className="reset">
              <Card>
                <CardContent className="stack-2" style={{ padding: "1rem" }}>
                  <div className="row gap-2 wrap">
                    <Badge
                      variant={
                        SEVERITY_BADGE_VARIANT[finding.severity] ?? "secondary"
                      }
                    >
                      {finding.severity}
                    </Badge>
                    <Badge variant="outline">{finding.source_system}</Badge>
                  </div>
                  <span className="text-sm font-medium">{finding.title}</span>
                  <span className="text-xs muted">{finding.description}</span>
                  {finding.resource_id && (
                    <span className="text-xs faint">
                      Resource:{" "}
                      <code className="kbd">{finding.resource_id}</code>
                    </span>
                  )}
                </CardContent>
              </Card>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════
// Collectors tab — credentialed providers (auth-gated)
// ════════════════════════════════════════════════════════════════════════

/**
 * A field descriptor for a collector's non-secret param form. `key` is the
 * request-body field name; only string params are surfaced (secrets never
 * appear here).
 */
type CollectorField = {
  key: string;
  label: string;
  placeholder?: string;
  required?: boolean;
};

/** A credentialed collector entry: its label, fields, and the api call. */
type CollectorSpec = {
  id: string;
  label: string;
  description: string;
  fields: CollectorField[];
  run: (body: Record<string, unknown>) => Promise<SecurityFinding[]>;
};

const COLLECTORS: CollectorSpec[] = [
  {
    id: "aws",
    label: "AWS",
    description: "AWS Config + Security Hub. Credentials via the boto3 chain.",
    fields: [
      { key: "region", label: "Region", placeholder: "us-east-1" },
      { key: "profile", label: "Profile", placeholder: "default" },
    ],
    run: (body) => api.collectAws(body),
  },
  {
    id: "github",
    label: "GitHub",
    description: "GitHub repo posture. Token via server $GITHUB_TOKEN.",
    fields: [
      {
        key: "repo",
        label: "Repository",
        placeholder: "owner/repo",
        required: true,
      },
    ],
    run: (body) => api.collectGithub(body),
  },
  {
    id: "okta",
    label: "Okta",
    description: "Okta user posture. Token via server $OKTA_API_TOKEN.",
    fields: [
      {
        key: "org_url",
        label: "Org URL",
        placeholder: "https://your-org.okta.com",
        required: true,
      },
    ],
    run: (body) => api.collectOkta(body),
  },
  {
    id: "google-workspace",
    label: "Google Workspace",
    description:
      "Google Workspace user posture: Directory accounts, 2-Step Verification, admins, login events. Token via server $GOOGLE_WORKSPACE_ACCESS_TOKEN.",
    fields: [
      {
        key: "customer",
        label: "Customer",
        placeholder: "my_customer",
      },
    ],
    run: (body) => api.collectGoogleWorkspace(body),
  },
  {
    id: "sql-postgres",
    label: "PostgreSQL",
    description:
      "Read-only Postgres posture. Password via server-side env var.",
    fields: [
      {
        key: "connection_uri",
        label: "Connection URI (no password)",
        placeholder: "postgres://reader@db.example.com/app",
        required: true,
      },
    ],
    run: (body) => api.collectSql("postgres", body),
  },
  {
    id: "databricks",
    label: "Databricks",
    description: "Databricks workspace posture. Auth via SDK unified resolver.",
    fields: [
      {
        key: "workspace_url",
        label: "Workspace URL",
        placeholder: "https://my-workspace.cloud.databricks.com",
        required: true,
      },
    ],
    run: (body) => api.collectDatabricks(body),
  },
  {
    id: "snowflake",
    label: "Snowflake",
    description: "Snowflake posture. Password/key sourced server-side.",
    fields: [
      {
        key: "account",
        label: "Account",
        placeholder: "acme-prod",
        required: true,
      },
      { key: "user", label: "User", placeholder: "AUDIT_USER", required: true },
    ],
    run: (body) => api.collectSnowflake(body),
  },
  {
    id: "vanta",
    label: "Vanta",
    description: "Vanta vendor inventory. Token via server $VANTA_API_TOKEN.",
    fields: [
      {
        key: "base_url",
        label: "Base URL",
        placeholder: "https://api.vanta.com",
      },
    ],
    run: (body) => api.collectVanta(body),
  },
  {
    id: "drata",
    label: "Drata",
    description: "Drata vendor inventory. Token via server $DRATA_API_TOKEN.",
    fields: [
      {
        key: "base_url",
        label: "Base URL",
        placeholder: "https://public-api.drata.com",
      },
    ],
    run: (body) => api.collectDrata(body),
  },
  {
    id: "bitsight",
    label: "BitSight",
    description: "BitSight portfolio. Token via server $BITSIGHT_API_TOKEN.",
    fields: [
      {
        key: "base_url",
        label: "Base URL",
        placeholder: "https://api.bitsighttech.com",
      },
    ],
    run: (body) => api.collectBitsight(body),
  },
  {
    id: "securityscorecard",
    label: "SecurityScorecard",
    description:
      "SSC portfolio. Token via server $SECURITYSCORECARD_API_TOKEN.",
    fields: [
      {
        key: "portfolio_id",
        label: "Portfolio id (optional)",
        placeholder: "first available if blank",
      },
    ],
    run: (body) => api.collectSecurityscorecard(body),
  },
];

function CollectorsTab({ authed }: { authed: boolean }) {
  const [selectedId, setSelectedId] = useState<string>(COLLECTORS[0].id);
  const selected = COLLECTORS.find((c) => c.id === selectedId) ?? COLLECTORS[0];

  return (
    <div className="stack-6">
      <section className="stack-3" aria-label="Collector picker">
        <h2 className="section-num">Choose a collector</h2>
        <div
          className="row wrap gap-2"
          role="radiogroup"
          aria-label="Collector"
        >
          {COLLECTORS.map((c) => (
            <button
              key={c.id}
              type="button"
              role="radio"
              aria-checked={selectedId === c.id}
              onClick={() => setSelectedId(c.id)}
              className={cn("pill", selectedId === c.id && "on")}
            >
              {c.label}
            </button>
          ))}
        </div>
      </section>

      <CollectorForm key={selected.id} spec={selected} authed={authed} />
    </div>
  );
}

function CollectorForm({
  spec,
  authed,
}: {
  spec: CollectorSpec;
  authed: boolean;
}) {
  const [form, setForm] = useState<Record<string, string>>({});
  const [confirming, setConfirming] = useState(false);

  const mutation = useMutation({
    mutationFn: () => {
      // Send only non-empty fields; the server fills defaults.
      const body: Record<string, unknown> = {};
      for (const field of spec.fields) {
        const value = (form[field.key] ?? "").trim();
        if (value.length > 0) body[field.key] = value;
      }
      return spec.run(body);
    },
    onSuccess: () => setConfirming(false),
  });

  const missingRequired = spec.fields.some(
    (f) => f.required && (form[f.key] ?? "").trim().length === 0,
  );
  const canRun = authed && !missingRequired && !mutation.isPending;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="base">{spec.label} collector</CardTitle>
        <CardDescription>{spec.description}</CardDescription>
      </CardHeader>
      <CardContent className="stack-5">
        <form
          className="stack-5"
          aria-label={`${spec.label} collector form`}
          onSubmit={(e) => {
            e.preventDefault();
            if (canRun) setConfirming(true);
          }}
        >
          {spec.fields.map((field) => {
            const inputId = `collect-${spec.id}-${field.key}`;
            return (
              <div className="stack-2" key={field.key}>
                <Label htmlFor={inputId}>{field.label}</Label>
                <Input
                  id={inputId}
                  value={form[field.key] ?? ""}
                  onChange={(e) =>
                    setForm({ ...form, [field.key]: e.target.value })
                  }
                  placeholder={field.placeholder}
                  required={field.required}
                />
              </div>
            );
          })}

          <div className="row-between border-t pt-4">
            <p className="text-xs muted">
              {authed
                ? "Running hits an external API with server-side credentials."
                : "Disabled — configure API authentication to enable."}
            </p>
            {confirming ? (
              <div className="row gap-2">
                <Button
                  type="button"
                  variant="destructive"
                  disabled={!canRun}
                  onClick={() => mutation.mutate()}
                >
                  {mutation.isPending
                    ? "Running..."
                    : "Confirm — run collector"}
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => setConfirming(false)}
                >
                  Cancel
                </Button>
              </div>
            ) : (
              <Button type="submit" disabled={!canRun}>
                Run collector
              </Button>
            )}
          </div>
        </form>

        {mutation.isError && (
          <Alert variant="destructive">
            <AlertTitle>Collector failed</AlertTitle>
            <AlertDescription>{apiErrorText(mutation.error)}</AlertDescription>
          </Alert>
        )}

        {mutation.isSuccess && <FindingsResult findings={mutation.data} />}
      </CardContent>
    </Card>
  );
}

// ════════════════════════════════════════════════════════════════════════
// OCSF ingest tab — inline content (local) OR url (networked, auth-gated)
// ════════════════════════════════════════════════════════════════════════

function OcsfTab({ authed }: { authed: boolean }) {
  const [mode, setMode] = useState<"content" | "url">("content");
  const [content, setContent] = useState("");
  const [url, setUrl] = useState("");
  // SECURE-BY-DEFAULT: the SSRF guard starts ON. Unchecking it disables the
  // private-IP block for the URL fetch.
  const [blockPrivateIps, setBlockPrivateIps] = useState(true);
  const [parseError, setParseError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: (body: {
      content?: unknown;
      url?: string;
      block_private_ips?: boolean;
    }) => api.collectOcsf(body),
  });

  // URL mode is networked → auth-gate it. Inline content mode is local-only.
  const isUrlMode = mode === "url";
  const runDisabled =
    mutation.isPending ||
    (isUrlMode
      ? !authed || url.trim().length === 0
      : content.trim().length === 0);

  const submit = () => {
    setParseError(null);
    if (isUrlMode) {
      mutation.mutate({
        url: url.trim(),
        block_private_ips: blockPrivateIps,
      });
      return;
    }
    // Inline content: parse the supplied OCSF JSON locally before sending.
    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch {
      setParseError("Could not parse — paste valid OCSF JSON.");
      return;
    }
    mutation.mutate({ content: parsed });
  };

  return (
    <div className="stack-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">OCSF ingest</CardTitle>
          <CardDescription>
            Ingest OCSF Compliance / Detection Finding JSON. Inline content is
            parsed locally; URL mode fetches over the network and is auth-gated.
          </CardDescription>
        </CardHeader>
        <CardContent className="stack-5">
          <div
            className="row wrap gap-2"
            role="radiogroup"
            aria-label="OCSF input mode"
          >
            <button
              type="button"
              role="radio"
              aria-checked={mode === "content"}
              onClick={() => setMode("content")}
              className={cn("pill", mode === "content" && "on")}
            >
              Inline content
            </button>
            <button
              type="button"
              role="radio"
              aria-checked={mode === "url"}
              onClick={() => setMode("url")}
              className={cn("pill", mode === "url" && "on")}
            >
              URL
            </button>
          </div>

          {mode === "content" ? (
            <div className="stack-2">
              <Label htmlFor="ocsf-content">OCSF JSON</Label>
              <p className="text-xs muted">
                A single OCSF finding object or a JSON array of them. Local-only
                — no network, no credentials.
              </p>
              <Textarea
                id="ocsf-content"
                value={content}
                onChange={(e) => {
                  setContent(e.target.value);
                  if (parseError) setParseError(null);
                }}
                rows={6}
                placeholder={'[\n  { "class_uid": 2003, "...": "..." }\n]'}
              />
            </div>
          ) : (
            <div className="stack-4">
              <div className="stack-2">
                <Label htmlFor="ocsf-url">URL</Label>
                <Input
                  id="ocsf-url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example.com/findings.ocsf.json"
                />
              </div>

              <div className="stack-2">
                <div className="row gap-2" style={{ alignItems: "center" }}>
                  <input
                    type="checkbox"
                    id="ocsf-block-private-ips"
                    checked={blockPrivateIps}
                    onChange={(e) => setBlockPrivateIps(e.target.checked)}
                  />
                  <Label htmlFor="ocsf-block-private-ips">
                    Block private IPs (SSRF guard)
                  </Label>
                </div>
                {!blockPrivateIps && (
                  <Alert variant="destructive" role="note">
                    <AlertTitle>SSRF guard disabled</AlertTitle>
                    <AlertDescription>
                      Unchecking this disables the SSRF guard — the URL may
                      resolve to a private / loopback / link-local / metadata
                      address. Only opt out for a trusted internal endpoint.
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            </div>
          )}

          <div className="row-between border-t pt-4">
            <p className="text-xs muted">
              {isUrlMode && !authed
                ? "URL mode is networked — configure API authentication to enable."
                : "Submitting ingests the OCSF findings."}
            </p>
            <Button type="button" disabled={runDisabled} onClick={submit}>
              {mutation.isPending ? "Ingesting..." : "Ingest OCSF"}
            </Button>
          </div>

          {parseError && (
            <Alert variant="destructive">
              <AlertTitle>Could not read OCSF JSON</AlertTitle>
              <AlertDescription>{parseError}</AlertDescription>
            </Alert>
          )}

          {mutation.isError && (
            <Alert variant="destructive">
              <AlertTitle>Could not ingest OCSF</AlertTitle>
              <AlertDescription>
                {apiErrorText(mutation.error)}
              </AlertDescription>
            </Alert>
          )}

          {mutation.isSuccess && <FindingsResult findings={mutation.data} />}
        </CardContent>
      </Card>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════
// Nessus tab: text upload, local-only (NOT auth-gated, no path/URL)
// ════════════════════════════════════════════════════════════════════════

function NessusTab() {
  const [content, setContent] = useState("");
  const [cadenceSlug, setCadenceSlug] = useState("");
  const [saveEvidence, setSaveEvidence] = useState(true);

  const mutation = useMutation({
    mutationFn: (body: NessusCollectRequest) => api.collectNessus(body),
  });

  const submit = () => {
    const body: NessusCollectRequest = {
      content,
      save_evidence: saveEvidence,
    };
    const trimmedSlug = cadenceSlug.trim();
    if (trimmedSlug.length > 0) body.cadence_slug = trimmedSlug;
    mutation.mutate(body);
  };

  const canSubmit = content.trim().length > 0 && !mutation.isPending;

  return (
    <div className="stack-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">Nessus scan (.nessus XML)</CardTitle>
          <CardDescription>
            Ingest a Nessus v2 scan export. Text upload only; no path, no URL,
            no credentials: parsed server-side with defusedxml.
          </CardDescription>
        </CardHeader>
        <CardContent className="stack-5">
          <div className="stack-2">
            <Label htmlFor="nessus-content">Nessus XML</Label>
            <p className="text-xs muted">
              The full &lt;NessusClientData_v2&gt; export. Local-only; no
              network, no credentials.
            </p>
            <Textarea
              id="nessus-content"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              rows={6}
              placeholder={
                '<NessusClientData_v2>\n  <Report name="...">...</Report>\n</NessusClientData_v2>'
              }
            />
          </div>

          <div className="stack-2">
            <Label htmlFor="nessus-cadence-slug">Cadence slug (optional)</Label>
            <Input
              id="nessus-cadence-slug"
              value={cadenceSlug}
              onChange={(e) => setCadenceSlug(e.target.value)}
              placeholder="fedramp-conmon-scans"
            />
          </div>

          <div className="row gap-2" style={{ alignItems: "center" }}>
            <input
              type="checkbox"
              id="nessus-save-evidence"
              checked={saveEvidence}
              onChange={(e) => setSaveEvidence(e.target.checked)}
            />
            <Label htmlFor="nessus-save-evidence">
              Save the scan-report evidence artifact
            </Label>
          </div>

          <div className="row-between border-t pt-4">
            <p className="text-xs muted">
              Submitting parses the XML server-side and, if enabled, saves one
              evidence artifact for `conmon series` to read.
            </p>
            <Button type="button" disabled={!canSubmit} onClick={submit}>
              {mutation.isPending ? "Ingesting..." : "Ingest Nessus scan"}
            </Button>
          </div>

          {mutation.isError && (
            <Alert variant="destructive">
              <AlertTitle>Could not ingest Nessus scan</AlertTitle>
              <AlertDescription>
                {apiErrorText(mutation.error)}
              </AlertDescription>
            </Alert>
          )}

          {mutation.isSuccess && (
            <div className="stack-3">
              <p className="text-sm font-medium">
                Scan{" "}
                {mutation.data.manifest.is_complete ? "complete" : "incomplete"}
                ;{" "}
                {mutation.data.evidence.saved
                  ? `evidence saved (lineage ${mutation.data.evidence.lineage_id})`
                  : "evidence not saved"}
              </p>
              <FindingsResult findings={mutation.data.findings} />
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════
// Greenbone tab: text upload, local-only (NOT auth-gated, no path/URL)
// ════════════════════════════════════════════════════════════════════════

function GreenboneTab() {
  const [content, setContent] = useState("");
  const [cadenceSlug, setCadenceSlug] = useState("");
  const [saveEvidence, setSaveEvidence] = useState(true);

  const mutation = useMutation({
    mutationFn: (body: GreenboneCollectRequest) => api.collectGreenbone(body),
  });

  const submit = () => {
    const body: GreenboneCollectRequest = {
      content,
      save_evidence: saveEvidence,
    };
    const trimmedSlug = cadenceSlug.trim();
    if (trimmedSlug.length > 0) body.cadence_slug = trimmedSlug;
    mutation.mutate(body);
  };

  const canSubmit = content.trim().length > 0 && !mutation.isPending;

  return (
    <div className="stack-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">Greenbone report (GMP XML)</CardTitle>
          <CardDescription>
            Ingest a Greenbone Community Edition GMP report export. Text upload
            only: no path, no URL, no credentials, parsed server-side with
            defusedxml.
          </CardDescription>
        </CardHeader>
        <CardContent className="stack-5">
          <div className="stack-2">
            <Label htmlFor="greenbone-content">Greenbone XML</Label>
            <p className="text-xs muted">
              The GMP &lt;report&gt; export (wrapped or bare inner form).
              Local-only: no network, no credentials.
            </p>
            <Textarea
              id="greenbone-content"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              rows={6}
              placeholder={
                '<report id="...">\n  <report id="...">...</report>\n</report>'
              }
            />
          </div>

          <div className="stack-2">
            <Label htmlFor="greenbone-cadence-slug">
              Cadence slug (optional)
            </Label>
            <Input
              id="greenbone-cadence-slug"
              value={cadenceSlug}
              onChange={(e) => setCadenceSlug(e.target.value)}
              placeholder="fedramp-conmon-scans"
            />
          </div>

          <div className="row gap-2" style={{ alignItems: "center" }}>
            <input
              type="checkbox"
              id="greenbone-save-evidence"
              checked={saveEvidence}
              onChange={(e) => setSaveEvidence(e.target.checked)}
            />
            <Label htmlFor="greenbone-save-evidence">
              Save the scan-report evidence artifact
            </Label>
          </div>

          <div className="row-between border-t pt-4">
            <p className="text-xs muted">
              Submitting parses the XML server-side and, if enabled, saves one
              evidence artifact for `conmon series` to read.
            </p>
            <Button type="button" disabled={!canSubmit} onClick={submit}>
              {mutation.isPending ? "Ingesting..." : "Ingest Greenbone scan"}
            </Button>
          </div>

          {mutation.isError && (
            <Alert variant="destructive">
              <AlertTitle>Could not ingest Greenbone scan</AlertTitle>
              <AlertDescription>
                {apiErrorText(mutation.error)}
              </AlertDescription>
            </Alert>
          )}

          {mutation.isSuccess && (
            <div className="stack-3">
              <p className="text-sm font-medium">
                Scan{" "}
                {mutation.data.manifest.is_complete ? "complete" : "incomplete"}
                {". "}
                {mutation.data.evidence.saved
                  ? `Evidence saved (lineage ${mutation.data.evidence.lineage_id})`
                  : "Evidence not saved"}
              </p>
              <FindingsResult findings={mutation.data.findings} />
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════
// Convert tab — local-only (NOT auth-gated)
// ════════════════════════════════════════════════════════════════════════

function ConvertTab() {
  const [content, setContent] = useState("");
  const [toFormat, setToFormat] = useState("ocsf");
  const [parseError, setParseError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.collectConvert(body),
  });

  const submit = () => {
    setParseError(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch {
      setParseError("Could not parse — paste valid findings JSON.");
      return;
    }
    mutation.mutate({ content: parsed, to_format: toFormat });
  };

  const canSubmit = content.trim().length > 0 && !mutation.isPending;

  return (
    <div className="stack-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">Convert findings</CardTitle>
          <CardDescription>
            Round-trip a findings document through the OCSF mapping layer.
            LOCAL-ONLY — no network, no credentials.
          </CardDescription>
        </CardHeader>
        <CardContent className="stack-5">
          <div className="stack-2">
            <Label htmlFor="convert-content">Findings JSON</Label>
            <p className="text-xs muted">
              A single SecurityFinding object or a JSON array of them.
            </p>
            <Textarea
              id="convert-content"
              value={content}
              onChange={(e) => {
                setContent(e.target.value);
                if (parseError) setParseError(null);
              }}
              rows={6}
              placeholder={'[\n  { "title": "...", "severity": "high" }\n]'}
            />
          </div>

          <div className="stack-2">
            <Label htmlFor="convert-format">Output format</Label>
            <Input
              id="convert-format"
              value={toFormat}
              onChange={(e) => setToFormat(e.target.value)}
              placeholder="ocsf"
              style={{ maxWidth: "12rem" }}
            />
          </div>

          <div className="row-end border-t pt-4">
            <Button type="button" disabled={!canSubmit} onClick={submit}>
              {mutation.isPending ? "Converting..." : "Convert"}
            </Button>
          </div>

          {parseError && (
            <Alert variant="destructive">
              <AlertTitle>Could not read findings JSON</AlertTitle>
              <AlertDescription>{parseError}</AlertDescription>
            </Alert>
          )}

          {mutation.isError && (
            <Alert variant="destructive">
              <AlertTitle>Could not convert</AlertTitle>
              <AlertDescription>
                {apiErrorText(mutation.error)}
              </AlertDescription>
            </Alert>
          )}

          {mutation.isSuccess && (
            <div className="stack-2">
              <p className="text-sm font-medium">
                {mutation.data.length} record
                {mutation.data.length === 1 ? "" : "s"} converted
              </p>
              <pre
                className="mono text-xs box"
                style={{ whiteSpace: "pre-wrap", overflowX: "auto" }}
              >
                {JSON.stringify(mutation.data, null, 2)}
              </pre>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════
// Status tab — which collectors are installed + which creds are set
// ════════════════════════════════════════════════════════════════════════

function StatusTab() {
  const query = useQuery({
    queryKey: ["collectors-status"],
    queryFn: () => api.collectorsStatus(),
  });

  return (
    <div className="stack-6">
      <section className="stack-3" aria-label="Collector status">
        <h2 className="section-num">Collector status</h2>

        {query.isError && (
          <Card className="border-dest" role="alert">
            <CardContent className="card-body" style={{ padding: "1.5rem" }}>
              <span className="text-sm text-destructive">
                Could not fetch collector status. Is the backend running?
              </span>
            </CardContent>
          </Card>
        )}

        {query.isLoading && <div className="skel" style={{ height: "8rem" }} />}

        {query.isSuccess && (
          <Card>
            <CardContent className="card-body" style={{ padding: "1.5rem" }}>
              <pre
                className="mono text-xs box"
                style={{ whiteSpace: "pre-wrap", overflowX: "auto" }}
              >
                {JSON.stringify(query.data, null, 2)}
              </pre>
            </CardContent>
          </Card>
        )}
      </section>
    </div>
  );
}
