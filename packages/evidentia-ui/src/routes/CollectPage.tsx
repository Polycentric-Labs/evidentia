import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

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
  type EnterpriseRetentionCollectRequest,
  type EnterpriseRetentionDemoScenario,
  type EntraM365CollectRequest,
  type EntraM365CollectResult,
  type EntraM365DemoScenario,
  type GreenboneCollectRequest,
  type NessusCollectRequest,
  type SecurityFinding,
} from "@/lib/api";
import { IS_DEMO } from "@/lib/demo";
import {
  buildEnterpriseRetentionRequest,
  parseEnterpriseRetentionRequest,
  parseEnterpriseRetentionResponse,
  snapshotEnterpriseRetentionRequest,
  EnterpriseRetentionResponseError,
  ENTERPRISE_REQUEST_BYTE_LIMIT,
  type EnterpriseProvider,
  type EnterpriseRetentionResponse,
} from "@/lib/enterprise-retention";
import { cn } from "@/lib/utils";
import { StorageRetentionTab } from "@/routes/StorageRetentionTab";
import { RegistryCollectAction } from "@/routes/RegistryCollectAction";

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
 * These local parsing surfaces do not require a configured AuthProvider:
 *   - Convert (`collectConvert`): round-trips findings through the OCSF
 *                                 mapping layer; no network.
 *   - OCSF inline `content` ingest: parses supplied JSON locally.
 *   - Nessus scan ingest (`collectNessus`): parses a supplied .nessus XML
 *                                 export; text upload only, no path, no
 *                                 URL, no credentials.
 *   - Greenbone scan ingest (`collectGreenbone`): parses a supplied GMP
 *                                 report XML export; text upload only,
 *                                 same posture as the Nessus tab.
 *   - Entra/M365 with only DLP export selected: parses supplied JSON locally.
 * Configured read-role checks still apply to these local surfaces.
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
    staleTime: 30_000,
    refetchInterval: 30_000,
    refetchOnMount: "always",
  });
  // Default CLOSED: until we know auth is ON, treat the deployment as
  // unsecured and keep the credentialed Run buttons disabled.
  const authed = health.data?.auth_configured ?? false;
  const freshAuth =
    health.isSuccess &&
    !health.isStale &&
    !health.isFetching &&
    health.data.auth_configured === true;
  const verifyEntraAuth = async () => {
    const checked = await health.refetch();
    return checked.isSuccess && checked.data?.auth_configured === true;
  };

  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">Collect</h1>
        <p className="page-sub">
          Collect security findings and source completeness information.
        </p>
      </header>

      <CredentialsNote authed={authed} />

      <Tabs defaultValue="collectors">
        <TabsList className="h-auto max-w-full flex-wrap justify-start">
          <TabsTrigger value="collectors">Collectors</TabsTrigger>
          <TabsTrigger value="entra-m365">Entra/M365</TabsTrigger>
          <TabsTrigger value="storage-retention">Storage retention</TabsTrigger>
          <TabsTrigger value="enterprise-retention">
            Enterprise retention
          </TabsTrigger>
          <TabsTrigger value="registries">Public registries</TabsTrigger>
          <TabsTrigger value="ocsf">OCSF ingest</TabsTrigger>
          <TabsTrigger value="nessus">Nessus scan</TabsTrigger>
          <TabsTrigger value="greenbone">Greenbone report</TabsTrigger>
          <TabsTrigger value="convert">Convert</TabsTrigger>
          <TabsTrigger value="status">Status</TabsTrigger>
        </TabsList>

        <TabsContent value="collectors">
          <CollectorsTab authed={authed} />
        </TabsContent>
        <TabsContent value="entra-m365">
          <EntraM365Tab freshAuth={freshAuth} verifyAuth={verifyEntraAuth} />
        </TabsContent>
        <TabsContent value="storage-retention">
          <StorageRetentionTab
            freshAuth={freshAuth}
            verifyAuth={verifyEntraAuth}
          />
        </TabsContent>
        <TabsContent value="enterprise-retention">
          <EnterpriseRetentionTab
            freshAuth={freshAuth}
            verifyAuth={verifyEntraAuth}
          />
        </TabsContent>
        <TabsContent value="registries">
          <RegistryCollectAction
            freshAuth={freshAuth}
            verifyAuth={verifyEntraAuth}
          />
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

type EntraCapability = NonNullable<
  EntraM365CollectRequest["capabilities"]
>[number];
const ENTRA_CAPABILITIES: ReadonlyArray<readonly [EntraCapability, string]> = [
  ["conditional-access", "Conditional Access"],
  ["authentication-registration", "Authentication registration"],
  ["sign-ins", "Sign-ins"],
  ["directory-roles", "Directory roles"],
  ["managed-devices", "Managed devices"],
  ["retention-labels", "Retention labels"],
  ["dlp-export", "DLP export"],
  ["defender-alerts", "Defender alerts"],
  ["defender-incidents", "Defender incidents"],
];
const ENTRA_DLP_LIMIT = 4_194_304;

function EntraM365Tab({
  freshAuth,
  verifyAuth,
}: {
  freshAuth: boolean;
  verifyAuth: () => Promise<boolean>;
}) {
  const [tenantLabel, setTenantLabel] = useState(
    IS_DEMO ? "synthetic-demo" : "",
  );
  const [selected, setSelected] = useState<EntraCapability[]>(
    ENTRA_CAPABILITIES.map(([name]) => name),
  );
  const [lookback, setLookback] = useState("30");
  const [maxItems, setMaxItems] = useState("10000");
  const [maxPages, setMaxPages] = useState("100");
  const [dlpContent, setDlpContent] = useState<string>();
  const [dlpFormat, setDlpFormat] =
    useState<NonNullable<EntraM365CollectRequest["dlp_format"]>>(
      "evidentia-dlp-v1",
    );
  const [fileError, setFileError] = useState<string>();
  const [readingFile, setReadingFile] = useState(false);
  const [scenario, setScenario] = useState<EntraM365DemoScenario>("partial");
  const fileVersion = useRef(0);
  const fileInput = useRef<HTMLInputElement>(null);
  const needsGraph = selected.some((name) => name !== "dlp-export");
  const hasDlp = selected.includes("dlp-export");
  const validInteger = (value: string, maximum: number) =>
    /^[0-9]+$/.test(value) &&
    Number.isInteger(Number(value)) &&
    Number(value) >= 1 &&
    Number(value) <= maximum;
  const valid =
    /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(tenantLabel) &&
    selected.length > 0 &&
    validInteger(lookback, 30) &&
    validInteger(maxItems, 10000) &&
    validInteger(maxPages, 100) &&
    !fileError;
  const mutation = useMutation({
    mutationFn: async ({
      body,
      demoScenario,
    }: {
      body: EntraM365CollectRequest;
      demoScenario: EntraM365DemoScenario;
    }) => {
      if (
        new TextEncoder().encode(JSON.stringify(body)).byteLength > 8_388_608
      ) {
        throw new Error("The encoded request exceeds the 8 MiB size limit.");
      }
      if (
        !IS_DEMO &&
        body.capabilities?.some((name) => name !== "dlp-export") &&
        !(await verifyAuth())
      ) {
        throw new Error(
          "Graph collection requires current API authentication.",
        );
      }
      return api.collectEntraM365(body, demoScenario);
    },
  });

  const readFile = async (file: File | undefined) => {
    const version = ++fileVersion.current;
    setDlpContent(undefined);
    setFileError(undefined);
    setReadingFile(false);
    if (!file) return;
    if (file.size > ENTRA_DLP_LIMIT) {
      setFileError("The DLP export exceeds the 4 MiB size limit.");
      return;
    }
    setReadingFile(true);
    try {
      const buffer = await file.arrayBuffer();
      if (version !== fileVersion.current) return;
      if (buffer.byteLength > ENTRA_DLP_LIMIT) throw new Error("size");
      const text = new TextDecoder("utf-8", {
        fatal: true,
        ignoreBOM: true,
      }).decode(buffer);
      setDlpContent(text);
    } catch {
      if (version === fileVersion.current)
        setFileError("The export must be valid UTF-8 JSON within 4 MiB.");
    } finally {
      if (version === fileVersion.current) setReadingFile(false);
    }
  };

  const toggleCapability = (name: EntraCapability, enabled: boolean) => {
    setSelected((current) =>
      ENTRA_CAPABILITIES.map(([key]) => key).filter((key) =>
        key === name ? enabled : current.includes(key),
      ),
    );
    if (name === "dlp-export" && !enabled) {
      ++fileVersion.current;
      setDlpContent(undefined);
      setFileError(undefined);
      setReadingFile(false);
      if (fileInput.current) fileInput.current.value = "";
    }
  };

  return (
    <section className="stack-6" aria-label="Entra/M365 collection">
      <Card>
        <CardHeader>
          <CardTitle>Entra ID and Microsoft 365</CardTitle>
          <CardDescription>
            Collect configuration and event observations with explicit source
            limits. This does not establish tenant-wide compliance or effective
            enforcement.
          </CardDescription>
        </CardHeader>
        <CardContent className="stack-4">
          {IS_DEMO && (
            <Alert>
              <AlertTitle>Synthetic examples</AlertTitle>
              <AlertDescription>
                These fixed examples show incomplete collection results. No
                tenant is queried.
              </AlertDescription>
            </Alert>
          )}
          {!IS_DEMO && needsGraph && !freshAuth && (
            <Alert role="status">
              <AlertTitle>API authentication required</AlertTitle>
              <AlertDescription>
                Graph collection is disabled until current API health confirms
                authentication is configured. DLP-only collection uses a local
                export and still honors read permissions.
              </AlertDescription>
            </Alert>
          )}
          <form
            className="stack-4"
            onSubmit={(event) => {
              event.preventDefault();
              if (
                !valid ||
                readingFile ||
                mutation.isPending ||
                (!IS_DEMO && needsGraph && !freshAuth)
              )
                return;
              const body: EntraM365CollectRequest = {
                tenant_label: tenantLabel,
                capabilities: [...selected],
                lookback_days: Number(lookback),
                max_items: Number(maxItems),
                max_pages: Number(maxPages),
              };
              if (hasDlp && dlpContent !== undefined) {
                body.dlp_content = dlpContent;
                body.dlp_format = dlpFormat;
              }
              mutation.mutate({ body, demoScenario: scenario });
            }}
          >
            <fieldset
              className="stack-4"
              disabled={IS_DEMO || mutation.isPending}
            >
              <div className="stack-2">
                <Label htmlFor="entra-tenant">Tenant label</Label>
                <Input
                  id="entra-tenant"
                  value={tenantLabel}
                  required
                  maxLength={64}
                  onChange={(event) => setTenantLabel(event.target.value)}
                  placeholder="Nonsecret operator alias"
                />
                <p className="text-xs muted">
                  Operator-declared label. Authenticated tenant identity is
                  unverified.
                </p>
              </div>
              <fieldset className="stack-2">
                <legend>Capabilities</legend>
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  {ENTRA_CAPABILITIES.map(([name, label]) => (
                    <label key={name} className="row gap-2">
                      <input
                        type="checkbox"
                        checked={selected.includes(name)}
                        onChange={(event) =>
                          toggleCapability(name, event.target.checked)
                        }
                      />
                      {label}
                    </label>
                  ))}
                </div>
              </fieldset>
              <div className="grid gap-3 sm:grid-cols-3">
                <div className="stack-2">
                  <Label htmlFor="entra-lookback">Lookback days</Label>
                  <Input
                    id="entra-lookback"
                    type="number"
                    min={1}
                    max={30}
                    step={1}
                    value={lookback}
                    onChange={(event) => setLookback(event.target.value)}
                  />
                </div>
                <div className="stack-2">
                  <Label htmlFor="entra-max-items">
                    Maximum items per capability
                  </Label>
                  <Input
                    id="entra-max-items"
                    type="number"
                    min={1}
                    max={10000}
                    step={1}
                    value={maxItems}
                    onChange={(event) => setMaxItems(event.target.value)}
                  />
                </div>
                <div className="stack-2">
                  <Label htmlFor="entra-max-pages">
                    Maximum pages per capability
                  </Label>
                  <Input
                    id="entra-max-pages"
                    type="number"
                    min={1}
                    max={100}
                    step={1}
                    value={maxPages}
                    onChange={(event) => setMaxPages(event.target.value)}
                  />
                </div>
              </div>
              <div className="stack-2">
                <Label htmlFor="entra-dlp">DLP JSON export</Label>
                <Input
                  id="entra-dlp"
                  ref={fileInput}
                  type="file"
                  accept="application/json,.json"
                  disabled={!hasDlp}
                  onChange={(event) => {
                    void readFile(event.target.files?.[0]);
                  }}
                />
                <p className="text-xs muted">
                  Optional UTF-8 JSON, at most 4 MiB. Upload content only; no
                  server path or token.
                </p>
              </div>
              <div className="stack-2">
                <Label htmlFor="entra-dlp-format">DLP export format</Label>
                <select
                  id="entra-dlp-format"
                  className="input"
                  disabled={!hasDlp || dlpContent === undefined}
                  value={dlpFormat}
                  onChange={(event) =>
                    setDlpFormat(
                      event.target.value === "scubagear-provider-v1"
                        ? "scubagear-provider-v1"
                        : "evidentia-dlp-v1",
                    )
                  }
                >
                  <option value="evidentia-dlp-v1">Evidentia DLP v1</option>
                  <option value="scubagear-provider-v1">
                    ScubaGear provider v1
                  </option>
                </select>
              </div>
            </fieldset>
            {IS_DEMO && (
              <div className="stack-2">
                <Label htmlFor="entra-scenario">
                  Synthetic result scenario
                </Label>
                <select
                  id="entra-scenario"
                  className="input"
                  disabled={mutation.isPending}
                  value={scenario}
                  onChange={(event) =>
                    setScenario(
                      event.target.value === "unavailable"
                        ? "unavailable"
                        : "partial",
                    )
                  }
                >
                  <option value="partial">Partial collection</option>
                  <option value="unavailable">All sources unavailable</option>
                </select>
              </div>
            )}
            {fileError && (
              <p role="alert" className="text-sm text-destructive">
                {fileError}
              </p>
            )}
            {readingFile && (
              <p role="status">Reading the bounded local export.</p>
            )}
            <Button
              type="submit"
              disabled={
                !valid ||
                readingFile ||
                mutation.isPending ||
                (!IS_DEMO && needsGraph && !freshAuth)
              }
            >
              {mutation.isPending
                ? "Collecting Entra/M365"
                : "Collect Entra/M365"}
            </Button>
          </form>
          {mutation.isError && (
            <Alert variant="destructive">
              <AlertTitle>Collection failed</AlertTitle>
              <AlertDescription>
                {apiErrorText(mutation.error)}
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>
      {mutation.data && <EntraM365Result result={mutation.data} />}
    </section>
  );
}

function EntraM365Result({ result }: { result: EntraM365CollectResult }) {
  const [downloadError, setDownloadError] = useState(false);
  const download = () => {
    let url: string | undefined;
    let link: HTMLAnchorElement | undefined;
    try {
      url = URL.createObjectURL(
        new Blob([JSON.stringify(result, null, 2) + "\n"], {
          type: "application/json",
        }),
      );
      link = document.createElement("a");
      link.href = url;
      link.download = "entra-m365-result.json";
      document.body.append(link);
      link.click();
      setDownloadError(false);
    } catch {
      setDownloadError(true);
    } finally {
      link?.remove();
      if (url) URL.revokeObjectURL(url);
    }
  };
  return (
    <div className="stack-6" aria-label="Entra/M365 result">
      <Alert variant={result.status === "complete" ? "default" : "destructive"}>
        <AlertTitle>
          {result.status === "complete"
            ? "Requested scope complete"
            : `Collection incomplete: ${result.status}`}
        </AlertTitle>
        <AlertDescription>
          Findings retained: {result.findings.length}. Full surface complete:{" "}
          {result.full_surface_complete ? "yes" : "no"}. Review every capability
          state, including sources with no findings.
        </AlertDescription>
      </Alert>
      <div className="stack-2">
        <p>
          Tenant label: {result.provenance.tenant_label}. Identity basis:{" "}
          {result.provenance.identity_basis}. Authenticated tenant identity
          verified:{" "}
          {result.provenance.authenticated_identity_verified ? "yes" : "no"}.
        </p>
        <p className="mono text-xs">
          Run: {result.manifest.run_id}. Collection window:{" "}
          {result.manifest.collection_started_at} to{" "}
          {result.manifest.collection_finished_at}.
        </p>
        <Button type="button" variant="outline" onClick={download}>
          Download full result JSON
        </Button>
        {downloadError && (
          <p role="alert">
            The result could not be downloaded. The collection remains available
            here.
          </p>
        )}
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {result.capabilities.map((cap) => (
          <Card key={cap.name} aria-label={`${cap.name} capability result`}>
            <CardHeader>
              <CardTitle>
                {ENTRA_CAPABILITIES.find(([name]) => name === cap.name)?.[1] ??
                  cap.name}
              </CardTitle>
              <Badge variant="outline">{cap.state}</Badge>
            </CardHeader>
            <CardContent className="stack-2 text-sm">
              <p>
                Scanned: {cap.scanned}. In scope: {cap.matched_filter}.
                Collected: {cap.collected}.
              </p>
              <p>
                Duplicate records: {cap.duplicate_records}. Pages:{" "}
                {cap.pages_completed}. Requests: {cap.requests_attempted}.
              </p>
              <p>
                Credential basis: {cap.credential_basis ?? "not requested"}.
                Declared mode:{" "}
                {cap.declared_auth_mode ?? "not applicable or unknown"}.
              </p>
              <p className="mono text-xs">
                Requested window:{" "}
                {cap.requested_window_start ?? "not applicable"} to{" "}
                {cap.requested_window_end ?? "not applicable"}.
              </p>
              <p className="mono text-xs">
                Observed range: {cap.observed_first ?? "unavailable"} to{" "}
                {cap.observed_last ?? "unavailable"}.
              </p>
              <p className="mono text-xs">
                Capability collection: {cap.started_at ?? "not started"} to{" "}
                {cap.finished_at ?? "not finished"}.
              </p>
              <ul>
                {cap.diagnostics.map((diagnostic, index) => (
                  <li key={`${diagnostic.code}-${index}`}>
                    {diagnostic.code}: {diagnostic.count}
                    {diagnostic.http_status === null
                      ? ""
                      : ` (HTTP ${diagnostic.http_status})`}
                  </li>
                ))}
              </ul>
              <details>
                <summary>Field coverage</summary>
                <pre
                  className="mono text-xs"
                  style={{ whiteSpace: "pre-wrap" }}
                >
                  {JSON.stringify(cap.field_coverage, null, 2)}
                </pre>
              </details>
            </CardContent>
          </Card>
        ))}
      </div>
      {result.findings.length > 0 && (
        <div className="stack-3">
          {result.findings.length > 100 && (
            <p>
              Showing the first 100 findings. Download the full JSON for all
              retained observations.
            </p>
          )}
          <FindingsResult findings={result.findings.slice(0, 100)} />
          <details>
            <summary>Source observations, first 10 findings</summary>
            <pre
              className="mono text-xs"
              style={{ whiteSpace: "pre-wrap", overflowX: "auto" }}
            >
              {JSON.stringify(result.findings.slice(0, 10), null, 2)}
            </pre>
          </details>
        </div>
      )}
    </div>
  );
}

const ENTERPRISE_HINTS: Record<EnterpriseProvider, string> = {
  "google-vault":
    "Read each selected matter and its holds. Default and custom retention rules, and coverage of held records, remain unassessed.",
  "splunk-enterprise":
    "Read each selected index's configuration. Event coverage, archival execution, SmartStore, volumes and cluster-wide configuration remain unassessed.",
  "elastic-ilm":
    "Read selected indexes, ILM service status and referenced current policies. This is not an atomic provider snapshot; document coverage and lifecycle execution remain unassessed.",
};
const enterpriseDemoTargets = (provider: EnterpriseProvider) =>
  provider === "google-vault"
    ? ["matter-0", "matter-1"]
    : ["events-0", "events-1"];
function enterpriseError(error: unknown): string {
  if (error instanceof EnterpriseRetentionResponseError) return error.message;
  if (error instanceof ApiError) {
    if (error.status === 401)
      return "API authentication is required. Check the deployment's access configuration.";
    if (error.status === 403)
      return "Read access or use of the selected profile was denied.";
    if ([400, 413, 415, 422].includes(error.status))
      return "The enterprise request is invalid or exceeds the accepted limits.";
    if (error.status === 503)
      return "Enterprise collection is unavailable in this installation.";
  }
  return "Enterprise collection failed. Check the API's availability and try again.";
}

function EnterpriseRetentionTab({
  freshAuth,
  verifyAuth,
}: {
  freshAuth: boolean;
  verifyAuth: () => Promise<boolean>;
}) {
  const [provider, setProvider] = useState<EnterpriseProvider>("google-vault");
  const [profile, setProfile] = useState(IS_DEMO ? "selected" : "");
  const [scope, setScope] = useState(IS_DEMO ? "synthetic" : "");
  const [targets, setTargets] = useState<string[]>(
    IS_DEMO ? enterpriseDemoTargets("google-vault") : [""],
  );
  const [scenario, setScenario] =
    useState<EnterpriseRetentionDemoScenario>("partial");
  const [result, setResult] = useState<EnterpriseRetentionResponse>();
  const [error, setError] = useState<string>();
  const [reading, setReading] = useState(false);
  const [fileRejected, setFileRejected] = useState(false);
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const generation = useRef(0);
  const fileInput = useRef<HTMLInputElement>(null);
  useEffect(
    () => () => {
      ++generation.current;
    },
    [],
  );
  const invalidate = () => {
    ++generation.current;
    setResult(undefined);
    setError(undefined);
    setReading(false);
    setFileRejected(false);
    if (fileInput.current) fileInput.current.value = "";
  };
  const readFile = async (file: File | undefined) => {
    if (running.current) return;
    invalidate();
    const active = generation.current;
    if (!file) return;
    setReading(true);
    try {
      if (file.size > ENTERPRISE_REQUEST_BYTE_LIMIT) throw new Error("size");
      const bytes = await file.arrayBuffer();
      if (generation.current !== active) return;
      if (bytes.byteLength > ENTERPRISE_REQUEST_BYTE_LIMIT)
        throw new Error("size");
      const raw = new TextDecoder("utf-8", {
        fatal: true,
        ignoreBOM: true,
      }).decode(bytes);
      const request = parseEnterpriseRetentionRequest(raw);
      setProvider(request.provider);
      setProfile(request.profile_alias);
      setScope(request.scope_label);
      setTargets(
        request.targets.map((target) =>
          "matter_id" in target ? target.matter_id : target.index,
        ),
      );
    } catch {
      if (generation.current === active) {
        setFileRejected(true);
        setError(
          "The request file must contain strict UTF-8 JSON within 64 KiB and a valid profile, scope and target selection.",
        );
      }
    } finally {
      if (generation.current === active) setReading(false);
    }
  };
  const submit = async () => {
    if (running.current || reading || fileRejected || (!IS_DEMO && !freshAuth))
      return;
    invalidate();
    let request: EnterpriseRetentionCollectRequest;
    try {
      request = buildEnterpriseRetentionRequest(
        provider,
        profile,
        scope,
        targets,
      );
    } catch (error) {
      setError(
        error instanceof Error
          ? error.message
          : "The enterprise request is invalid.",
      );
      return;
    }
    const expected = snapshotEnterpriseRetentionRequest(request);
    const active = generation.current;
    running.current = true;
    setBusy(true);
    try {
      if (!IS_DEMO) {
        let confirmed = false;
        try {
          confirmed = await verifyAuth();
        } catch {
          /* A failed health read leaves authentication unconfirmed. */
        }
        if (generation.current !== active) return;
        if (!confirmed) {
          setError(
            "Current API authentication could not be confirmed. No collection was started.",
          );
          return;
        }
      }
      const received = await api.collectEnterpriseRetention(request, scenario);
      if (generation.current === active)
        setResult(parseEnterpriseRetentionResponse(received.rawJson, expected));
    } catch (error) {
      if (generation.current === active) setError(enterpriseError(error));
    } finally {
      if (generation.current === active) {
        running.current = false;
        setBusy(false);
      }
    }
  };
  return (
    <section className="stack-6" aria-label="Enterprise retention collection">
      <Card>
        <CardHeader>
          <CardTitle>Enterprise retention configuration</CardTitle>
          <CardDescription>
            Collect configuration evidence for 1 to 20 selected resources
            through an administrator-configured profile. Observations do not
            establish record coverage, effective enforcement or compliance.
          </CardDescription>
        </CardHeader>
        <CardContent className="stack-4">
          {IS_DEMO && (
            <Alert role="note">
              <AlertTitle>Synthetic enterprise examples</AlertTitle>
              <AlertDescription>
                No tenant or server is queried. Choose a provider and result
                scenario to inspect fixed synthetic observations.
              </AlertDescription>
            </Alert>
          )}
          {!IS_DEMO && !freshAuth && (
            <Alert role="status">
              <AlertTitle>API authentication required</AlertTitle>
              <AlertDescription>
                Collection is disabled until current API health confirms
                authentication is configured. The API also checks read
                permission and access to the selected profile.
              </AlertDescription>
            </Alert>
          )}
          <form
            className="stack-4"
            aria-label="Enterprise retention request"
            noValidate
            onSubmit={(event) => {
              event.preventDefault();
              void submit();
            }}
          >
            <fieldset className="stack-4" disabled={busy}>
              <legend className="sr-only">Selected enterprise resources</legend>
              <div className="stack-2">
                <Label htmlFor="enterprise-provider">Enterprise provider</Label>
                <select
                  id="enterprise-provider"
                  className="input"
                  value={provider}
                  onChange={(event) => {
                    if (running.current) return;
                    const next = event.target.value;
                    if (
                      next !== "google-vault" &&
                      next !== "splunk-enterprise" &&
                      next !== "elastic-ilm"
                    )
                      return;
                    invalidate();
                    setProvider(next);
                    setTargets(IS_DEMO ? enterpriseDemoTargets(next) : [""]);
                  }}
                >
                  <option value="google-vault">Google Vault</option>
                  <option value="splunk-enterprise">Splunk Enterprise</option>
                  <option value="elastic-ilm">Elasticsearch ILM</option>
                </select>
              </div>
              <p className="text-sm muted">{ENTERPRISE_HINTS[provider]}</p>
              <fieldset className="stack-4" disabled={IS_DEMO}>
                <legend className="sr-only">
                  Profile and target selection
                </legend>
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="stack-2">
                    <Label htmlFor="enterprise-profile">Profile alias</Label>
                    <Input
                      id="enterprise-profile"
                      value={profile}
                      maxLength={64}
                      autoComplete="off"
                      spellCheck={false}
                      onChange={(event) => {
                        if (!running.current) {
                          invalidate();
                          setProfile(event.target.value);
                        }
                      }}
                    />
                    <p className="text-xs muted">
                      Nonsecret alias supplied by the administrator. Profiles
                      and credentials are configured on the API server.
                    </p>
                  </div>
                  <div className="stack-2">
                    <Label htmlFor="enterprise-scope">
                      Enterprise scope label
                    </Label>
                    <Input
                      id="enterprise-scope"
                      value={scope}
                      maxLength={64}
                      autoComplete="off"
                      spellCheck={false}
                      onChange={(event) => {
                        if (!running.current) {
                          invalidate();
                          setScope(event.target.value);
                        }
                      }}
                    />
                    <p className="text-xs muted">
                      Operator-declared label. Authenticated source identity
                      remains unverified.
                    </p>
                  </div>
                </div>
                {targets.map((target, index) => (
                  <div className="stack-2 rounded border p-3" key={index}>
                    <Label htmlFor={`enterprise-target-${index}`}>
                      {provider === "google-vault" ? "Matter ID" : "Index name"}{" "}
                      {index + 1}
                    </Label>
                    <Input
                      id={`enterprise-target-${index}`}
                      value={target}
                      maxLength={
                        provider === "google-vault"
                          ? 128
                          : provider === "splunk-enterprise"
                            ? 80
                            : 255
                      }
                      autoComplete="off"
                      spellCheck={false}
                      onChange={(event) => {
                        if (!running.current) {
                          invalidate();
                          setTargets((current) =>
                            current.map((item, n) =>
                              n === index ? event.target.value : item,
                            ),
                          );
                        }
                      }}
                    />
                    <Button
                      type="button"
                      variant="outline"
                      disabled={targets.length === 1}
                      onClick={() => {
                        if (!running.current) {
                          invalidate();
                          setTargets((current) =>
                            current.filter((_item, n) => n !== index),
                          );
                        }
                      }}
                    >
                      Remove enterprise target {index + 1}
                    </Button>
                  </div>
                ))}
                <Button
                  type="button"
                  variant="outline"
                  disabled={targets.length >= 20}
                  onClick={() => {
                    if (!running.current && targets.length < 20) {
                      invalidate();
                      setTargets((current) => [...current, ""]);
                    }
                  }}
                >
                  Add enterprise target
                </Button>
                <div className="stack-2">
                  <Label htmlFor="enterprise-request-file">
                    Enterprise request JSON
                  </Label>
                  <Input
                    id="enterprise-request-file"
                    ref={fileInput}
                    type="file"
                    accept="application/json,.json"
                    onChange={(event) => {
                      void readFile(event.target.files?.[0]);
                    }}
                  />
                  <p className="text-xs muted">
                    Optional local UTF-8 JSON request, at most 64 KiB.
                    Successful import fills this form; no server path or
                    credential is submitted.
                  </p>
                </div>
              </fieldset>
              {IS_DEMO && (
                <div className="stack-2">
                  <Label htmlFor="enterprise-scenario">
                    Enterprise synthetic scenario
                  </Label>
                  <select
                    id="enterprise-scenario"
                    className="input"
                    value={scenario}
                    onChange={(event) => {
                      const next = event.target.value;
                      if (
                        next === "complete" ||
                        next === "partial" ||
                        next === "unavailable"
                      ) {
                        invalidate();
                        setScenario(next);
                      }
                    }}
                  >
                    <option value="complete">Selected reads complete</option>
                    <option value="partial">Partial collection</option>
                    <option value="unavailable">Unavailable collection</option>
                  </select>
                </div>
              )}
            </fieldset>
            <p className="text-sm muted">
              Use literal matter IDs or index names. Collection does not
              enumerate all resources. Bounded reads can return partial or
              unavailable evidence.
            </p>
            <div className="flex flex-wrap gap-3">
              <Button
                type="submit"
                disabled={
                  busy || reading || fileRejected || (!IS_DEMO && !freshAuth)
                }
              >
                {busy
                  ? "Collecting enterprise configuration"
                  : IS_DEMO
                    ? "Show synthetic enterprise result"
                    : "Collect enterprise configuration"}
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={busy}
                onClick={() => {
                  if (running.current) return;
                  invalidate();
                  setProvider("google-vault");
                  setProfile(IS_DEMO ? "selected" : "");
                  setScope(IS_DEMO ? "synthetic" : "");
                  setTargets(
                    IS_DEMO ? enterpriseDemoTargets("google-vault") : [""],
                  );
                  setScenario("partial");
                }}
              >
                Reset enterprise form
              </Button>
            </div>
          </form>
          {reading && <p role="status">Reading the bounded local request.</p>}
          {busy && (
            <p role="status">
              Collecting selected configuration and retaining each source-read
              outcome.
            </p>
          )}
          {error && (
            <Alert variant="destructive">
              <AlertTitle>Enterprise collection could not finish</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>
      {result && (
        <EnterpriseRetentionResult
          response={result}
          key={result.result.manifest.run_id}
        />
      )}
    </section>
  );
}

function EnterpriseJson({ label, raw }: { label: string; raw: string }) {
  const [open, setOpen] = useState(false);
  return (
    <details
      className="rounded border p-3"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary className="cursor-pointer font-medium">{label}</summary>
      {open && (
        <pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs">
          <code>{raw}</code>
        </pre>
      )}
    </details>
  );
}
function EnterpriseRetentionResult({
  response,
}: {
  response: EnterpriseRetentionResponse;
}) {
  const { result, rawJson, nativeFieldsJson } = response;
  const [downloadError, setDownloadError] = useState(false);
  const download = () => {
    let url: string | undefined;
    let link: HTMLAnchorElement | undefined;
    try {
      url = URL.createObjectURL(
        new Blob([rawJson], { type: "application/json" }),
      );
      link = document.createElement("a");
      link.href = url;
      link.download = "enterprise-retention-result.json";
      document.body.append(link);
      link.click();
      setDownloadError(false);
    } catch {
      setDownloadError(true);
    } finally {
      link?.remove();
      if (url) URL.revokeObjectURL(url);
    }
  };
  return (
    <section className="stack-6" aria-label="Enterprise retention result">
      <Alert variant={result.status === "complete" ? "default" : "destructive"}>
        <AlertTitle>
          {result.status === "complete"
            ? "Selected reads complete"
            : `Collection incomplete: ${result.status}`}
        </AlertTitle>
        <AlertDescription>
          Completeness describes the selected reads. Configuration
          interpretation may still be limited. Compliance, record coverage and
          effective enforcement are unassessed.
        </AlertDescription>
      </Alert>
      <p>
        Provider: {result.provider}. Profile: {result.profile_alias}. Scope:{" "}
        {result.scope_label}. Identity basis: {result.identity_basis}.
        Authenticated identity verified: no.
      </p>
      <p className="mono text-xs">
        Run: {result.manifest.run_id}. Collection: {result.started_at} to{" "}
        {result.finished_at}.
      </p>
      <p>
        Resources requested: {result.manifest.resources_requested}. Resources
        attempted: {result.manifest.resources_attempted}. Unique reads:{" "}
        {result.manifest.reads_planned}. Reads complete:{" "}
        {result.manifest.reads_completed}. Findings retained:{" "}
        {result.findings.length}.
      </p>
      <p>
        Unassessed surfaces: {result.unassessed_surfaces.join(", ")}
        {result.provider === "google-vault"
          ? ". Retention rules assessed: no."
          : "."}
      </p>
      <Button type="button" variant="outline" onClick={download}>
        Download full enterprise result JSON
      </Button>
      {downloadError && (
        <p role="alert">
          The result could not be downloaded. The collection remains available
          here.
        </p>
      )}
      {result.diagnostics.length > 0 && (
        <ul>
          {result.diagnostics.map((item, index) => (
            <li key={index}>
              {item.code}
              {item.safe_http_status === null
                ? ""
                : ` (HTTP ${item.safe_http_status})`}
            </li>
          ))}
        </ul>
      )}
      <div className="grid gap-4 md:grid-cols-2">
        {result.resources.map((resource) => (
          <Card
            key={resource.canonical_resource_id}
            aria-label={`${resource.canonical_resource_id} result`}
          >
            <CardHeader>
              <CardTitle>
                {"matter_id" in resource.target
                  ? resource.target.matter_id
                  : resource.target.index}
              </CardTitle>
              <Badge variant="outline">{resource.status}</Badge>
            </CardHeader>
            <CardContent className="stack-2 text-sm">
              <p className="break-all mono">{resource.canonical_resource_id}</p>
              <p>Policy reference: {resource.policy_resolution}.</p>
              <ul>
                {resource.read_ids.map((id) => (
                  <li className="break-all" key={id}>
                    {id}
                  </li>
                ))}
              </ul>
              {resource.diagnostics.map((item, index) => (
                <p key={index}>{item.code}</p>
              ))}
            </CardContent>
          </Card>
        ))}
      </div>
      <div className="stack-4">
        {result.source_reads.map((read, index) => (
          <Card
            key={read.read_id}
            aria-label={`${read.kind} ${read.source_id} read`}
          >
            <CardHeader>
              <CardTitle>
                {read.kind}: {read.source_id}
              </CardTitle>
              <Badge variant="outline">{read.status}</Badge>
            </CardHeader>
            <CardContent className="stack-3 text-sm">
              <p>
                Method: {read.method_id}. Attempts: {read.attempts}. Responses:{" "}
                {read.responses_received}. Pages admitted: {read.pages_admitted}
                . Records admitted: {read.records_admitted}. Duplicate records:{" "}
                {read.duplicates_coalesced}. Quarantined conflicts:{" "}
                {read.conflicts_quarantined}.
              </p>
              <p>
                Terminal reason: {read.terminal_reason ?? "none"}. HTTP status:{" "}
                {read.safe_http_status ?? "not applicable or mixed"}. Raw bytes:{" "}
                {read.raw_bytes}. Decoded bytes: {read.decoded_bytes}.
              </p>
              <p className="mono text-xs">
                Read window: {read.started_at ?? "not started"} to{" "}
                {read.finished_at ?? "not finished"}.
              </p>
              {read.diagnostics.map((item, n) => (
                <p key={n}>{item.code}</p>
              ))}
              {read.observations.length > 10 && (
                <p>
                  Showing the first 10 observations. Download the full result
                  for every retained observation.
                </p>
              )}
              {read.observations.slice(0, 10).map((observed, n) => (
                <div
                  className="stack-2 rounded border p-3"
                  key={observed.source_identity}
                >
                  <p className="break-all">
                    Source: {observed.source_identity}. Interpretation:{" "}
                    {observed.interpretation_status}.
                  </p>
                  <p className="break-all mono text-xs">
                    Projection SHA-256: {observed.canonical_projection_sha256}
                  </p>
                  {observed.diagnostics.map((item, k) => (
                    <p key={k}>{item.code}</p>
                  ))}
                  <EnterpriseJson
                    label={`Native fields for ${observed.source_identity}`}
                    raw={nativeFieldsJson[index][n]}
                  />
                  <EnterpriseJson
                    label={`Field coverage for ${observed.source_identity}`}
                    raw={JSON.stringify(observed.field_coverage, null, 2)}
                  />
                </div>
              ))}
            </CardContent>
          </Card>
        ))}
      </div>
      <EnterpriseJson
        label="Aggregate field coverage"
        raw={JSON.stringify(result.field_coverage, null, 2)}
      />
      <EnterpriseJson label="Full enterprise result JSON" raw={rawJson} />
    </section>
  );
}
