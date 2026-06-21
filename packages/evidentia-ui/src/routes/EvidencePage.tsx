import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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
import {
  api,
  ApiError,
  type EvidenceArtifact,
  type EvidenceArtifactInput,
  type EvidenceSaveSummary,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import type { components } from "@/types/openapi";

/**
 * Evidence screen (lineage-centric).
 *
 * Evidence in Evidentia is a WORM (write-once-read-many) store: a saved
 * artifact is immutable, and "editing" means appending a NEW version to
 * the same lineage chain. There is intentionally NO "list all evidence"
 * endpoint — the store is addressed by lineage id. This screen therefore
 * works in two halves:
 *
 *   1. A lineage LOOKUP — type a lineage id, load its full version chain
 *      (`GET /api/evidence/{lineage_id}/history`), and inspect any version.
 *   2. A SAVE form — persist a new artifact (`POST /api/evidence`). Leave
 *      `lineage_id` blank to start a fresh chain, or set it to append a
 *      new version to an existing one. A WORM collision (re-saving a
 *      version that already exists) comes back as a 409 carrying the
 *      canonical `next_version` recovery hint.
 *
 * Trust boundary: the save response deliberately omits any filesystem
 * path — the UI shows artifact_id / lineage_id / version only.
 */

type EvidenceType = components["schemas"]["EvidenceType"];

const EVIDENCE_TYPE_OPTIONS: [EvidenceType, string][] = [
  ["configuration", "Configuration"],
  ["log", "Log"],
  ["screenshot", "Screenshot"],
  ["policy_document", "Policy document"],
  ["audit_report", "Audit report"],
  ["api_response", "API response"],
  ["test_result", "Test result"],
  ["attestation", "Attestation"],
  ["repository_metadata", "Repository metadata"],
  ["identity_data", "Identity data"],
];

const EVIDENCE_TYPE_LABELS: Record<EvidenceType, string> =
  Object.fromEntries(EVIDENCE_TYPE_OPTIONS) as Record<EvidenceType, string>;

/**
 * Pull a numeric `next_version` recovery hint out of an `ApiError` payload.
 *
 * FastAPI nests an `HTTPException(detail=...)` body under a top-level
 * `detail` key, so the 409 WORM-collision payload is
 * `{ detail: { detail, next_version } }`. Be defensive: accept either the
 * nested shape or a flat `{ next_version }` and return the integer if
 * present.
 */
function extractNextVersion(payload: unknown): number | null {
  if (!payload || typeof payload !== "object") return null;
  const top = payload as Record<string, unknown>;
  const candidates: unknown[] = [top.next_version];
  if (top.detail && typeof top.detail === "object") {
    candidates.push((top.detail as Record<string, unknown>).next_version);
  }
  for (const c of candidates) {
    if (typeof c === "number" && Number.isFinite(c)) return c;
  }
  return null;
}

export function EvidencePage() {
  // The id bound to the input vs. the id we've actually submitted a lookup
  // for — the query is gated on the submitted id so typing doesn't fire it.
  const [lineageInput, setLineageInput] = useState("");
  const [submittedLineage, setSubmittedLineage] = useState<string | null>(null);
  const [selectedVersion, setSelectedVersion] = useState<number | null>(null);

  const history = useQuery({
    queryKey: ["evidence-history", submittedLineage],
    queryFn: () => api.evidenceHistory(submittedLineage as string),
    enabled: submittedLineage !== null,
  });

  const items = history.data?.items ?? [];
  const selected =
    items.find((it) => it.version === selectedVersion) ?? null;

  const submitLookup = () => {
    const trimmed = lineageInput.trim();
    if (trimmed.length === 0) return;
    setSelectedVersion(null);
    setSubmittedLineage(trimmed);
  };

  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">Evidence</h1>
        <p className="page-sub">
          Append-only (WORM) evidence store. Artifacts are immutable; an
          edit appends a new version to a lineage chain. Look up a lineage
          to walk its history, or save a new artifact below.
        </p>
      </header>

      <SaveEvidenceForm
        loadedLineage={submittedLineage}
        onSaved={(summary) => {
          // If the save landed in the lineage we're currently viewing,
          // the history query is invalidated inside the form; surface the
          // new version by selecting it here.
          if (
            submittedLineage !== null &&
            summary.lineage_id === submittedLineage
          ) {
            setSelectedVersion(summary.version);
          }
        }}
      />

      <section className="stack-3" aria-label="Lineage lookup">
        <h2 className="section-num">Lineage history</h2>

        <form
          className="row wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            submitLookup();
          }}
        >
          <div className="stack-2" style={{ flex: "1 1 22rem" }}>
            <Label htmlFor="evidence-lineage">Lineage id</Label>
            <Input
              id="evidence-lineage"
              value={lineageInput}
              onChange={(e) => setLineageInput(e.target.value)}
              placeholder="e.g. 8f14e45f-ceea-467d-9f8b-2a1c0b7c4d3e"
              className="mono"
              autoComplete="off"
            />
          </div>
          <div
            className="row gap-2"
            style={{ alignItems: "flex-end", paddingBottom: "0.125rem" }}
          >
            <Button type="submit" disabled={lineageInput.trim().length === 0}>
              {history.isFetching ? "Loading..." : "Load history"}
            </Button>
          </div>
        </form>

        {submittedLineage === null && (
          <div className="empty-state">
            Enter a lineage id above to load its version chain. Evidence is
            addressed by lineage — there is no global list. Find ids with{" "}
            <code className="kbd">evidentia evidence list</code>.
          </div>
        )}

        {history.isError && (
          <Card className="border-dest">
            <CardContent className="card-body" style={{ padding: "1.5rem" }}>
              <span className="text-sm text-destructive">
                {history.error instanceof ApiError &&
                history.error.status === 404
                  ? `No evidence lineage found for that id.`
                  : "Could not fetch evidence history. Is the backend running?"}
              </span>
            </CardContent>
          </Card>
        )}

        {history.isLoading && submittedLineage !== null && (
          <ul
            className="reset grid"
            style={{
              gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
            }}
          >
            {Array.from({ length: 3 }).map((_, i) => (
              <li key={i} className="reset">
                <div className="skel" style={{ height: "8rem" }} />
              </li>
            ))}
          </ul>
        )}

        {history.isSuccess && items.length === 0 && (
          <div className="empty-state">
            That lineage has no versions yet.
          </div>
        )}

        {history.isSuccess && items.length > 0 && (
          <>
            <p className="text-xs muted">
              {items.length} version{items.length === 1 ? "" : "s"} in this
              lineage. Select one to inspect it.
            </p>
            <ul
              className="reset grid"
              style={{
                gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
              }}
            >
              {items.map((artifact, idx) => {
                const isSelected = artifact.version === selectedVersion;
                return (
                  <li
                    key={artifact.id ?? `${artifact.version}-${idx}`}
                    className="reset"
                  >
                    <button
                      type="button"
                      className="reset"
                      style={{
                        display: "block",
                        width: "100%",
                        textAlign: "left",
                        cursor: "pointer",
                      }}
                      aria-pressed={isSelected}
                      onClick={() =>
                        setSelectedVersion(
                          isSelected ? null : artifact.version,
                        )
                      }
                    >
                      <Card
                        className={cn(
                          "card-hover",
                          isSelected && "border-dest",
                        )}
                        style={{ height: "100%" }}
                      >
                        <CardHeader className="stack-2">
                          <div className="row gap-2 wrap">
                            <Badge variant="outline">v{artifact.version}</Badge>
                            <Badge variant="secondary">
                              {EVIDENCE_TYPE_LABELS[artifact.evidence_type] ??
                                artifact.evidence_type}
                            </Badge>
                          </div>
                          <CardTitle className="base">
                            {artifact.title}
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="pt-0 text-xs muted stack-2">
                          <div>
                            By{" "}
                            <code className="kbd">{artifact.collected_by}</code>
                          </div>
                          {artifact.collected_at && (
                            <div>
                              Collected{" "}
                              <span className="mono tnum">
                                {artifact.collected_at}
                              </span>
                            </div>
                          )}
                        </CardContent>
                      </Card>
                    </button>
                  </li>
                );
              })}
            </ul>
          </>
        )}

        {selected && (
          <EvidenceDetail
            artifact={selected}
            onClose={() => setSelectedVersion(null)}
          />
        )}
      </section>
    </div>
  );
}

/** In-page detail panel for a single evidence version. */
function EvidenceDetail({
  artifact,
  onClose,
}: {
  artifact: EvidenceArtifact;
  onClose: () => void;
}) {
  const tags = artifact.tags ?? [];
  return (
    <section className="stack-4" aria-labelledby="evidence-detail-heading">
      <Card>
        <CardHeader className="stack-2">
          <div
            className="row-between gap-4 wrap"
            style={{ alignItems: "flex-start" }}
          >
            <div className="stack-2">
              <CardTitle id="evidence-detail-heading" className="base">
                {artifact.title}
              </CardTitle>
              <CardDescription>
                <Badge variant="outline">v{artifact.version}</Badge>{" "}
                <Badge variant="secondary">
                  {EVIDENCE_TYPE_LABELS[artifact.evidence_type] ??
                    artifact.evidence_type}
                </Badge>
              </CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={onClose}>
              Close
            </Button>
          </div>
        </CardHeader>
        <CardContent className="stack-4 pt-0">
          {artifact.description && (
            <p className="text-sm muted">{artifact.description}</p>
          )}

          <dl className="stack-3 text-sm">
            <div className="stack-2">
              <dt className="text-xs faint">Source system</dt>
              <dd>
                <code className="kbd">{artifact.source_system}</code>
              </dd>
            </div>
            <div className="stack-2">
              <dt className="text-xs faint">Collected by</dt>
              <dd>
                <code className="kbd">{artifact.collected_by}</code>
              </dd>
            </div>
            {artifact.content_hash && (
              <div className="stack-2">
                <dt className="text-xs faint">Content hash (SHA-256)</dt>
                <dd>
                  <span className="mono text-xs">{artifact.content_hash}</span>
                </dd>
              </div>
            )}
            {artifact.lineage_id && (
              <div className="stack-2">
                <dt className="text-xs faint">Lineage id</dt>
                <dd>
                  <span className="mono text-xs">{artifact.lineage_id}</span>
                </dd>
              </div>
            )}
          </dl>

          {tags.length > 0 && (
            <div className="row gap-2 wrap" aria-label="Tags">
              {tags.map((tag) => (
                <Badge key={tag} variant="outline">
                  {tag}
                </Badge>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

const EMPTY_FORM = {
  title: "",
  evidence_type: "configuration" as EvidenceType,
  source_system: "",
  collected_by: "",
  description: "",
  tags: "",
  lineage_id: "",
};

/**
 * Save-evidence form. Sends the four required `EvidenceArtifactInput`
 * fields (title / evidence_type / source_system / collected_by) plus the
 * optional description, comma-split tags, and an optional lineage id (to
 * append a new version to an existing chain). `content_format` and
 * `sufficiency` carry their server-aligned defaults.
 */
function SaveEvidenceForm({
  loadedLineage,
  onSaved,
}: {
  loadedLineage: string | null;
  onSaved: (summary: EvidenceSaveSummary) => void;
}) {
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ ...EMPTY_FORM });
  const [summary, setSummary] = useState<EvidenceSaveSummary | null>(null);

  const mutation = useMutation({
    mutationFn: (body: EvidenceArtifactInput) => api.saveEvidence(body),
    onSuccess: (result) => {
      setSummary(result);
      setForm({ ...EMPTY_FORM });
      // Refresh the history view if the save landed in the loaded lineage.
      if (loadedLineage !== null && result.lineage_id === loadedLineage) {
        queryClient.invalidateQueries({
          queryKey: ["evidence-history", loadedLineage],
        });
      }
      onSaved(result);
    },
  });

  const canSubmit =
    form.title.trim().length > 0 &&
    form.source_system.trim().length > 0 &&
    form.collected_by.trim().length > 0 &&
    !mutation.isPending;

  const submit = () => {
    if (!canSubmit) return;
    setSummary(null);
    const tags = form.tags
      .split(",")
      .map((t) => t.trim())
      .filter((t) => t.length > 0);
    const lineageId = form.lineage_id.trim();
    mutation.mutate({
      title: form.title.trim(),
      evidence_type: form.evidence_type,
      source_system: form.source_system.trim(),
      collected_by: form.collected_by.trim(),
      content_format: "json",
      sufficiency: "unknown",
      version: 1,
      ...(form.description.trim().length > 0
        ? { description: form.description.trim() }
        : {}),
      ...(tags.length > 0 ? { tags } : {}),
      ...(lineageId.length > 0 ? { lineage_id: lineageId } : {}),
    });
  };

  const nextVersion =
    mutation.error instanceof ApiError && mutation.error.status === 409
      ? extractNextVersion(mutation.error.payload)
      : null;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="base">Save evidence</CardTitle>
        <CardDescription>
          Persist a new artifact to the WORM store. Leave the lineage id
          blank to start a new chain, or set it to append a new version to
          an existing one.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="stack-5"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <div className="grid grid-2">
            <div className="stack-2">
              <Label htmlFor="evidence-title">Title</Label>
              <Input
                id="evidence-title"
                value={form.title}
                onChange={(e) => setForm({ ...form, title: e.target.value })}
                placeholder="MFA enforced on admin console"
                required
              />
            </div>
            <div className="stack-2">
              <Label htmlFor="evidence-source">Source system</Label>
              <Input
                id="evidence-source"
                value={form.source_system}
                onChange={(e) =>
                  setForm({ ...form, source_system: e.target.value })
                }
                placeholder="aws-iam"
                required
              />
            </div>
          </div>

          <div className="grid grid-2">
            <div className="stack-2">
              <Label htmlFor="evidence-collected-by">Collected by</Label>
              <Input
                id="evidence-collected-by"
                value={form.collected_by}
                onChange={(e) =>
                  setForm({ ...form, collected_by: e.target.value })
                }
                placeholder="alice@example.com"
                required
              />
            </div>
            <div className="stack-2">
              <Label htmlFor="evidence-lineage-id">
                Lineage id <span className="faint">(optional)</span>
              </Label>
              <Input
                id="evidence-lineage-id"
                value={form.lineage_id}
                onChange={(e) =>
                  setForm({ ...form, lineage_id: e.target.value })
                }
                placeholder="append to an existing chain"
                className="mono"
                autoComplete="off"
              />
            </div>
          </div>

          <div className="stack-2">
            <span className="text-sm font-medium leading-none">
              Evidence type
            </span>
            <div
              className="row wrap gap-2"
              role="radiogroup"
              aria-label="Evidence type"
            >
              {EVIDENCE_TYPE_OPTIONS.map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  role="radio"
                  aria-checked={form.evidence_type === value}
                  onClick={() => setForm({ ...form, evidence_type: value })}
                  className={cn("pill", form.evidence_type === value && "on")}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="stack-2">
            <Label htmlFor="evidence-description">
              Description <span className="faint">(optional)</span>
            </Label>
            <Input
              id="evidence-description"
              value={form.description}
              onChange={(e) =>
                setForm({ ...form, description: e.target.value })
              }
              placeholder="What this evidence shows and how it was gathered"
            />
          </div>

          <div className="stack-2">
            <Label htmlFor="evidence-tags">
              Tags <span className="faint">(optional, comma-separated)</span>
            </Label>
            <Input
              id="evidence-tags"
              value={form.tags}
              onChange={(e) => setForm({ ...form, tags: e.target.value })}
              placeholder="soc2, access-control"
            />
          </div>

          <div className="row-between border-t pt-4">
            <p className="text-xs muted">
              Four required fields. The artifact is immutable once saved.
            </p>
            <Button type="submit" disabled={!canSubmit}>
              {mutation.isPending ? "Saving..." : "Save evidence"}
            </Button>
          </div>
        </form>

        {summary && (
          <Alert className="mt-4">
            <AlertTitle>Evidence saved</AlertTitle>
            <AlertDescription>
              <div className="stack-2 text-xs">
                <div>
                  Artifact id:{" "}
                  <code className="kbd">{summary.artifact_id}</code>
                </div>
                <div>
                  Lineage id:{" "}
                  <code className="kbd">{summary.lineage_id}</code>
                </div>
                <div>
                  Version: <code className="kbd">v{summary.version}</code>
                </div>
              </div>
            </AlertDescription>
          </Alert>
        )}

        {mutation.isError && (
          <Alert variant="destructive" className="mt-4">
            <AlertTitle>
              {nextVersion !== null
                ? "Version already exists"
                : "Could not save evidence"}
            </AlertTitle>
            <AlertDescription>
              {nextVersion !== null
                ? `That version already exists in this lineage (WORM store is append-only). Next available version is v${nextVersion}.`
                : mutation.error instanceof ApiError && mutation.error.payload
                  ? JSON.stringify(mutation.error.payload)
                  : String(mutation.error)}
            </AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
}
