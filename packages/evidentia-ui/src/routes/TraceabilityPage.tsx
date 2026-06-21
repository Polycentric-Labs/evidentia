import { useMutation } from "@tanstack/react-query";
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
import { api, ApiError, type TraceabilityMatrix } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { components } from "@/types/openapi";

/**
 * Control↔Threat Traceability console (`/traceability`).
 *
 * READ-MOSTLY counterpart to the CLI `evidentia traceability emit`. Builds a
 * Control↔Threat {@link TraceabilityMatrix} inline (title + framework +
 * catalog href + crosswalk source + a repeatable mappings editor) and posts
 * it to `POST /api/traceability/emit`, rendering the returned **UNSIGNED**
 * OSCAL profile as pretty-printed JSON plus a small control/threat summary.
 *
 * This console NEVER signs. GPG / Sigstore signing of the emitted profile
 * (`traceability emit --sign-with-gpg / --sign-with-sigstore`) is an air-gap
 * CLI operation by design and is deliberately NOT exposed over HTTP; the GUI
 * only ever emits the unsigned matrix.
 *
 * The emitted profile is typed loosely (`Record<string, unknown>`) in the
 * client because the server returns the bare OSCAL profile dict with no
 * dedicated response schema, so it is rendered as plain preformatted JSON —
 * React auto-escaping only, never raw HTML.
 */

// ── Enum option tables (mirror the OpenAPI ControlThreatMapping enums) ────

type Relationship = components["schemas"]["ControlThreatMapping"]["relationship"];
type ThreatFramework =
  components["schemas"]["ControlThreatMapping"]["threat_framework"];
type Coverage = components["schemas"]["ControlThreatMapping"]["coverage"];

const RELATIONSHIP_PICKER_OPTIONS: [Relationship, string][] = [
  ["mitigates", "Mitigates"],
  ["partially-mitigates", "Partially mitigates"],
  ["compensating", "Compensating"],
  ["detects", "Detects"],
];

const THREAT_FRAMEWORK_PICKER_OPTIONS: [ThreatFramework, string][] = [
  ["mitre-attack", "MITRE ATT&CK"],
  ["cwe", "CWE"],
  ["capec", "CAPEC"],
];

const COVERAGE_PICKER_OPTIONS: [Coverage, string][] = [
  ["full", "Full"],
  ["partial", "Partial"],
  ["compensating", "Compensating"],
];

/** A single mapping row in the editor (mirrors ControlThreatMapping). */
type MappingDraft = {
  control_id: string;
  threat_id: string;
  threat_name: string;
  threat_framework: ThreatFramework;
  relationship: Relationship;
  coverage: Coverage;
  notes: string;
};

const EMPTY_MAPPING: MappingDraft = {
  control_id: "",
  threat_id: "",
  threat_name: "",
  threat_framework: "mitre-attack",
  relationship: "mitigates",
  coverage: "full",
  notes: "",
};

const EMPTY_MATRIX = {
  title: "",
  framework_id: "",
  catalog_href: "",
  crosswalk_source: "self-attested",
};

/** Surface an ApiError payload (or any error) as readable text. */
function apiErrorText(error: unknown): string {
  if (error instanceof ApiError) {
    // 400 (no mappings — nothing to emit) returns `{detail: "..."}`; 422
    // (shape-invalid body) returns a structured validation payload.
    const payload = error.payload;
    if (payload && typeof payload === "object" && "detail" in payload) {
      const detail = (payload as { detail: unknown }).detail;
      if (typeof detail === "string") return detail;
    }
    if (payload != null) return JSON.stringify(payload);
    return error.message;
  }
  return String(error);
}

export function TraceabilityPage() {
  const [matrix, setMatrix] = useState({ ...EMPTY_MATRIX });
  const [mappings, setMappings] = useState<MappingDraft[]>([
    { ...EMPTY_MAPPING },
  ]);

  const mutation = useMutation({
    mutationFn: (body: TraceabilityMatrix) => api.traceabilityEmit(body),
  });

  // A row is complete only when its three required fields are filled.
  const validMappings = mappings.filter(
    (m) =>
      m.control_id.trim().length > 0 &&
      m.threat_id.trim().length > 0,
  );

  const canSubmit =
    matrix.title.trim().length > 0 &&
    matrix.framework_id.trim().length > 0 &&
    matrix.catalog_href.trim().length > 0 &&
    validMappings.length > 0 &&
    !mutation.isPending;

  const updateMapping = (idx: number, patch: Partial<MappingDraft>) =>
    setMappings((prev) =>
      prev.map((m, i) => (i === idx ? { ...m, ...patch } : m)),
    );

  const submit = () => {
    if (!canSubmit) return;
    const body: TraceabilityMatrix = {
      title: matrix.title.trim(),
      framework_id: matrix.framework_id.trim(),
      catalog_href: matrix.catalog_href.trim(),
      crosswalk_source: matrix.crosswalk_source.trim()
        ? matrix.crosswalk_source.trim()
        : "self-attested",
      mappings: validMappings.map((m) => ({
        control_id: m.control_id.trim(),
        threat_id: m.threat_id.trim(),
        threat_framework: m.threat_framework,
        relationship: m.relationship,
        coverage: m.coverage,
        ...(m.threat_name.trim() ? { threat_name: m.threat_name.trim() } : {}),
        ...(m.notes.trim() ? { notes: m.notes.trim() } : {}),
      })),
    };
    mutation.mutate(body);
  };

  const profile = mutation.data ?? null;

  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">Traceability</h1>
        <p className="page-sub">
          Build a Control↔Threat traceability matrix and emit it as an OSCAL
          profile. Read-mostly — the matrix is computed inline and nothing is
          persisted.
        </p>
      </header>

      <Alert>
        <AlertTitle>This console emits an UNSIGNED profile.</AlertTitle>
        <AlertDescription>
          The emitted OSCAL profile is never signed here. Signing is an air-gap
          CLI operation (
          <code className="kbd">
            evidentia traceability emit --sign-with-gpg
          </code>{" "}
          / <code className="kbd">--sign-with-sigstore</code>). This page only
          ever renders the unsigned matrix you build below.
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">Matrix</CardTitle>
          <CardDescription>
            Title, framework, and the catalog href are required. The crosswalk
            source records the provenance of the mappings (e.g.{" "}
            <code className="kbd">self-attested</code>).
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
                <Label htmlFor="matrix-title">Title</Label>
                <Input
                  id="matrix-title"
                  value={matrix.title}
                  onChange={(e) =>
                    setMatrix({ ...matrix, title: e.target.value })
                  }
                  placeholder="NIST 800-53 moderate — control↔threat coverage"
                  required
                />
              </div>
              <div className="stack-2">
                <Label htmlFor="matrix-framework">Framework id</Label>
                <Input
                  id="matrix-framework"
                  value={matrix.framework_id}
                  onChange={(e) =>
                    setMatrix({ ...matrix, framework_id: e.target.value })
                  }
                  placeholder="nist-800-53-rev5-moderate"
                  required
                />
              </div>
            </div>

            <div className="grid grid-2">
              <div className="stack-2">
                <Label htmlFor="matrix-catalog-href">Catalog href</Label>
                <Input
                  id="matrix-catalog-href"
                  value={matrix.catalog_href}
                  onChange={(e) =>
                    setMatrix({ ...matrix, catalog_href: e.target.value })
                  }
                  placeholder="catalogs/nist-800-53-rev5-moderate.json"
                  required
                />
              </div>
              <div className="stack-2">
                <Label htmlFor="matrix-crosswalk">Crosswalk source</Label>
                <Input
                  id="matrix-crosswalk"
                  value={matrix.crosswalk_source}
                  onChange={(e) =>
                    setMatrix({ ...matrix, crosswalk_source: e.target.value })
                  }
                  placeholder="self-attested"
                />
              </div>
            </div>

            <div className="stack-3">
              <span className="text-sm font-medium leading-none">Mappings</span>
              <p className="text-xs muted">
                Each row maps a control to a threat. Control id and threat id
                are required; threat name and notes are optional.
              </p>
              <ul className="reset stack-3" aria-label="Mappings editor">
                {mappings.map((mapping, idx) => (
                  <li key={idx} className="reset">
                    <div
                      className="stack-3 box"
                      aria-label={`Mapping ${idx + 1}`}
                    >
                      <div className="row gap-2 wrap">
                        <Input
                          aria-label={`Mapping ${idx + 1} control id`}
                          value={mapping.control_id}
                          onChange={(e) =>
                            updateMapping(idx, { control_id: e.target.value })
                          }
                          placeholder="Control id (e.g. AC-2)"
                          style={{ flex: "1 1 10rem" }}
                        />
                        <Input
                          aria-label={`Mapping ${idx + 1} threat id`}
                          value={mapping.threat_id}
                          onChange={(e) =>
                            updateMapping(idx, { threat_id: e.target.value })
                          }
                          placeholder="Threat id (e.g. T1078)"
                          style={{ flex: "1 1 10rem" }}
                        />
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          disabled={mappings.length === 1}
                          onClick={() =>
                            setMappings((prev) =>
                              prev.filter((_, i) => i !== idx),
                            )
                          }
                        >
                          Remove
                        </Button>
                      </div>

                      <div className="row gap-2 wrap">
                        <Input
                          aria-label={`Mapping ${idx + 1} threat name`}
                          value={mapping.threat_name}
                          onChange={(e) =>
                            updateMapping(idx, { threat_name: e.target.value })
                          }
                          placeholder="Threat name (optional)"
                          style={{ flex: "1 1 14rem" }}
                        />
                        <Input
                          aria-label={`Mapping ${idx + 1} notes`}
                          value={mapping.notes}
                          onChange={(e) =>
                            updateMapping(idx, { notes: e.target.value })
                          }
                          placeholder="Notes / rationale (optional)"
                          style={{ flex: "1 1 14rem" }}
                        />
                      </div>

                      <div
                        className="row wrap gap-2"
                        role="radiogroup"
                        aria-label={`Mapping ${idx + 1} threat framework`}
                      >
                        {THREAT_FRAMEWORK_PICKER_OPTIONS.map(
                          ([value, label]) => (
                            <button
                              key={value}
                              type="button"
                              role="radio"
                              aria-checked={mapping.threat_framework === value}
                              onClick={() =>
                                updateMapping(idx, { threat_framework: value })
                              }
                              className={cn(
                                "pill",
                                mapping.threat_framework === value && "on",
                              )}
                            >
                              {label}
                            </button>
                          ),
                        )}
                      </div>

                      <div
                        className="row wrap gap-2"
                        role="radiogroup"
                        aria-label={`Mapping ${idx + 1} relationship`}
                      >
                        {RELATIONSHIP_PICKER_OPTIONS.map(([value, label]) => (
                          <button
                            key={value}
                            type="button"
                            role="radio"
                            aria-checked={mapping.relationship === value}
                            onClick={() =>
                              updateMapping(idx, { relationship: value })
                            }
                            className={cn(
                              "pill",
                              mapping.relationship === value && "on",
                            )}
                          >
                            {label}
                          </button>
                        ))}
                      </div>

                      <div
                        className="row wrap gap-2"
                        role="radiogroup"
                        aria-label={`Mapping ${idx + 1} coverage`}
                      >
                        {COVERAGE_PICKER_OPTIONS.map(([value, label]) => (
                          <button
                            key={value}
                            type="button"
                            role="radio"
                            aria-checked={mapping.coverage === value}
                            onClick={() =>
                              updateMapping(idx, { coverage: value })
                            }
                            className={cn(
                              "pill",
                              mapping.coverage === value && "on",
                            )}
                          >
                            {label}
                          </button>
                        ))}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
              <div className="row-end">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    setMappings((prev) => [...prev, { ...EMPTY_MAPPING }])
                  }
                >
                  Add mapping
                </Button>
              </div>
            </div>

            <div className="row-between border-t pt-4">
              <p className="text-xs muted">
                At least one mapping with a control id and threat id is
                required. The emitted profile is UNSIGNED.
              </p>
              <Button type="submit" disabled={!canSubmit}>
                {mutation.isPending ? "Emitting..." : "Emit"}
              </Button>
            </div>
          </form>

          {mutation.isError && (
            <Alert variant="destructive" className="mt-4">
              <AlertTitle>Could not emit the traceability matrix</AlertTitle>
              <AlertDescription>
                {apiErrorText(mutation.error)}
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {mutation.isPending && (
        <Card aria-label="Emitting">
          <CardContent className="card-body" style={{ padding: "1.5rem" }}>
            <div className="skel" style={{ height: "6rem" }} />
            <p className="mt-3 text-xs muted">Emitting the OSCAL profile…</p>
          </CardContent>
        </Card>
      )}

      {profile && <ProfilePanel profile={profile} />}
    </div>
  );
}

/**
 * Render the returned UNSIGNED OSCAL profile: a small derived summary (control
 * / threat counts when extractable from the imported groups) plus the bare
 * profile JSON pretty-printed in a `<pre>` (plain text, never raw HTML).
 */
function ProfilePanel({ profile }: { profile: Record<string, unknown> }) {
  const summary = deriveSummary(profile);
  return (
    <section className="stack-4" aria-label="Emitted OSCAL profile">
      <Card>
        <CardHeader className="row-between">
          <CardTitle className="base">Emitted OSCAL profile</CardTitle>
          <Badge variant="outline">Unsigned</Badge>
        </CardHeader>
        <CardContent className="stack-4">
          <p className="text-xs muted">
            {summary.controlCount != null
              ? `${summary.controlCount} control${summary.controlCount === 1 ? "" : "s"}`
              : "Controls n/a"}
            {summary.threatCount != null
              ? ` · ${summary.threatCount} threat link${summary.threatCount === 1 ? "" : "s"}`
              : ""}
            {" · sign via the CLI to attach a signature."}
          </p>
          <pre
            className="mono text-xs box"
            style={{ whiteSpace: "pre-wrap", overflowX: "auto" }}
          >
            {JSON.stringify(profile, null, 2)}
          </pre>
        </CardContent>
      </Card>
    </section>
  );
}

/**
 * Best-effort control/threat counts from the emitted OSCAL profile. The
 * exporter encodes each control as an `import.include-controls[].with-ids`
 * entry and threat links in the props/links — but the server response has no
 * dedicated schema, so this reads defensively and returns `null` when a count
 * cannot be derived (the JSON is always rendered regardless).
 */
function deriveSummary(profile: Record<string, unknown>): {
  controlCount: number | null;
  threatCount: number | null;
} {
  const controlIds = new Set<string>();
  const threatRefs = new Set<string>();

  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const item of node) walk(item);
      return;
    }
    if (node && typeof node === "object") {
      const obj = node as Record<string, unknown>;
      const withIds = obj["with-ids"];
      if (Array.isArray(withIds)) {
        for (const id of withIds) {
          if (typeof id === "string") controlIds.add(id);
        }
      }
      const name = obj["name"];
      const value = obj["value"];
      if (
        (name === "threat-id" || name === "threat_id") &&
        typeof value === "string"
      ) {
        threatRefs.add(value);
      }
      for (const v of Object.values(obj)) walk(v);
    }
  };
  walk(profile);

  return {
    controlCount: controlIds.size > 0 ? controlIds.size : null,
    threatCount: threatRefs.size > 0 ? threatRefs.size : null,
  };
}
