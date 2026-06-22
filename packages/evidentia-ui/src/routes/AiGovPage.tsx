import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  api,
  ApiError,
  type AISystemClassification,
  type AISystemDescriptor,
  type AISystemEntry,
  type AISystemRegisterRequest,
  type FIPS199CategorizeRequest,
  type OMBImpactRequest,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import type { components } from "@/types/openapi";

/**
 * AI-governance console (/ai-gov) — the registry over the
 * `evidentia ai-gov` family:
 *
 *   - Classify  — one-shot rule-based EU AI Act / NIST AI RMF verdict
 *     for a system descriptor (no persistence).
 *   - Register  — classify + persist a system into the local registry.
 *   - Registry  — list the persisted systems with an optional EU AI Act
 *     tier filter; click a card for the detail panel (edit / retire /
 *     FIPS-199 categorize / OMB impact / delete).
 *
 * Mirrors the GovernancePage + TprmPage list+detail+mutation rhythm:
 * a create form, a filtered card grid, and an in-page detail panel
 * whose mutations invalidate the registry query on success. The
 * registry endpoints serialize entries as a free-form object
 * (`AISystemEntry`), so the page reads them through `normalizeEntry`,
 * which tolerates both the real backend's NESTED shape
 * (`descriptor.name`, `classification.eu_ai_act_tier`, `system_id`)
 * and the flattened demo shim shape (`name`, `eu_ai_act_tier`, `id`).
 */

// ── Enum option tables (mirror the OpenAPI ai-governance schemas) ─────

type DeploymentStatus = components["schemas"]["DeploymentStatus"];
type EUAIActTier = components["schemas"]["EUAIActTier"];
type FIPS199Impact = components["schemas"]["FIPS199Impact"];
type OMBImpactCategory = components["schemas"]["OMBImpactCategory"];

const TIER_FILTER_OPTIONS: [EUAIActTier | null, string][] = [
  [null, "All tiers"],
  ["unacceptable", "Unacceptable"],
  ["high", "High"],
  ["limited", "Limited"],
  ["minimal", "Minimal"],
];

const DEPLOYMENT_PICKER_OPTIONS: [DeploymentStatus, string][] = [
  ["proposed", "Proposed"],
  ["in_development", "In development"],
  ["pilot", "Pilot"],
  ["production", "Production"],
  ["retired", "Retired"],
];

const FIPS_PICKER_OPTIONS: [FIPS199Impact, string][] = [
  ["low", "Low"],
  ["moderate", "Moderate"],
  ["high", "High"],
];

const OMB_PICKER_OPTIONS: [OMBImpactCategory, string][] = [
  ["rights_impacting", "Rights-impacting"],
  ["safety_impacting", "Safety-impacting"],
  ["rights_and_safety_impacting", "Rights & safety"],
  ["neither", "Neither"],
];

const DEPLOYMENT_LABELS: Record<DeploymentStatus, string> = {
  proposed: "Proposed",
  in_development: "In development",
  pilot: "Pilot",
  production: "Production",
  retired: "Retired",
};

/** Map an EU AI Act tier to the matching severity Badge variant. */
const TIER_BADGE_VARIANT: Record<
  EUAIActTier,
  "critical" | "high" | "medium" | "low"
> = {
  unacceptable: "critical",
  high: "high",
  limited: "medium",
  minimal: "low",
};

// ── Free-form entry normalization ────────────────────────────────────
//
// The registry endpoints serialize each entry as `Record<string,
// unknown>`. The real backend nests (`descriptor.name`,
// `classification.eu_ai_act_tier`, `system_id`); the demo shim flattens
// (`name`, `eu_ai_act_tier`, `id`). `normalizeEntry` reads nested-first
// with a flat fallback so the UI renders against either.

interface NormalizedSystem {
  id: string | null;
  name: string;
  purpose: string | null;
  owner: string | null;
  provider: string | null;
  deploymentStatus: string | null;
  tier: EUAIActTier | null;
  sspReference: string | null;
  fips: {
    confidentiality: string | null;
    integrity: string | null;
    availability: string | null;
    overall: string | null;
  } | null;
  ombImpact: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === "object"
    ? (value as Record<string, unknown>)
    : null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function normalizeEntry(entry: AISystemEntry): NormalizedSystem {
  const descriptor = asRecord(entry.descriptor);
  const classification = asRecord(entry.classification);

  const id = asString(entry.system_id) ?? asString(entry.id);
  const name =
    asString(descriptor?.name) ?? asString(entry.name) ?? "(unnamed system)";
  const purpose = asString(descriptor?.purpose) ?? asString(entry.purpose);

  const tierRaw =
    asString(classification?.eu_ai_act_tier) ?? asString(entry.eu_ai_act_tier);
  const tier =
    tierRaw === "unacceptable" ||
    tierRaw === "high" ||
    tierRaw === "limited" ||
    tierRaw === "minimal"
      ? (tierRaw as EUAIActTier)
      : null;

  const fipsRecord =
    asRecord(entry.fips_199_categorization) ?? asRecord(entry.fips199);
  const fips = fipsRecord
    ? {
        confidentiality:
          asString(fipsRecord.confidentiality_impact) ??
          asString(fipsRecord.confidentiality),
        integrity:
          asString(fipsRecord.integrity_impact) ??
          asString(fipsRecord.integrity),
        availability:
          asString(fipsRecord.availability_impact) ??
          asString(fipsRecord.availability),
        overall: asString(fipsRecord.overall),
      }
    : null;

  const ombRecord = asRecord(entry.omb_impact);
  const ombImpact =
    asString(entry.omb_impact) ?? asString(ombRecord?.category);

  return {
    id,
    name,
    purpose,
    owner: asString(entry.owner),
    provider: asString(entry.provider),
    deploymentStatus: asString(entry.deployment_status),
    tier,
    sspReference: asString(entry.ssp_reference),
    fips,
    ombImpact,
  };
}

/** Surface an ApiError payload (or any error) as readable text. */
function apiErrorText(error: unknown): string {
  if (error instanceof ApiError && error.payload != null) {
    return JSON.stringify(error.payload);
  }
  return String(error);
}

export function AiGovPage() {
  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">AI governance</h1>
        <p className="page-sub">
          EU AI Act / NIST AI RMF classification plus a FIPS 199 + OMB
          M-24-10 AI-system registry.
        </p>
      </header>

      <ClassifySection />

      <RegisterForm />

      <RegistrySection />
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════
// Classify (one-shot, no persistence)
// ════════════════════════════════════════════════════════════════════════

const EMPTY_DESCRIPTOR = {
  name: "",
  purpose: "",
  affects_natural_persons: false,
  interacts_with_natural_persons: false,
  generates_synthetic_content: false,
  is_prohibited_practice: false,
};

/** Build the descriptor body from the form, sending only the fields the
 *  form exposes; the server defaults the rest (annex_iii_domain etc.). */
function descriptorBody(
  form: typeof EMPTY_DESCRIPTOR,
): AISystemDescriptor {
  return {
    name: form.name.trim(),
    purpose: form.purpose.trim(),
    affects_natural_persons: form.affects_natural_persons,
    interacts_with_natural_persons: form.interacts_with_natural_persons,
    generates_synthetic_content: form.generates_synthetic_content,
    is_prohibited_practice: form.is_prohibited_practice,
  } as AISystemDescriptor;
}

function ClassifySection() {
  const [form, setForm] = useState({ ...EMPTY_DESCRIPTOR });
  const [result, setResult] = useState<AISystemClassification | null>(null);

  const mutation = useMutation({
    mutationFn: (body: AISystemDescriptor) => api.classifyAiSystem(body),
    onSuccess: (data) => setResult(data),
  });

  const canSubmit =
    form.name.trim().length > 0 &&
    form.purpose.trim().length > 0 &&
    !mutation.isPending;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="base">Classify a system</CardTitle>
        <CardDescription>
          Run the rule-based EU AI Act / NIST AI RMF classifier over a system
          descriptor. Informational only — not a legal determination.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="stack-5"
          aria-label="Classify system"
          onSubmit={(e) => {
            e.preventDefault();
            if (!canSubmit) return;
            mutation.mutate(descriptorBody(form));
          }}
        >
          <div className="grid grid-2">
            <div className="stack-2">
              <Label htmlFor="classify-name">Name</Label>
              <Input
                id="classify-name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Credit adjudication assistant"
                required
              />
            </div>
            <div className="stack-2">
              <Label htmlFor="classify-purpose">Purpose</Label>
              <Input
                id="classify-purpose"
                value={form.purpose}
                onChange={(e) => setForm({ ...form, purpose: e.target.value })}
                placeholder="What the system does."
                required
              />
            </div>
          </div>

          <fieldset className="stack-2 reset">
            <legend className="text-sm font-medium leading-none">
              Risk-elevating attributes
            </legend>
            <div className="row wrap gap-4">
              <label className="row gap-2 text-sm" htmlFor="classify-affects">
                <input
                  id="classify-affects"
                  type="checkbox"
                  checked={form.affects_natural_persons}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      affects_natural_persons: e.target.checked,
                    })
                  }
                />
                Affects natural persons
              </label>
              <label className="row gap-2 text-sm" htmlFor="classify-interacts">
                <input
                  id="classify-interacts"
                  type="checkbox"
                  checked={form.interacts_with_natural_persons}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      interacts_with_natural_persons: e.target.checked,
                    })
                  }
                />
                Interacts with natural persons
              </label>
              <label className="row gap-2 text-sm" htmlFor="classify-synthetic">
                <input
                  id="classify-synthetic"
                  type="checkbox"
                  checked={form.generates_synthetic_content}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      generates_synthetic_content: e.target.checked,
                    })
                  }
                />
                Generates synthetic content
              </label>
              <label className="row gap-2 text-sm" htmlFor="classify-prohibited">
                <input
                  id="classify-prohibited"
                  type="checkbox"
                  checked={form.is_prohibited_practice}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      is_prohibited_practice: e.target.checked,
                    })
                  }
                />
                Self-reported prohibited practice
              </label>
            </div>
          </fieldset>

          <div className="row-between border-t pt-4">
            <p className="text-xs muted">
              Name and purpose are required; the rest default to safe values.
            </p>
            <Button type="submit" disabled={!canSubmit}>
              {mutation.isPending ? "Classifying..." : "Classify"}
            </Button>
          </div>
        </form>

        {mutation.isError && (
          <Alert variant="destructive" className="mt-4">
            <AlertTitle>Could not classify system</AlertTitle>
            <AlertDescription>{apiErrorText(mutation.error)}</AlertDescription>
          </Alert>
        )}

        {result && (
          <div className="stack-3 mt-4 border-t pt-4">
            <div className="row gap-2 wrap">
              <span className="text-sm font-medium">
                {result.descriptor_name}
              </span>
              <Badge variant={TIER_BADGE_VARIANT[result.eu_ai_act_tier]}>
                {result.eu_ai_act_tier}
              </Badge>
            </div>
            <div className="row gap-2 wrap" aria-label="NIST AI RMF functions">
              {(result.applicable_nist_ai_rmf_functions ?? []).map((fn) => (
                <Badge key={fn} variant="outline">
                  {fn}
                </Badge>
              ))}
            </div>
            {(result.rationale ?? []).length > 0 && (
              <ul className="reset stack-1 text-xs muted">
                {(result.rationale ?? []).map((line, idx) => (
                  <li key={idx}>{line}</li>
                ))}
              </ul>
            )}
            <p className="text-xs faint">{result.disclaimer}</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ════════════════════════════════════════════════════════════════════════
// Register (classify + persist)
// ════════════════════════════════════════════════════════════════════════

const EMPTY_REGISTER = {
  ...EMPTY_DESCRIPTOR,
  owner: "",
  provider: "",
  deployment_status: "proposed" as DeploymentStatus,
};

function RegisterForm() {
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ ...EMPTY_REGISTER });

  const mutation = useMutation({
    mutationFn: (body: AISystemRegisterRequest) => api.registerAiSystem(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ai-gov-systems"] });
      setForm({ ...EMPTY_REGISTER });
    },
  });

  const canSubmit =
    form.name.trim().length > 0 &&
    form.purpose.trim().length > 0 &&
    form.owner.trim().length > 0 &&
    form.provider.trim().length > 0 &&
    !mutation.isPending;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="base">Register a system</CardTitle>
        <CardDescription>
          Classify and persist a system into the local registry. The server
          fills the system_id and stores the classification verdict.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="stack-5"
          aria-label="Register system"
          onSubmit={(e) => {
            e.preventDefault();
            if (!canSubmit) return;
            mutation.mutate({
              descriptor: descriptorBody(form),
              owner: form.owner.trim(),
              provider: form.provider.trim(),
              deployment_status: form.deployment_status,
            });
          }}
        >
          <div className="grid grid-2">
            <div className="stack-2">
              <Label htmlFor="register-name">Name</Label>
              <Input
                id="register-name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Credit adjudication assistant"
                required
              />
            </div>
            <div className="stack-2">
              <Label htmlFor="register-purpose">Purpose</Label>
              <Input
                id="register-purpose"
                value={form.purpose}
                onChange={(e) => setForm({ ...form, purpose: e.target.value })}
                placeholder="What the system does."
                required
              />
            </div>
          </div>

          <div className="grid grid-2">
            <div className="stack-2">
              <Label htmlFor="register-owner">Owner</Label>
              <Input
                id="register-owner"
                value={form.owner}
                onChange={(e) => setForm({ ...form, owner: e.target.value })}
                placeholder="ai.gov.lead@example.com"
                required
              />
            </div>
            <div className="stack-2">
              <Label htmlFor="register-provider">Provider</Label>
              <Input
                id="register-provider"
                value={form.provider}
                onChange={(e) =>
                  setForm({ ...form, provider: e.target.value })
                }
                placeholder="In-house team or vendor name"
                required
              />
            </div>
          </div>

          <fieldset className="stack-2 reset">
            <legend className="text-sm font-medium leading-none">
              Risk-elevating attributes
            </legend>
            <div className="row wrap gap-4">
              <label className="row gap-2 text-sm" htmlFor="register-affects">
                <input
                  id="register-affects"
                  type="checkbox"
                  checked={form.affects_natural_persons}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      affects_natural_persons: e.target.checked,
                    })
                  }
                />
                Affects natural persons
              </label>
              <label className="row gap-2 text-sm" htmlFor="register-interacts">
                <input
                  id="register-interacts"
                  type="checkbox"
                  checked={form.interacts_with_natural_persons}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      interacts_with_natural_persons: e.target.checked,
                    })
                  }
                />
                Interacts with natural persons
              </label>
              <label className="row gap-2 text-sm" htmlFor="register-synthetic">
                <input
                  id="register-synthetic"
                  type="checkbox"
                  checked={form.generates_synthetic_content}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      generates_synthetic_content: e.target.checked,
                    })
                  }
                />
                Generates synthetic content
              </label>
              <label
                className="row gap-2 text-sm"
                htmlFor="register-prohibited"
              >
                <input
                  id="register-prohibited"
                  type="checkbox"
                  checked={form.is_prohibited_practice}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      is_prohibited_practice: e.target.checked,
                    })
                  }
                />
                Self-reported prohibited practice
              </label>
            </div>
          </fieldset>

          <div className="stack-2">
            <span className="text-sm font-medium leading-none">
              Deployment status
            </span>
            <div
              className="row wrap gap-2"
              role="radiogroup"
              aria-label="Deployment status"
            >
              {DEPLOYMENT_PICKER_OPTIONS.map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  role="radio"
                  aria-checked={form.deployment_status === value}
                  onClick={() =>
                    setForm({ ...form, deployment_status: value })
                  }
                  className={cn(
                    "pill",
                    form.deployment_status === value && "on",
                  )}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="row-between border-t pt-4">
            <p className="text-xs muted">
              Name, purpose, owner, and provider are required.
            </p>
            <Button type="submit" disabled={!canSubmit}>
              {mutation.isPending ? "Registering..." : "Register system"}
            </Button>
          </div>
        </form>

        {mutation.isError && (
          <Alert variant="destructive" className="mt-4">
            <AlertTitle>Could not register system</AlertTitle>
            <AlertDescription>{apiErrorText(mutation.error)}</AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
}

// ════════════════════════════════════════════════════════════════════════
// Registry (list + detail)
// ════════════════════════════════════════════════════════════════════════

function RegistrySection() {
  const [tierFilter, setTierFilter] = useState<EUAIActTier | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["ai-gov-systems", tierFilter],
    queryFn: () => api.listAiSystems({ tier: tierFilter ?? undefined }),
  });

  // The list endpoint returns a BARE array (no envelope).
  const systems = (query.data ?? []).map(normalizeEntry);
  const selected = systems.find((s) => s.id === selectedId) ?? null;

  return (
    <section className="stack-3" aria-label="AI system registry">
      <h2 className="section-num">Registry</h2>

      <div
        className="row gap-2 wrap"
        role="radiogroup"
        aria-label="Filter by EU AI Act tier"
      >
        {TIER_FILTER_OPTIONS.map(([value, label]) => (
          <button
            key={value ?? "all-tiers"}
            type="button"
            role="radio"
            aria-checked={tierFilter === value}
            onClick={() => setTierFilter(value)}
            className={cn("chip", tierFilter === value && "on")}
          >
            {label}
          </button>
        ))}
      </div>

      {query.isError && (
        <Card className="border-dest" role="alert">
          <CardContent className="card-body" style={{ padding: "1.5rem" }}>
            <span className="text-sm text-destructive">
              Could not fetch AI systems. Is the backend running?
            </span>
          </CardContent>
        </Card>
      )}

      {query.isLoading && (
        <ul
          className="reset grid"
          style={{
            gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))",
          }}
        >
          {Array.from({ length: 4 }).map((_, i) => (
            <li key={i} className="reset">
              <div className="skel" style={{ height: "8rem" }} />
            </li>
          ))}
        </ul>
      )}

      {query.isSuccess && systems.length === 0 && (
        <div className="empty-state">
          {tierFilter
            ? "No systems match this tier."
            : "No AI systems registered yet. Register your first above."}
        </div>
      )}

      {systems.length > 0 && (
        <ul
          className="reset grid"
          style={{
            gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))",
          }}
        >
          {systems.map((system, idx) => {
            const isSelected = system.id != null && system.id === selectedId;
            const selectable = system.id != null;
            return (
              <li key={system.id ?? `${system.name}-${idx}`} className="reset">
                <Card
                  className={cn(
                    "card-hover",
                    isSelected && "ring-2 ring-primary",
                  )}
                  style={{
                    height: "100%",
                    cursor: selectable ? "pointer" : undefined,
                  }}
                  onClick={
                    selectable
                      ? () =>
                          setSelectedId((prev) =>
                            prev === system.id ? null : system.id,
                          )
                      : undefined
                  }
                  role={selectable ? "button" : undefined}
                  tabIndex={selectable ? 0 : undefined}
                  aria-pressed={selectable ? isSelected : undefined}
                  aria-label={selectable ? `System ${system.name}` : undefined}
                  onKeyDown={
                    selectable
                      ? (e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            setSelectedId((prev) =>
                              prev === system.id ? null : system.id,
                            );
                          }
                        }
                      : undefined
                  }
                >
                  <CardHeader className="stack-2">
                    <div className="row gap-2 wrap">
                      {system.tier ? (
                        <Badge variant={TIER_BADGE_VARIANT[system.tier]}>
                          {system.tier}
                        </Badge>
                      ) : (
                        <Badge variant="secondary">unclassified</Badge>
                      )}
                      {system.deploymentStatus && (
                        <Badge variant="outline">
                          {DEPLOYMENT_LABELS[
                            system.deploymentStatus as DeploymentStatus
                          ] ?? system.deploymentStatus.replace(/_/g, " ")}
                        </Badge>
                      )}
                    </div>
                    <CardTitle className="base">{system.name}</CardTitle>
                  </CardHeader>
                  <CardContent className="pt-0 text-xs muted stack-2">
                    <div>
                      Owner:{" "}
                      {system.owner ? (
                        <code className="kbd">{system.owner}</code>
                      ) : (
                        <span className="dim">unassigned</span>
                      )}
                    </div>
                    <div>
                      Provider:{" "}
                      {system.provider ? (
                        <code className="kbd">{system.provider}</code>
                      ) : (
                        <span className="dim">unknown</span>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </li>
            );
          })}
        </ul>
      )}

      {selected && selected.id && (
        <SystemDetailPanel
          system={selected}
          systemId={selected.id}
          onClose={() => setSelectedId(null)}
        />
      )}
    </section>
  );
}

function SystemDetailPanel({
  system,
  systemId,
  onClose,
}: {
  system: NormalizedSystem;
  systemId: string;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [confirmingDelete, setConfirmingDelete] = useState(false);

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["ai-gov-systems"] });

  const retireMutation = useMutation({
    mutationFn: () => api.retireAiSystem(systemId),
    onSuccess: invalidate,
  });

  const deleteMutation = useMutation({
    mutationFn: () => api.deleteAiSystem(systemId),
    onSuccess: () => {
      invalidate();
      onClose();
    },
  });

  return (
    <Card aria-label="System detail" className="border-t">
      <CardHeader className="row-between">
        <div className="stack-2">
          <CardTitle className="base">{system.name}</CardTitle>
          <CardDescription>
            {system.tier ? (
              <Badge variant={TIER_BADGE_VARIANT[system.tier]}>
                {system.tier}
              </Badge>
            ) : (
              <Badge variant="secondary">unclassified</Badge>
            )}{" "}
            &middot; <code className="kbd">{systemId}</code>
          </CardDescription>
        </div>
        <Button type="button" variant="ghost" onClick={onClose}>
          Close
        </Button>
      </CardHeader>
      <CardContent
        className="stack-5"
        aria-busy={retireMutation.isPending || deleteMutation.isPending}
      >
        {editing ? (
          <EditSystemForm
            system={system}
            systemId={systemId}
            onCancel={() => setEditing(false)}
            onSaved={() => {
              invalidate();
              setEditing(false);
            }}
          />
        ) : (
          <div className="stack-4">
            <dl className="grid grid-2 text-sm">
              <div className="stack-1">
                <dt className="muted text-xs">Purpose</dt>
                <dd>{system.purpose ?? "—"}</dd>
              </div>
              <div className="stack-1">
                <dt className="muted text-xs">Owner</dt>
                <dd>
                  {system.owner ? (
                    <code className="kbd">{system.owner}</code>
                  ) : (
                    "—"
                  )}
                </dd>
              </div>
              <div className="stack-1">
                <dt className="muted text-xs">Provider</dt>
                <dd>
                  {system.provider ? (
                    <code className="kbd">{system.provider}</code>
                  ) : (
                    "—"
                  )}
                </dd>
              </div>
              <div className="stack-1">
                <dt className="muted text-xs">Deployment status</dt>
                <dd>
                  {system.deploymentStatus ? (
                    <Badge variant="outline">
                      {DEPLOYMENT_LABELS[
                        system.deploymentStatus as DeploymentStatus
                      ] ?? system.deploymentStatus.replace(/_/g, " ")}
                    </Badge>
                  ) : (
                    "—"
                  )}
                </dd>
              </div>
              <div className="stack-1">
                <dt className="muted text-xs">FIPS 199 overall</dt>
                <dd>
                  {system.fips?.overall ? (
                    <Badge variant="outline">{system.fips.overall}</Badge>
                  ) : (
                    <span className="dim">not categorized</span>
                  )}
                </dd>
              </div>
              <div className="stack-1">
                <dt className="muted text-xs">OMB M-24-10 impact</dt>
                <dd>
                  {system.ombImpact ? (
                    <Badge variant="outline">
                      {system.ombImpact.replace(/_/g, " ")}
                    </Badge>
                  ) : (
                    <span className="dim">not set</span>
                  )}
                </dd>
              </div>
            </dl>

            <CardFooter className="row wrap gap-2 pt-0">
              <Button type="button" onClick={() => setEditing(true)}>
                Edit
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={
                  retireMutation.isPending ||
                  system.deploymentStatus === "retired"
                }
                onClick={() => retireMutation.mutate()}
              >
                {retireMutation.isPending ? "Retiring..." : "Retire"}
              </Button>
              {confirmingDelete ? (
                <>
                  <Button
                    type="button"
                    variant="destructive"
                    onClick={() => deleteMutation.mutate()}
                    disabled={deleteMutation.isPending}
                  >
                    {deleteMutation.isPending
                      ? "Deleting..."
                      : "Confirm delete"}
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    onClick={() => setConfirmingDelete(false)}
                  >
                    Cancel
                  </Button>
                </>
              ) : (
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setConfirmingDelete(true)}
                >
                  Delete
                </Button>
              )}
            </CardFooter>

            {retireMutation.isError && (
              <Alert variant="destructive">
                <AlertTitle>Could not retire system</AlertTitle>
                <AlertDescription>
                  {apiErrorText(retireMutation.error)}
                </AlertDescription>
              </Alert>
            )}

            {deleteMutation.isError && (
              <Alert variant="destructive">
                <AlertTitle>Could not delete system</AlertTitle>
                <AlertDescription>
                  {apiErrorText(deleteMutation.error)}
                </AlertDescription>
              </Alert>
            )}

            <FipsCategorizeForm systemId={systemId} onSaved={invalidate} />

            <OmbImpactForm systemId={systemId} onSaved={invalidate} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}

/** Inline edit — partial update of owner / provider / deployment_status. */
function EditSystemForm({
  system,
  systemId,
  onCancel,
  onSaved,
}: {
  system: NormalizedSystem;
  systemId: string;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const [form, setForm] = useState({
    owner: system.owner ?? "",
    provider: system.provider ?? "",
    deployment_status: (system.deploymentStatus ??
      "proposed") as DeploymentStatus,
    ssp_reference: system.sspReference ?? "",
  });

  const mutation = useMutation({
    mutationFn: () =>
      api.updateAiSystem(systemId, {
        owner: form.owner.trim() ? form.owner.trim() : undefined,
        provider: form.provider.trim() ? form.provider.trim() : undefined,
        deployment_status: form.deployment_status,
        ssp_reference: form.ssp_reference.trim()
          ? form.ssp_reference.trim()
          : undefined,
      }),
    onSuccess: onSaved,
  });

  return (
    <form
      className="stack-5"
      aria-label="Edit system"
      onSubmit={(e) => {
        e.preventDefault();
        if (mutation.isPending) return;
        mutation.mutate();
      }}
    >
      <div className="grid grid-2">
        <div className="stack-2">
          <Label htmlFor="edit-owner">Owner</Label>
          <Input
            id="edit-owner"
            value={form.owner}
            onChange={(e) => setForm({ ...form, owner: e.target.value })}
          />
        </div>
        <div className="stack-2">
          <Label htmlFor="edit-provider">Provider</Label>
          <Input
            id="edit-provider"
            value={form.provider}
            onChange={(e) => setForm({ ...form, provider: e.target.value })}
          />
        </div>
      </div>

      <div className="stack-2">
        <Label htmlFor="edit-ssp">SSP reference (optional)</Label>
        <Input
          id="edit-ssp"
          value={form.ssp_reference}
          onChange={(e) =>
            setForm({ ...form, ssp_reference: e.target.value })
          }
          placeholder="eMASS link or docstore handle"
        />
      </div>

      <div className="stack-2">
        <span className="text-sm font-medium leading-none">
          Deployment status
        </span>
        <div
          className="row wrap gap-2"
          role="radiogroup"
          aria-label="Edit deployment status"
        >
          {DEPLOYMENT_PICKER_OPTIONS.map(([value, label]) => (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={form.deployment_status === value}
              onClick={() => setForm({ ...form, deployment_status: value })}
              className={cn(
                "pill",
                form.deployment_status === value && "on",
              )}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="row gap-2 border-t pt-4">
        <Button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? "Saving..." : "Save changes"}
        </Button>
        <Button type="button" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
      </div>

      {mutation.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not update system</AlertTitle>
          <AlertDescription>{apiErrorText(mutation.error)}</AlertDescription>
        </Alert>
      )}
    </form>
  );
}

/** FIPS 199 categorization — C / I / A impact + optional overall/rationale. */
function FipsCategorizeForm({
  systemId,
  onSaved,
}: {
  systemId: string;
  onSaved: () => void;
}) {
  const [confidentiality, setConfidentiality] =
    useState<FIPS199Impact>("moderate");
  const [integrity, setIntegrity] = useState<FIPS199Impact>("moderate");
  const [availability, setAvailability] = useState<FIPS199Impact>("low");
  const [rationale, setRationale] = useState("");

  const mutation = useMutation({
    mutationFn: (body: FIPS199CategorizeRequest) =>
      api.categorizeFipsAiSystem(systemId, body),
    onSuccess: onSaved,
  });

  const impactRow = (
    label: string,
    value: FIPS199Impact,
    onChange: (next: FIPS199Impact) => void,
  ) => (
    <div className="stack-2">
      <span className="text-sm font-medium leading-none">{label}</span>
      <div className="row wrap gap-2" role="radiogroup" aria-label={label}>
        {FIPS_PICKER_OPTIONS.map(([optValue, optLabel]) => (
          <button
            key={optValue}
            type="button"
            role="radio"
            aria-checked={value === optValue}
            onClick={() => onChange(optValue)}
            className={cn("pill", value === optValue && "on")}
          >
            {optLabel}
          </button>
        ))}
      </div>
    </div>
  );

  return (
    <form
      className="stack-4 border-t pt-4"
      aria-label="Categorize FIPS 199"
      onSubmit={(e) => {
        e.preventDefault();
        if (mutation.isPending) return;
        mutation.mutate({
          confidentiality,
          integrity,
          availability,
          ...(rationale.trim() ? { rationale: rationale.trim() } : {}),
        });
      }}
    >
      <h3 className="section-num">Categorize FIPS 199</h3>
      <div className="grid grid-2">
        {impactRow("Confidentiality", confidentiality, setConfidentiality)}
        {impactRow("Integrity", integrity, setIntegrity)}
        {impactRow("Availability", availability, setAvailability)}
      </div>
      <div className="stack-2">
        <Label htmlFor="fips-rationale">Rationale (optional)</Label>
        <Textarea
          id="fips-rationale"
          value={rationale}
          onChange={(e) => setRationale(e.target.value)}
          placeholder="Why these impact levels apply."
        />
      </div>
      <div className="row-end">
        <Button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? "Saving..." : "Set FIPS 199"}
        </Button>
      </div>

      {mutation.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not categorize system</AlertTitle>
          <AlertDescription>{apiErrorText(mutation.error)}</AlertDescription>
        </Alert>
      )}
    </form>
  );
}

/** OMB M-24-10 impact — single category select. */
function OmbImpactForm({
  systemId,
  onSaved,
}: {
  systemId: string;
  onSaved: () => void;
}) {
  const [category, setCategory] =
    useState<OMBImpactCategory>("rights_impacting");

  const mutation = useMutation({
    mutationFn: (body: OMBImpactRequest) =>
      api.setOmbImpactAiSystem(systemId, body),
    onSuccess: onSaved,
  });

  return (
    <form
      className="stack-4 border-t pt-4"
      aria-label="Set OMB impact"
      onSubmit={(e) => {
        e.preventDefault();
        if (mutation.isPending) return;
        mutation.mutate({ category });
      }}
    >
      <h3 className="section-num">Set OMB impact</h3>
      <div
        className="row wrap gap-2"
        role="radiogroup"
        aria-label="OMB impact category"
      >
        {OMB_PICKER_OPTIONS.map(([value, label]) => (
          <button
            key={value}
            type="button"
            role="radio"
            aria-checked={category === value}
            onClick={() => setCategory(value)}
            className={cn("pill", category === value && "on")}
          >
            {label}
          </button>
        ))}
      </div>
      <div className="row-end">
        <Button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? "Saving..." : "Set OMB impact"}
        </Button>
      </div>

      {mutation.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not set OMB impact</AlertTitle>
          <AlertDescription>{apiErrorText(mutation.error)}</AlertDescription>
        </Alert>
      )}
    </form>
  );
}
