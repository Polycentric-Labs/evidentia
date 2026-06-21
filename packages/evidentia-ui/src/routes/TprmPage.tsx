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
  type ConcentrationReport,
  type CriticalityTier,
  type DDQuestionnaireIngestResult,
  type Questionnaire,
  type Vendor,
  type VendorInput,
  type VendorType,
} from "@/lib/api";
import { cn } from "@/lib/utils";

// ── Enum option tables (mirror the OpenAPI VendorType / CriticalityTier) ──

const TIER_FILTER_OPTIONS: [CriticalityTier | null, string][] = [
  [null, "All tiers"],
  ["critical", "Critical"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
];

const TYPE_FILTER_OPTIONS: [VendorType | null, string][] = [
  [null, "All types"],
  ["saas", "SaaS"],
  ["subservice_org", "Subservice org"],
  ["contractor", "Contractor"],
  ["data_processor", "Data processor"],
  ["cloud_provider", "Cloud provider"],
  ["open_source", "Open source"],
];

const TIER_PICKER_OPTIONS: [CriticalityTier, string][] = [
  ["critical", "Critical"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
];

const TYPE_PICKER_OPTIONS: [VendorType, string][] = [
  ["saas", "SaaS"],
  ["subservice_org", "Subservice org"],
  ["contractor", "Contractor"],
  ["data_processor", "Data processor"],
  ["cloud_provider", "Cloud provider"],
  ["open_source", "Open source"],
];

/** Map a criticality tier to the matching severity Badge variant. */
const TIER_BADGE_VARIANT: Record<
  CriticalityTier,
  "critical" | "high" | "medium" | "low"
> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

const TYPE_LABELS: Record<VendorType, string> = {
  saas: "SaaS",
  subservice_org: "Subservice org",
  contractor: "Contractor",
  data_processor: "Data processor",
  cloud_provider: "Cloud provider",
  open_source: "Open source",
};

/**
 * TPRM — third-party vendor inventory.
 *
 * Lists the local vendor store (`GET /api/tprm/vendors`, a
 * `{total, skip, limit, vendors}` envelope) with criticality-tier + type
 * filter chips, and exposes a "New vendor" form wired to
 * `POST /api/tprm/vendors`. The form sends only the five required
 * `VendorInput` fields; the server fills id / created_at / updated_at and
 * computes `next_review_due` from the criticality cadence.
 */
export function TprmPage() {
  const [tierFilter, setTierFilter] = useState<CriticalityTier | null>(null);
  const [typeFilter, setTypeFilter] = useState<VendorType | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["tprm-vendors", tierFilter, typeFilter],
    queryFn: () =>
      api.listVendors({
        criticality_tier: tierFilter ?? undefined,
        type: typeFilter ?? undefined,
      }),
  });

  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">TPRM</h1>
        <p className="page-sub">
          {query.data
            ? `${query.data.vendors.length} of ${query.data.total} vendors`
            : "Third-party vendor inventory."}
        </p>
      </header>

      <NewVendorForm />

      <ConcentrationSection />

      <section className="stack-3" aria-label="Vendor inventory">
        <h2 className="section-num">Vendor inventory</h2>

        <div className="row wrap gap-3" aria-label="Filters">
          <div
            className="row gap-2 wrap"
            role="radiogroup"
            aria-label="Filter by criticality tier"
          >
            {TIER_FILTER_OPTIONS.map(([value, label]) => (
              <button
                key={value ?? "all"}
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
          <div
            className="row gap-2 wrap"
            role="radiogroup"
            aria-label="Filter by vendor type"
          >
            {TYPE_FILTER_OPTIONS.map(([value, label]) => (
              <button
                key={value ?? "all"}
                type="button"
                role="radio"
                aria-checked={typeFilter === value}
                onClick={() => setTypeFilter(value)}
                className={cn("chip", typeFilter === value && "on")}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        {query.isError && (
          <Card className="border-dest">
            <CardContent className="card-body" style={{ padding: "1.5rem" }}>
              <span className="text-sm text-destructive">
                Could not fetch vendors. Is the backend running?
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
            {Array.from({ length: 6 }).map((_, i) => (
              <li key={i} className="reset">
                <div className="skel" style={{ height: "8rem" }} />
              </li>
            ))}
          </ul>
        )}

        {query.isSuccess && query.data.vendors.length === 0 && (
          <div className="empty-state">
            {tierFilter || typeFilter
              ? "No vendors match your filters."
              : "No vendors yet. Add your first vendor above."}
          </div>
        )}

        {query.isSuccess && query.data.vendors.length > 0 && (
          <ul
            className="reset grid"
            style={{
              gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))",
            }}
          >
            {query.data.vendors.map((vendor) => (
              <li key={vendor.id ?? vendor.name} className="reset">
                <VendorCard
                  vendor={vendor}
                  selected={selectedId != null && vendor.id === selectedId}
                  onSelect={() =>
                    vendor.id != null &&
                    setSelectedId((prev) =>
                      prev === vendor.id ? null : (vendor.id ?? null),
                    )
                  }
                />
              </li>
            ))}
          </ul>
        )}

        {selectedId != null && (
          <VendorDetailPanel
            vendorId={selectedId}
            onClose={() => setSelectedId(null)}
          />
        )}
      </section>
    </div>
  );
}

function VendorCard({
  vendor,
  selected,
  onSelect,
}: {
  vendor: Vendor;
  selected: boolean;
  onSelect: () => void;
}) {
  const tier = vendor.criticality_tier;
  const selectable = vendor.id != null;
  return (
    <Card
      className={cn("card-hover", selected && "ring-2 ring-primary")}
      style={{ height: "100%", cursor: selectable ? "pointer" : undefined }}
      onClick={selectable ? onSelect : undefined}
      role={selectable ? "button" : undefined}
      tabIndex={selectable ? 0 : undefined}
      aria-pressed={selectable ? selected : undefined}
      aria-label={selectable ? `Vendor ${vendor.name}` : undefined}
      onKeyDown={
        selectable
          ? (e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onSelect();
              }
            }
          : undefined
      }
    >
      <CardHeader className="stack-2">
        <div className="row gap-2 wrap">
          <Badge variant={TIER_BADGE_VARIANT[tier]}>{tier}</Badge>
          <Badge variant="outline">{TYPE_LABELS[vendor.type]}</Badge>
        </div>
        <CardTitle className="base">{vendor.name}</CardTitle>
      </CardHeader>
      <CardContent className="pt-0 text-xs muted stack-2">
        <div>
          Owner: <code className="kbd">{vendor.relationship_owner}</code>
        </div>
        <div>
          Next review due:{" "}
          {vendor.next_review_due ? (
            <code className="kbd">{vendor.next_review_due}</code>
          ) : (
            <span className="dim">not scheduled</span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

const EMPTY_FORM = {
  name: "",
  type: "saas" as VendorType,
  criticality_tier: "high" as CriticalityTier,
  relationship_owner: "",
  contract_start_date: "",
};

function NewVendorForm() {
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ ...EMPTY_FORM });

  const mutation = useMutation({
    mutationFn: (body: VendorInput) => api.createVendor(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tprm-vendors"] });
      setForm({ ...EMPTY_FORM });
    },
  });

  const canSubmit =
    form.name.trim().length > 0 &&
    form.relationship_owner.trim().length > 0 &&
    form.contract_start_date.length > 0 &&
    !mutation.isPending;

  const submit = () => {
    if (!canSubmit) return;
    // The required VendorInput fields. `residual_risk_score` is required by the
    // schema but defaults to 0 ("unscored"); operators set the real 1–25 score
    // later from the due-diligence-review outcome (CLI `tprm vendor edit`), so
    // the create form sends the 0 default. `additionalProperties: false` on the
    // server — no extra keys.
    mutation.mutate({
      name: form.name.trim(),
      type: form.type,
      criticality_tier: form.criticality_tier,
      relationship_owner: form.relationship_owner.trim(),
      contract_start_date: form.contract_start_date,
      residual_risk_score: 0,
    });
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="base">New vendor</CardTitle>
        <CardDescription>
          Add a vendor to the local inventory. The server computes the next
          due-diligence review date from the criticality tier.
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
              <Label htmlFor="vendor-name">Name</Label>
              <Input
                id="vendor-name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Acme Cloud Inc."
                required
              />
            </div>
            <div className="stack-2">
              <Label htmlFor="vendor-owner">Relationship owner</Label>
              <Input
                id="vendor-owner"
                value={form.relationship_owner}
                onChange={(e) =>
                  setForm({ ...form, relationship_owner: e.target.value })
                }
                placeholder="alice@example.com"
                required
              />
            </div>
          </div>

          <div className="stack-2">
            <Label htmlFor="vendor-contract-start">Contract start date</Label>
            <Input
              id="vendor-contract-start"
              type="date"
              value={form.contract_start_date}
              onChange={(e) =>
                setForm({ ...form, contract_start_date: e.target.value })
              }
              required
              style={{ maxWidth: "16rem" }}
            />
          </div>

          <div className="stack-2">
            <span className="text-sm font-medium leading-none">Type</span>
            <div
              className="row wrap gap-2"
              role="radiogroup"
              aria-label="Vendor type"
            >
              {TYPE_PICKER_OPTIONS.map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  role="radio"
                  aria-checked={form.type === value}
                  onClick={() => setForm({ ...form, type: value })}
                  className={cn("pill", form.type === value && "on")}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="stack-2">
            <span className="text-sm font-medium leading-none">
              Criticality tier
            </span>
            <div
              className="row wrap gap-2"
              role="radiogroup"
              aria-label="Criticality tier"
            >
              {TIER_PICKER_OPTIONS.map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  role="radio"
                  aria-checked={form.criticality_tier === value}
                  onClick={() =>
                    setForm({ ...form, criticality_tier: value })
                  }
                  className={cn("pill", form.criticality_tier === value && "on")}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="row-between border-t pt-4">
            <p className="text-xs muted">
              Five required fields. The vendor lands in the inventory below.
            </p>
            <Button type="submit" disabled={!canSubmit}>
              {mutation.isPending ? "Adding..." : "Add vendor"}
            </Button>
          </div>
        </form>

        {mutation.isError && (
          <Alert variant="destructive" className="mt-4">
            <AlertTitle>Could not add vendor</AlertTitle>
            <AlertDescription>
              {mutation.error instanceof ApiError && mutation.error.payload
                ? JSON.stringify(mutation.error.payload)
                : String(mutation.error)}
            </AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
}

/** Surface an ApiError payload (or any error) as readable text. */
function apiErrorText(error: unknown): string {
  if (error instanceof ApiError && error.payload != null) {
    return JSON.stringify(error.payload);
  }
  return String(error);
}

/**
 * Concentration report — `GET /api/tprm/concentration` (CLI `tprm
 * concentration`). Fetched on demand: the button kicks a query that
 * aggregates the inventory across dimensions (4th-party / region / type)
 * and renders the per-value distribution as structured text.
 */
function ConcentrationSection() {
  const [show, setShow] = useState(false);
  const query = useQuery<ConcentrationReport>({
    queryKey: ["tprm-concentration"],
    queryFn: () => api.tprmConcentration(),
    enabled: show,
  });

  return (
    <section className="stack-3" aria-label="Concentration report">
      <div className="row-between">
        <h2 className="section-num">Concentration report</h2>
        <Button
          type="button"
          variant="outline"
          onClick={() => {
            setShow(true);
            if (show) query.refetch();
          }}
          disabled={query.isFetching}
        >
          {query.isFetching
            ? "Running..."
            : show
              ? "Refresh report"
              : "Run concentration report"}
        </Button>
      </div>

      {show && query.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not run concentration report</AlertTitle>
          <AlertDescription>{apiErrorText(query.error)}</AlertDescription>
        </Alert>
      )}

      {show && query.isSuccess && (
        <Card>
          <CardContent className="card-body stack-3" style={{ padding: "1.5rem" }}>
            <p className="text-xs muted">
              {query.data.total_vendors} vendors analyzed
              {query.data.generated_at
                ? ` · generated ${query.data.generated_at}`
                : ""}
              {query.data.threshold != null
                ? ` · threshold ${query.data.threshold}%`
                : ""}
            </p>
            {(query.data.dimensions ?? []).length === 0 ? (
              <span className="text-sm muted">No dimensions in this report.</span>
            ) : (
              <div className="stack-3">
                {(query.data.dimensions ?? []).map((dim) => (
                  <div key={dim.dimension} className="stack-2">
                    <h3 className="text-sm font-medium">
                      {dim.dimension}{" "}
                      <span className="muted">
                        ({dim.total_unique_values} unique ·{" "}
                        {dim.vendors_with_value} vendors)
                      </span>
                    </h3>
                    <ul className="reset stack-1">
                      {(dim.distribution ?? []).map((vc) => (
                        <li
                          key={vc.value}
                          className="row-between text-xs"
                          style={{ gap: "0.75rem" }}
                        >
                          <code className="kbd">{vc.value}</code>
                          <span
                            className={cn(
                              "muted",
                              vc.exceeds_threshold && "text-destructive",
                            )}
                          >
                            {vc.count} ({vc.percentage}%)
                            {vc.exceeds_threshold ? " ⚠" : ""}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </section>
  );
}

/**
 * Vendor detail panel — fetches the selected vendor
 * (`GET /api/tprm/vendors/{id}`) and exposes the remaining TPRM verbs:
 * inline edit (`PUT /api/tprm/vendors/{id}`), delete
 * (`DELETE /api/tprm/vendors/{id}`), DD-questionnaire generate
 * (`POST .../dd-questionnaire`) and ingest (`POST .../dd-questionnaire/ingest`).
 * The vendor-mutating verbs (edit / delete) invalidate the vendor-list query;
 * DD-questionnaire ingest is PARSE-ONLY (no vendor mutation), so it does not.
 */
function VendorDetailPanel({
  vendorId,
  onClose,
}: {
  vendorId: string;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [confirmingDelete, setConfirmingDelete] = useState(false);

  const detail = useQuery<Vendor>({
    queryKey: ["tprm-vendor", vendorId],
    queryFn: () => api.getVendor(vendorId),
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["tprm-vendors"] });
    queryClient.invalidateQueries({ queryKey: ["tprm-vendor", vendorId] });
  };

  const deleteMutation = useMutation({
    mutationFn: () => api.deleteVendor(vendorId),
    onSuccess: () => {
      invalidate();
      onClose();
    },
  });

  return (
    <Card aria-label="Vendor detail" className="border-t">
      <CardHeader className="row-between">
        <CardTitle className="base">Vendor detail</CardTitle>
        <Button type="button" variant="ghost" onClick={onClose}>
          Close
        </Button>
      </CardHeader>
      <CardContent className="stack-5">
        {detail.isLoading && <div className="skel" style={{ height: "6rem" }} />}

        {detail.isError && (
          <Alert variant="destructive">
            <AlertTitle>Could not load vendor</AlertTitle>
            <AlertDescription>{apiErrorText(detail.error)}</AlertDescription>
          </Alert>
        )}

        {detail.isSuccess &&
          (editing ? (
            <EditVendorForm
              vendor={detail.data}
              vendorId={vendorId}
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
                  <dt className="muted text-xs">Name</dt>
                  <dd>{detail.data.name}</dd>
                </div>
                <div className="stack-1">
                  <dt className="muted text-xs">Owner</dt>
                  <dd>
                    <code className="kbd">{detail.data.relationship_owner}</code>
                  </dd>
                </div>
                <div className="stack-1">
                  <dt className="muted text-xs">Type</dt>
                  <dd>{TYPE_LABELS[detail.data.type]}</dd>
                </div>
                <div className="stack-1">
                  <dt className="muted text-xs">Criticality tier</dt>
                  <dd>
                    <Badge
                      variant={TIER_BADGE_VARIANT[detail.data.criticality_tier]}
                    >
                      {detail.data.criticality_tier}
                    </Badge>
                  </dd>
                </div>
                <div className="stack-1">
                  <dt className="muted text-xs">Contract start</dt>
                  <dd>
                    <code className="kbd">
                      {detail.data.contract_start_date}
                    </code>
                  </dd>
                </div>
                <div className="stack-1">
                  <dt className="muted text-xs">Residual risk score</dt>
                  <dd>{detail.data.residual_risk_score}</dd>
                </div>
              </dl>

              <CardFooter className="row wrap gap-2 pt-0">
                <Button type="button" onClick={() => setEditing(true)}>
                  Edit
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

              {deleteMutation.isError && (
                <Alert variant="destructive">
                  <AlertTitle>Could not delete vendor</AlertTitle>
                  <AlertDescription>
                    {apiErrorText(deleteMutation.error)}
                  </AlertDescription>
                </Alert>
              )}
            </div>
          ))}

        {detail.isSuccess && <DdQuestionnaireSection vendorId={vendorId} />}
      </CardContent>
    </Card>
  );
}

/** Inline edit form — sends the full VendorInput body to PUT. */
function EditVendorForm({
  vendor,
  vendorId,
  onCancel,
  onSaved,
}: {
  vendor: Vendor;
  vendorId: string;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const [form, setForm] = useState({
    name: vendor.name,
    type: vendor.type,
    criticality_tier: vendor.criticality_tier,
    relationship_owner: vendor.relationship_owner,
    contract_start_date: vendor.contract_start_date,
    residual_risk_score: vendor.residual_risk_score,
  });

  const mutation = useMutation({
    mutationFn: (body: VendorInput) => api.updateVendor(vendorId, body),
    onSuccess: onSaved,
  });

  const canSubmit =
    form.name.trim().length > 0 &&
    form.relationship_owner.trim().length > 0 &&
    form.contract_start_date.length > 0 &&
    !mutation.isPending;

  return (
    <form
      className="stack-5"
      aria-label="Edit vendor"
      onSubmit={(e) => {
        e.preventDefault();
        if (!canSubmit) return;
        mutation.mutate({
          name: form.name.trim(),
          type: form.type,
          criticality_tier: form.criticality_tier,
          relationship_owner: form.relationship_owner.trim(),
          contract_start_date: form.contract_start_date,
          residual_risk_score: form.residual_risk_score,
        });
      }}
    >
      <div className="grid grid-2">
        <div className="stack-2">
          <Label htmlFor="edit-vendor-name">Name</Label>
          <Input
            id="edit-vendor-name"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            required
          />
        </div>
        <div className="stack-2">
          <Label htmlFor="edit-vendor-owner">Relationship owner</Label>
          <Input
            id="edit-vendor-owner"
            value={form.relationship_owner}
            onChange={(e) =>
              setForm({ ...form, relationship_owner: e.target.value })
            }
            required
          />
        </div>
      </div>

      <div className="grid grid-2">
        <div className="stack-2">
          <Label htmlFor="edit-vendor-contract-start">Contract start date</Label>
          <Input
            id="edit-vendor-contract-start"
            type="date"
            value={form.contract_start_date}
            onChange={(e) =>
              setForm({ ...form, contract_start_date: e.target.value })
            }
            required
          />
        </div>
        <div className="stack-2">
          <Label htmlFor="edit-vendor-residual">Residual risk score</Label>
          <Input
            id="edit-vendor-residual"
            type="number"
            min={0}
            max={25}
            value={form.residual_risk_score}
            onChange={(e) =>
              setForm({
                ...form,
                residual_risk_score: Number(e.target.value),
              })
            }
          />
        </div>
      </div>

      <div className="stack-2">
        <span className="text-sm font-medium leading-none">Type</span>
        <div className="row wrap gap-2" role="radiogroup" aria-label="Edit vendor type">
          {TYPE_PICKER_OPTIONS.map(([value, label]) => (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={form.type === value}
              onClick={() => setForm({ ...form, type: value })}
              className={cn("pill", form.type === value && "on")}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="stack-2">
        <span className="text-sm font-medium leading-none">Criticality tier</span>
        <div
          className="row wrap gap-2"
          role="radiogroup"
          aria-label="Edit criticality tier"
        >
          {TIER_PICKER_OPTIONS.map(([value, label]) => (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={form.criticality_tier === value}
              onClick={() => setForm({ ...form, criticality_tier: value })}
              className={cn("pill", form.criticality_tier === value && "on")}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="row gap-2 border-t pt-4">
        <Button type="submit" disabled={!canSubmit}>
          {mutation.isPending ? "Saving..." : "Save changes"}
        </Button>
        <Button type="button" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
      </div>

      {mutation.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not update vendor</AlertTitle>
          <AlertDescription>{apiErrorText(mutation.error)}</AlertDescription>
        </Alert>
      )}
    </form>
  );
}

/**
 * DD-questionnaire generate + ingest. Generate kicks
 * `POST /api/tprm/vendors/{id}/dd-questionnaire` and renders the returned
 * structured questionnaire. Ingest is PARSE-ONLY: the operator pastes a
 * completed `Questionnaire` document (the generated questionnaire JSON with
 * each `questions[].vendor_response` filled in), which is parsed to an object
 * and POSTed to `.../dd-questionnaire/ingest`; the endpoint correlates the
 * responses to the vendor WITHOUT mutating it, and the returned
 * `DDQuestionnaireIngestResult` (correlated responses + carry-forward
 * questionnaire id / format + timestamp) is rendered below.
 */
function DdQuestionnaireSection({ vendorId }: { vendorId: string }) {
  const [questionnaire, setQuestionnaire] = useState<Questionnaire | null>(null);
  const [documentText, setDocumentText] = useState("");
  const [parseError, setParseError] = useState<string | null>(null);

  const generate = useMutation({
    mutationFn: () => api.ddQuestionnaireGenerate(vendorId),
    onSuccess: (data) => setQuestionnaire(data),
  });

  const ingest = useMutation({
    mutationFn: (document: Questionnaire) =>
      api.ddQuestionnaireIngest(vendorId, document),
  });

  /**
   * Parse the pasted completed-questionnaire JSON into a `Questionnaire`
   * document. The backend ingest endpoint is the source of truth for shape
   * validation (it returns 400/422 on a malformed document), so this only
   * guards against non-JSON / non-object text before the round-trip.
   */
  const parseDocument = (text: string): Questionnaire | null => {
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      setParseError("Could not parse — paste valid questionnaire JSON.");
      return null;
    }
    if (value == null || typeof value !== "object" || Array.isArray(value)) {
      setParseError("Expected a questionnaire object (the generated JSON).");
      return null;
    }
    setParseError(null);
    return value as Questionnaire;
  };

  const submitIngest = () => {
    const document = parseDocument(documentText);
    if (document == null) return;
    ingest.mutate(document);
  };

  /** Seed the ingest textarea with the generated questionnaire JSON so the
   *  operator can fill in each `vendor_response` and submit the document. */
  const prefillFromGenerated = () => {
    if (questionnaire == null) return;
    setParseError(null);
    setDocumentText(JSON.stringify(questionnaire, null, 2));
  };

  const canIngest = documentText.trim().length > 0 && !ingest.isPending;

  return (
    <section className="stack-3 border-t pt-4" aria-label="Due-diligence questionnaire">
      <div className="row-between">
        <h3 className="text-sm font-medium">Due-diligence questionnaire</h3>
        <Button
          type="button"
          variant="outline"
          onClick={() => generate.mutate()}
          disabled={generate.isPending}
        >
          {generate.isPending ? "Generating..." : "Generate DD questionnaire"}
        </Button>
      </div>

      {generate.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not generate questionnaire</AlertTitle>
          <AlertDescription>{apiErrorText(generate.error)}</AlertDescription>
        </Alert>
      )}

      {questionnaire && (
        <div className="stack-2">
          <div className="row-between">
            <p className="text-sm font-medium">{questionnaire.title}</p>
            <Button
              type="button"
              variant="outline"
              onClick={prefillFromGenerated}
            >
              Fill responses
            </Button>
          </div>
          <p className="text-xs muted">
            Format: <code className="kbd">{questionnaire.format}</code>
            {questionnaire.licensing_attribution
              ? ` · ${questionnaire.licensing_attribution}`
              : ""}
          </p>
          <ul className="reset stack-2">
            {(questionnaire.questions ?? []).map((q) => (
              <li key={q.id} className="text-xs stack-1">
                <div>
                  <code className="kbd">{q.id}</code>{" "}
                  <span className="muted">[{q.domain}]</span>
                </div>
                <div>{q.question_text}</div>
                {q.response_options && q.response_options.length > 0 && (
                  <div className="muted">
                    Options: {q.response_options.join(" / ")}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="stack-2">
        <Label htmlFor="dd-document">Ingest completed questionnaire</Label>
        <p className="text-xs muted">
          Paste the completed questionnaire JSON — the generated document with
          each question&apos;s <code className="kbd">vendor_response</code>{" "}
          filled in. Ingest correlates the responses without changing the
          vendor.
        </p>
        <Textarea
          id="dd-document"
          value={documentText}
          onChange={(e) => {
            setDocumentText(e.target.value);
            if (parseError) setParseError(null);
          }}
          rows={6}
          placeholder={
            '{\n  "format": "evidentia-generic",\n  "questions": [\n    { "id": "EVG-GOV-01", "vendor_response": "Yes" }\n  ]\n}'
          }
        />
        <div className="row gap-2">
          <Button type="button" onClick={submitIngest} disabled={!canIngest}>
            {ingest.isPending ? "Ingesting..." : "Ingest questionnaire"}
          </Button>
        </div>
      </div>

      {parseError && (
        <Alert variant="destructive">
          <AlertTitle>Could not read questionnaire</AlertTitle>
          <AlertDescription>{parseError}</AlertDescription>
        </Alert>
      )}

      {ingest.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not ingest questionnaire</AlertTitle>
          <AlertDescription>{apiErrorText(ingest.error)}</AlertDescription>
        </Alert>
      )}

      {ingest.isSuccess && <IngestResult result={ingest.data} />}
    </section>
  );
}

/**
 * Render the PARSE-ONLY correlation result from
 * `POST .../dd-questionnaire/ingest`: the resolved vendor, the carry-forward
 * questionnaire id / format / ingest timestamp, and the per-question
 * correlated responses map (keyed by `question.id`).
 */
function IngestResult({ result }: { result: DDQuestionnaireIngestResult }) {
  const responseEntries = Object.entries(result.responses);
  return (
    <Alert>
      <AlertTitle>Questionnaire ingested</AlertTitle>
      <AlertDescription>
        <div className="stack-2">
          <p>
            Correlated to vendor{" "}
            <code className="kbd">{result.vendor.name ?? result.vendor.id}</code>{" "}
            (parse-only — the vendor was not modified).
          </p>
          <p className="text-xs muted">
            {result.questionnaire_id ? (
              <>
                Questionnaire{" "}
                <code className="kbd">{result.questionnaire_id}</code>
                {" · "}
              </>
            ) : null}
            {result.format ? (
              <>
                Format <code className="kbd">{result.format}</code>
                {" · "}
              </>
            ) : null}
            Ingested <code className="kbd">{result.ingested_at}</code>
          </p>
          {responseEntries.length === 0 ? (
            <p className="text-xs muted">No responses correlated.</p>
          ) : (
            <ul className="reset stack-1">
              {responseEntries.map(([questionId, response]) => (
                <li
                  key={questionId}
                  className="row-between text-xs"
                  style={{ gap: "0.75rem" }}
                >
                  <code className="kbd">{questionId}</code>
                  <span className="muted">
                    {response === "" ? (
                      <span className="dim">no response</span>
                    ) : (
                      response
                    )}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </AlertDescription>
    </Alert>
  );
}
