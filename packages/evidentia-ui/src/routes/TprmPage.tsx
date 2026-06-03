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
  type CriticalityTier,
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
                <VendorCard vendor={vendor} />
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function VendorCard({ vendor }: { vendor: Vendor }) {
  const tier = vendor.criticality_tier;
  return (
    <Card className="card-hover" style={{ height: "100%" }}>
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
