import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";

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
  type ModelInventory,
  type ModelInventoryInput,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import type { components } from "@/types/openapi";

/**
 * Model-risk inventory screen (SR 11-7 / SR 26-02).
 *
 * Lists the local model-inventory store (`GET /api/model-risk/models`, a
 * `{total, skip, limit, items}` envelope) as a card grid. Selecting a card
 * opens an in-page detail panel showing the full `ModelInventory` record
 * with four actions:
 *   - **Edit** — an inline form that PUTs the required fields back through
 *     `updateModel`.
 *   - **Delete** — a two-step confirm wired to `deleteModel`.
 *   - **Documentation** — fetches the server-rendered model-card markdown
 *     (`modelDocumentation`) and shows it as preformatted text.
 *   - **Validation report** — fetches the validation-report markdown
 *     (`modelValidationReport`) and shows it as preformatted text.
 *
 * A "New model" form at the top sends the six required `ModelInventoryInput`
 * fields (name / owner / purpose / methodology / tier / vendor_or_internal);
 * the server fills id / timestamps and computes `next_validation_due` from
 * the tier cadence. Every mutation invalidates the list query on success.
 *
 * Markdown from the two report endpoints is rendered as preformatted text
 * only (a `<pre>` whose text content is the raw string); the report markdown
 * is never passed through any raw-HTML React prop.
 */

type Tier = components["schemas"]["Tier"];
type Methodology = components["schemas"]["Methodology"];
type Provenance = components["schemas"]["Provenance"];

const TIER_OPTIONS: [Tier, string][] = [
  ["tier_1", "Tier 1"],
  ["tier_2", "Tier 2"],
  ["tier_3", "Tier 3"],
];

const TIER_LABELS: Record<Tier, string> = {
  tier_1: "Tier 1",
  tier_2: "Tier 2",
  tier_3: "Tier 3",
};

/** Tier -> severity Badge variant (tier_1 = highest scrutiny). */
const TIER_BADGE_VARIANT: Record<Tier, "critical" | "high" | "medium"> = {
  tier_1: "critical",
  tier_2: "high",
  tier_3: "medium",
};

const METHODOLOGY_OPTIONS: [Methodology, string][] = [
  ["statistical", "Statistical"],
  ["ml", "ML"],
  ["rules_based", "Rules-based"],
  ["llm", "LLM"],
  ["expert_judgment", "Expert judgment"],
  ["hybrid", "Hybrid"],
];

const METHODOLOGY_LABELS: Record<Methodology, string> = {
  statistical: "Statistical",
  ml: "ML",
  rules_based: "Rules-based",
  llm: "LLM",
  expert_judgment: "Expert judgment",
  hybrid: "Hybrid",
};

const PROVENANCE_OPTIONS: [Provenance, string][] = [
  ["internal", "Internal"],
  ["vendor", "Vendor"],
];

const PROVENANCE_LABELS: Record<Provenance, string> = {
  internal: "Internal",
  vendor: "Vendor",
};

export function ModelRiskPage() {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["model-risk"],
    queryFn: () => api.listModels(),
  });

  const items = query.data?.items ?? [];
  const selected = items.find((it) => it.id === selectedId) ?? null;

  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">Model risk</h1>
        <p className="page-sub">
          {query.data
            ? `${items.length} of ${query.data.total} models`
            : "SR 11-7 model-risk inventory."}
        </p>
      </header>

      <NewModelForm />

      <section className="stack-3" aria-label="Model inventory">
        <h2 className="section-num">Model inventory</h2>

        {query.isError && (
          <Card className="border-dest" role="alert">
            <CardContent className="card-body" style={{ padding: "1.5rem" }}>
              <span className="text-sm text-destructive">
                Could not fetch models. Is the backend running?
              </span>
            </CardContent>
          </Card>
        )}

        {query.isLoading && (
          <ul
            className="reset grid"
            style={{
              gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
            }}
          >
            {Array.from({ length: 6 }).map((_, i) => (
              <li key={i} className="reset">
                <div className="skel" style={{ height: "8rem" }} />
              </li>
            ))}
          </ul>
        )}

        {query.isSuccess && items.length === 0 && (
          <div className="empty-state">
            No models yet. Register your first model above, or with{" "}
            <code className="kbd">evidentia model-risk add</code>.
          </div>
        )}

        {items.length > 0 && (
          <ul
            className="reset grid"
            style={{
              gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
            }}
          >
            {items.map((model) => {
              const isSelected = model.id === selectedId;
              return (
                <li key={model.id ?? model.name} className="reset">
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
                      setSelectedId(isSelected ? null : (model.id ?? null))
                    }
                  >
                    <Card
                      className={cn("card-hover", isSelected && "border-dest")}
                      style={{ height: "100%" }}
                    >
                      <CardHeader className="stack-2">
                        <div className="row gap-2 wrap">
                          <Badge variant={TIER_BADGE_VARIANT[model.tier]}>
                            {TIER_LABELS[model.tier]}
                          </Badge>
                          <Badge variant="outline">
                            {METHODOLOGY_LABELS[model.methodology]}
                          </Badge>
                          <Badge variant="secondary">
                            {PROVENANCE_LABELS[model.vendor_or_internal]}
                          </Badge>
                        </div>
                        <CardTitle className="base">{model.name}</CardTitle>
                      </CardHeader>
                      <CardContent className="pt-0 text-xs muted stack-2">
                        <div>
                          Owner: <code className="kbd">{model.owner}</code>
                        </div>
                        <div>
                          Next validation due:{" "}
                          {model.next_validation_due ? (
                            <code className="kbd">
                              {model.next_validation_due}
                            </code>
                          ) : (
                            <span className="dim">not scheduled</span>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      {selected && (
        <ModelDetail
          model={selected}
          onClose={() => setSelectedId(null)}
          onDeleted={() => setSelectedId(null)}
        />
      )}
    </div>
  );
}

/**
 * In-page detail panel for a single model: full record + the four actions
 * (Edit / Delete / Documentation / Validation report).
 */
function ModelDetail({
  model,
  onClose,
  onDeleted,
}: {
  model: ModelInventory;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  // Which markdown report (if any) is currently displayed.
  const [report, setReport] = useState<"documentation" | "validation" | null>(
    null,
  );

  const deleteMutation = useMutation({
    mutationFn: () => api.deleteModel(model.id ?? ""),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["model-risk"] });
      onDeleted();
    },
  });

  const docQuery = useQuery({
    queryKey: ["model-risk", model.id, "documentation"],
    queryFn: () => api.modelDocumentation(model.id ?? ""),
    enabled: report === "documentation",
  });

  const validationQuery = useQuery({
    queryKey: ["model-risk", model.id, "validation-report"],
    queryFn: () => api.modelValidationReport(model.id ?? ""),
    enabled: report === "validation",
  });

  if (editing) {
    return (
      <EditModelForm
        model={model}
        onCancel={() => setEditing(false)}
        onSaved={() => setEditing(false)}
      />
    );
  }

  return (
    <section
      className="stack-4"
      aria-labelledby="model-detail-heading"
      aria-busy={deleteMutation.isPending}
    >
      <Card>
        <CardHeader className="stack-2">
          <div
            className="row-between gap-4 wrap"
            style={{ alignItems: "flex-start" }}
          >
            <div className="stack-2">
              <CardTitle id="model-detail-heading" className="base">
                {model.name}
              </CardTitle>
              <CardDescription>
                <Badge variant={TIER_BADGE_VARIANT[model.tier]}>
                  {TIER_LABELS[model.tier]}
                </Badge>{" "}
                <Badge variant="outline">
                  {METHODOLOGY_LABELS[model.methodology]}
                </Badge>{" "}
                <Badge variant="secondary">
                  {PROVENANCE_LABELS[model.vendor_or_internal]}
                </Badge>
              </CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={onClose}>
              Close
            </Button>
          </div>
        </CardHeader>
        <CardContent className="stack-4 pt-0">
          <dl className="stack-3 text-sm">
            <Field label="Owner">
              <code className="kbd">{model.owner}</code>
            </Field>
            <Field label="Purpose">{model.purpose}</Field>
            {model.vendor_id && (
              <Field label="Vendor id">
                <code className="kbd">{model.vendor_id}</code>
              </Field>
            )}
            <Field label="Last validation date">
              {model.last_validation_date ?? (
                <span className="dim">never</span>
              )}
            </Field>
            <Field label="Next validation due">
              {model.next_validation_due ?? (
                <span className="dim">not scheduled</span>
              )}
            </Field>
            <Field label="Retirement plan">
              {model.retirement_plan ?? (
                <span className="dim">none — indefinite use</span>
              )}
            </Field>
            <Field label="Inputs">
              {model.inputs && model.inputs.length > 0 ? (
                model.inputs.map((i) => i.name).join(", ")
              ) : (
                <span className="dim">none documented</span>
              )}
            </Field>
            <Field label="Outputs">
              {model.outputs && model.outputs.length > 0 ? (
                model.outputs.map((o) => o.name).join(", ")
              ) : (
                <span className="dim">none documented</span>
              )}
            </Field>
            <Field label="Open findings">
              {model.validation_findings && model.validation_findings.length > 0
                ? model.validation_findings.length
                : 0}
            </Field>
            {model.notes && <Field label="Notes">{model.notes}</Field>}
          </dl>

          {deleteMutation.isError && (
            <Alert variant="destructive">
              <AlertTitle>Could not delete model</AlertTitle>
              <AlertDescription>
                {deleteMutation.error instanceof ApiError &&
                deleteMutation.error.payload
                  ? JSON.stringify(deleteMutation.error.payload)
                  : String(deleteMutation.error)}
              </AlertDescription>
            </Alert>
          )}

          <div className="row gap-2 wrap border-t pt-4" aria-label="Actions">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setEditing(true)}
            >
              Edit
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() =>
                setReport(report === "documentation" ? null : "documentation")
              }
              aria-pressed={report === "documentation"}
            >
              Documentation
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() =>
                setReport(report === "validation" ? null : "validation")
              }
              aria-pressed={report === "validation"}
            >
              Validation report
            </Button>
            {confirmingDelete ? (
              <div className="row gap-2 wrap" aria-label="Confirm delete">
                <span className="text-xs faint">Delete this model?</span>
                <Button
                  type="button"
                  variant="destructive"
                  size="sm"
                  disabled={deleteMutation.isPending}
                  onClick={() => deleteMutation.mutate()}
                >
                  {deleteMutation.isPending ? "Deleting..." : "Confirm delete"}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setConfirmingDelete(false)}
                >
                  Cancel
                </Button>
              </div>
            ) : (
              <Button
                type="button"
                variant="destructive"
                size="sm"
                onClick={() => setConfirmingDelete(true)}
              >
                Delete
              </Button>
            )}
          </div>

          {report === "documentation" && (
            <MarkdownReport
              heading="Model documentation"
              isLoading={docQuery.isLoading}
              isError={docQuery.isError}
              markdown={docQuery.data}
            />
          )}
          {report === "validation" && (
            <MarkdownReport
              heading="Validation report"
              isLoading={validationQuery.isLoading}
              isError={validationQuery.isError}
              markdown={validationQuery.data}
            />
          )}
        </CardContent>
      </Card>
    </section>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="stack-1">
      <dt className="text-xs faint">{label}</dt>
      <dd className="reset">{children}</dd>
    </div>
  );
}

/**
 * Renders a server-rendered markdown report as PREFORMATTED TEXT only.
 * The string is placed in a `<pre>` as JSX text content, so React escapes
 * it; the markdown is never treated as HTML.
 */
function MarkdownReport({
  heading,
  isLoading,
  isError,
  markdown,
}: {
  heading: string;
  isLoading: boolean;
  isError: boolean;
  markdown: string | undefined;
}) {
  return (
    <div className="stack-2">
      <h3 className="section-num">{heading}</h3>
      {isLoading && <div className="skel" style={{ height: "6rem" }} />}
      {isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not load {heading.toLowerCase()}</AlertTitle>
          <AlertDescription>
            The report endpoint returned an error.
          </AlertDescription>
        </Alert>
      )}
      {!isLoading && !isError && markdown != null && (
        <pre
          className="kbd"
          style={{
            whiteSpace: "pre-wrap",
            overflowX: "auto",
            padding: "1rem",
            margin: 0,
          }}
        >
          {markdown}
        </pre>
      )}
    </div>
  );
}

const EMPTY_FORM = {
  name: "",
  owner: "",
  purpose: "",
  methodology: "ml" as Methodology,
  tier: "tier_2" as Tier,
  vendor_or_internal: "internal" as Provenance,
};

type ModelFormState = typeof EMPTY_FORM;

/** Build the required-fields `ModelInventoryInput` body from the form state. */
function toInput(form: ModelFormState): ModelInventoryInput {
  return {
    name: form.name.trim(),
    owner: form.owner.trim(),
    purpose: form.purpose.trim(),
    methodology: form.methodology,
    tier: form.tier,
    vendor_or_internal: form.vendor_or_internal,
  };
}

function NewModelForm() {
  const queryClient = useQueryClient();
  const [form, setForm] = useState<ModelFormState>({ ...EMPTY_FORM });

  const mutation = useMutation({
    mutationFn: (body: ModelInventoryInput) => api.createModel(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["model-risk"] });
      setForm({ ...EMPTY_FORM });
    },
  });

  const canSubmit =
    form.name.trim().length > 0 &&
    form.owner.trim().length > 0 &&
    form.purpose.trim().length > 0 &&
    !mutation.isPending;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="base">New model</CardTitle>
        <CardDescription>
          Register a model in the inventory. The server fills the id +
          timestamps and computes the next validation-due date from the tier.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ModelFields
          form={form}
          setForm={setForm}
          idPrefix="new-model"
          onSubmit={() => {
            if (canSubmit) mutation.mutate(toInput(form));
          }}
          footer={
            <div className="row-between border-t pt-4">
              <p className="text-xs muted">
                Six required fields. The model lands in the inventory below.
              </p>
              <Button type="submit" disabled={!canSubmit}>
                {mutation.isPending ? "Adding..." : "Add model"}
              </Button>
            </div>
          }
        />

        {mutation.isError && (
          <Alert variant="destructive" className="mt-4">
            <AlertTitle>Could not add model</AlertTitle>
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

function EditModelForm({
  model,
  onCancel,
  onSaved,
}: {
  model: ModelInventory;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const queryClient = useQueryClient();
  const [form, setForm] = useState<ModelFormState>({
    name: model.name,
    owner: model.owner,
    purpose: model.purpose,
    methodology: model.methodology,
    tier: model.tier,
    vendor_or_internal: model.vendor_or_internal,
  });

  const mutation = useMutation({
    mutationFn: (body: ModelInventoryInput) =>
      api.updateModel(model.id ?? "", body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["model-risk"] });
      onSaved();
    },
  });

  const canSubmit =
    form.name.trim().length > 0 &&
    form.owner.trim().length > 0 &&
    form.purpose.trim().length > 0 &&
    !mutation.isPending;

  return (
    <section className="stack-4" aria-label="Edit model">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">Edit model</CardTitle>
          <CardDescription>{model.name}</CardDescription>
        </CardHeader>
        <CardContent>
          <ModelFields
            form={form}
            setForm={setForm}
            idPrefix="edit-model"
            onSubmit={() => {
              if (canSubmit) mutation.mutate(toInput(form));
            }}
            footer={
              <div className="row gap-2 wrap border-t pt-4">
                <Button type="submit" disabled={!canSubmit}>
                  {mutation.isPending ? "Saving..." : "Save changes"}
                </Button>
                <Button type="button" variant="outline" onClick={onCancel}>
                  Cancel
                </Button>
              </div>
            }
          />

          {mutation.isError && (
            <Alert variant="destructive" className="mt-4">
              <AlertTitle>Could not save model</AlertTitle>
              <AlertDescription>
                {mutation.error instanceof ApiError && mutation.error.payload
                  ? JSON.stringify(mutation.error.payload)
                  : String(mutation.error)}
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

/** Shared required-field inputs for the create + edit forms. */
function ModelFields({
  form,
  setForm,
  idPrefix,
  onSubmit,
  footer,
}: {
  form: ModelFormState;
  setForm: (next: ModelFormState) => void;
  idPrefix: string;
  onSubmit: () => void;
  footer: ReactNode;
}) {
  return (
    <form
      className="stack-5"
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit();
      }}
    >
      <div className="grid grid-2">
        <div className="stack-2">
          <Label htmlFor={`${idPrefix}-name`}>Name</Label>
          <Input
            id={`${idPrefix}-name`}
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            placeholder="Fraud-detector LLM-v0.4"
            required
          />
        </div>
        <div className="stack-2">
          <Label htmlFor={`${idPrefix}-owner`}>Owner</Label>
          <Input
            id={`${idPrefix}-owner`}
            value={form.owner}
            onChange={(e) => setForm({ ...form, owner: e.target.value })}
            placeholder="alice@example.com"
            required
          />
        </div>
      </div>

      <div className="stack-2">
        <Label htmlFor={`${idPrefix}-purpose`}>Purpose</Label>
        <Input
          id={`${idPrefix}-purpose`}
          value={form.purpose}
          onChange={(e) => setForm({ ...form, purpose: e.target.value })}
          placeholder="Score consumer credit applications..."
          required
        />
      </div>

      <div className="stack-2">
        <span className="text-sm font-medium leading-none">Methodology</span>
        <div
          className="row wrap gap-2"
          role="radiogroup"
          aria-label="Methodology"
        >
          {METHODOLOGY_OPTIONS.map(([value, label]) => (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={form.methodology === value}
              onClick={() => setForm({ ...form, methodology: value })}
              className={cn("pill", form.methodology === value && "on")}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="stack-2">
        <span className="text-sm font-medium leading-none">Tier</span>
        <div className="row wrap gap-2" role="radiogroup" aria-label="Tier">
          {TIER_OPTIONS.map(([value, label]) => (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={form.tier === value}
              onClick={() => setForm({ ...form, tier: value })}
              className={cn("pill", form.tier === value && "on")}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="stack-2">
        <span className="text-sm font-medium leading-none">Provenance</span>
        <div
          className="row wrap gap-2"
          role="radiogroup"
          aria-label="Provenance"
        >
          {PROVENANCE_OPTIONS.map(([value, label]) => (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={form.vendor_or_internal === value}
              onClick={() => setForm({ ...form, vendor_or_internal: value })}
              className={cn("pill", form.vendor_or_internal === value && "on")}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {footer}
    </form>
  );
}
