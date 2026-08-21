/**
 * AI acquisitions console — OMB M-25-22 procurement lifecycle (v0.12).
 *
 * Surfaces the four `ai-gov acquisition` CLI verbs
 * (`register` / `list` / `show` / `set-phase`) that shipped api-only in
 * v0.11.0, closing their `docs/cli-gui-parity.yaml` rows.
 *
 * Shape mirrors the other CRUD consoles: a list of cards, a register
 * form, and a detail panel that carries the §4 phase roll-up plus the
 * set-phase form. The backend declares real response models
 * (v0.12 WU-3), so everything here is typed against generated schemas
 * rather than `Record<string, unknown>`.
 */
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
import { Textarea } from "@/components/ui/textarea";
import {
  api,
  ApiError,
  type AcquisitionPhase,
  type AcquisitionPhaseStatus,
  type AIAcquisition,
  type HighImpactDetermination,
  type RegisterAcquisitionRequest,
  type SetAcquisitionPhaseRequest,
} from "@/lib/api";
import { cn } from "@/lib/utils";

const QUERY_KEY = ["ai-gov-acquisitions"];

/** The six M-25-22 §4 lifecycle phases, in procurement order. */
const PHASE_OPTIONS: [AcquisitionPhase, string][] = [
  ["identification_of_requirements", "Identification of requirements"],
  ["market_research_and_planning", "Market research & planning"],
  ["solicitation_development", "Solicitation development"],
  ["selection_and_award", "Selection & award"],
  ["contract_administration", "Contract administration"],
  ["contract_closeout", "Contract closeout"],
];

const PHASE_STATUS_OPTIONS: [AcquisitionPhaseStatus, string][] = [
  ["not_started", "Not started"],
  ["in_progress", "In progress"],
  ["complete", "Complete"],
];

/** §4(a) initial determination, in M-25-21 vocabulary. */
const DETERMINATION_OPTIONS: [HighImpactDetermination, string][] = [
  ["not_assessed", "Not assessed"],
  ["not_high_impact", "Not high-impact"],
  ["high_impact", "Likely high-impact"],
];

function apiErrorText(error: unknown): string {
  return error instanceof ApiError
    ? error.message
    : error instanceof Error
      ? error.message
      : "Unknown error";
}

function phaseLabel(phase: string): string {
  return PHASE_OPTIONS.find(([value]) => value === phase)?.[1] ?? phase;
}

export function AcquisitionsPage() {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const listQuery = useQuery({
    queryKey: QUERY_KEY,
    queryFn: () => api.listAcquisitions(),
  });

  return (
    <div className="stack-6">
      <div className="stack-2">
        <h1 className="page-title">AI acquisitions</h1>
        <p className="muted">
          OMB M-25-22 procurement-lifecycle tracking. Each record carries the
          §4(a) high-impact determination and per-phase status across the six
          §4 lifecycle phases.
        </p>
      </div>

      <RegisterAcquisitionForm onRegistered={setSelectedId} />

      {listQuery.isPending && <p className="muted">Loading acquisitions…</p>}

      {listQuery.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not load acquisitions</AlertTitle>
          <AlertDescription>{apiErrorText(listQuery.error)}</AlertDescription>
        </Alert>
      )}

      {listQuery.data && (
        <section className="stack-4" aria-label="Tracked acquisitions">
          <h2 className="section-num">
            Tracked acquisitions{" "}
            <Badge variant="secondary">{listQuery.data.count}</Badge>
          </h2>

          {listQuery.data.count === 0 ? (
            <p className="muted">
              No acquisitions tracked yet. Register one above.
            </p>
          ) : (
            <div className="stack-3">
              {listQuery.data.acquisitions.map((record) => (
                <AcquisitionCard
                  key={record.acquisition_id}
                  record={record}
                  selected={record.acquisition_id === selectedId}
                  onSelect={() =>
                    setSelectedId(
                      record.acquisition_id === selectedId
                        ? null
                        : (record.acquisition_id ?? null),
                    )
                  }
                />
              ))}
            </div>
          )}
        </section>
      )}

      {selectedId && (
        <AcquisitionDetailPanel
          acquisitionId={selectedId}
          onClose={() => setSelectedId(null)}
        />
      )}
    </div>
  );
}

function AcquisitionCard({
  record,
  selected,
  onSelect,
}: {
  record: AIAcquisition;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <Card
      aria-label={`Acquisition ${record.name}`}
      className={cn(selected && "border-primary")}
    >
      <CardHeader>
        <div className="row-between">
          <div className="stack-1">
            <CardTitle>{record.name}</CardTitle>
            {record.solicitation_reference && (
              <CardDescription>
                {record.solicitation_reference}
              </CardDescription>
            )}
          </div>
          <div className="row gap-2">
            <Badge
              variant={
                record.likely_high_impact === "high_impact"
                  ? "destructive"
                  : "secondary"
              }
            >
              {DETERMINATION_OPTIONS.find(
                ([value]) => value === record.likely_high_impact,
              )?.[1] ?? record.likely_high_impact}
            </Badge>
            <Button variant="outline" size="sm" onClick={onSelect}>
              {selected ? "Hide" : "Details"}
            </Button>
          </div>
        </div>
      </CardHeader>
      {record.description && (
        <CardContent>
          <p className="muted text-sm">{record.description}</p>
        </CardContent>
      )}
    </Card>
  );
}

function AcquisitionDetailPanel({
  acquisitionId,
  onClose,
}: {
  acquisitionId: string;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const detailQuery = useQuery({
    queryKey: [...QUERY_KEY, acquisitionId],
    queryFn: () => api.getAcquisition(acquisitionId),
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: QUERY_KEY });
  };

  return (
    <Card aria-label="Acquisition detail" className="border-t">
      <CardHeader>
        <div className="row-between">
          <CardTitle>Acquisition detail</CardTitle>
          <Button variant="ghost" size="sm" onClick={onClose}>
            Close
          </Button>
        </div>
      </CardHeader>
      <CardContent className="stack-4">
        {detailQuery.isPending && <p className="muted">Loading…</p>}

        {detailQuery.isError && (
          <Alert variant="destructive">
            <AlertTitle>Could not load acquisition</AlertTitle>
            <AlertDescription>
              {apiErrorText(detailQuery.error)}
            </AlertDescription>
          </Alert>
        )}

        {detailQuery.data && (
          <>
            <section className="stack-2" aria-label="Lifecycle progress">
              <h3 className="section-num">§4 lifecycle progress</h3>
              <div className="row wrap gap-2">
                <Badge variant="secondary">
                  {detailQuery.data.progress.complete} /{" "}
                  {detailQuery.data.progress.total} complete
                </Badge>
                <Badge variant="secondary">
                  {detailQuery.data.progress.in_progress} in progress
                </Badge>
                <Badge variant="secondary">
                  {detailQuery.data.progress.missing.length} not recorded
                </Badge>
                {detailQuery.data.progress.lifecycle_complete && (
                  <Badge>Lifecycle complete</Badge>
                )}
              </div>
              {detailQuery.data.progress.missing.length > 0 && (
                <p className="muted text-sm">
                  No status recorded for:{" "}
                  {detailQuery.data.progress.missing
                    .map((phase) => phaseLabel(phase))
                    .join(", ")}
                  .
                </p>
              )}
            </section>

            <SetPhaseForm
              acquisitionId={acquisitionId}
              onSaved={() => {
                invalidate();
                detailQuery.refetch();
              }}
            />
          </>
        )}
      </CardContent>
    </Card>
  );
}

function RegisterAcquisitionForm({
  onRegistered,
}: {
  onRegistered: (acquisitionId: string) => void;
}) {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [solicitation, setSolicitation] = useState("");
  const [description, setDescription] = useState("");
  const [determination, setDetermination] =
    useState<HighImpactDetermination>("not_assessed");

  const mutation = useMutation({
    mutationFn: (body: RegisterAcquisitionRequest) =>
      api.registerAcquisition(body),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: QUERY_KEY });
      setName("");
      setSolicitation("");
      setDescription("");
      setDetermination("not_assessed");
      onRegistered(result.acquisition_id);
    },
  });

  return (
    <form
      className="stack-4 rounded-md border p-4"
      aria-label="Register acquisition"
      onSubmit={(e) => {
        e.preventDefault();
        if (mutation.isPending) return;
        mutation.mutate({
          name: name.trim(),
          likely_high_impact: determination,
          ...(solicitation.trim()
            ? { solicitation_reference: solicitation.trim() }
            : {}),
          ...(description.trim() ? { description: description.trim() } : {}),
        });
      }}
    >
      <h2 className="section-num">Register an acquisition</h2>

      <div className="stack-2">
        <Label htmlFor="acquisition-name">Name</Label>
        <Input
          id="acquisition-name"
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Case-triage LLM service"
        />
      </div>

      <div className="stack-2">
        <Label htmlFor="acquisition-solicitation">
          Solicitation reference (optional)
        </Label>
        <Input
          id="acquisition-solicitation"
          value={solicitation}
          onChange={(e) => setSolicitation(e.target.value)}
          placeholder="RFP-2026-014"
        />
      </div>

      <div className="stack-2">
        <Label htmlFor="acquisition-description">
          Description (optional)
        </Label>
        <Textarea
          id="acquisition-description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="What is being procured, and for which mission need."
        />
      </div>

      <div className="stack-2">
        <span className="text-sm font-medium leading-none">
          §4(a) initial determination
        </span>
        <div
          className="row wrap gap-2"
          role="radiogroup"
          aria-label="Initial high-impact determination"
        >
          {DETERMINATION_OPTIONS.map(([value, label]) => (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={determination === value}
              onClick={() => setDetermination(value)}
              className={cn("pill", determination === value && "on")}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="row-end">
        <Button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? "Registering…" : "Register acquisition"}
        </Button>
      </div>

      {mutation.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not register acquisition</AlertTitle>
          <AlertDescription>{apiErrorText(mutation.error)}</AlertDescription>
        </Alert>
      )}
    </form>
  );
}

function SetPhaseForm({
  acquisitionId,
  onSaved,
}: {
  acquisitionId: string;
  onSaved: () => void;
}) {
  const [phase, setPhase] = useState<AcquisitionPhase>(
    "identification_of_requirements",
  );
  const [status, setStatus] = useState<AcquisitionPhaseStatus>("in_progress");
  const [notes, setNotes] = useState("");

  const mutation = useMutation({
    mutationFn: (body: SetAcquisitionPhaseRequest) =>
      api.setAcquisitionPhase(acquisitionId, body),
    onSuccess: onSaved,
  });

  return (
    <form
      className="stack-4 border-t pt-4"
      aria-label="Set acquisition phase"
      onSubmit={(e) => {
        e.preventDefault();
        if (mutation.isPending) return;
        mutation.mutate({
          phase,
          status,
          ...(notes.trim() ? { notes: notes.trim() } : {}),
        });
      }}
    >
      <h3 className="section-num">Set lifecycle phase (OMB M-25-22 §4)</h3>

      <div className="stack-2">
        <span className="text-sm font-medium leading-none">Phase</span>
        <div
          className="row wrap gap-2"
          role="radiogroup"
          aria-label="Lifecycle phase"
        >
          {PHASE_OPTIONS.map(([value, label]) => (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={phase === value}
              onClick={() => setPhase(value)}
              className={cn("pill", phase === value && "on")}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="stack-2">
        <span className="text-sm font-medium leading-none">Status</span>
        <div
          className="row wrap gap-2"
          role="radiogroup"
          aria-label="Phase status"
        >
          {PHASE_STATUS_OPTIONS.map(([value, label]) => (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={status === value}
              onClick={() => setStatus(value)}
              className={cn("pill", status === value && "on")}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="stack-2">
        <Label htmlFor="phase-notes">Notes (optional)</Label>
        <Textarea
          id="phase-notes"
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          placeholder="Contracting-officer context, dates, or evidence links."
        />
      </div>

      <div className="row-end">
        <Button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? "Saving…" : "Set phase"}
        </Button>
      </div>

      {mutation.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not set phase</AlertTitle>
          <AlertDescription>{apiErrorText(mutation.error)}</AlertDescription>
        </Alert>
      )}
    </form>
  );
}

export default AcquisitionsPage;
