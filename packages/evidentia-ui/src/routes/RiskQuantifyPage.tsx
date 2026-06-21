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
import { Textarea } from "@/components/ui/textarea";
import {
  api,
  ApiError,
  type RiskQuantifyRequest,
  type RiskQuantifyResponse,
} from "@/lib/api";
import { cn } from "@/lib/utils";

// ── FAIR factor / scenario editor types ─────────────────────────────────
//
// Each FAIR factor is either a single-point scalar or a 3-point PERT range
// (low / most_likely / high — the `PERTRange` schema). The form keeps every
// factor as strings so the inputs stay controlled; `buildScenario` parses
// them to the `number | PERTRange` shape the API expects right before submit.

type FactorMode = "scalar" | "pert";

interface FactorDraft {
  mode: FactorMode;
  scalar: string;
  low: string;
  mostLikely: string;
  high: string;
}

interface ScenarioDraft {
  name: string;
  description: string;
  primaryLoss: FactorDraft;
  secondaryLoss: FactorDraft;
  tef: FactorDraft;
  vulnerability: FactorDraft;
}

type Method = "open-fair" | "fair-mc";

const METHOD_OPTIONS: [Method, string][] = [
  ["open-fair", "Open FAIR (deterministic)"],
  ["fair-mc", "FAIR Monte Carlo"],
];

const emptyFactor = (scalar = ""): FactorDraft => ({
  mode: "scalar",
  scalar,
  low: "",
  mostLikely: "",
  high: "",
});

const emptyScenario = (): ScenarioDraft => ({
  name: "",
  description: "",
  // Seed with illustrative defaults so a first-time operator can submit a
  // valid request immediately and tweak from there.
  primaryLoss: emptyFactor("50000"),
  secondaryLoss: emptyFactor("0"),
  tef: emptyFactor("12"),
  vulnerability: emptyFactor("0.3"),
});

/** A FAIR factor value: scalar OR a 3-point PERT range. */
type FactorValue = number | { low: number; most_likely: number; high: number };

/** Parse one factor draft into the `number | PERTRange` API shape. */
function buildFactor(draft: FactorDraft): FactorValue {
  if (draft.mode === "pert") {
    return {
      low: Number(draft.low),
      most_likely: Number(draft.mostLikely),
      high: Number(draft.high),
    };
  }
  return Number(draft.scalar);
}

/** Is every numeric input on this factor draft a finite number? */
function factorFilled(draft: FactorDraft): boolean {
  const ok = (s: string) => s.trim() !== "" && Number.isFinite(Number(s));
  return draft.mode === "pert"
    ? ok(draft.low) && ok(draft.mostLikely) && ok(draft.high)
    : ok(draft.scalar);
}

function scenarioReady(s: ScenarioDraft): boolean {
  return (
    s.name.trim().length > 0 &&
    s.description.trim().length > 0 &&
    factorFilled(s.primaryLoss) &&
    factorFilled(s.secondaryLoss) &&
    factorFilled(s.tef) &&
    factorFilled(s.vulnerability)
  );
}

function buildRequest(
  method: Method,
  scenarios: ScenarioDraft[],
  iterations: number,
  seed: string,
): RiskQuantifyRequest {
  const body: RiskQuantifyRequest = {
    method,
    iterations,
    scenarios: scenarios.map((s) => ({
      name: s.name.trim(),
      description: s.description.trim(),
      primary_loss: buildFactor(s.primaryLoss),
      secondary_loss: buildFactor(s.secondaryLoss),
      tef: buildFactor(s.tef),
      vulnerability: buildFactor(s.vulnerability),
    })),
  };
  if (method === "fair-mc" && seed.trim() !== "") {
    body.seed = Number(seed);
  }
  return body;
}

const fmtMoney = (n: number) =>
  n.toLocaleString(undefined, {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
  });

// ── Type guards on the discriminated response union ──────────────────────

function isOpenFair(
  r: RiskQuantifyResponse,
): r is Extract<RiskQuantifyResponse, { total_ale: number }> {
  return "total_ale" in r;
}

/**
 * Risk Quantify — FAIR / Open FAIR risk-quantification console.
 *
 * Builds a `POST /api/risk/quantify` request: a method toggle (open-fair /
 * fair-mc), a repeatable scenarios editor (each FAIR factor scalar OR PERT
 * range), plus Monte-Carlo iterations + seed. Renders the deterministic
 * per-scenario ALE + total (open-fair) or the P10/P50/P90 + mean simulation
 * bands (fair-mc).
 */
export function RiskQuantifyPage() {
  const [method, setMethod] = useState<Method>("open-fair");
  const [iterations, setIterations] = useState(10000);
  const [seed, setSeed] = useState("");
  const [scenarios, setScenarios] = useState<ScenarioDraft[]>([
    emptyScenario(),
  ]);

  const mutation = useMutation({
    mutationFn: (body: RiskQuantifyRequest) => api.riskQuantify(body),
  });

  const patchScenario = (idx: number, patch: Partial<ScenarioDraft>) =>
    setScenarios((prev) =>
      prev.map((s, i) => (i === idx ? { ...s, ...patch } : s)),
    );

  const patchFactor = (
    idx: number,
    key: keyof Pick<
      ScenarioDraft,
      "primaryLoss" | "secondaryLoss" | "tef" | "vulnerability"
    >,
    patch: Partial<FactorDraft>,
  ) =>
    setScenarios((prev) =>
      prev.map((s, i) =>
        i === idx ? { ...s, [key]: { ...s[key], ...patch } } : s,
      ),
    );

  const addScenario = () =>
    setScenarios((prev) => [...prev, emptyScenario()]);

  const removeScenario = (idx: number) =>
    setScenarios((prev) =>
      prev.length === 1 ? prev : prev.filter((_, i) => i !== idx),
    );

  const canSubmit =
    scenarios.length > 0 && scenarios.every(scenarioReady) && !mutation.isPending;

  const submit = () => {
    if (!canSubmit) return;
    mutation.mutate(buildRequest(method, scenarios, iterations, seed));
  };

  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">Risk Quantify</h1>
        <p className="page-sub">
          Quantify cyber risk in dollars with Open FAIR. Build one or more
          scenarios, pick a method, and get per-scenario ALE (deterministic)
          or P10/P50/P90 loss bands (Monte Carlo).
        </p>
      </header>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">Configuration</CardTitle>
          <CardDescription>
            Choose the quantification method. Monte Carlo adds iteration +
            seed controls for reproducible percentile bands.
          </CardDescription>
        </CardHeader>
        <CardContent className="stack-5">
          <div className="stack-2">
            <span className="text-sm font-medium leading-none">Method</span>
            <div
              className="row wrap gap-2"
              role="radiogroup"
              aria-label="Quantification method"
            >
              {METHOD_OPTIONS.map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  role="radio"
                  aria-checked={method === value}
                  onClick={() => setMethod(value)}
                  className={cn("pill", method === value && "on")}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          {method === "fair-mc" && (
            <div className="grid grid-2">
              <div className="stack-2">
                <Label htmlFor="mc-iterations">Iterations</Label>
                <Input
                  id="mc-iterations"
                  type="number"
                  min={1}
                  max={1000000}
                  value={iterations}
                  onChange={(e) =>
                    setIterations(
                      Math.max(
                        1,
                        Math.min(1000000, Number(e.target.value) || 10000),
                      ),
                    )
                  }
                />
                <p className="text-xs muted">
                  FAIR-U convergence point is ~10,000; capped at 1,000,000.
                </p>
              </div>
              <div className="stack-2">
                <Label htmlFor="mc-seed">Seed (optional)</Label>
                <Input
                  id="mc-seed"
                  type="number"
                  placeholder="e.g. 42 for reproducible bands"
                  value={seed}
                  onChange={(e) => setSeed(e.target.value)}
                />
                <p className="text-xs muted">
                  Set a seed for deterministic, golden-file-friendly runs.
                </p>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <section className="stack-3" aria-label="Scenarios">
        <div className="row-between">
          <h2 className="section-num">Scenarios</h2>
          <Button type="button" variant="outline" onClick={addScenario}>
            Add scenario
          </Button>
        </div>

        {scenarios.map((scenario, idx) => (
          <ScenarioEditor
            key={idx}
            index={idx}
            scenario={scenario}
            canRemove={scenarios.length > 1}
            onPatch={(patch) => patchScenario(idx, patch)}
            onPatchFactor={(key, patch) => patchFactor(idx, key, patch)}
            onRemove={() => removeScenario(idx)}
          />
        ))}
      </section>

      <div className="row-end gap-2">
        <Button onClick={submit} disabled={!canSubmit}>
          {mutation.isPending ? "Quantifying..." : "Quantify risk"}
        </Button>
      </div>

      {mutation.isError && (
        <Alert variant="destructive">
          <AlertTitle>
            {mutation.error instanceof ApiError &&
            (mutation.error.status === 400 || mutation.error.status === 422)
              ? `Invalid request (HTTP ${mutation.error.status})`
              : "Could not quantify risk"}
          </AlertTitle>
          <AlertDescription>
            {mutation.error instanceof ApiError && mutation.error.payload
              ? JSON.stringify(mutation.error.payload)
              : String(mutation.error)}
          </AlertDescription>
        </Alert>
      )}

      {mutation.isSuccess && <ResultPanel result={mutation.data} />}
    </div>
  );
}

// ── Scenario editor ──────────────────────────────────────────────────────

interface ScenarioEditorProps {
  index: number;
  scenario: ScenarioDraft;
  canRemove: boolean;
  onPatch: (patch: Partial<ScenarioDraft>) => void;
  onPatchFactor: (
    key: keyof Pick<
      ScenarioDraft,
      "primaryLoss" | "secondaryLoss" | "tef" | "vulnerability"
    >,
    patch: Partial<FactorDraft>,
  ) => void;
  onRemove: () => void;
}

function ScenarioEditor({
  index,
  scenario,
  canRemove,
  onPatch,
  onPatchFactor,
  onRemove,
}: ScenarioEditorProps) {
  const nameId = `scenario-name-${index}`;
  const descId = `scenario-desc-${index}`;
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="row-between">
          <CardTitle className="base">Scenario {index + 1}</CardTitle>
          {canRemove && (
            <Button
              type="button"
              variant="outline"
              onClick={onRemove}
              aria-label={`Remove scenario ${index + 1}`}
            >
              Remove
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="stack-5">
        <div className="grid grid-2">
          <div className="stack-2">
            <Label htmlFor={nameId}>Name</Label>
            <Input
              id={nameId}
              value={scenario.name}
              onChange={(e) => onPatch({ name: e.target.value })}
              placeholder="Credential stuffing on customer login"
            />
          </div>
        </div>
        <div className="stack-2">
          <Label htmlFor={descId}>Description</Label>
          <Textarea
            id={descId}
            value={scenario.description}
            onChange={(e) => onPatch({ description: e.target.value })}
            placeholder="Threat, asset, and impact narrative."
          />
        </div>

        <div className="grid grid-2">
          <FactorField
            label="Primary loss ($)"
            idBase={`primary-loss-${index}`}
            draft={scenario.primaryLoss}
            onChange={(patch) => onPatchFactor("primaryLoss", patch)}
          />
          <FactorField
            label="Secondary loss ($)"
            idBase={`secondary-loss-${index}`}
            draft={scenario.secondaryLoss}
            onChange={(patch) => onPatchFactor("secondaryLoss", patch)}
          />
          <FactorField
            label="Threat event frequency (events/yr)"
            idBase={`tef-${index}`}
            draft={scenario.tef}
            onChange={(patch) => onPatchFactor("tef", patch)}
          />
          <FactorField
            label="Vulnerability (0–1)"
            idBase={`vulnerability-${index}`}
            draft={scenario.vulnerability}
            onChange={(patch) => onPatchFactor("vulnerability", patch)}
          />
        </div>
      </CardContent>
    </Card>
  );
}

// ── FAIR factor field (scalar OR PERT range) ─────────────────────────────

interface FactorFieldProps {
  label: string;
  idBase: string;
  draft: FactorDraft;
  onChange: (patch: Partial<FactorDraft>) => void;
}

function FactorField({ label, idBase, draft, onChange }: FactorFieldProps) {
  return (
    <div className="stack-2">
      <span className="text-sm font-medium leading-none">{label}</span>
      <div
        className="row gap-2"
        role="radiogroup"
        aria-label={`${label} estimate type`}
      >
        <button
          type="button"
          role="radio"
          aria-checked={draft.mode === "scalar"}
          onClick={() => onChange({ mode: "scalar" })}
          className={cn("chip", draft.mode === "scalar" && "on")}
        >
          Scalar
        </button>
        <button
          type="button"
          role="radio"
          aria-checked={draft.mode === "pert"}
          onClick={() => onChange({ mode: "pert" })}
          className={cn("chip", draft.mode === "pert" && "on")}
        >
          PERT range
        </button>
      </div>

      {draft.mode === "scalar" ? (
        <Input
          id={`${idBase}-scalar`}
          type="number"
          aria-label={`${label} value`}
          value={draft.scalar}
          onChange={(e) => onChange({ scalar: e.target.value })}
        />
      ) : (
        <div className="row gap-2">
          <Input
            id={`${idBase}-low`}
            type="number"
            aria-label={`${label} low`}
            placeholder="low"
            value={draft.low}
            onChange={(e) => onChange({ low: e.target.value })}
          />
          <Input
            id={`${idBase}-mode`}
            type="number"
            aria-label={`${label} most likely`}
            placeholder="most likely"
            value={draft.mostLikely}
            onChange={(e) => onChange({ mostLikely: e.target.value })}
          />
          <Input
            id={`${idBase}-high`}
            type="number"
            aria-label={`${label} high`}
            placeholder="high"
            value={draft.high}
            onChange={(e) => onChange({ high: e.target.value })}
          />
        </div>
      )}
    </div>
  );
}

// ── Result rendering ─────────────────────────────────────────────────────

function ResultPanel({ result }: { result: RiskQuantifyResponse }) {
  if (isOpenFair(result)) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">
            Open FAIR result — {result.scenario_count} scenario
            {result.scenario_count === 1 ? "" : "s"}
          </CardTitle>
          <CardDescription>
            Total ALE:{" "}
            <span className="font-medium">{fmtMoney(result.total_ale)}</span>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="reset rounded-lg border">
            {result.scenarios.map((s, i) => (
              <li
                key={s.id}
                className={cn(
                  "reset row gap-3 px-4 py-3",
                  i > 0 && "border-t",
                )}
              >
                <div className="flex-1 text-sm">
                  <div className="font-medium">{s.name}</div>
                  <div className="text-xs muted">
                    LEF {s.lef.toLocaleString()} /yr · Loss magnitude{" "}
                    {fmtMoney(s.loss_magnitude)}
                  </div>
                </div>
                <span className="font-medium">{fmtMoney(s.ale)}</span>
                <Badge variant="outline" className="capitalize">
                  {s.risk_category}
                </Badge>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    );
  }

  // fair-mc — percentile bands per simulation.
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="base">
          FAIR Monte Carlo result — {result.scenario_count} scenario
          {result.scenario_count === 1 ? "" : "s"}
        </CardTitle>
        <CardDescription>
          Per-scenario loss-exceedance percentile bands.
        </CardDescription>
      </CardHeader>
      <CardContent className="stack-3">
        {result.simulations.map((sim) => (
          <div key={sim.scenario_id} className="rounded-lg border p-4 stack-2">
            <div className="row-between">
              <span className="text-sm font-medium">{sim.scenario_name}</span>
              <span className="text-xs muted">
                {sim.iterations.toLocaleString()} iterations
              </span>
            </div>
            <div className="grid grid-2">
              <Band label="P10" value={fmtMoney(sim.p10)} />
              <Band label="P50 (median)" value={fmtMoney(sim.p50)} />
              <Band label="P90" value={fmtMoney(sim.p90)} />
              <Band label="Mean" value={fmtMoney(sim.mean)} />
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function Band({ label, value }: { label: string; value: string }) {
  return (
    <div className="stack-2">
      <span className="text-xs muted">{label}</span>
      <span className="font-medium">{value}</span>
    </div>
  );
}
