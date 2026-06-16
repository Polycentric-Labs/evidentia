import {
  ArrowRight,
  BadgeCheck,
  Check,
  ExternalLink,
  FileSignature,
  FlaskConical,
  Layers,
  Loader2,
  Play,
  ScanLine,
  ShieldCheck,
} from "lucide-react";
import { useCallback, useRef, useState, type ReactNode } from "react";

import { MetricCard, SeverityBar } from "@/components/common/console";
import { GapTable } from "@/components/gap/GapTable";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { simulateSse } from "@/lib/demo/demo-api";
import {
  FDA_524B_GAPS,
  FDA_524B_REPORT,
  FDA_ORG,
  FDA_RUN_STEPS,
  FDA_SIGNED_ARTIFACT,
  FDA_SYSTEM,
  FDA_TRACEABILITY,
  type RunStep,
  type TraceRow,
  type TraceStatus,
} from "@/lib/demo/fda-fixtures";

/**
 * FDA Section 524B premarket-cybersecurity demo landing page.
 *
 * The single, full-bleed story for the static `VITE_DEMO=true` bundle: one
 * click runs a synthetic gap analysis against FDA's Appendix-1 security control
 * categories, reveals the gaps, traces every STRIDE threat to its 524B control
 * and its verification test, and ends on a signed, reproducible evidence
 * artifact. Renders entirely from `@/lib/demo/fda-fixtures` — zero backend, no
 * `/api` calls. Reuses the console's `MetricCard` / `SeverityBar` / `GapTable`
 * so the results section matches the live Gap Analyze page one-for-one.
 */

type RunPhase = "idle" | "running" | "done";

/** Per-step UI state during the run animation. */
type StepState = "pending" | "active" | "done";

const REPORT = FDA_524B_REPORT;
const coverage = Math.round(REPORT.coverage_percentage);
const satisfied = REPORT.total_controls_in_inventory;
const categories = REPORT.total_controls_required;

export function FdaDemoPage() {
  const [phase, setPhase] = useState<RunPhase>("idle");
  const [stepStates, setStepStates] = useState<StepState[]>(() =>
    FDA_RUN_STEPS.map(() => "pending"),
  );
  const resultsRef = useRef<HTMLDivElement | null>(null);

  const runAnalysis = useCallback(async () => {
    // Reset the stepper and flip into the running phase.
    setPhase("running");
    setStepStates(FDA_RUN_STEPS.map(() => "pending"));

    let index = 0;
    // ~2s total: 6 steps × ~320ms. simulateSse awaits gapMs *before* each
    // event, so the first step lights up after one tick, the rest follow.
    await simulateSse<RunStep>(
      FDA_RUN_STEPS,
      () => {
        const current = index;
        setStepStates((prev) =>
          prev.map((s, i) => {
            if (i < current) return "done";
            if (i === current) return "active";
            return s;
          }),
        );
        index += 1;
      },
      320,
    );

    // Mark every step done, then reveal results.
    setStepStates(FDA_RUN_STEPS.map(() => "done"));
    setPhase("done");

    // Bring the freshly revealed results into view (after paint).
    requestAnimationFrame(() => {
      resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }, []);

  const running = phase === "running";
  const revealed = phase === "done";
  const buttonLabel = running
    ? "Running…"
    : revealed
      ? "Re-run 524B gap analysis"
      : "Run 524B gap analysis";

  return (
    <div className="fda-page">
      {/* 1 ── Top banner strip ─────────────────────────────────────────── */}
      <div className="fda-strip" role="status">
        <FlaskConical className="fda-strip-ic" aria-hidden />
        <span>
          Synthetic demonstration data · powered by{" "}
          <a
            href="https://github.com/Polycentric-Labs/evidentia"
            target="_blank"
            rel="noreferrer"
            className="fda-strip-link"
          >
            Evidentia
          </a>{" "}
          (open source) · no live backend.
        </span>
      </div>

      <div className="fda-container">
        {/* 2 ── Hero ───────────────────────────────────────────────────── */}
        <header className="fda-hero">
          <p className="fda-eyebrow">
            <ShieldCheck className="fda-eyebrow-ic" aria-hidden />
            FDA Section 524B · Premarket Cybersecurity
          </p>
          <h1 className="fda-h1">A device cybersecurity submission, as auditable software.</h1>
          <p className="fda-lede">
            Evidentia runs a live gap analysis against FDA&apos;s Appendix&nbsp;1
            security control categories, traces every threat to its control and
            its test, and ends on a signed, reproducible evidence artifact — the
            same chain of custody a 524B premarket package rests on.
          </p>

          <div className="fda-hero-cta">
            <Button
              size="lg"
              onClick={runAnalysis}
              disabled={running}
              aria-controls="fda-run-region"
              aria-busy={running}
            >
              {running ? (
                <Loader2 className="fda-spin" aria-hidden />
              ) : revealed ? (
                <ScanLine aria-hidden />
              ) : (
                <Play aria-hidden />
              )}
              {buttonLabel}
            </Button>
            <p className="fda-analyzing">
              Analyzing: <span className="mono">{FDA_SYSTEM}</span> ·{" "}
              <span className="fda-org">{FDA_ORG}</span>
            </p>
          </div>
        </header>

        {/* 3 ── Run animation ──────────────────────────────────────────── */}
        {phase !== "idle" && (
          <section
            id="fda-run-region"
            className="fda-run"
            role="region"
            aria-label="Gap analysis run progress"
            aria-live="polite"
          >
            <ol className="fda-steps reset">
              {FDA_RUN_STEPS.map((step, i) => {
                const state = stepStates[i];
                return (
                  <li key={step.label} className="fda-step" data-state={state}>
                    <span className="fda-step-ic" aria-hidden>
                      {state === "done" ? (
                        <Check className="fda-step-check" />
                      ) : state === "active" ? (
                        <Loader2 className="fda-spin" />
                      ) : (
                        <span className="fda-step-dot" />
                      )}
                    </span>
                    <span className="fda-step-text">
                      <span className="fda-step-label">{step.label}</span>
                      <span className="fda-step-detail mono">{step.detail}</span>
                    </span>
                  </li>
                );
              })}
            </ol>
          </section>
        )}

        {/* 4 ── Results ────────────────────────────────────────────────── */}
        {revealed && (
          <div ref={resultsRef} className="fda-revealed stack-8">
            <FdaResults />
            <FdaTraceability rows={FDA_TRACEABILITY} />
            <FdaSignedArtifact />
          </div>
        )}

        {/* 7 ── Footer ─────────────────────────────────────────────────── */}
        <footer className="fda-footer">
          <p className="muted">
            Evidentia is open source (Apache-2.0).
          </p>
          <div className="fda-footer-links">
            <a className="fda-footer-link" href="#/gap/analyze">
              Explore the full console <ArrowRight className="fda-inline-ic" aria-hidden />
            </a>
            <a
              className="fda-footer-link"
              href="https://github.com/Polycentric-Labs/evidentia"
              target="_blank"
              rel="noreferrer"
            >
              <ExternalLink className="fda-inline-ic" aria-hidden /> GitHub
            </a>
          </div>
        </footer>
      </div>
    </div>
  );
}

/**
 * Results block — mirrors GapAnalyzePage's `GapResults`: three MetricCards, a
 * Card with the SeverityBar, and the shared GapTable, all reused verbatim.
 */
function FdaResults() {
  return (
    <section className="stack-5" aria-labelledby="fda-results-heading">
      <header className="fda-section-head">
        <p className="section-num">
          <span className="sn-badge">01</span>
          Gap analysis
        </p>
        <h2 id="fda-results-heading" className="h2-lg">
          Coverage against FDA 524B Appendix&nbsp;1
        </h2>
        <p className="muted fda-section-sub">
          Eight security control categories required; {satisfied} satisfied in
          the device inventory, {REPORT.total_gaps} open gaps.
        </p>
      </header>

      <div className="grid grid-3">
        <MetricCard
          icon={ShieldCheck}
          label="Coverage"
          value={`${coverage}%`}
          description={`${satisfied} / ${categories} categories satisfied`}
          bar={coverage}
        />
        <MetricCard
          icon={ScanLine}
          label="Total gaps"
          value={
            <span className="fda-metric-badges">
              {REPORT.total_gaps}
              <span className="fda-metric-chips">
                <Badge variant="critical">{REPORT.critical_gaps} critical</Badge>
                <Badge variant="high">{REPORT.high_gaps} high</Badge>
                <Badge variant="medium">{REPORT.medium_gaps} medium</Badge>
              </span>
            </span>
          }
          description="open across the Appendix 1 categories"
        />
        <MetricCard
          icon={Layers}
          label="Appendix 1 categories"
          value={String(categories)}
          description="FDA premarket security control categories"
        />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">Severity distribution</CardTitle>
          <CardDescription>
            {REPORT.total_gaps} open gaps across the FDA 524B Appendix&nbsp;1
            categories, by gap severity.
          </CardDescription>
        </CardHeader>
        <CardContent className="pt-0">
          <SeverityBar gaps={FDA_524B_GAPS} />
        </CardContent>
      </Card>

      <GapTable gaps={FDA_524B_GAPS} />
    </section>
  );
}

/** STRIDE threat → 524B control → verification test, the differentiated view. */
function FdaTraceability({ rows }: { rows: TraceRow[] }) {
  return (
    <section className="stack-5" aria-labelledby="fda-trace-heading">
      <header className="fda-section-head">
        <p className="section-num">
          <span className="sn-badge">02</span>
          Traceability
        </p>
        <h2 id="fda-trace-heading" className="h2-lg">
          Threat&nbsp;→&nbsp;control&nbsp;→&nbsp;evidence
        </h2>
        <p className="muted fda-section-sub">
          Every STRIDE-categorized device threat mapped to the Appendix&nbsp;1
          control that mitigates it and the test that proves it — the chain an
          FDA premarket package is built on.
        </p>
      </header>

      <div className="fda-trace-grid">
        {rows.map((row) => (
          <article
            key={`${row.controlId}-${row.threat}`}
            className="fda-trace-card card"
            data-status={row.status}
          >
            <div className="fda-trace-top">
              <Badge variant="outline" className="fda-stride">
                {row.stride}
              </Badge>
              <TraceStatusBadge status={row.status} />
            </div>

            <div className="fda-trace-flow">
              <div className="fda-trace-node">
                <span className="fda-trace-kicker">Threat</span>
                <p className="fda-trace-threat">{row.threat}</p>
              </div>

              <ArrowRight className="fda-trace-arrow" aria-hidden />

              <div className="fda-trace-node">
                <span className="fda-trace-kicker">524B control</span>
                <p className="fda-trace-control">
                  <span className="kbd">{row.controlId}</span>{" "}
                  <span className="fda-trace-control-name">{row.controlName}</span>
                </p>
              </div>

              <ArrowRight className="fda-trace-arrow" aria-hidden />

              <div className="fda-trace-node">
                <span className="fda-trace-kicker">Evidence / test</span>
                <p className="fda-trace-evidence">{row.evidence}</p>
              </div>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

/** Status pill colored by traceability status (gap/partial/satisfied). */
function TraceStatusBadge({ status }: { status: TraceStatus }) {
  if (status === "gap") {
    return <Badge variant="critical">Gap</Badge>;
  }
  if (status === "partial") {
    return <Badge variant="high">Partial</Badge>;
  }
  return (
    <Badge variant="secondary" className="fda-status-satisfied">
      <Check className="fda-inline-ic" aria-hidden /> Satisfied
    </Badge>
  );
}

/** The signed evidence artifact — the wow finish. */
function FdaSignedArtifact() {
  const a = FDA_SIGNED_ARTIFACT;
  return (
    <section className="stack-5" aria-labelledby="fda-artifact-heading">
      <header className="fda-section-head">
        <p className="section-num">
          <span className="sn-badge">03</span>
          Evidence
        </p>
        <h2 id="fda-artifact-heading" className="h2-lg">
          A signed, reproducible evidence artifact
        </h2>
        <p className="muted fda-section-sub">
          The run emits an OSCAL Assessment Results envelope and signs it — the
          result is reproducible, attributable, and tamper-evident.
        </p>
      </header>

      <Card className="fda-artifact-card card-accent-top">
        <CardContent className="fda-artifact-body">
          <div className="fda-artifact-head">
            <div className="fda-artifact-file">
              <FileSignature className="fda-artifact-file-ic" aria-hidden />
              <div className="stack-2">
                <p className="fda-artifact-filename mono">{a.filename}</p>
                <p className="muted fda-artifact-fw">
                  Framework: <span className="kbd">{a.framework}</span>
                </p>
              </div>
            </div>
            <span className="fda-verified" role="status">
              <BadgeCheck className="fda-verified-ic" aria-hidden />
              Verified ✓
            </span>
          </div>

          <dl className="fda-artifact-grid">
            <ArtifactField label="SHA-256" mono title={a.sha256}>
              {middleTruncate(a.sha256, 14, 12)}
            </ArtifactField>
            <ArtifactField label="Run ID (ULID)" mono>
              {a.runId}
            </ArtifactField>
            <ArtifactField label="Signed at">
              {formatSignedAt(a.signedAt)}
            </ArtifactField>
            <ArtifactField label="Signer">{a.signer}</ArtifactField>
            <ArtifactField label="Rekor log index" mono>
              {a.rekorLogIndex}
            </ArtifactField>
            <ArtifactField label="Status">
              <span className="fda-artifact-status">
                <ShieldCheck className="fda-inline-ic" aria-hidden /> Tamper-evident
              </span>
            </ArtifactField>
          </dl>

          <p className="fda-artifact-note muted">
            Real deployments sign keylessly via Sigstore (Fulcio&nbsp;+ Rekor
            transparency log); this is a pre-signed illustration with a test key.
          </p>
        </CardContent>
      </Card>
    </section>
  );
}

function ArtifactField({
  label,
  children,
  mono = false,
  title,
}: {
  label: string;
  children: ReactNode;
  mono?: boolean;
  title?: string;
}) {
  return (
    <div className="fda-field box">
      <dt className="fda-field-label">{label}</dt>
      <dd className={mono ? "fda-field-value mono" : "fda-field-value"} title={title}>
        {children}
      </dd>
    </div>
  );
}

/** Middle-truncate a long string (e.g. a SHA-256) for compact display. */
function middleTruncate(value: string, head: number, tail: number): string {
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

/** Render an ISO timestamp as a stable, readable UTC string. */
function formatSignedAt(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z")}`;
}
