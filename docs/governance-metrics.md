# Governance metrics — KRI / KPI / KGI

Comprehensive walkthrough of Evidentia's governance metrics
primitives, introduced in v0.7.11 P1.5 G3. Closes the third
governance overlay piece (alongside v0.7.10 P1.5 G1 Three Lines
of Defense + G2 Effective Challenge log).

## Why KRI / KPI / KGI?

Risk-management programs distinguish three classes of metric by
**what** they measure + **when** they signal:

- **KRI** (Key Risk Indicator) — *leading* metric warning that
  risk is approaching or exceeding its tolerance threshold.
  Example: "Failed-login rate per 1,000 logins crossed 3.0 last
  week" warns of credential-stuffing pressure before any actual
  breach.
- **KPI** (Key Performance Indicator) — *lagging* metric measuring
  how effectively a control or process is being executed.
  Example: "Mean-time-to-patch HIGH CVE = 9.4 days" measures the
  patch-management process, not the risk itself.
- **KGI** (Key Goal Indicator) — *outcome* metric measuring
  whether the risk-management strategy is achieving its goal.
  Example: "Zero material data breaches in the last 12 months"
  measures the strategic outcome.

This taxonomy aligns with the IIA 3LOD Three Lines Model 2020 +
COSO ERM 2017 framework + ISO 31000 risk-management vocabulary.
Federal regulators (OCC + FRB + FFIEC) routinely cite these
classifications in examination guidance.

## Module surface

```
evidentia governance metrics
├── add        # define a new metric
├── observe    # record a new observation
├── list       # filterable list of metrics
├── show       # show one metric's full history
├── delete     # remove a metric
└── report     # Markdown dashboard report
```

Public Python surface (`evidentia_core.governance.metrics`):

- `MetricKind` enum (kri / kpi / kgi)
- `MetricDirection` enum (higher_is_worse / higher_is_better)
- `MetricStatus` enum (comfortable / watch / breach / no_data)
- `MetricObservation` schema (date + value + optional note)
- `Metric` schema (name + description + kind + direction + unit +
  optional thresholds + observation history)
- `evaluate_metric()` deterministic threshold evaluation
- `generate_metrics_report()` deterministic Markdown dashboard

## Status state machine

A metric's current status is derived deterministically from its
**latest observation** + **direction** + **thresholds**:

```
HIGHER_IS_WORSE (e.g., failed-login rate, attack volume):
  value < warning_threshold       → COMFORTABLE
  value ≥ warning_threshold       → WATCH
  value ≥ critical_threshold      → BREACH

HIGHER_IS_BETTER (e.g., patch coverage, MFA enrollment %):
  value > warning_threshold       → COMFORTABLE
  value ≤ warning_threshold       → WATCH
  value ≤ critical_threshold      → BREACH

No observations                   → NO_DATA
Missing critical_threshold        → cannot reach BREACH
Missing warning_threshold         → cannot reach WATCH
```

If no thresholds are set, the metric tracks observation history
only — status stays `COMFORTABLE` regardless of value.

## Quick-start

### Define a KRI (failed-login rate)

```bash
$ evidentia governance metrics add \
    --name "Failed-login rate" \
    --description "Failed logins per 1k logins per day" \
    --kind kri \
    --direction higher_is_worse \
    --unit "per 1k logins" \
    --warning-threshold 2.0 \
    --critical-threshold 4.0 \
    --owner-email security-ops@bank.example
Added metric Failed-login rate (id: 80e8b404-...)
```

### Define a KPI (patch coverage %)

```bash
$ evidentia governance metrics add \
    --name "Patch coverage (HIGH CVE within 30 days)" \
    --description "% of HIGH-severity CVEs patched within 30 days SLA" \
    --kind kpi \
    --direction higher_is_better \
    --unit "%" \
    --warning-threshold 80.0 \
    --critical-threshold 60.0 \
    --owner-email vuln-mgmt@bank.example
Added metric Patch coverage (id: bb5e8c0d-...)
```

Note the inversion — for "higher is better" metrics, the WATCH
threshold is the operator's "drop-below-this is concerning" line,
and CRITICAL is "drop-below-this is unacceptable."

### Define a KGI (zero material breaches)

```bash
$ evidentia governance metrics add \
    --name "Material data breaches (12-month rolling)" \
    --description "Count of material data breaches in trailing 12 months" \
    --kind kgi \
    --direction higher_is_worse \
    --unit "breaches" \
    --warning-threshold 1.0 \
    --critical-threshold 1.0 \
    --owner-email ciso@bank.example
```

### Record observations

```bash
$ evidentia governance metrics observe 80e8b404 \
    --value 1.5 \
    --observed-at 2026-01-15 \
    --note "Q1 baseline; below warning threshold"
Recorded observation 1.5 per 1k logins on 2026-01-15 for Failed-login rate; current status: comfortable

$ evidentia governance metrics observe 80e8b404 \
    --value 3.2 \
    --observed-at 2026-02-15
Recorded observation 3.2 per 1k logins on 2026-02-15 for Failed-login rate; current status: watch

$ evidentia governance metrics observe 80e8b404 \
    --value 4.5 \
    --observed-at 2026-03-15 \
    --note "Coordinated credential-stuffing campaign detected"
Recorded observation 4.5 per 1k logins on 2026-03-15 for Failed-login rate; current status: breach
```

### Dashboard report

```bash
$ evidentia governance metrics report --output reports/metrics-2026-q1.md
```

Sample output:

```markdown
# Governance Metrics Dashboard

> ⚠️ **1 metric(s) in BREACH state.** Review the Per-kind sections
> below; documented escalation paths apply.

| Status | Count |
| --- | --- |
| BREACH | 1 |
| WATCH | 0 |
| COMFORTABLE | 1 |
| NO_DATA | 1 |
| **Total** | **3** |

## KRI — Key Risk Indicators (leading metrics)

| Name | Latest | Status | Warn / Crit | Owner |
| --- | --- | --- | --- | --- |
| Failed-login rate | 4.5 per 1k logins | breach | 2.0 / 4.0 | security-ops@bank.example |
```

## Cross-link with the wider governance overlay

KRI/KPI/KGI metrics integrate with the v0.7.10 + v0.7.11
governance overlay:

- **Three Lines of Defense (G1)**: assign each metric an
  `owner_email` corresponding to a 1LOD / 2LOD / 3LOD owner.
  The 3LOD lines-report shows owner distribution across lines.
- **Effective Challenge log (G2)**: when a metric crosses
  WATCH/BREACH, an EffectiveChallenge event documents the 2nd-
  line review of the underlying control.
- **Workflows (G5)**: a workflow template can specify
  "BREACH on metric X triggers workflow run" via the operator's
  external automation; Evidentia's workflows are operator-driven.
- **Open FAIR risk quantification (G4)**: KRIs feed FAIR
  scenarios via the TEF (threat event frequency) factor.
- **Model risk (v0.7.10 P0.6)**: drift KRIs on a model trigger
  validation cycles via workflows.

## Strategic positioning

Most commercial GRC platforms (Vanta, Drata, Optro, OneTrust)
offer KRI dashboards as a paid feature — typically gated behind
"Enterprise" or "Premium" tiers at $20K-$50K/year per institution.
Evidentia ships the same primitive in OSS Apache 2.0 with
deterministic Markdown reporting, integration with the rest of
the governance overlay, and JSON-file persistence operators can
back up + version-control with their existing tooling.

## See also

- `docs/audit-chain-of-custody.md` — retention metadata + WORM
- `docs/risk-quantification.md` — Open FAIR
- `docs/financial-sector-overlay.md` — TPRM + Model Risk + 3LOD
- `docs/v0.7.11-plan.md` — release plan
