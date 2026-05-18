# Federal-SI walk-through (v0.9.4 P3.1 + v0.9.5 P2.1/P2.2 refinement)

> Operator persona: federal Systems Integrator (SI) procurement
> officer at a CSP candidate. Walks the operator through a realistic
> compliance + AI-governance workflow against synthetic fixtures in
> `tests/data/walkthrough-federal-si/`.
>
> Deferred since v0.9.0 §31.A. v0.9.4 P3.1 shipped the synthetic data
> + the initial recipe. v0.9.5 P2.1 added AI-persona validation +
> v0.9.5 P2.2 added the POA&M → OSCAL emit step. Smoke-tested by
> `tests/integration/test_walkthrough_federal_si.py`.

## Trustworthiness of Evidentia itself (read first)

Before sliding Evidentia into a federal authorization boundary,
verify the tool meets self-attestation expectations under EO 14028
+ OMB M-22-18 + CISA Secure by Design Pledge + NIST SP 800-218
SSDF practice PS.3.1 (cryptographic verification of integrity):

```bash
# 1. PyPI PEP 740 attestations (signed by GitHub Actions OIDC
#    identity `https://github.com/Polycentric-Labs/evidentia`):
pypi-attestations verify pypi \
  --repository https://github.com/Polycentric-Labs/evidentia \
  $(pip download evidentia==0.9.4 --no-deps -d ./tmp_verify/ \
      && ls ./tmp_verify/)

# 2. Container image (cosign keyless OIDC + SLSA Provenance v1):
cosign verify ghcr.io/polycentric-labs/evidentia:v0.9.4 \
  --certificate-identity-regexp \
    "https://github.com/Polycentric-Labs/evidentia" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# 3. CycloneDX SBOM attached to the GitHub Release (ingestible by
#    your SBOM aggregator: Dependency-Track / Trivy / etc.).
```

All three are required artifacts under FedRAMP RFC-0024 (machine-
readable authorization packages, Sept 30 2026 initial-compliance
deadline) and the CISA Secure Software Self-Attestation Form. If
the verify steps fail, file a v0.9.5 supply-chain incident ticket
against the repo — that's a stop-ship.

## Why this walk-through exists

The federal-SI buyer persona is a compliance-engineering manager
responsible for the **monthly POA&M heartbeat** of one or more
authorization packages. Three downstream consumers depend on the
artifacts this persona produces:

1. **3PAO assessor** (Coalfire / Schellman / A-LIGN / etc.) — ingests
   OSCAL POA&M + assessment-result deltas at annual assessment.
2. **Agency AO (authorizing official)** — reviews POA&M status +
   residual-risk justifications before re-authorization signature.
3. **FedRAMP PMO / DoD CCSP** — ingests machine-readable
   authorization packages per RFC-0024 (Sept 30 2026 deadline);
   grades against the FedRAMP POA&M Template Completion Guide
   v3.0.

The persona has TWO surfaces that overlap heavily for an SI
shipping AI-powered systems into regulated environments:

1. **Continuous compliance** for the SI's own SaaS / cloud
   infrastructure under FedRAMP Continuous Monitoring (CA-7 policy
   + RA-5 / CA-7(4) operational scans + IR-5 incident tracking).
   The FedRAMP PMO grades on weighted-CVSS open-POA&M-line counts
   against remediation SLAs: 30 days HIGH / 90 days MODERATE / 180
   days LOW. *Internal* health dashboards aside, this is the
   metric that matters at the AO desk.
2. **AI-governance attestation** for AI/ML systems the SI deploys
   to support federal contracts. The PRIMARY federal lens is
   **OMB M-24-10** (Rights-Impacting / Safety-Impacting / Neither
   categorization) plus **NIST AI RMF 1.0** (Govern / Map /
   Measure / Manage functions). EU AI Act tier classification is
   SECONDARY — useful when the same AI system also serves EU
   customers, but not the headline lens at a federal AO desk.

Both surfaces have hard deadlines (monthly POA&M attestation,
NIST AI RMF / AI Executive Order obligations on federal AI use
cases, FedRAMP 20x / RFC-0024 machine-readable authorization
deadline Sept 30 2026, EU AI Act Article 50 prohibitions
August 2 2026 for EU-exporting SIs).

The walk-through demonstrates Evidentia's end-to-end coverage of
the SI's typical day-to-day in 8 steps. Each step has expected
output documented so an operator can spot a regression without
needing to know the internal data model. The persona's perspective
is captured at the end ("What this walks-through validates" +
"Known limitations" sections).

## Pre-requisites

```bash
pip install evidentia
# Optional: containerized for FedRAMP-High air-gap compatibility
docker pull ghcr.io/polycentric-labs/evidentia:v0.9.4
```

## Step 1 — Confirm catalogs

```bash
evidentia catalog list | grep -E "(nist|fedramp|nist-ai-rmf|eu-ai-act)"
```

**Expected**: at minimum the bundled NIST 800-53 Rev 5 (baselines
Low/Moderate/High; 156/323/443 controls respectively after RFC-
0027/0030), the FedRAMP overlay, NIST AI RMF 1.0, and EU AI Act
statutory excerpts. Evidentia ships 89 framework catalogs by
default; this filter narrows to the ones the SI workflow
exercises.

NIST 800-53 **Rev 5** is current as of mid-2026; **Rev 6** is
still in NIST's IPD/FPD pipeline (not bundled). FedRAMP Rev 5
baselines are the operative target for new authorizations and
the Sept 30 2026 RFC-0024 machine-readable deadline.

## Step 2 — Run CONMON cycle check

```bash
evidentia conmon check \
  --last-completed-file tests/data/walkthrough-federal-si/state.yaml \
  --today 2026-05-18
```

**Expected**: 1 OVERDUE cadence, 1 DUE_SOON cadence, 5 CURRENT
cadences against the mixed-state fixture.

Federal-SI persona note: NIST 800-53 **CA-7** is the policy
umbrella ("the Continuous Monitoring strategy document exists and
is reviewed"), not a monthly operational task. What's actually
scanned monthly is the family of operational controls (RA-5
vulnerability scanning, CA-7(4) authenticated scans, IR-5
incident tracking). The walk-through state file treats CA-7 as a
cadence for demo simplicity; production deployments track
operational-scan dates against POA&M remediation windows, not
against the policy-control review cadence.

If you have a daemon running, run instead:

```bash
evidentia conmon watch --poll \
  --state-file tests/data/walkthrough-federal-si/state.yaml \
  --poll-interval 60 \
  --window-days 14 \
  --status-file /tmp/conmon-daemon.status.json \
  --history-file /tmp/conmon-daemon.history.jsonl \
  --state-lock
```

— with the v0.9.4 `--state-lock` flag for safe concurrent
`mark-completed` invocations, `--status-file` for the v0.9.4 P2.1
companion `GET /api/conmon/daemon-status` health-check endpoint,
and the v0.9.5 P2.3 `--history-file` for the
`GET /api/conmon/daemon-history` flap-detection endpoint.

> **CLI flag naming note**: `conmon check` uses `--last-completed-
> file`; `conmon health` + `conmon watch` use `--state-file` for
> the same on-disk YAML schema. This is a historic inconsistency
> tracked for a v0.9.6 normalization pass.

## Step 3 — Compute framework health

```bash
evidentia conmon health \
  --state-file tests/data/walkthrough-federal-si/state.yaml \
  --today 2026-05-18 \
  --window-days 14 \
  --json
```

**Expected JSON shape**: per-framework attention-bucket counts +
overall health score. With the fixture, expect ~`0.857` overall
(6 of 7 not-overdue / 7 total).

Federal-SI persona note: the `overall_health_score: 0.857` is an
**internal operator dashboard metric** suitable for a SIEM /
Grafana view of the SI's own ConMon program. It is **NOT** the
metric submitted to the FedRAMP PMO at monthly POA&M cadence.
PMO submissions are graded on weighted-CVSS open-POA&M-line
counts against remediation SLA (30 / 90 / 180 days for HIGH /
MODERATE / LOW). Operators wanting the PMO-grade view emit OSCAL
POA&M (Step 8 below) rather than reading the health score.

## Step 4 — Classify AI systems

**Primary lens (federal)**: under OMB M-24-10, AI use cases are
categorized as **Rights-Impacting** / **Safety-Impacting** /
**Neither**. NIST AI RMF 1.0 provides the Govern / Map / Measure /
Manage functions structure. Evidentia v0.9.4 surfaces the EU AI
Act tier classifier as a *secondary* lens — useful for SIs whose
AI systems also serve EU customers, and as a proxy for the
"how risky is this AI?" question that NIST AI RMF asks via its
Map function. v0.9.6+ will surface OMB M-24-10 categorization as a
first-class field; today the EU AI Act tier is the closest in-
product approximation.

```bash
# High-risk system (employment domain, Annex III — proxy for
# OMB M-24-10 Rights-Impacting since employment decisions affect
# the rights of natural persons)
evidentia ai-gov classify \
  --descriptor tests/data/walkthrough-federal-si/ai-systems.yaml \
  --json

# Compare against minimal-risk system
evidentia ai-gov classify \
  --descriptor tests/data/walkthrough-federal-si/ai-systems-low-risk.yaml \
  --json
```

**Expected**: first call returns `eu_ai_act_tier: "high"` (Annex
III employment domain + advisory decision role); second returns
`eu_ai_act_tier: "minimal"` (no Annex III; no natural-person
impact).

This is the classification call SIs make at procurement-evaluation
time when deciding which AI components a candidate vendor can
deploy into a federal environment. Federal procurement teams
typically pair this with an internal **OMB M-24-10
categorization** worksheet + an **NIST AI RMF Profile** for the
relevant agency mission.

## Step 5 — Register AI systems

```bash
EVIDENTIA_AI_REGISTRY_DIR=/tmp/walkthrough-federal-si-registry \
evidentia ai-gov register \
  --descriptor tests/data/walkthrough-federal-si/ai-systems.yaml \
  --provider acme-ai \
  --owner federal-si-hr-team \
  --deployment-status pilot
```

**Expected**: `Registered AI system: federal-si-resume-screener`
+ a UUID `system_id`. The registry-store sidecar `_idempotency.json`
also tracks any `X-Idempotency-Key` headers if the same call is
re-issued via the REST surface (v0.9.4 P1.3).

Federal-SI persona note: federal AI System Inventory entries
under OMB M-24-10 §5(a) also carry **FIPS 199** impact tags
(Confidentiality / Integrity / Availability — Low / Moderate /
High), an **authorizing-official assignment**, an **ATO status
field**, and a link to the **System Security Plan (SSP)** the AI
system lives inside. Evidentia v0.9.4 carries provider / owner /
deployment-status; FIPS 199 + ATO-linkage are tracked for
v0.9.6+ surfacing as first-class fields. For today's deployments,
operators capture those in a sidecar YAML referenced by the
`owner` field, or via the v0.9.5 Phase 3 collaboration-primitive
custom fields.

## Step 6 — List registered AI systems

```bash
EVIDENTIA_AI_REGISTRY_DIR=/tmp/walkthrough-federal-si-registry \
evidentia ai-gov list --tier high --json
```

**Expected**: array with one entry (the high-risk system just
registered) — confirms the tier filter works and the registry
persisted correctly.

## Step 7 — Lifecycle transitions

```bash
# Promote pilot → production after stakeholder review
EVIDENTIA_AI_REGISTRY_DIR=/tmp/walkthrough-federal-si-registry \
evidentia ai-gov update <system_id> --deployment-status production

# Retire after contract end (preserves history)
EVIDENTIA_AI_REGISTRY_DIR=/tmp/walkthrough-federal-si-registry \
evidentia ai-gov retire <system_id>
```

**Expected**: `Updated` then `Retired` messages. The entry stays
in the registry — `evidentia ai-gov show <system_id>` still
resolves with `deployment_status: "retired"`. Auditors
investigating a historical AI deployment can still trace
ownership + classification.

Federal-SI persona note: promoting a federal-AI system from
pilot → production *within* an authorization boundary typically
triggers a **FedRAMP Significant Change Request (SCR)** plus an
**OMB M-24-10 AI Use Case Inventory update**. Evidentia's
`ai-gov update` fires the `AI_SYSTEM_UPDATED` lifecycle audit
event for downstream automation, but does **NOT** auto-emit the
SCR Form (the FedRAMP-PMO-required template). Operators produce
the SCR Form out-of-band and submit through their existing
authorization-package workflow.

## Step 8 — POA&M emit + OSCAL machine-readable (v0.9.5 P2.2)

For the federal-SI workflow, the **OSCAL POA&M** is the headline
artifact. The persona's monthly heartbeat is: run gap analysis →
emit POA&M items → format as OSCAL 1.1.2 plan-of-action-and-
milestones → submit to FedRAMP PMO via the RFC-0024-compliant
machine-readable channel.

```bash
# 1. Gap-analyze the SI's inventory against the FedRAMP Moderate
#    baseline (the inventory fixture stands in for the SI's real
#    cloud configuration export):
evidentia gap-analysis run \
  --inventory tests/data/walkthrough-federal-si/inventory.yaml \
  --framework nist-800-53-rev5-moderate \
  --output /tmp/walkthrough-gap-report.json

# 2. Create POA&M items from the gap report (one POA&M line per
#    open finding; severity inherited from the gap classification):
evidentia poam create-from-gap-report \
  --gap-report /tmp/walkthrough-gap-report.json \
  --output /tmp/walkthrough-poam.json

# 3. Emit OSCAL 1.1.2 plan-of-action-and-milestones:
evidentia poam export-oscal \
  --input /tmp/walkthrough-poam.json \
  --output /tmp/walkthrough-poam.oscal.json

# 4. Validate against NIST's OSCAL JSON schema:
evidentia oscal validate /tmp/walkthrough-poam.oscal.json
```

**Expected**: a valid OSCAL plan-of-action-and-milestones JSON
document with SHA-256 back-matter integrity references to every
source-evidence file. This document is what the SI submits to the
3PAO at annual assessment and to the FedRAMP PMO at the monthly
POA&M cadence (post-RFC-0024 deadline, this is the machine-
readable submission format).

Federal-SI persona note: the FedRAMP POA&M Template Completion
Guide v3.0 prescribes specific column semantics (Severity,
Detection Source, POA&M Items Open, Original Detection Date,
Risk Adjustment, Deviation Request, etc.) that Evidentia's
OSCAL emit preserves via OSCAL's prop+annotation mechanism. The
v3.0 template's MS Excel form remains the FedRAMP PMO ingest
channel until the RFC-0024 full deadline (Sept 30 2027); OSCAL
1.1.2 emit interoperates with both.

## What this walk-through validates

| Phase | Capability tested | Federal-SI consumer |
|---|---|---|
| 0 | Supply-chain trustworthiness (PEP 740 + cosign + SBOM) | Procurement officer self-attestation |
| 1 | Catalog discovery — 89 bundled frameworks load | All |
| 2 | CONMON cycle classification — overdue/due_soon bucketing | SI compliance ops; internal SIEM |
| 3 | Framework health scoring — JSON output for SIEM ingest | SI compliance ops only (NOT PMO-grade) |
| 4 | EU AI Act tier classification — Annex III + risk attributes | Procurement evaluation; pairs with OMB M-24-10 |
| 5 | AI registry persistence — file-backed atomic write | OMB M-24-10 AI Use Case Inventory |
| 6 | Registry query with tier filter | Inventory roll-ups |
| 7 | Lifecycle CLI verbs (v0.9.4 P2.3) — update + retire firing audit events | SI compliance ops; pairs with SCR Form out-of-band |
| 8 | POA&M emit + OSCAL 1.1.2 plan-of-action-and-milestones | 3PAO annual assessment; FedRAMP PMO monthly POA&M; RFC-0024 |

If any step diverges from "expected", file a v0.9.6 bug ticket
with the actual output. The integration test
`tests/integration/test_walkthrough_federal_si.py` runs steps 2-4
+ 6 in CI to catch regressions in the smoke surface; the full
end-to-end (including REST endpoints, daemon, and Step 8 OSCAL
emit) is operator-driven.

## Known limitations (be honest with your AO)

The walk-through was AI-persona-reviewed for v0.9.5 by a
simulated senior federal-SI procurement officer (see
`docs/walkthrough-validation-v0.9.5.md` for the validation
artifact). Limitations the persona surfaced and the v0.9.5 cycle
addressed:

- **EU AI Act-first framing**: the v0.9.4 doc led with EU AI Act
  tier classification, which is the wrong primary lens for a
  federal-SI persona. v0.9.5 reframed with OMB M-24-10 +
  NIST AI RMF as primary, EU AI Act as secondary.
- **CLI flag bug in Step 2**: v0.9.4 doc referenced
  `--state-file` for `conmon check` (which actually uses
  `--last-completed-file`). Fixed in v0.9.5.
- **No FedRAMP 20x / RFC-0024 framing**: the v0.9.4 doc didn't
  acknowledge the Sept 30 2026 machine-readable deadline. v0.9.5
  added Step 8 (OSCAL POA&M emit) + RFC-0024 context.
- **CA-7-as-monthly-task framing**: clarified CA-7 is the policy
  umbrella, not an operational monthly check.
- **Health score conflation**: the 0.857 metric is internal
  dashboard, not PMO-grade. v0.9.5 added the explicit caveat.

Limitations still open for v0.9.6+:

- **FIPS 199 categorization on AI registry**: tracked as a
  first-class field; today carried in the `owner` sidecar or via
  the v0.9.5 Phase 3 custom fields.
- **SCR Form auto-emit**: Evidentia fires the lifecycle audit
  event but does not generate the FedRAMP-PMO SCR template.
  Operator produces SCR out-of-band.
- **CLI flag naming consistency**: `conmon check` vs `conmon
  health` use different flag names for the same on-disk schema.
- **Real federal-SI operator review**: the v0.9.5 validation was
  AI-persona-driven; a real domain-expert review remains the
  highest-value v0.9.6 follow-up.

## See also

- `tests/data/walkthrough-federal-si/README.md` — fixture provenance
- `docs/walkthrough-validation-v0.9.5.md` — AI-persona validation report
- `docs/conmon-runbook.md` — CONMON operator workflows
- `docs/poam-runbook.md` — POA&M operator workflows
- `docs/conmon-daemon-deployment.md` — daemon deployment guide
- FedRAMP RFC-0024 — Machine-readable authorization packages
- OMB M-24-10 — Advancing governance, innovation, and risk
  management for agency use of AI
- NIST AI RMF 1.0 — AI risk management framework
- NIST SP 800-218 SSDF — Secure Software Development Framework
- CISA Secure by Design Pledge — voluntary commitment to
  software supply-chain hardening
