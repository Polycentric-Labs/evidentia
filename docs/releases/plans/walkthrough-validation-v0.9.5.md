# Federal-SI walk-through validation — AI-persona report (v0.9.5 P2.1)

> **Status**: validation artifact for the v0.9.5 walkthrough
> refinement pass. Captures the AI-persona-driven review that
> drove the v0.9.5 changes to `docs/walkthrough-federal-si.md`.
>
> **Persona**: "Sarah Reyes" — simulated senior procurement
> officer at a tier-1 federal-SI CSP candidate (Booz Allen /
> SAIC / Leidos / GDIT / Peraton tier). 12 years federal
> procurement, 4 FedRAMP Moderate ATOs led, 2 DoD IL5 sponsor
> packages.
>
> **Date**: 2026-05-18 | **Doc reviewed**: `docs/walkthrough-
> federal-si.md` at v0.9.4 ship state | **Driven by**:
> `docs/v0.9.5-plan.md` P2.1 ("Real federal-SI domain-expert
> walk-through"; AI-persona substitute per Allen's
> 2026-05-18 lock-in pending real-operator review in v0.9.6+).

## Honest scope statement

This validation is **AI-persona-driven**, not real-operator-
driven. The persona was constructed from authoritative public
sources (FedRAMP RFC-0024, OMB M-24-10, NIST AI RMF 1.0,
NIST SP 800-218 SSDF, FedRAMP 20x program documents) plus the
training-data corpus on federal procurement workflows. It is a
useful *first-pass refinement signal* — the persona surfaced
findings the original-author Claude didn't see — but it is
**NOT a substitute for a real federal-SI domain-expert review**.
The v0.9.6+ cycle should solicit a real procurement officer to
walk through the post-v0.9.5 doc and report their additional
friction points.

## Findings summary

10 refinement recommendations surfaced. Severity breakdown:

| Severity | Count | Status in v0.9.5 |
|---|---|---|
| HIGH | 3 | All 3 closed in v0.9.5 P2.1 |
| MEDIUM | 4 | All 4 closed in v0.9.5 P2.1 |
| LOW | 2 | Both closed in v0.9.5 P2.1 |
| DEFER | 1 | Closed in v0.9.5 P2.2 (Step 8 OSCAL POA&M) |

## Findings detail

### R1 — HIGH (CLI bug) — Step 2 `--state-file` should be `--last-completed-file`

The v0.9.4 doc Step 2 used `--state-file` for `conmon check`. The
actual CLI flag is `--last-completed-file`
(`packages/evidentia/src/evidentia/cli/conmon.py:265`). The
integration test at `tests/integration/test_walkthrough_federal_
si.py:66` uses the correct flag — only the doc was wrong.

**v0.9.5 fix**: doc now uses `--last-completed-file` + adds a
callout box documenting the historic flag-naming inconsistency
(`conmon check --last-completed-file` vs `conmon health --state-
file` vs `conmon watch --state-file`) as a v0.9.6 normalization
target.

### R2 — HIGH — Reframe AI lens around OMB M-24-10 / NIST AI RMF, not EU AI Act

The v0.9.4 doc led with EU AI Act tier classification as the
primary federal lens — which is incorrect. Federal SIs cite OMB
M-24-10 (Rights-Impacting / Safety-Impacting / Neither
categorization) and NIST AI RMF 1.0 (Govern / Map / Measure /
Manage). EU AI Act is secondary, useful for SIs whose AI systems
also serve EU customers.

**v0.9.5 fix**: Step 4 reframed with OMB M-24-10 + NIST AI RMF as
primary, EU AI Act tier classification as a useful proxy /
secondary lens. The pre-amble paragraph also leads with the
federal lens.

### R3 — HIGH — Add FedRAMP 20x / RFC-0024 / OSCAL machine-readable framing

The v0.9.4 doc didn't acknowledge FedRAMP 20x or RFC-0024
(machine-readable authorization packages, Sept 30 2026 initial-
compliance deadline). Any GRC tool walk-through targeting federal
SI buyers in mid-2026 must address this.

**v0.9.5 fix**: pre-amble + Step 8 both reference RFC-0024 + the
Sept 30 2026 deadline. Step 8 adds the OSCAL 1.1.2 POA&M emit
demonstration that maps directly to the RFC-0024 submission
channel.

### R4 — MEDIUM — Clarify CA-7 is a meta-control, not a monthly task

The v0.9.4 doc framed NIST 800-53 CA-7 as a monthly cadence. In
practice CA-7 is the **policy umbrella** ("the Continuous
Monitoring strategy document exists + is reviewed"); the
operational monthly tasks are RA-5 / CA-7(4) / IR-5.

**v0.9.5 fix**: Step 2 explanation clarifies CA-7 is the policy
control; operational scans run under the operational-control
family. The state fixture retains CA-7 as a cadence for demo
simplicity but the doc explains why production deployments differ.

### R5 — MEDIUM — Distinguish internal health score from FedRAMP-PMO-grade reporting

The v0.9.4 doc showed a `0.857` overall_health_score without
indicating this is an internal dashboard metric, not the metric
submitted to the FedRAMP PMO at monthly POA&M cadence.

**v0.9.5 fix**: Step 3 adds the explicit "internal dashboard,
NOT PMO-grade" caveat. The PMO-grade weighted-CVSS POA&M-line-
count framing is referenced + the Step 8 OSCAL emit is the
PMO-submission path.

### R6 — MEDIUM — Add FIPS 199 categorization to the AI system registry walkthrough

Federal AI inventories under OMB M-24-10 §5(a) also carry FIPS
199 impact tags + ATO-boundary linkage. The v0.9.4 doc didn't
mention these.

**v0.9.5 fix**: Step 5 calls out FIPS 199 + ATO-linkage as
tracked-for-v0.9.6+ surfacing, with the interim guidance that
operators use the v0.9.5 Phase 3 custom-fields surface or a
sidecar YAML referenced via the `owner` field.

### R7 — MEDIUM — Document SCR (Significant Change Request) adjacency

The v0.9.4 doc said "Promote pilot → production after stakeholder
review" without acknowledging this triggers a FedRAMP SCR Form
and an OMB M-24-10 AI Use Case Inventory update.

**v0.9.5 fix**: Step 7 adds the SCR + OMB M-24-10 inventory
update callout, explicitly bounding Evidentia's scope (fires the
audit event; does NOT auto-emit the SCR Form).

### R8 — LOW — Add 3PAO / AO downstream-consumer perspective

The v0.9.4 doc framed the walk-through as a self-contained loop.
In reality the artifacts feed three downstream human roles: 3PAO
assessor, agency AO, FedRAMP PMO.

**v0.9.5 fix**: pre-amble adds the three-consumer framing. The
Step 8 OSCAL POA&M emit explicitly references 3PAO annual
assessment + FedRAMP PMO monthly cadence + RFC-0024 channel.

### R9 — LOW — Add CISA Secure by Design + NIST SP 800-218 SSDF references for Evidentia itself

A federal-SI procurement officer's first question on an OSS GRC
tool is "can I attest the tool is secure-by-design under EO 14028
+ OMB M-22-18 + CISA Secure by Design Pledge?" Evidentia ships
all the required artifacts (sigstore, PEP 740 attestations, SLSA
Provenance v1, CycloneDX SBOM) but the v0.9.4 walk-through didn't
surface them to federal buyers.

**v0.9.5 fix**: new "Trustworthiness of Evidentia itself (read
first)" section at the top of the doc, with explicit
`pypi-attestations verify`, `cosign verify`, and SBOM
references. Maps to NIST SP 800-218 SSDF practice PS.3.1 +
CISA Secure Software Self-Attestation Form expectations.

### R10 — DEFER (v0.9.5+) — Add Step 8 OSCAL POA&M emit demonstration

The v0.9.4 doc deferred POA&M emit + OSCAL plan-of-action-and-
milestones to "Future enhancements." For a federal-SI walk-
through, this is the HEADLINE artifact — the monthly POA&M is
the heartbeat of the authorization-package program.

**v0.9.5 fix (P2.2 closure)**: Step 8 added. Walks through
gap-analysis run → POA&M create-from-gap-report → OSCAL emit →
validate. References FedRAMP POA&M Template Completion Guide
v3.0 + the RFC-0024 machine-readable channel.

## Things the doc gets RIGHT (preserved)

### P1 — Self-aware "designed without operator feedback" disclosure

The v0.9.4 "Future enhancements" line "Real federal-SI domain-
expert review (the walk-through was designed without operator
feedback)" earned credibility with the persona. v0.9.5 preserved
this self-awareness and expanded it into the "Known limitations"
section.

### P2 — CI-tested expected outputs

Every step has an "Expected" line backed by
`tests/integration/test_walkthrough_federal_si.py`. This is a
level of rigor most vendor GRC walk-throughs don't match. v0.9.5
preserved + extended the CI test coverage where possible.

### P3 — Mixed-state CONMON fixture (1 overdue + 1 due-soon + 5 current)

The `state.yaml` fixture deliberately puts the operator in front
of a realistic mid-cycle ConMon snapshot, not a green-all-checks
scenario. Preserved as-is.

## Sources

The persona's framing was constructed from:

- [FedRAMP RFC-0024: Machine-Readable Authorization Packages](https://www.fedramp.gov/rfcs/0024/)
- [FedRAMP 20x program overview](https://www.fedramp.gov/blog/2025-07-15-fedramp-20x-program-overview/)
- [OSCAL POA&M Model v1.1.2 JSON Reference (NIST)](https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/)
- [Use of OSCAL by FedRAMP (automate.fedramp.gov)](https://automate.fedramp.gov/about/use-of-oscal-by-fedramp/)
- [Guide to OSCAL-Based FedRAMP POA&M Rev 5 (fedramp.gov)](https://www.fedramp.gov/assets/resources/documents/Guide-to-OSCAL-Based-FedRAMP-Plan-of-Action-and-Milestones-(POA&M)-Rev-5.docx)
- [FedRAMP Baseline Rev 5 Transition Guide (fedramp.gov)](https://www.fedramp.gov/resources/documents/FedRAMP_Baselines_Rev5_Transition_Guide.pdf)
- OMB M-24-10 — Advancing governance, innovation, and risk management for agency use of AI
- NIST AI RMF 1.0 — AI risk management framework
- NIST SP 800-218 SSDF — Secure Software Development Framework

## Replay recipe (v0.9.6+ refresh)

To re-run this validation against the v0.9.5+ doc:

```bash
# Either invoke the pre-release-review skill's walk-through
# validation step, OR spawn a fresh agent with the v0.9.5 P2.1
# prompt template at .claude/skills/pre-release-review/
# references/walkthrough-validation.md (TBD — bookmark for the
# pre-release-review v5 update).
```

## Cross-references

- `docs/walkthrough-federal-si.md` — the v0.9.5-refined walk-through this report drove
- `docs/v0.9.5-plan.md` — P2.1 spec
- `docs/poam-runbook.md` — operator runbook for the Step 8 POA&M workflow
