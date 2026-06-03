# Security review - v0.10.5

> **Status**: reconstructed in-cycle artifact for the v0.10.5 ship. The
> security-review write-up was not authored as an in-repo doc at ship
> time (the v0.10.5 + v0.10.6 reviews were captured in internal memory
> rather than as in-repo docs); this public companion was backfilled
> during the v0.10.8 docs close-out from the `CHANGELOG.md` `[0.10.5]`
> block, [`docs/v0.10.5-plan.md`](v0.10.5-plan.md), and the annotated
> `v0.10.5` tag object.
>
> **Theme**: output-format expansion (OCSF Detection Finding 2004 +
> CycloneDX VEX emit) + a workspace refactor (the `evidentia-eval`
> package extraction, 8th package) + collector idempotency hardening for
> the v1.0 API freeze + a positioning rewrite (no metaphors; EU AI Act
> Annex III date correction) + the commercial-validation foundation (a
> design-partner-program draft).
>
> **Structure note**: this document follows the structure and voice of
> [`docs/security-review-v0.10.4.md`](security-review-v0.10.4.md), which
> was the last in-repo security-review doc committed before this
> backfill. It is the structural model here.
>
> **Sourcing discipline + the per-run-JSON gap**: there is **no per-run
> `/pre-release-review` JSON for v0.10.5**. The audit-trail run directory
> `.local/pre-release-review/runs/` jumps from the
> `2026-05-24T21-41-48Z-v0.10.4-prototype.json` record straight to the
> `2026-05-31T01-55-11Z-v0.10.7.json` record, with no v0.10.5 or v0.10.6
> file in between. So the Step-7 numeric results, exact per-pass finding
> tallies, the container digest, the `release.yml` run duration, and the
> consecutive-PROCEED-CLEAN streak position for this cycle are **not
> derivable from in-repo sources**; the Step-7 ship record for v0.10.5
> lives in private memory. Every such fact below is marked inline
> **`VERIFY-LIMITED`** with a pointer to where it can be confirmed. Facts
> that the CHANGELOG block, the plan, or the tag object state directly
> are used as-is with the source cited.

## Cycle scope

v0.10.5 is the fifth patch on the v0.10.x line, tagged 2026-05-26 (the
`[0.10.5]` CHANGELOG date and the `v0.10.5` tag-object date; the tag
commit `a688b20` is dated `2026-05-26 00:03 -0400`). Six cycle commits
were authored 2026-05-25 between v0.10.4 (tagged 2026-05-24) and this
tag, all on the same `main` branch (the `git rev-list v0.10.4..v0.10.5`
count is 9, which includes the chore(release) + interim commits).

The 2026-05-24 v0.10.5 plan originally targeted Phases 1-5 (the "OSS
first-mover artifacts" theme: OSPS Baseline catalog + OSCAL conversion +
`OSPS-CONFORMANCE.md` + `SECURITY.md` refresh + `EOL.md` +
verification-recipe). A 2026-05-25 full-sweep research pass redirected
the cycle to Phases 7-12, deferring Phases 1-5 to v0.10.6 with no scope
loss (see [`docs/v0.10.5-plan.md`](v0.10.5-plan.md) §0 and §0.A for the
plan-vs-actual reconciliation). The shipped scope was:

1. **`evidentia gap analyze --format ocsf-detection` (Phase 7).** Gap
   analysis output emits as an OCSF Detection Finding (`class_uid` 2004)
   JSON array - the SIEM-target counterpart to v0.10.4's Compliance
   Finding 2003 emit (Splunk / Elastic / Microsoft Sentinel / Datadog
   ingest 2004 natively as production traffic). Detection Finding has no
   native `compliance` object, so the framework and control_id ride in
   `finding_info.types[]` as a stable `<framework>/<control_id>`
   identifier (mirroring the SARIF `rule_id` shape); the full gap JSON is
   preserved under `unmapped["evidentia"]["gap"]` for round-trip
   fidelity. New `evidentia_core.gap_analyzer.ocsf_detection.gap_report_to_ocsf_detection_array`
   library helper.
2. **`evidentia gap analyze --format cyclonedx-vex` (Phase 8).** Gap
   analysis output emits as a CycloneDX 1.6 VEX document, additive over
   the existing release-time CycloneDX SBOM emit. Each `ControlGap`
   becomes one CycloneDX `vulnerability` entry; `analysis.state` is
   derived from the gap's `implementation_status` + `GapStatus` per a
   documented state-mapping table (including a `not_affected` +
   `code_not_reachable` justification for accepted gaps and a
   `code_not_present` justification for not-applicable). New
   `evidentia_core.gap_analyzer.vex.gap_report_to_cyclonedx_vex` library
   helper. `OutputFormat` Literal extended additively per
   [`docs/api-stability.md`](api-stability.md) §3 to add `"ocsf-detection"`
   + `"cyclonedx-vex"`; the six prior emits are unchanged.
3. **`evidentia-eval` workspace package extraction (Phase 9, 8th
   package).** The DFAH determinism + faithfulness harness moves out of
   `evidentia-ai/eval/` to its own pip-installable package with its own
   optional extra (`evidentia-eval[faithfulness-semantic]` for the
   sentence-transformers + numpy path). Same public symbols, same
   signatures - only the import path changes. The `evidentia_ai.eval.*`
   import paths remain as deprecation shims that re-export from
   `evidentia_eval.*` and emit a `DeprecationWarning`, with removal
   scheduled for v0.12.0 (a 2-minor-version migration window per
   [`docs/api-stability.md`](api-stability.md) §1).
4. **Collector idempotency hardening for the v1.0 API freeze (Phase
   10).** A new `evidentia_core.models.common.deterministic_finding_id(source_system, source_finding_id)`
   helper computes a UUID v5 from natural keys under a pinned
   `NAMESPACE_EVIDENTIA_FINDING`. A new `@model_validator(mode="before")`
   on `SecurityFinding` runs the derivation when no explicit `id=` is
   supplied and both `source_system` + `source_finding_id` are present.
   Effect: two `collect()` runs against an unchanged source produce
   byte-identical `id` values, closing the audit-flagged gap that
   unchanged sources previously yielded random `uuid4()` ids. Additive
   only (explicit `id=` always wins; OCSF round-trip preserved;
   pre-v0.10.5 OSCAL AR documents continue to load). New NORMATIVE
   [`docs/collector-idempotency-audit.md`](collector-idempotency-audit.md)
   refutes the principal-engineer architecture audit on two specifics
   (no collector uses timestamp cursors; no DB-backed findings store
   exists - OSCAL AR is the canonical sink).
5. **Positioning rewrite (Phase 11).** Positioning §10 rewritten to drop
   all metaphors (direct enumerated claims only until reference customers
   exist), and the EU AI Act Annex III date corrected from 2026-08-02 to
   2027-12-02 per the Digital Omnibus political agreement of 2026-05-07.
   The v1.0 acceptance gates were rewritten so the OpenSSF Gold
   honest-gap is tied to SOC 2 Type I segregation-of-duties (see
   [`docs/v1.0-transition.md`](v1.0-transition.md) §"Acceptance gates for
   v1.0").
6. **Commercial-validation foundation (Phase 12, draft).** A
   `design-partner-program.md` v0 draft describing a fixed-fee
   readiness engagement, with the service name "Evidentia CMMC + FedRAMP
   Readiness Accelerator" locked per a 4-lens validated naming pass. This
   is a draft document and a name-lock only; no code surface changed.

Reported cycle health at ship (from the `[0.10.5]` CHANGELOG block and
the plan's §0 post-ship gates): **3,443 tests pass / 14 skipped / 3,457
collected across 278 source files (was 268 at v0.10.4); mypy strict 0/0;
ruff clean.** Workspace ships **8 PyPI packages** (was 7; `evidentia-eval`
added in Phase 9). `uv sync --all-packages` clean.

## Review structure

The review and validation discipline for this cycle ran direct-on-`main`
per Evidentia's standing direct-push pattern. **Because no per-run JSON
exists for v0.10.5, the per-pass finding tables that the v0.10.4 doc
populated from its JSON cannot be reconstructed here.** The table below
records what the CHANGELOG and plan attest plus what is marked
`VERIFY-LIMITED` for the controller to confirm from the private Step-7
ship-memory.

| Pass | Scope | Verdict |
|---|---|---|
| `/security-review` (pre-tag) | The v0.10.5 phase diffs (`v0.10.4..HEAD`): the two new gap-output emitters (`ocsf_detection.py` + `vex.py`), the `evidentia-eval` package extraction, the `SecurityFinding` idempotency validator, and the positioning/design-partner docs | **Recorded PROCEED-CLEAN** in the cycle ship-memory. `VERIFY-LIMITED` - the exact invocation count, the per-dimension pass table, and the CRITICAL/HIGH/MEDIUM/LOW tallies are not derivable in-repo (no per-run JSON); confirm against the private ship-memory. The two new emitters are one-way serializers over the existing in-memory gap report (no new input-trust boundary; the VEX/Detection arrays are produced, not parsed), and the package extraction is an import-path move with byte-identical symbols. |
| `/code-review` (auto-fire on the emitter + refactor deltas) | Same phase diffs | `VERIFY-LIMITED` - the CRITICAL/HIGH/MEDIUM/LOW tallies and any deferred-item list are not derivable in-repo. The v0.10.4 doc's "Deferred to v0.10.5" ledger (CR-V105-1 through CR-V105-6 plus the LOW/INFO stylistic batch) was the inbound queue for this cycle; whether each item landed in v0.10.5 versus rolled forward is recorded only in the private ship-memory. |
| Idempotency-audit pass (Phase 10) | The 13-collector + 1-ingest-module surface | NORMATIVE [`docs/collector-idempotency-audit.md`](collector-idempotency-audit.md) authored; per-collector PASS/GAP verdicts on cursor model, natural-key shape, and finding-identity contract. The single real gap documented (random `uuid4()` on `SecurityFinding.id` despite stable `source_finding_id` natural keys) was closed in-cycle by the Phase 10 validator. This is a determinism/data-integrity hardening, not a security vulnerability. |

> **0-finding framing**: the cycle is recorded in ship-memory as a
> PROCEED-CLEAN ship. No CRITICAL / HIGH / MEDIUM / LOW security finding
> is attributed to v0.10.5 in the `[0.10.5]` CHANGELOG block (it carries
> no `### Security` subsection - there was no CVE/advisory remediation
> work this cycle), and the plan records no open security finding.
> `VERIFY-LIMITED` - confirm the precise findings array against the
> private ship-memory, since the per-run JSON that would normally hold it
> does not exist for this version.

## Security-relevant change analysis

Three of the shipped changes touch security-adjacent surfaces. None
introduced a new attack surface, for the reasons recorded below (drawn
from the CHANGELOG + plan; the formal per-dimension verdict is
`VERIFY-LIMITED` per the ship-memory):

| Change | Surface | Why it does not widen the attack surface |
|---|---|---|
| OCSF Detection (2004) + CycloneDX VEX emit | Output serialization | Both are **one-way emitters** over the already-validated in-memory gap report. No new parser, no new external input is trusted; the gap JSON is re-serialized into a second envelope shape. The framework/control_id carried in Detection `finding_info.types[]` is the same data already present in the report. |
| `evidentia-eval` extraction | Packaging / import graph | A move of existing symbols to a new package with byte-identical signatures. The notable security-relevant property is a **shrink** of the production import graph: a new `tests/unit/test_ai/test_lazy_imports.py` pins, via subprocess assertions, that `import evidentia_ai` (and the production risk-statement entry points) do not pull torch / transformers / sentence-transformers into `sys.modules` - a hard contract for the air-gap-clean install posture, replacing a prior soft convention. |
| `SecurityFinding.id` deterministic derivation | Finding identity | Additive `@model_validator`; explicit `id=` always wins, the OCSF round-trip via `unmapped["evidentia"]` is unchanged, and pre-v0.10.5 OSCAL AR documents continue to load. The derivation is UUID v5 over a NUL-separated natural-key pair under a pinned namespace; the model-layer tests cover NUL-separator collision resistance and empty-input rejection. This is a determinism guarantee, not an authn/authz or injection surface. |

## Step 7 - post-tag verification

The post-tag verification for v0.10.5 followed the same publish-targets
contract as the surrounding v0.10.x cycles (PEP 740 attestation sweep,
container smoke, osv-scan on the published SBOM, Scorecard delta,
fresh-venv install, cosign keyless + SLSA Provenance v1). **The numeric
results are `VERIFY-LIMITED`** - they are not derivable in-repo because
no per-run JSON exists for v0.10.5; the Step-7 ship record lives in
private memory. One concrete downstream fact is independently attested:
the v0.10.6 plan (`docs/v0.10.6-plan.md` §1) records that "all 8 PyPI
packages [are] live with PEP 740 attestations" for v0.10.5 and cites the
v0.10.5 container digest as
`sha256:f315c1fc20ed93227d79b6576da9e3bb74e3901e76cab5f0af65cfd8b98bb1de`.

| Step | Check | Expected (per the publish-targets contract) | Result |
|---|---|---|---|
| 7.A | PEP 740 attestation sweep | all 8 wheels attested | Recorded live (8/8) per v0.10.6 plan §1; exact verify-command output `VERIFY-LIMITED` |
| 7.B | Container smoke | `docker run ...:v0.10.5 --version` → "Evidentia v0.10.5" | `VERIFY-LIMITED` |
| 7.C | osv-scanner on published SBOM | clean (modulo known-acknowledged carries) | `VERIFY-LIMITED` |
| 7.D | Scorecard delta | the v0.10.6 cycle's H1 hygiene item attributes a Scorecard regression to **6.2** observed at the v0.10.5 ship (alerts #121 + #122, `PinnedDependenciesID` on `verify-changelog.yml`), restored in v0.10.6 | Regression to 6.2 attested by the v0.10.6 CHANGELOG/plan; exact v0.10.5 Scorecard sub-step output `VERIFY-LIMITED` |
| 7.E | Fresh-venv install | `pip install evidentia==0.10.5` green | `VERIFY-LIMITED` |
| 7.F | cosign verify keyless OIDC + SLSA Provenance v1 | PASS | `VERIFY-LIMITED` |
| 7.G | Memory ship-doc + lessons-learned + CHANGELOG cross-check | landed in internal/private memory (this in-repo doc is the backfilled public companion) | Recorded (ship-memory) |

**Step 7 verdict**: PROCEED-CLEAN (per ship-memory) - the Step-7 numeric
sub-step results are not derivable from the CHANGELOG / plan / tag and
must be confirmed from the private ship-memory. The container digest
(above) is confirmed from the GHCR `v0.10.5` release and cross-confirms
the v0.10.6-plan §1 second-hand attestation; the streak position is
interpolated (~18th) from the v0.10.7 per-run JSON.

## Findings ledger

### Security findings

No SECURITY-class finding (CRITICAL / HIGH / MEDIUM / LOW) is attributed
to v0.10.5 in the `[0.10.5]` CHANGELOG block or the plan. The block
carries no `### Security` subsection. `VERIFY-LIMITED` - confirm the
empty-findings array against the private ship-memory.

### Determinism / data-integrity item (closed in-cycle)

| ID | Class | Description | Disposition |
|---|---|---|---|
| (Phase 10 idempotency gap) | Data integrity / determinism | Collectors derived `SecurityFinding.id` as a random `uuid4()` even when a stable `source_finding_id` natural key was present, so two `collect()` runs against an unchanged source produced non-matching ids - a principal-engineer-audit-flagged gap ahead of the v1.0 API freeze. | **Closed in-cycle** by the Phase 10 `deterministic_finding_id` UUID v5 derivation + the `SecurityFinding` `@model_validator`; covered by `tests/unit/test_collectors/test_idempotency.py` + `tests/unit/test_models/test_finding_idempotency.py`. Not a security vulnerability. |

### Lessons-learned item surfaced this cycle (LL-V105-1)

The v0.10.5 ship surfaced **LL-V105-1**, a release-process lesson (not a
code finding) about partial-publish risk for a newly-added PyPI package.
The v0.10.5 cycle added a new workspace package (`evidentia-eval`), and
the lesson is the new-PyPI-project pending-publisher readiness gap. It is
recorded in the skill-side lessons-learned register
(`.local/pre-release-review/lessons-learned.yaml` LL-V105-1) and was
acted on in v0.10.6 (a new "Pre-publish credential readiness check" Step
2.A added to [`docs/release-checklist.md`](release-checklist.md), plus a
skill-side Step 5.D sub-check). `VERIFY-LIMITED` - the exact v0.10.5
publish sequencing / whether any wheel published out of order is recorded
only in the private ship-memory.

## Aggregate cycle metrics

| Metric | v0.10.5 |
|---|---|
| Tests | 3,443 pass / 14 skip / 3,457 collected (per CHANGELOG `[0.10.5]`) |
| mypy strict | 0 issues / 278 source files (was 268 at v0.10.4) |
| ruff | clean |
| PyPI packages | 8 (was 7; `evidentia-eval` added in Phase 9) |
| Cycle commits (authored 2026-05-25) | 6 phase commits (`git rev-list v0.10.4..v0.10.5` = 9 incl. release/interim) |
| New library entry points | 2 (`gap_report_to_ocsf_detection_array`, `gap_report_to_cyclonedx_vex`) |
| SECURITY-class findings | 0 attributed in CHANGELOG/plan (`VERIFY-LIMITED` against ship-memory) |
| Determinism/data-integrity items closed | 1 (Phase 10 finding-id idempotency) |
| Release-process lessons logged | 1 (LL-V105-1; remediated in v0.10.6) |
| Tag | `v0.10.5`, 2026-05-26 |
| Tag commit | `a688b204cce963d2efe286b6accc69e28ee95edd` (annotated tag; tagger Allen Byrd, 2026-05-26) |
| Container digest | `sha256:f315c1fc20ed93227d79b6576da9e3bb74e3901e76cab5f0af65cfd8b98bb1de` (confirmed 2026-06-03 from the GHCR `v0.10.5` release; cross-confirms the `docs/v0.10.6-plan.md` §1 second-hand attestation) |
| `release.yml` duration | `VERIFY-LIMITED` (no per-run JSON for v0.10.5) |
| Consecutive PROCEED-CLEAN streak | ~18th (interpolated: the v0.10.7 per-run JSON pins v0.10.4 as the 17th and v0.10.7 as ~20th, with v0.10.5 / v0.10.6 between) |
| **Overall verdict** | **PROCEED-CLEAN ship (per ship-memory)** - streak position `VERIFY-LIMITED` |

## Cross-references

- CHANGELOG block: [CHANGELOG.md §[0.10.5]](../CHANGELOG.md)
- Plan: [docs/v0.10.5-plan.md](v0.10.5-plan.md) (§0 actual-scope + §0.A deferred Phases 1-5)
- Structural model: [docs/security-review-v0.10.4.md](security-review-v0.10.4.md)
- Forward direction: [docs/v0.10.6-plan.md](v0.10.6-plan.md) (§2.A carries the deferred Phases 1-5; §1 cites the v0.10.5 container digest + PEP 740 status)
- OCSF Detection emit: [docs/ocsf-mapping.md](ocsf-mapping.md) (§7.B)
- Collector idempotency: [docs/collector-idempotency-audit.md](collector-idempotency-audit.md) (NORMATIVE)
- Positioning + v1.0 gates: [docs/positioning-and-value.md](positioning-and-value.md) §10 + [docs/v1.0-transition.md](v1.0-transition.md)
- Per-run JSON (audit trail): **does not exist for v0.10.5** - the run directory `.local/pre-release-review/runs/` skips from `2026-05-24...v0.10.4` to `2026-05-31...v0.10.7`; the Step-7 ship record is in private memory

---

*Reconstructed during the v0.10.8 docs close-out from the `CHANGELOG.md`
`[0.10.5]` block, `docs/v0.10.5-plan.md`, and the annotated `v0.10.5` tag
object. No per-run `/pre-release-review` JSON exists for v0.10.5, so
Step-7 numeric results, exact finding tallies, the consecutive-streak
position, and the `release.yml` duration are not derivable in-repo and
are marked `VERIFY-LIMITED` for confirmation against the private ship-
memory before this document is treated as the canonical v0.10.5 security
review. Reviewer of record: Allen Byrd `<allenfbyrd>`.*
