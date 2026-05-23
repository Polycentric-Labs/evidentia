# Security review — v0.10.0

> **Status**: in-cycle artifact for the v0.10.0 ship — the v4
> pre-release-review's 5th canonical deliverable.
>
> **Theme**: OCSF-aligned findings schema + SARIF CI-gate output.
> Opens the v0.10.x research-driven integration line.

## Cycle scope

v0.10.0 is the first minor of the v0.10.x line. It executes the
keystone recommendation from the 2026-05-21 post-v0.9.9
competitive / integration research pass: an OCSF-aligned normalized
findings schema, a bidirectional OCSF Compliance Finding mapping
layer, SARIF 2.1.0 output for `evidentia gap`, and refactored AWS /
GitHub / Postgres collectors that populate the new fields. The
remaining ~11 collectors and the third-party OCSF ingestion
collector are deferred to v0.10.1. See `docs/v0.10.0-plan.md` for
the phase-by-phase scope and `docs/ocsf-mapping.md` for the OCSF
field map.

## Review structure

v0.10.0 was reviewed under the v4 default pre-tag variant: 7-step
flow + diff + 1-hop dep closure (Step 1.4 scope = option 1). The
changeset is on `main` (local), so the `/security-review` and
`/code-review` builtins (which auto-scope to current-branch-vs-main)
have no feature-branch diff to target — per
`security-review-integration.md` the delta was reviewed by direct
inspection (same disposition as v0.9.8 + v0.9.9).

| Pass | Scope | Verdict |
|---|---|---|
| 3 — commit re-test + 1-hop closure | The v0.10.0 changeset: 7 unpushed commits on `main` (`01df1f5` OCSF schema + mapping; `3ac011a` pilot collectors; `9f70721` SARIF; `abbd348` v0.10.0 docs; `5af2f11` research docs; `7615e39` README refresh; `8656e5c` positioning skip-by-reuse note). 10 importer files inspected via 1-hop closure on the touched modules. | PROCEED-CLEAN |
| 4 — full surface walk (v4 tightened) | 4 new surfaces (OCSF mapping, SARIF emit, the 2 new `SecurityFinding` fields, the `[ocsf]` extra) + 5 modified collector files. 10 adversarial probes against the 2 new surfaces (PASS); the 8 unchanged subsystems re-validated via the full 3292-test suite. | PROCEED-CLEAN |
| 6.C — final pre-tag pass | Pending (see §"16-row pre-push gate" below — filled at Step 6 entry). | TBD |

## Findings ledger

| ID | Bucket | Category | Location | CVSS v3.1 | CWE | EPSS | Disposition |
|---|---|---|---|---|---|---|---|
| **F-V100-L1** | **LOW** | trust-boundary (note) | `packages/evidentia-core/src/evidentia_core/ocsf/finding_mapping.py:259-260` | n/a (not exploitable at v0.10.0) | CWE-345 (Insufficient Verification of Data Authenticity, proxy) | n/a | **Accept for v0.10.0; v0.10.1 ingestion-collector design** must either (a) verify the OCSF doc's origin (signature / digest) before honoring the `unmapped["evidentia"]` block, or (b) strip the block on untrusted input. Pydantic re-validates either way, so corrupted blocks fail safely; the residual risk is identity / attribution forging by a *valid* OCSF producer. Tracked in `docs/v0.10.1-plan.md`. |

**Zero CRITICAL / HIGH / MEDIUM.** 1 LOW accepted with documented
v0.10.1 design follow-up.

## Security category sweep — direct delta inspection

| Category | Verdict |
|---|---|
| Injection (SQL / shell / path) | NONE — no shell commands, no path construction from user input, no SQL in v0.10.0 code. |
| Deserialization | Pydantic `model_validate` only (typed, safe). OCSF input re-validated via `py_ocsf_models.ComplianceFinding.model_validate`. |
| Weak crypto | sha256 used in `gap_analyzer/sarif.py` for stable `partialFingerprints` (de-dup keying, not crypto identity). Acceptable per SARIF use. |
| Secret exposure | No `__repr__` overrides; no credential handling in v0.10.0 code. |
| Authz bypass | No new auth or authz surface. |
| DoS / resource exhaustion | OCSF + SARIF transforms are O(n_findings) / O(n_gaps); bounded by upstream collector limits. Adversarial probe: 500 gaps → 500 results in 0.002s. |
| Regex / ReDoS | No new regex in v0.10.0. |
| Trust boundary | F-V100-L1 (LOW) — `finding_from_ocsf` trusts the `unmapped["evidentia"]` block. Not exploitable at v0.10.0 (ingestion collector deferred to v0.10.1); documented and tracked. |
| Supply chain | `py-ocsf-models>=0.9.0,<0.10.0` added as optional `[ocsf]` extra. Apache-2.0, Prowler-team-maintained, narrow pre-1.0 pin, lazy-imported. `uv.lock` records 0.9.0. |

## `/security-review` + `/code-review`

The v0.10.0 changeset is on `main` (local) with 7 unpushed commits,
so the `/security-review` and `/code-review` builtins have no
feature-branch diff to scope against. Per
`security-review-integration.md` the review was conducted by direct
file inspection of the changeset.

**`/code-review` triggers** evaluated at Step 3 entry:

| Trigger | Fired? | Detail |
|---|---|---|
| 1 — new public API / CLI / route | NO | No new FastAPI routes, no new Typer commands, no new top-level Pydantic BaseModels in `routers/` / `cli/` / `schemas.py`. The `ComplianceStatus(str, Enum)` is an enum, not a BaseModel; `--format sarif` is a help-text expansion on an existing CLI option. |
| 2 — new file under `packages/*/src/` | **YES** | 3 new source files: `gap_analyzer/sarif.py`, `ocsf/__init__.py`, `ocsf/finding_mapping.py`. All three inspected directly: pure functions, lazy imports where needed, typed boundary exceptions (`OCSFMappingError`), no audit-state mutation, no I/O. |
| 3 — >500 LOC delta | **YES** | 2555 LOC across 34 files. The volume is dominated by the OCSF mapping module (326 lines) + the 5 new test files (Phase 3 collector tests). Direct inspection covers all code-bearing additions. |
| 4 — security-relevant subsystem touched | NO | The diff touches `ocsf/` (new — not in the trigger-4 path list `security/ | network_guard | oscal/(signing\|sigstore) | secret | audit`). No files matching the trigger-4 pattern. |

Triggers 2 + 3 fired; direct inspection covered both. No additional
`/code-review`-derived findings beyond F-V100-L1.

## 16-row pre-push gate (Step 6.C — filled at Step 6 entry)

_Filled by Step 6 when the 16-row gate runs against the final
release-prep state (post-version-bump, post-CHANGELOG-rename)._

## Carry-over disposition

| Finding | Severity | Disposition |
|---|---|---|
| paramiko CVE-2026-44405 / GHSA-r374-rxx8-8654 | LOW (CLOSED in v0.9.9) | Stays closed. v0.10.0 does not touch the dependency chain that pulled it in (`compliance-trestle` 4.0.3 unchanged). |
| pyjwt PYSEC-2025-183 / CVE-2025-45768 | DISPUTED (scored 7.0) | Allowlisted in `osv-scanner.toml` with `ignoreUntil = 2026-11-21` re-validation date. Carried unchanged from v0.9.9. |

**Zero unfixed CRITICAL / HIGH / MEDIUM at v0.10.0 pre-tag.**

## Standards alignment

- **NIST SSDF PW.5** — code review with audit-defensible CVSS / CWE
  scoring: all findings carry the columns per `bug-bucketing.md` v4
  G7.
- **NIST SSDF PS.3** — supply-chain verification: `py-ocsf-models`
  added as a narrow-pinned optional extra; `osv-scanner --sbom`
  pre-push gate inherited from v0.9.9 will run at Step 6.C.
- **OpenSSF Best Practices Silver** — threat model maintained per v4
  G5 (1 day old at Step 1.5); supply-chain provenance via
  PEP 740 + SLSA L3 at Step 7.
- **ISO 27001:2022 A.8.27** + **SOC 2 Type II CC7.1** — security
  testing of new code surfaces (10 adversarial probes recorded in
  `docs/capability-matrix.md` v0.10.0 PRE-TAG section).

## Cross-references

- `docs/v0.10.0-plan.md` — phase-by-phase scope (Phases 0–5).
- `docs/ocsf-mapping.md` — NORMATIVE field-by-field SecurityFinding ↔
  OCSF Compliance Finding mapping reference.
- `docs/api-stability.md` — `finding.py` joins the frozen-models
  table; `evidentia_core.ocsf` entry point documented.
- `docs/capability-matrix.md` — v0.10.0 PRE-TAG re-validation
  snapshot (Step 4).
- `docs/threat-model.md` — v0.10.0 attack-surface delta section.
- `docs/integration-survey.md` — competitive/integration research
  pass that recommended the OCSF + SARIF moves.
- `docs/v0.10.1-plan.md` — deferred items + F-V100-L1 design
  follow-up.
- `.local/pre-release-review/runs/2026-05-23T02-09-21Z.json` — per-run
  log (25th in the series; private to operator workstation).
