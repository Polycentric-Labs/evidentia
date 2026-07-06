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
| 6.C — final pre-tag pass | Full HEAD vs `v0.9.9` direct delta inspection; 16-row pre-push gate (filled below); 2 NEW MEDIUM findings caught + fixed in-place (F-V100-M1 + F-V100-S1). | PROCEED-CLEAN |

## Findings ledger

| ID | Bucket | Category | Location | CVSS v3.1 | CWE | EPSS | Disposition |
|---|---|---|---|---|---|---|---|
| **F-V100-L1** | **LOW** | trust-boundary (note) | `packages/evidentia-core/src/evidentia_core/ocsf/finding_mapping.py:259-260` | n/a (not exploitable at v0.10.0) | CWE-345 (Insufficient Verification of Data Authenticity, proxy) | n/a | **Accept for v0.10.0; v0.10.1 ingestion-collector design** must either (a) verify the OCSF doc's origin (signature / digest) before honoring the `unmapped["evidentia"]` block, or (b) strip the block on untrusted input. Pydantic re-validates either way, so corrupted blocks fail safely; the residual risk is identity / attribution forging by a *valid* OCSF producer. Tracked in `docs/v0.10.1-plan.md`. |
| **F-V100-M1** | **MEDIUM** | release tooling — third-party pin over-bump | `scripts/bump_version.py` (substitution logic) | n/a (process / build tooling) | CWE-697 (Incorrect Comparison, proxy) | n/a | **Fixed in-place at Step 6 entry**; tooling fix deferred to v0.10.1 Phase 5. `scripts/bump_version.py --to 0.10.0` substituted the `py-ocsf-models>=0.9.0,<0.10.0` pin to `>=0.10.0,<0.11.0` — the substitution logic does not distinguish inter-package pins from third-party pins matching the same `>=0.X.0,<0.Y.0` shape. The bumped pin was unsatisfiable (no `py-ocsf-models 0.10.0` exists) and would have broken any fresh install; **caught by `uv sync` during the Step 6 pre-tag gate** (which is exactly the value of running the gate). Reverted manually to `>=0.9.0,<0.10.0` in `packages/evidentia-core/pyproject.toml` + root `pyproject.toml`; `uv sync --all-packages --all-extras` re-ran clean; `uv.lock` records `py-ocsf-models 0.9.0`. Underlying tooling bug tracked for v0.10.1 (harden the substitution to use `[tool.uv.sources]` workspace allowlist or an explicit Evidentia-package allowlist). |
| **F-V100-S1** | **MEDIUM** (supply chain) | transitive CVE (host-header validation bypass) | `starlette 1.0.0` (transitive via `fastapi` + `sse-starlette`) | n/a (OSV severity unscored) | CWE-20 (Improper Input Validation, proxy) | n/a | **Fixed in-place at Step 6 gate**. PYSEC-2026-161 / GHSA-86qp-5c8j-p5mr — "missing Host header validation poisons request.url.path, bypassing path-based security checks". Surfaced by the Row 14 `osv-scanner --sbom` gate after the v0.10.0 dev-venv sync. Closed by `uv lock --upgrade-package starlette` (1.0.0 → 1.0.1, the upstream patch release) + `uv sync --all-packages --all-extras`; no Evidentia pin range needed to move (fastapi's pin already allows 1.0.1). Re-ran osv-scan → clean; re-ran pytest → green. Bumps the value-add of the v4 Row 14 gate to **2 real CVE closures inline** across the v0.9.x → v0.10.x line. |

**Zero CRITICAL / HIGH.** 2 MEDIUM **fixed in-place** at Step 6
(F-V100-M1 — release-tooling pin over-bump, F-V100-S1 — starlette
transitive CVE PYSEC-2026-161, both caught by the gate); 1 LOW
accepted with documented v0.10.1 design follow-up (F-V100-L1).

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

## 16-row pre-push gate (Step 6.C)

| # | Check | v0.10.0 outcome |
|---|---|---|
| 1 | Credential pattern sweep of `v0.9.9..HEAD` diff | PASS — 0 hits |
| 2 | Claude-attribution sweep of diff content | PASS — 0 hits |
| 3 | Commit-message attribution sweep | PASS — 0 hits in `v0.9.9..HEAD` |
| 4 | `.gitignore` secret-store coverage | PASS — `.env*` / `*.pem` / `*.key` / `*.crt` / `*.p12` / `*.pfx` / `secrets/` / `credentials.json` covered |
| 5 | Tracked secret-shape files | PASS — only pre-existing `.env.example` placeholder |
| 6 | Test gate | PASS — 3295 passed / 14 skipped |
| 7 | Type/lint gate | PASS — mypy strict 0/0 across 265 source files (7 packages); ruff clean |
| 8 | Build sanity | PASS — 7 wheels + 7 sdists at 0.10.0; `twine check` all PASSED |
| 9 | Identity | PASS — `Allen Byrd <125306425+allenfbyrd@users.noreply.github.com>` |
| 10 | Branch sanity | PASS — on `main`, 10 commits ahead of `origin/main` at chore(release) time |
| 11 | Legacy long-lived secrets | PASS — only `CODECOV_TOKEN`; no legacy `PYPI_API_TOKEN` (OIDC Trusted Publisher) |
| 12 | Code-scanning alert delta since v0.9.9 | PASS — 0 NEW open HIGH alerts |
| 13 | Container CVE scan (Trivy) | WARN-SKIP — `trivy` not installed; v0.10.0 made no Dockerfile changes; `release.yml publish-container` rebuilds + cosign-signs at tag (Step 7.5 verified clean) |
| 14 | Vulnerability aging SLO (`osv-scanner --sbom`) | PASS after F-V100-S1 fix — starlette 1.0.0 → 1.0.1 closed PYSEC-2026-161 / GHSA-86qp-5c8j-p5mr inline; re-scan clean |
| 15 | License / SCA enforcement | WARN-SKIP — `pip-licenses` not installed; only new third-party dep is `py-ocsf-models` (Apache-2.0) |
| 16 | Secret-rotation cadence | PASS — `CODECOV_TOKEN` updated 5 days ago (well under 90-day threshold) |

Rows 13/15 degrade gracefully on absent optional tooling — same
disposition as the prior 24 PROCEED-CLEAN cycles. Zero blocking
findings. F-V100-S1 + F-V100-M1 each surfaced at this gate and were
fixed in-place before the tag.

## Step 7 post-tag verification

Per v4 G1. Runs after `release.yml` publishes to PyPI + GHCR.

| Sub-step | Outcome |
|---|---|
| 7.1 `release.yml` run | ✅ **success** in 222s (~3:42 tag-to-publish); run id `26321828405` |
| 7.3 PEP 740 attestation verify (7 wheels) | ✅ **7/7 OK** via `pypi-attestations verify pypi --repository https://github.com/Polycentric-Labs/evidentia "pypi:<wheel-name>"` |
| 7.5 Cosign container verify | ✅ **VERIFIED** — `cosign verify ghcr.io/polycentric-labs/evidentia:v0.10.0` reports SLSA Provenance v1 signed by `release.yml` via Fulcio + Rekor; image digest `sha256:1eedd6d6652666509921df81388b799c68a351d8cd7db885601225869c8637b8` |
| 7.5 Docker smoke | ✅ `docker run … version` → `Evidentia v0.10.0 / Python 3.14.5`; `catalog list` returns `89 framework(s)` |
| 7.6 Published SBOM osv-scan | ✅ **CLEAN** — `evidentia-sbom.cdx.json` from the GitHub Release scanned with `osv-scanner --sbom`; 183 packages; no issues. (Published SBOM is the narrower release-install closure; the local dev SBOM has 225 packages because of `--all-extras` AI/DAST tools that don't ship.) |
| 7.7 Scorecard | ✅ **success** for `7556f5f` (v0.10.0 commit); 0 open HIGH code-scanning alerts |
| 7.8 Fresh-venv install smoke | ✅ `python -m venv` + `pip install "evidentia==0.10.0"` → `evidentia version` returns `Evidentia v0.10.0 / Python 3.14.2`; `evidentia catalog list` loads `Loaded catalog 'NIST SP 800-53 Rev 5.2.0 ...': 1196 controls in 20 families` and returns `89 framework(s)` |
| 7.9 Release notes audit | ✅ CHANGELOG-style summary present (auto-extracted from `[0.10.0]` block); `evidentia-sbom.cdx.json` attached as release asset |
| 7.10 Memory + audit-log update | this section; plus a fresh entry appended to `MEMORY.md` for v0.10.0 SHIPPED |

**Verdict**: PROCEED-CLEAN confirmed post-tag — **25th consecutive**
of the v0.7.x → v0.8.x → v0.9.x → v0.10.x line. v0.10.0 SHIPPED.

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
