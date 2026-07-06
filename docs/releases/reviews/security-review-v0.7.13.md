# v0.7.13 Pre-tag /security-review (canonical)

> **Status**: Pre-tag review complete; tag pending Allen approval.
> **Skill**: `/pre-release-review` v4 (`2026.04.30-v4`).
> **Variant**: Pre-tag (full v4 7-step).
> **Diff range**: `v0.7.12..HEAD` (6 commits, +1340/-113 lines,
> 28 files, 0 commits pushed at review time).
> **Review date**: 2026-05-04.

This is the 6th canonical Pre-tag deliverable per v4 G7. CVSS / CWE
/ EPSS columns + 6-framework compliance mapping (NIST SSDF + SLSA +
ISO 27001 + SOC 2 + DORA + OpenSSF) inline below.

---

## Verdict

**PROCEED-CLEAN** — third consecutive PROCEED-CLEAN of the v0.7.x
cycle (v0.7.11 + v0.7.12 + v0.7.13). 0 unfixed findings at Pre-tag
close; 0 inline-fixes required during the review.

This is a wrap-up release for the v0.7.x cycle: dependency
modernization (Codecov fix), P3 carry-over closures, and
release-notes hygiene. No new public surfaces are added; the
attack surface is carry-forward from v0.7.12.

---

## /security-review invocation summary (G12 — manual deep-pass)

The `/security-review` skill is session-locked from v0.7.12 prior
invocations. The v0.7.13 review uses a **manual deep-pass on each
commit's diff** following the `/security-review` skill's
methodology (reading the diff with security lens; tracing data
flow from external input → sensitive operation; checking each
of the OWASP top-10 categories against the change set).

| Inv | Step | Scope | Verdict | Findings | Disposition |
|---|---|---|---|---|---|
| 1 | Step 3 | `v0.7.12..HEAD` diff (6 commits) | PROCEED-CLEAN | 0 | All 6 commits classified — no new attack surface; defensive narrowing where applicable |
| 2 | Step 4 | Per-subsystem on B (collectors) + C (integrations) + D (TPRM); A/E/F/G/H unchanged | PROCEED-CLEAN | 0 | Existing capability-matrix carries forward; v0.7.13 delta is defensive |
| 3 | Step 6.C | Pre-push final pass on full v0.7.12..HEAD diff | DOCUMENTED_SKIP_BY_REUSE | n/a | No diff change between Step 3 and Step 6.C; no Step 5 inline-fixes; identical analysis surface |

---

## Findings table

| ID | Sev | CVSS | CWE | EPSS | Location | Disposition |
|---|---|---|---|---|---|---|
*(empty — PROCEED-CLEAN)*

---

## Per-commit security analysis (Step 3 detail)

### `7c86de1 fix(ci): Codecov source_pkgs fix`

- **Files**: `pyproject.toml` only
- **Surface**: `[tool.coverage.run]` config — `source = [...]` →
  `source_pkgs = [...]`
- **Risk lens**: Coverage data is read-only metadata about the
  test suite. The Cobertura XML records line-coverage counts +
  file paths; no source code or vendor data flows through the
  upload. The configuration change affects how coverage.py
  walks source files, not which inputs reach the runtime.
- **Verdict**: No security impact. Closes the
  `test_statement_coverage80` Silver criterion (operational
  hygiene, not new attack surface).

### `0727889 docs(dockerfile): policy doc + Scorecard suppression rationale`

- **Files**: `Dockerfile` (comment block), `docs/dockerfile-pinning.md` (new)
- **Surface**: ASCII comment + markdown documentation
- **Risk lens**: No code change. The Dockerfile `pip install`
  line is unchanged; only the comment above it is extended.
  The new doc captures the rationale for exact-version pinning
  (vs full hash-pinning) + the recurring-alert dismissal
  runbook.
- **Verdict**: No security impact. Documents existing policy
  rather than changing it.

### `8768433 chore(refinements): close 3 P3 carry-overs (M-9 + L-2 + L-4)`

- **Files**: vanta/drata collectors (`_is_high_risk` extension),
  TPRM questionnaire (debug logging), trestle conformance test
  (M-9 UUID identity), vanta+drata test files (L-2 extended-field
  tests)
- **Surface**:
  - Vanta + Drata `_is_high_risk` extended w/ 7 additional
    field-name probes + nested-block probes + `SEVERE` matched
    value. Helper still returns `bool` and reads from API
    response dicts; defensive: returns False on unrecognized
    shapes.
  - TPRM `parse_sig_template` adds `_log.debug(...)` calls
    on row-walk decisions (sparse, label-mismatch, already-
    populated, pre-fill). Debug logging is gated by operator
    log-level config.
  - OSCAL UUID conformance test uses trestle round-trip;
    pure test, no production code change.
- **Risk lens**:
  - High-risk detection: more sensitive than before, never
    less. Returns False on unknown values + only matches
    `HIGH` / `CRITICAL` / `SEVERE` (case-insensitive). No
    risk of false positives causing harm — the helper drives
    a `vendor-high-risk:<id>` finding emission, which is
    informational + reviewed by operators.
  - Debug logging: row labels come from operator-supplied
    XLSX (Shared Assessments licensed templates). The
    label values are not executed as code; they go to stderr
    via Python's standard logging. Operators opting into
    debug-level logging accept that template content lands
    in their log streams (their licensing concern, not a new
    sensitive surface introduced by Evidentia).
  - OSCAL test: pure test code; no production reach.
- **Verdict**: No security impact. Defensive extensions +
  diagnostic visibility only.

### `415ab29 chore(refinements): partial v0.7.8 LOW × 9 closure`

- **Files**: powerbi extract.py, tableau extract.py,
  snowflake collector.py
- **Surface**:
  - PowerBI `_row_value`: list/tuple branch filters Nones
    before join (fixes "None;x;None" leakage); type-match
    tightened from `hasattr(.value)` to `isinstance(Enum)`.
  - Tableau `_serialize`: same pattern as PowerBI.
  - Snowflake `_to_utc_iso`: new helper that force-casts
    naive datetimes to UTC before isoformat.
- **Risk lens**:
  - Enum tightening: STRICTLY more conservative — only true
    Enum instances now take the value-extraction branch. A
    Pydantic model with a `.value` field accidentally
    matching the previous duck-type check is no longer
    misclassified.
  - tz-cast: Snowflake LOGIN_HISTORY rows previously emitted
    naive isoformat (ambiguous timestamp) → now tz-aware ISO
    8601. Tightens audit-trail correlation; doesn't expose
    new info.
- **Verdict**: No security impact. Correctness fixes that
  reduce ambiguity in audit trails + downstream BI output.

### `a794cd0 docs(v0.7.13): doc-consistency + workflow fix`

- **Files**: README.md, ROADMAP.md, threat-model.md,
  v0.8.0-plan.md, CHANGELOG.md (docs); release.yml (workflow);
  scripts/extract_changelog_block.py (new); test
  (test_extract_changelog_block.py — new)
- **Surface (workflow)**:
  - New `Extract release body from CHANGELOG` step in
    publish-pypi job. Runs:
    ```
    python scripts/extract_changelog_block.py "$version"
    ```
    where `$version=${GITHUB_REF_NAME#v}`.
  - Sanity gate: refuses if extracted body < 1500 bytes.
- **Risk lens**:
  - Tag creation is publishing-authority-gated to Allen.
    `$GITHUB_REF_NAME` therefore comes from a trusted source.
  - The python script does file IO on `CHANGELOG.md` (trusted)
    + writes `release-body.md` (workspace artifact). No
    `eval()` / `exec()`. No external network. No shell
    interpolation of CHANGELOG content.
  - The script uses `re.escape()` on the version input
    before pattern construction → no regex injection from
    a malicious version string (which couldn't exist
    anyway given the tag-creation gate).
  - 21 self-tests in `test_extract_changelog_block.py`
    cover every shipped block + edge cases (dotted-prefix
    mismatch / non-existent version / synthetic block
    rendering). Self-tests exercise the security-relevant
    paths.
- **Verdict**: No security impact. The workflow change
  closes the structural gap that produced 9 stub release
  bodies (v0.7.5–v0.7.12); the input source for the script
  is trusted (CHANGELOG.md is a public-OSS-tree-only
  artifact).

### `8143679 chore(release): bump to 0.7.13`

- **Files**: 9 files (Dockerfile + 6 pyproject.toml + uv.lock +
  package.json + workspace pyproject.toml)
- **Surface**: Version strings + inter-package pin lower-bound
  tightenings via `scripts/bump_version.py` (existing v0.7.12
  pin-trap fix).
- **Risk lens**: No code-logic change. The pin-trap fix was
  validated end-to-end at v0.7.12 ship (Step 7.8 fresh-venv
  install resolved all 6 packages at 0.7.12 first-attempt).
- **Verdict**: No security impact.

---

## v0.7.13 attack-surface delta summary

Per `docs/threat-model.md` v0.7.13 sub-section: **zero new public
surfaces**. The work is entirely:

- Dependency modernization (Codecov upload pipeline)
- Internal hygiene (P3 closures + LOW × 5 fixes)
- Documentation (Dockerfile policy + M-4 deferral)
- Release ergonomics (release.yml CHANGELOG auto-population)

All 8 trust boundaries + STRIDE entries from v0.7.12 carry
forward unchanged. The 3 cloud-WORM backends, 6 retention
stores, GDPR purge-flow, and FAIR Monte Carlo simulator
remain as documented in §v0.7.12.

---

## Adversarial probing summary (v0.7.13 surfaces)

Coverage: **0 of 0 vectors** (no new external-input surfaces in
v0.7.13). Carry-forward verification per the existing capability-
matrix snapshot.

| Vector | Coverage |
|---|---|
| Bad input | n/a (no new endpoints) |
| Missing dependency | Codecov upload step uses `fail_ci_if_error: false` (failure to upload doesn't fail the build); `extract_changelog_block.py` self-tests cover edge cases |
| Network failure | n/a (no new network surfaces) |
| Expired credential | n/a (no new auth flows) |
| Malformed config | New `release.yml` step refuses to publish if extracted body < 1500 bytes (sanity gate against malformed CHANGELOG) |
| Concurrent request / race | n/a (no new concurrent surfaces) |
| Large-input DoS | Per CLAUDE.md hard exclusions, this is not a security-finding category |

---

## 16-row pre-push gate

In-band rows (verified at Pre-tag time):

| # | Check | Status |
|---|---|---|
| 1 | pytest passing | ✅ 2100 (was 2075 at v0.7.12; +25 new this cycle) |
| 2 | mypy --strict 0/0 | ✅ 188 source files (unchanged) |
| 3 | ruff clean | ✅ |
| 4 | Standing-rule keyword sweep | ✅ clean across 6 commits + full diff |
| 5 | Author attribution | ✅ only "Allen Byrd" across all 6 commits |

Out-of-band rows (fire post-push, post-tag, or post-publish per
the v4 Step 7 deliverable):

| # | Check | When |
|---|---|---|
| 6 | Code-scanning alert delta | Post-push CodeQL run; #101 dismissal in Batch A; alert count → 0 open |
| 7 | Container CVE scan (Trivy) | Post-tag `release-container.yml` |
| 8 | Vulnerability aging SLO | Post-push Dependabot scan |
| 9 | License/SCA SPDX allowlist | Post-push CycloneDX SBOM build |
| 10 | Reproducible-build verification | Deferred to v0.8.0 G4 (paired with full hash-pinning) |
| 11 | SBOM diff vs prior tag | Tag-time `release.yml` |
| 12 | (alias of #6 — code-scanning delta) | Post-push |
| 13 | PEP 740 verify | Post-publish (Step 7.3) |
| 14 | Cosign verify container | Post-publish (Step 7.5a) |
| 15 | osv-scanner --sbom | Post-publish (Step 7.6) |
| 16 | Scorecard re-run delta | Post-push `scorecard.yml` |

Step 7 post-tag verification will close all 16 rows after the
actual tag + push.

---

## Compliance framework mapping (v4 G15)

| Step | NIST SSDF | SLSA | ISO 27001:2022 | SOC 2 Type II | DORA | OpenSSF Scorecard |
|---|---|---|---|---|---|---|
| Step 3 /security-review (manual) | PS.1 + PS.3 | n/a (pre-build) | A.8.28 (secure coding) | CC8.1 (change mgmt) | Art.5 (operational resilience: secure-by-design) | Code-Review check |
| Step 4 capability re-validation | PS.3.2 + PW.4 | n/a | A.8.29 (security testing) | CC8.1 + CC7.2 | Art.6 (testing) | Vulnerabilities check |
| Step 5 commit decomposition | PS.2 | n/a | A.8.31 (separation of dev/test/prod) | CC8.1 | n/a | Maintained + Code-Review |
| Step 6 release-checklist + final review | RV.1 + RV.2 | L1+L2 build provenance | A.8.30 (outsourced dev) — n/a | CC8.1 + CC9.1 | Art.7 (ICT incident reporting) | n/a |
| Step 6 pre-push gate (16 rows) | RV.2 + RV.3 | L1+L2 | A.8.32 (change mgmt) | CC8.1 | Art.7 | Pinned-Dependencies + License + CII-Best-Practices |
| Step 7 post-tag verification | PS.3.1 (provenance) + PS.3.2 (verify) | **L3** (build provenance signed; reproducible) | A.8.33 (test data: SBOM + verify) | CC8.1 + CC9.1 | Art.30 (third-party audit signals) | Signed-Releases + SBOM checks |

---

## Per-run JSON

`.local/pre-release-review/runs/2026-05-04T-v0713-pretag.json` —
captures the full run state including: variant + scope-confirm
answer + manual-mode verdict + step-output verification gates +
findings + dispositions + per-step timing. (Generated post-Step-7;
v4 G13 deliverable.)

---

## Memory pointer

To be persisted post-ship:
`~/.claude/projects/.../memory/evidentia_v0_7_13_shipped.md`
covers: tag SHA, image digest, PEP 740 verify outputs, cosign
verify outputs, full Step 7 post-tag verification snapshot.

---

## Cross-reference

- `docs/v0.7.12-plan.md` — the previous release-plan (P0 + P1 + P3 carry-overs from v0.7.11)
- `docs/threat-model.md` — v0.7.13 attack-surface delta
- `docs/capability-matrix.md` — v0.7.12 in-progress snapshot (carries forward; no new surfaces)
- `docs/release-checklist.md` Steps 5.5 + 9.5 — doc-consistency + release-notes audit practices (added in v0.7.12)
- `docs/dockerfile-pinning.md` — v0.7.13 P3 deliverable: Scorecard PinnedDependencies policy
- `docs/v0.8.0-plan.md` — M-4 deferral now formally documented (carry-forward to v0.8.0 P0.4)
- `CHANGELOG.md` `[0.7.13]` — full per-feature change log
- `~/.claude/skills/pre-release-review/SKILL.md` — v4 skill
- `~/.claude/projects/.../memory/evidentia_release_documentation_practice.md` — practice memory pointer (v0.7.12 P5.2; updated in v0.7.13 with the workflow auto-population fix that closes the stub-body gap structurally)
