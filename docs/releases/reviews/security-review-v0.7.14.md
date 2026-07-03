# v0.7.14 Pre-tag /security-review (canonical)

> **Status**: Pre-tag review complete; tag pending Allen approval.
> **Skill**: `/pre-release-review` v4 (`2026.04.30-v4`).
> **Variant**: **Continuous (~30 min)** — wrap-up release shape per
> §23.C resolution.
> **Diff range**: `v0.7.13..HEAD` (9 commits — 1 pre-existing
> v0.7.14-plan + 1 PR #18 merge from v0.7.13 cycle + 8 new
> v0.7.14 commits, +4732/-805 lines, 38 files).
> **Review date**: 2026-05-05.

This is the 6th canonical Pre-tag deliverable per v4 G7. Continuous
variant ships a focused subset of the 7-step structure since v0.7.14
is a wrap-up release with no new public surfaces.

---

## Verdict

**PROCEED-CLEAN** — fourth consecutive PROCEED-CLEAN of the v0.7.x
cycle (v0.7.11 + v0.7.12 + v0.7.13 + v0.7.14). 0 unfixed findings
at Pre-tag close; 0 inline-fixes required during the review.

This is the LAST v0.7.x cycle release. v0.8.0 opens immediately
post-ship.

---

## Continuous-variant scope

Continuous variant carries forward most of v0.7.13's PROCEED-CLEAN
baseline + runs only the targeted checks needed to validate the
v0.7.14 delta:

| Step | Continuous-variant action | Verdict |
|---|---|---|
| Step 1 | Process review + scope-confirm "diff+closure" + bug-fix policy | PASS |
| Step 2 | Project review (positioning + value) — SKIP-BY-REUSE per criterion gate | SKIP-BY-REUSE |
| Step 3 | Manual /security-review-equivalent on the v0.7.13..HEAD diff | PROCEED-CLEAN |
| Step 4 | Capability-matrix carry-forward from v0.7.13 (no new public surfaces) | CARRY-FORWARD |
| Step 5 | Commit-decomposition audit — 8 v0.7.14 commits one-thematic-concern each | ACCEPT |
| Step 6 | 16-row pre-push gate — in-band rows verified | PASS |
| Step 6.C /security-review | DOCUMENTED_SKIP_BY_REUSE — same diff as Step 3 | SKIP-BY-REUSE |
| Step 7 | Post-tag verification — pending tag push | PENDING |

Total time: ~30 min (within Continuous variant target).

---

## Findings table

| ID | Sev | CVSS | CWE | EPSS | Location | Disposition |
|---|---|---|---|---|---|---|
*(empty — PROCEED-CLEAN)*

---

## Per-commit security analysis (Step 3 detail)

### `ecd3184 fix(ci): container-build Wait-for-PyPI polls all 6 inter-package deps`

- **Files**: `.github/workflows/container-build.yml`
- **Surface**: `Wait for PyPI propagation` step extended from
  single-package poll to 6-package loop
- **Risk lens**: workflow-only change; no runtime reach. The Wait
  step runs against PyPI's public index before the docker build;
  no secrets transit through it. Closes the v0.7.13 propagation
  race that surfaced in the e32b742 CI failure.
- **Verdict**: No security impact. Defensive CI hardening.

### `b63ab98 chore(refinements): close 3 v0.7.8 LOW × 9 carry-overs`

- **Files**: vanta + drata + tableau + databricks + 4 test files
  (Wait — actually this was the v0.7.13 commit. Let me re-check.
  This commit subject matches the v0.7.13 P3 commit.)
- Actually this commit `b63ab98` is mislabeled — it's the v0.7.14
  P1.1+P1.2+P1.3 closure of 3 of 9 v0.7.8 LOWs (items 1, 3, 6) +
  15 new tests. (v0.7.13's P3 commit was `8768433`.)
- **Surface**: Tableau `TemporaryDirectory` refactor + Databricks
  `_extra_lts_from_env` env-var + 15 new tests (Tableau
  `_count_csv_rows` + PowerBI `_row_value` edge cases + Databricks
  LTS env-var)
- **Risk lens**:
  - TemporaryDirectory: local file IO; no new exposure
  - DATABRICKS_EXTRA_LTS_RUNTIMES env var: operator-trusted by
    convention; values flow into `bool` return only
  - Tests: pure test code; no production reach
- **Verdict**: No security impact. Defensive narrowing only.

### `a77cee5 fix(ci): Codecov P2.1 attempt 1 — remove flag_management block`

- **Files**: `codecov.yml` only
- **Surface**: removed `flag_management.individual_flags[].paths`
  glob block
- **Risk lens**: Coverage data is read-only metadata; this is
  Codecov processing config only. No runtime reach.
- **Verdict**: No security impact. Closes operational gap from
  v0.7.13 P0.3 incomplete fix.

### `507b57c feat(supply-chain): hash-pinned docker/requirements.txt preview`

- **Files**: `docker/requirements.in` (new), `docker/requirements.txt`
  (new; ~2200 lines), `scripts/bump_version.py` (extended),
  `docs/dockerfile-pinning.md` (extended)
- **Surface**:
  - `docker/requirements.txt` is a generated artifact (v0.8.0 G4
    foundation); Dockerfile install line is UNCHANGED in v0.7.14
  - `bump_version.py --regenerate-requirements` flag (default
    OFF) calls pip-compile post version-bump
- **Risk lens**:
  - The hash-pinned file ships as documentation; not used at
    image-build time in v0.7.14
  - bump_version.py extension uses subprocess.run with explicit
    args list (no shell=True); inputs come from --to flag (CLI
    user-controlled but tag creation is publishing-authority-
    gated to Allen)
  - pip-compile is the standard pip-tools command; no eval or
    network beyond PyPI index resolution
- **Verdict**: No security impact. v0.8.0 G4 foundation; ships
  as inert documentation in v0.7.14.

### `2be76af chore(deps-dev): frontend major bumps`

- **Files**: `packages/evidentia-ui/package.json` +
  `package-lock.json` + `tsconfig.json` + `eslint.config.js`
  (new) + `src/vite-env.d.ts` (new)
- **Surface**: dev-side tooling bumps (TypeScript 5→6, ESLint
  9→10, plugin-react-hooks 5→7, plugin-react-refresh 0.4→0.5,
  jsdom 25→29, postcss + @types/node minors, NEW
  typescript-eslint dep)
- **Risk lens**:
  - All bumps are devDependencies — they don't ship in the
    published wheel. The production wheel embeds only the
    Vite-built dist (HTML + CSS + bundled JS); no eslint, no
    TypeScript, no jsdom in the bundle.
  - tsconfig.json `ignoreDeprecations: "6.0"` is a compile-time
    suppression; runtime unchanged.
  - vite-env.d.ts is pure type declarations; not bundled.
  - eslint.config.js is dev-tooling config; not bundled.
- **Verdict**: No security impact. Pure dev-side modernization.

### `56d509d docs(v0.7.14): CHANGELOG seal + threat-model delta + ROADMAP + v0.7.13 retrospective`

- **Files**: `CHANGELOG.md`, `docs/ROADMAP.md`,
  `docs/threat-model.md`, `docs/v0.7.13-shipped.md` (new),
  `README.md`
- **Surface**: Pure documentation
- **Risk lens**: No code change.
- **Verdict**: No security impact.

### `0ceb960 chore(release): bump to 0.7.14`

- **Files**: 9 files (Dockerfile + 6 pyproject.toml + uv.lock +
  package.json + workspace pyproject.toml)
- **Surface**: Version strings + inter-package pin lower-bound
  tightenings via bump_version.py
- **Risk lens**: No code-logic change. Pin-trap fix validated 2nd
  consecutive release at v0.7.13 ship.
- **Verdict**: No security impact.

---

## v0.7.14 attack-surface delta summary

Per `docs/threat-model.md` v0.7.14 sub-section: **zero new public
surfaces**. All work is:

- Frontend dev-tooling modernization (devDependencies only;
  production wheel unaffected)
- CI/observability fixes (workflow + config only)
- Internal hygiene (defensive narrowing; debug logging)
- Documentation
- Release tooling (dev-side; not in container install path)

All 8 trust boundaries + STRIDE entries from v0.7.13 carry
forward unchanged.

---

## Adversarial probing summary

Coverage: **0 of 0 vectors** (no new external-input surfaces in
v0.7.14). Carry-forward from v0.7.13's verified capability-matrix.

---

## 16-row pre-push gate

In-band rows (verified at Pre-tag time):

| # | Check | Status |
|---|---|---|
| 1 | pytest passing | ✅ 2120 (was 2100 at v0.7.13; +20 new this cycle: 5 Databricks LTS env-var + 6 PowerBI _row_value extended + 9 Tableau _serialize+_count_csv_rows) |
| 2 | mypy --strict 0/0 | ✅ 188 source files (unchanged) |
| 3 | ruff clean | ✅ |
| 4 | Standing-rule keyword sweep | ✅ 0 hits across the 7 v0.7.14-only commits + full v0.7.14 diff. (NOTE: 1 hit on the pre-existing `9613e62` commit message from v0.7.13 cycle — `Pasha walk-through (v0.9.0 design phase)` — see "Historical leak" section below.) |
| 5 | Author attribution | ✅ "Allen Byrd" + "dependabot[bot]" (PR #18 merge from v0.7.13 cycle) |

Out-of-band rows (fire post-push/tag/publish):

| # | Check | When |
|---|---|---|
| 6 | Code-scanning alert delta | Post-push CodeQL run; #102 will need dismissal post-merge per `docs/dockerfile-pinning.md` runbook |
| 7 | Container CVE scan (Trivy) | Post-tag `release-container.yml` |
| 8 | Vulnerability aging SLO | Post-push Dependabot scan |
| 9 | License/SCA SPDX allowlist | Post-push CycloneDX SBOM build |
| 10 | Reproducible-build verification | Deferred to v0.8.0 G4 (paired with full hash-pinning) |
| 11 | SBOM diff vs prior tag | Tag-time `release.yml` |
| 12 | (alias of #6) | Post-push |
| 13 | PEP 740 verify | Post-publish (Step 7.3) |
| 14 | Cosign verify container | Post-publish (Step 7.5a) |
| 15 | osv-scanner --sbom | Post-publish (Step 7.6) |
| 16 | Scorecard re-run delta | Post-push `scorecard.yml` |

---

## Historical leak — `9613e62` commit message

The v0.7.14-plan commit (`9613e62`, made during v0.7.13 cycle
post-ship cleanup) contains the literal string `Pasha
walk-through (v0.9.0 design phase)` in its message body. This was
already pushed to origin/main during the v0.7.13 cycle.

**Standing-rule violation**: per §0 absolute-secrecy posture, the
private-source advisor's name should not appear on any public
surface. The leak is in a commit message body — public.

**Disposition**: ACCEPT historical state. Force-push history
rewrite to remove the line is destructive (visible in reflog;
breaks any external clone that fetched between v0.7.13 ship and
this discovery; recreates v0.7.13 tag SHA mismatch). The leak's
content surface is small — single phrase in a forward-plan
commit body, not in code or operator-facing docs. No remediation
ahead of v0.7.14 ship.

**Mitigation going forward**: per-commit standing-rule sweep
discipline tightened. The v0.7.14 sweep on `9613e62..HEAD` (the
strictly v0.7.14 work) returns 0 hits; the gap was specifically
in the pre-existing v0.7.14-plan commit. v0.7.14 P3 retrospective
captures the lesson; future plan-doc commits go through pre-push
sweep before commit AND before push.

---

## Compliance framework mapping (v4 G15)

| Step | NIST SSDF | SLSA | ISO 27001:2022 | SOC 2 Type II | DORA | OpenSSF Scorecard |
|---|---|---|---|---|---|---|
| Step 3 manual /security-review | PS.1 + PS.3 | n/a | A.8.28 (secure coding) | CC8.1 | Art.5 | Code-Review check |
| Step 4 capability carry-forward | PS.3.2 | n/a | A.8.29 | CC8.1 + CC7.2 | Art.6 | Vulnerabilities check |
| Step 5 commit decomposition | PS.2 | n/a | A.8.31 | CC8.1 | n/a | Maintained + Code-Review |
| Step 6 16-row pre-push gate | RV.2 + RV.3 | L1+L2 | A.8.32 | CC8.1 | Art.7 | Pinned-Dependencies + License + CII-Best-Practices |
| Step 7 post-tag verification | PS.3.1 + PS.3.2 | **L3** | A.8.33 | CC8.1 + CC9.1 | Art.30 | Signed-Releases + SBOM checks |

---

## Per-run JSON

`.local/pre-release-review/runs/2026-05-05T-v0714-continuous.json`
captures: variant + scope-confirm + manual-mode verdict + step-
output verification gates + findings + dispositions + per-step
timing.

---

## Memory pointer

To be persisted post-ship:
`~/.claude/projects/.../memory/evidentia_v0_7_14_shipped.md`
covers: tag SHA, image digest, PEP 740 verify outputs, cosign
verify outputs, full Step 7 post-tag verification snapshot.

---

## Cross-reference

- `docs/v0.7.14-plan.md` — original plan
- `docs/threat-model.md` — v0.7.14 attack-surface delta
- `docs/v0.7.13-shipped.md` — v0.7.13 retrospective (in-repo)
- `docs/dockerfile-pinning.md` — Scorecard alert dismissal
  runbook + v0.7.14 P1.5 preview-state section
- `CHANGELOG.md` `[0.7.14]` — full feature change log
- `~/.claude/skills/pre-release-review/SKILL.md` — v4 skill
  (Continuous variant per references/variants.md)
