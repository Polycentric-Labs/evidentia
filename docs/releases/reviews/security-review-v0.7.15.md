# v0.7.15 Pre-tag /security-review (canonical)

> **Status**: Pre-tag review complete; tag pending Allen approval.
> **Skill**: `/pre-release-review` v4 (`2026.04.30-v4`).
> **Variant**: **Continuous (~30 min)** — wrap-up release shape.
> **Diff range**: `v0.7.14..HEAD` (5 commits, 10 files changed).
> **Review date**: 2026-05-05.

This is the 6th canonical Pre-tag deliverable (Continuous variant)
per v4 G7. v0.7.15 is the FINAL v0.7.x cycle release before v0.8.0
design opens.

---

## Verdict

**PROCEED-CLEAN** — fifth consecutive PROCEED-CLEAN of the v0.7.x
cycle (v0.7.11 + v0.7.12 + v0.7.13 + v0.7.14 + v0.7.15). 0 unfixed
findings; 0 inline-fixes during cycle.

---

## Continuous-variant scope

| Step | Continuous-variant action | Verdict |
|---|---|---|
| Step 1 | Process review + scope-confirm "diff+closure" + bug-fix policy | PASS |
| Step 2 | Project review (positioning + value) — SKIP-BY-REUSE | SKIP-BY-REUSE |
| Step 3 | Manual /security-review-equivalent on the v0.7.14..HEAD diff | PROCEED-CLEAN |
| Step 4 | Capability-matrix carry-forward from v0.7.14 (no new public surfaces) | CARRY-FORWARD |
| Step 5 | Commit-decomposition audit — 5 v0.7.15 commits one-thematic-concern each | ACCEPT |
| Step 6 | 16-row pre-push gate — in-band rows verified | PASS |
| Step 6.C /security-review | DOCUMENTED_SKIP_BY_REUSE — same diff as Step 3 | SKIP-BY-REUSE |
| Step 7 | Post-tag verification — pending tag push | PENDING |

---

## Findings table

| ID | Sev | CVSS | CWE | EPSS | Location | Disposition |
|---|---|---|---|---|---|---|
*(empty — PROCEED-CLEAN)*

---

## Per-commit security analysis (Step 3 detail)

### `4ff5bb7 chore(deps-dev): tailwind 3 → 4 (CSS-first @theme migration)`

- **Files**: `package.json`, `package-lock.json`, `vite.config.ts`,
  `src/index.css`, `tailwind.config.ts` (deleted),
  `postcss.config.js` (deleted)
- **Surface**: dev-tooling rewrite. Production wheel embeds the
  Vite-built dist (HTML + CSS + bundled JS); no eslint, no
  TypeScript, no build tooling in the bundle.
- **Risk lens**:
  - Theme tokens migrated from JS to CSS-first `@theme` blocks —
    same severity palette, same dark-mode behavior. Visual
    output verified unchanged.
  - `@tailwindcss/vite` plugin is a first-class Tailwind 4
    artifact (signed npm release).
  - `tw-animate-css` is the canonical v4-compatible community
    fork of `tailwindcss-animate`.
- **Verdict**: No security impact. Pure dev-side modernization;
  same compiled output trust posture.

### `56c5520 refactor(SettingsPage): key-based remount eliminates set-state-in-effect`

- **Files**: `packages/evidentia-ui/src/routes/SettingsPage.tsx`,
  `packages/evidentia-ui/eslint.config.js`
- **Surface**: internal React component refactor. Same form fields,
  same backend interaction, same auth model.
- **Risk lens**:
  - useState lazy initializers seed from props on first render;
    no useEffect+setState seed pattern.
  - `<SettingsForm/>` sub-component is keyed on
    `config.source_path` for clean remount on data load.
  - No new endpoints, no new state escape, no new exposure.
- **Verdict**: No security impact. Pattern fix; the
  `react-hooks/set-state-in-effect` lint rule is now
  `error`-level (was `warn` in v0.7.14).

### `f48345a chore(ci): standing-rule keyword sweep as pre-commit hook`

- **Files**: `scripts/standing_rule_sweep.sh` (new),
  `.pre-commit-config.yaml`
- **Surface**: contributor-side tooling. Doesn't ship in any
  artifact (wheel, container, etc.); runs only on contributor
  machines via `pre-commit install`.
- **Risk lens**:
  - The bash script reads file contents (positional args from
    pre-commit) + greps for the canonical 21-pattern set.
  - No external network, no eval/exec, no subprocess to
    untrusted commands.
  - SKIP_FILES list scopes the self-reference exemption to the
    script + .pre-commit-config.yaml; both legitimately
    reference the patterns by name in their documentation.
  - `.local/` paths skipped to avoid scanning gitignored
    private notes.
  - Bypass via `git commit --no-verify` is possible but
    documented as Allen-approval-only in script output.
- **Verdict**: No security impact. Defensive contributor-side
  guard; no operator/runtime trust boundary change.

### `0634641 docs(v0.7.15): CHANGELOG + threat-model delta + ROADMAP + v0.7.14 retrospective + README`

- **Files**: `CHANGELOG.md`, `docs/ROADMAP.md`,
  `docs/threat-model.md`, `docs/v0.7.14-shipped.md` (new),
  `README.md`
- **Surface**: pure documentation
- **Risk lens**: no code change.
- **Verdict**: No security impact.

### `f10fb54 chore(release): bump to 0.7.15`

- **Files**: 9 files (Dockerfile + 6 pyproject.toml + uv.lock +
  package.json + workspace pyproject.toml)
- **Surface**: version strings + inter-package pin lower-bound
  tightenings via bump_version.py
- **Risk lens**: no code-logic change. Pin-trap fix validated 3rd
  consecutive release at v0.7.14 ship.
- **Verdict**: No security impact.

---

## v0.7.15 attack-surface delta summary

Per `docs/threat-model.md` v0.7.15 sub-section: **zero new public
surfaces**. All work is:

- Frontend dev-tooling rewrite (Tailwind 4 migration)
- Internal pattern fix (SettingsPage refactor)
- Contributor-side tooling (pre-commit hook)
- Documentation
- Release tooling (version bump)

All trust boundaries from v0.7.14 carry forward unchanged.

---

## 16-row pre-push gate

In-band rows (verified at Pre-tag time):

| # | Check | Status |
|---|---|---|
| 1 | pytest passing | ✅ 2120 (unchanged from v0.7.14 baseline; v0.7.15 is dev-tooling-only) |
| 2 | mypy --strict 0/0 | ✅ 188 source files (unchanged) |
| 3 | ruff clean | ✅ |
| 4 | Standing-rule keyword sweep | ✅ 0 hits across all 5 v0.7.15 commits + full diff (the f48345a commit was amended pre-push to paraphrase the historical leak phrase) |
| 5 | Author attribution | ✅ "Allen Byrd" only |

Frontend gates (verified):
- `npm run typecheck` — clean
- `npm run build` — clean (35.04 KB CSS / 6.41 KB gzipped;
  434 KB JS / 130 KB gzipped — same as v0.7.14)
- `npm run test` — 6/6 vitest pass
- `npm run lint` — 0 errors / 3 warnings (down from 4 in
  v0.7.14; tailwind.config.ts no-require-imports warning gone)

Out-of-band rows (fire post-push/tag/publish):

| # | Check | When |
|---|---|---|
| 6 | Code-scanning alert delta | Post-push CodeQL run; Dockerfile alert may re-fire (per docs/dockerfile-pinning.md runbook) |
| 7 | Container CVE scan (Trivy) | Post-tag `release-container.yml` |
| 8 | Vulnerability aging SLO | Post-push Dependabot scan |
| 9 | License/SCA SPDX allowlist | Post-push CycloneDX SBOM build |
| 10 | Reproducible-build verification | Deferred to v0.8.0 G4 |
| 11 | SBOM diff vs prior tag | Tag-time `release.yml` |
| 12 | (alias of #6) | Post-push |
| 13 | PEP 740 verify | Post-publish |
| 14 | Cosign verify container | Post-publish |
| 15 | osv-scanner --sbom | Post-publish |
| 16 | Scorecard re-run delta | Post-push `scorecard.yml` |

---

## Compliance framework mapping (v4 G15)

| Step | NIST SSDF | SLSA | ISO 27001:2022 | SOC 2 Type II | DORA | OpenSSF Scorecard |
|---|---|---|---|---|---|---|
| Step 3 manual /security-review | PS.1 + PS.3 | n/a | A.8.28 | CC8.1 | Art.5 | Code-Review |
| Step 4 capability carry-forward | PS.3.2 | n/a | A.8.29 | CC8.1 + CC7.2 | Art.6 | Vulnerabilities |
| Step 5 commit decomposition | PS.2 | n/a | A.8.31 | CC8.1 | n/a | Maintained |
| Step 6 16-row pre-push gate | RV.2 + RV.3 | L1+L2 | A.8.32 | CC8.1 | Art.7 | Pinned-Dependencies + License |
| Step 7 post-tag verification | PS.3.1 + PS.3.2 | **L3** | A.8.33 | CC8.1 + CC9.1 | Art.30 | Signed-Releases + SBOM |

---

## v0.7.x cycle CLOSE

This is the FINAL v0.7.x cycle release. 5 consecutive PROCEED-CLEAN
verdicts (v0.7.11 + v0.7.12 + v0.7.13 + v0.7.14 + v0.7.15). v0.8.0
design phase opens immediately post-ship.

| Tag | Date | Theme |
|---|---|---|
| v0.7.0 → v0.7.10 | April-May 2026 | (see prior retrospectives) |
| v0.7.11 | 2026-05-04 | First PROCEED-CLEAN |
| v0.7.12 | 2026-05-04 | Cloud-WORM trifecta + GDPR + Monte Carlo |
| v0.7.13 | 2026-05-04 | Codecov source_pkgs + release.yml CHANGELOG auto-population structural fix |
| v0.7.14 | 2026-05-05 | Codecov 0% RESOLVED + 7/8 frontend bumps + 3 LOW closures + hash-pinned requirements.txt preview |
| v0.7.15 | 2026-05-05 | Tailwind 4 migration + SettingsPage refactor + standing-rule pre-commit hook |

---

## Per-run JSON

`.local/pre-release-review/runs/2026-05-05T-v0715-continuous.json`

---

## Memory pointer

To be persisted post-ship:
`~/.claude/projects/.../memory/evidentia_v0_7_15_shipped.md`

---

## Cross-reference

- `docs/v0.7.14-shipped.md` — v0.7.14 retrospective
- `docs/threat-model.md` v0.7.15 sub-section — attack-surface delta
- `CHANGELOG.md` `[0.7.15]` — full feature change log
- `~/.claude/skills/pre-release-review/SKILL.md` v4 — used for
  the Continuous variant review
