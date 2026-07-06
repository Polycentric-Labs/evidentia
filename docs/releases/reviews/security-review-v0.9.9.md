# Security review — v0.9.9

> **Status**: in-cycle artifact for the v0.9.9 ship — the v4
> pre-release-review's 5th canonical deliverable.
>
> **Theme**: supply-chain hygiene + pre-push gate fidelity.

## Cycle scope

v0.9.9 is a focused supply-chain patch — **no source or test code
changed**. It closes the `paramiko` CVE carried forward from v0.9.8,
adds an `osv-scanner --sbom` pre-push gate, and clears the entire
Dependabot PR queue. See `docs/v0.9.9-plan.md` for the phase-by-phase
scope.

## Review structure

v0.9.9 was reviewed in a single direct-file-inspection pass. The
changeset is committed directly to `main` (the project's documented
solo-developer workflow — `docs/release-checklist.md` Step 8), so
there is no feature-branch diff for `/security-review` to auto-scope
against; per `security-review-integration.md` the delta is reviewed
by direct inspection — the same disposition as the v0.9.8 Pass-2
supply-chain review.

| Pass | Scope | Verdict |
|---|---|---|
| 1 — supply-chain + gate delta | The v0.9.9 changeset: 5 merged Dependabot group PRs, 3 closed orphaned PRs, the `osv-scanner` gate (`scripts/run_osv_scan.py` + `osv-scanner.toml` + the `osv-scan` CI job), the `compliance-trestle` 4.0.3 bump, the version bump, and the ship docs. | PROCEED-CLEAN |

## Findings ledger

Zero findings across all four buckets. The v0.9.9 changeset adds no
product attack surface:

- **`scripts/run_osv_scan.py`** — build-time tooling. Invokes
  `cyclonedx-py` and `osv-scanner` via fixed `subprocess` argument
  lists (no `shell=True`, no interpolation of untrusted input). Runs
  in CI and pre-tag only, never inside a deployed Evidentia process.
- **`osv-scan` CI job** — installs `osv-scanner` v2.3.8 from a
  pinned GitHub release URL, SHA256-verified against a committed
  digest. No floating version, no `curl | sh`.
- **`osv-scanner.toml`** — one allowlist entry (pyjwt
  PYSEC-2025-183, disputed) with a reason and an `ignoreUntil`
  re-validation date.
- **Dependency bumps** — five Dependabot grouped version-update PRs,
  all CI-green; no new third-party package introduced.

| Finding | Severity | Status |
|---|---|---|
| (none) | — | Zero CRITICAL / HIGH / MEDIUM / LOW / INFO |

## Carry-over disposition

| Finding | Severity | Disposition |
|---|---|---|
| paramiko CVE-2026-44405 / GHSA-r374-rxx8-8654 | LOW | **CLOSED** — `compliance-trestle` 4.0.2 → 4.0.3 pulls `paramiko` 4.0.0 → 5.0.0, past the `<= 4.0.0` vulnerable range. `paramiko` is a dev-only transitive dependency (via `compliance-trestle`, OSCAL round-trip tests); no Evidentia code imports it. |
| pyjwt PYSEC-2025-183 / CVE-2025-45768 | DISPUTED (scored 7.0) | **Accepted — now allowlisted.** Disputed by the pyjwt maintainer; no fix version exists. Transitive-only; Evidentia exposes no operator-chosen-key JWT-minting surface. Recorded in `osv-scanner.toml` with `ignoreUntil = 2026-11-21` to force re-validation. Unchanged from the v0.9.8 disposition. |
| idna alert #17 (CVE-2026-45409) | MEDIUM | **Verified-stale.** `uv.lock` and `docker/requirements.txt` already pin `idna 3.15` (= `first_patched`, on `main` since v0.9.8). The alert remained `open` after the v0.9.9 push — GitHub's auto-dismiss triggers on a dependency-graph *change* that moves a package out of range, and `idna` did not change this cycle. Not a live vulnerability; see Step 7 for the post-tag disposition. |

**Zero unfixed CRITICAL / HIGH / MEDIUM / LOW at v0.9.9 ship.**

## `/security-review` + `/code-review`

The v0.9.9 changeset is direct-to-`main`, so the `/security-review`
and `/code-review` builtins (which auto-scope to current-branch-vs-
main) have no feature-branch diff to target. Per
`security-review-integration.md` the review was conducted by direct
file inspection of the changeset. `/code-review` trigger 2 (a new
source file — `scripts/run_osv_scan.py`) is satisfied by the direct
inspection in the findings ledger above: ~110 lines of build
tooling, fixed-argument `subprocess` calls, no product surface.
Triggers 1, 3, 4 did not fire (no new public API, < 500 LOC, no
security-sensitive product module touched).

## Dependabot queue + config audit

The cycle cleared the full 8-PR Dependabot queue:

- **5 merged** — the `python-dev`, `npm-runtime`, `npm-dev`, and
  `github-actions` groups + the Docker base-image digest. All
  CI-green.
- **3 closed** — `#29` / `#30` / `#32`, orphaned PRs from a `pip` /
  `uv-docker` Dependabot ecosystem no longer present in
  `.github/dependabot.yml`. They targeted only
  `docker/requirements.txt`, which `release.yml` regenerates from
  `uv.lock` at release time (G4 Path 2) — superseded.
- **`.github/dependabot.yml` audited** — `uv` (all 7 `pyproject.toml`
  via `uv.lock`), `npm` (`evidentia-ui`), `github-actions`, and
  `docker` (the `Dockerfile` base image). No coverage gap:
  `docker/requirements.txt` is a release-regenerated derived
  artifact and correctly has no separate `pip` watcher. The 11 stale
  `dependabot/*` remote-tracking refs were pruned.

## 16-row pre-push gate (Step 6.C)

| # | Check | v0.9.9 outcome |
|---|---|---|
| 1 | Credential sweep of diff | PASS — 0 hits |
| 2 | Claude-attribution in diff content | PASS — 0 hits in the v0.9.9 diff (the `Claude` strings elsewhere in `docs/release-checklist.md` are pre-existing prose, not in this changeset) |
| 3 | Commit-message attribution sweep | PASS — `v0.9.8..HEAD` is 5 `dependabot[bot]` commits + Allen Byrd commits; 0 Claude attribution |
| 4 | `.gitignore` secret-store coverage | PASS — `.env*`, `*.pem/.key/.crt/.p12/.pfx`, `secrets/`, `credentials.json` all covered |
| 5 | Tracked secret-store files | PASS — none tracked |
| 6 | Test gate | PASS — 3250 passed / 14 skipped |
| 7 | Type / lint gate | PASS — mypy strict clean (261 files / 7 packages); ruff clean |
| 8 | Build sanity | PASS — 7 evidentia-* packages built at 0.9.9 (wheel + sdist); `twine check` PASSED |
| 9 | Identity | PASS — Allen Byrd / canonical noreply identity |
| 10 | Branch sanity | PASS — on `main`, 3 v0.9.9 commits ahead of `origin/main` |
| 11 | Legacy secrets | PASS — only `CODECOV_TOKEN`; no legacy `PYPI_API_TOKEN` |
| 12 | Code-scanning alert delta | PASS — 0 open code-scanning alerts |
| 13 | Container CVE scan (Trivy) | WARN-SKIP — `trivy` not installed. v0.9.9's only Dockerfile change is the Dependabot base-image digest bump (#24), which #24's own CI `Build + smoke test` check verified GREEN before merge; `release.yml` `publish-container` rebuilds + cosign-signs at tag |
| 14 | Vulnerability aging SLO | PASS — 0 HIGH/CRITICAL deps unpatched; paramiko CVE-2026-44405 (LOW) CLOSED this cycle; the NEW `osv-scanner --sbom` gate ran clean (no un-allowlisted findings) |
| 15 | License / SCA enforcement | WARN-SKIP — `pip-licenses` not installed; the dependency bumps are version updates of already-present packages — no new third-party package, license posture unchanged |
| 16 | Secret-rotation cadence | PARTIAL — repo secret `CODECOV_TOKEN` present; SSH-key age unverifiable (gh token lacks the `admin:public_key` scope) |

Rows 13 / 15 / 16 degrade gracefully on absent optional tooling and
a withheld gh scope — none touches the v0.9.9 delta's actual
surface. Zero blocking findings.

## Gate-fidelity note

The `osv-scanner --sbom` gate added this cycle directly addresses
the v0.9.8 gate-fidelity lesson: it runs in CI (the `osv-scan` job)
and pre-tag (`docs/release-checklist.md` Step 5) through one shared
script, `scripts/run_osv_scan.py`. A CI gate and its documented
counterpart now run an identical check, by construction.

## Source-file count reconciliation

mypy reports **261** source files (v0.9.8 docs reported 262).
`git ls-files` confirms 261 tracked `.py` files under
`packages/*/src/`, and the v0.9.9 changeset adds none — the
`packages/*/src/` tree is byte-identical to v0.9.8. The v0.9.8
"262" was a +1 over-count; v0.9.9 docs use the verified 261, and
the v0.9.8 historical docs are left unchanged.

## Cross-references

- `CHANGELOG.md` `[0.9.9]` block
- `docs/v0.9.9-plan.md` — phase-by-phase cycle plan
- `docs/threat-model.md` — v0.9.9 attack-surface delta
- `docs/capability-matrix.md` — v0.9.9 SHIPPED snapshot
- `docs/ROADMAP.md` — v0.9.9 SHIPPED transition
- `docs/security-review-v0.9.8.md` — prior-cycle artifact (carried the paramiko LOW now closed)

## PROCEED-CLEAN gate verdict

**PROCEED-CLEAN** for the v0.9.9 ship. The single review pass
returned PROCEED-CLEAN; the 16-row pre-push gate carries zero
blocking findings (3 rows WARN/PARTIAL-degraded on absent tooling,
none material to the delta). Zero unfixed CRITICAL / HIGH / MEDIUM /
LOW. The paramiko LOW carried from v0.9.8 is closed.

**24th consecutive PROCEED-CLEAN** of the v0.7.x → v0.8.x → v0.9.x
line.

## Step 7 — post-tag verification

`release.yml` run `26243446599` — conclusion **success** (both jobs:
`Build and publish to PyPI` + `Build and publish container image to
ghcr.io`). Tag `v0.9.9`.

| Sub-step | Outcome |
|---|---|
| `release.yml` completion | ✓ success — publish-pypi + publish-container |
| PEP 740 attestations | ✓ 7/7 wheels verified (`pypi-attestations verify pypi --repository https://github.com/Polycentric-Labs/evidentia`) |
| Container — cosign keyless verify | ✓ Verified OK — Rekor transparency log + cert chain + SLSA provenance v1; image digest `sha256:2adc9e366a465577bd6ae9aa154c8de6a339f9346f9ee3e8327c67775df2c78e` |
| SBOM osv-scan | ✓ the published GitHub-release SBOM (182 packages) — `No issues found`; the disputed pyjwt advisory is allowlisted in `osv-scanner.toml` |
| Fresh-venv install | ✓ `evidentia[gui]==0.9.9` from PyPI; `evidentia version` → `Evidentia v0.9.9`; `catalog list` → 89 frameworks (the 7-package inter-version pin-trap resolved cleanly) |
| GitHub Release notes | ✓ CHANGELOG `[0.9.9]` auto-populated (4932-byte body); CycloneDX SBOM attached as a release asset |
| Code-scanning alerts | ✓ 0 open |
| `tests` CI on the `main` push | ✓ success — including the NEW `osv-scan` job's first live run (osv-scanner v2.3.8) |

### Dependabot alert disposition

| Alert | Severity | Post-tag state |
|---|---|---|
| #9 paramiko CVE-2026-44405 | LOW | **`fixed`** — auto-resolved once the v0.9.9 push moved `paramiko` to 5.0.0 in `uv.lock`. |
| #17 idna CVE-2026-45409 | MEDIUM | **`open` — verified-stale.** `idna 3.15` (= `first_patched`) is in `uv.lock`, `docker/requirements.txt`, and the published 0.9.9 wheels' resolved closure. The alert did not auto-resolve because the v0.9.9 push did not *change* `idna` (it has been 3.15 on `main` since v0.9.8); GitHub's auto-dismiss triggers on a dependency-graph change that moves a package out of range. Not a live vulnerability — the fix is shipped. Recommended action: a one-off manual dismissal (`gh api repos/Polycentric-Labs/evidentia/dependabot/alerts/17 -X PATCH -f state=dismissed -f dismissed_reason=inaccurate`), or leave it for GitHub's next periodic re-scan. |

### Step 7 verdict

**PROCEED-CLEAN confirmed post-tag.** The published PyPI + GHCR
artifacts verify against their build provenance; the post-tag
osv-scan of the published SBOM is clean; the fresh-venv install
resolves all 7 inter-package pins to 0.9.9. The one open Dependabot
alert (#17 idna) is verified-stale — the fix is shipped. v0.9.9 is
SHIPPED.

**24th consecutive PROCEED-CLEAN** of the v0.7.x → v0.8.x → v0.9.x
line.
