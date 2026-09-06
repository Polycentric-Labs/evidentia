# Security review: v0.12.1

**Release**: v0.12.1, tagged 2026-09-06 on main `04f7105` (PR #276), a day-N
container rebuild in the v0.10.18 pattern.
**Review shape**: right-sized `/pre-release-review` (G29). The change adds no
new endpoint, no new credential path and no new publish surface, so the
ceremony was Step 1 checks, the 21-row pre-push gate, one diff-scoped
`/security-review-scoped` pass, the Step 6 overview and Step 7 post-tag
verification. Per-run JSON: `.local/pre-release-review/runs/2026-09-06T02-41-02Z-v0.12.1.json`
(started 2026-09-06T02:41:02Z, completed 2026-09-06T02:45:11Z).

## Cycle scope

Diff = v0.12.0..main HEAD 04f7105 (15 commits, 80 files, +4687/-1621), dominated by the already-merged v0.13 cycle-open batch (#259, reviewed via CI gates + red-first tests), the trestle-5.0 conformance fix (#268), six Dependabot batches, and the release PR #276 (preflight run 34004527568 GREEN incl. DHI final stage).

The rebuild itself: the `python:3.13-slim` builder digest moved `ffb752e…` to
`9d2e5553…` at all four pin sites and the `dhi.io/python:3.13` runtime moved
`e512071…` to `fec89928…`, after the 2026-08-31 post-publish rescan found
openssl 3.5.6 in the published v0.12.0 image carrying DEBIAN-CVE-2026-14456,
-14457 and -18798 (High, fixed in 3.5.7). The two open Dependabot advisories
(transformers, browserslist) closed in the same release, the Dependabot uv job's
weekly resolver errors were silenced with removal-triggered ignore rules, and the
ai-gov descriptor fields gained an engine-independent non-blank pattern after the
2026-09-03 stateful DAST run.

## Verdict

**PROCEED-CLEAN (right-sized): all 21 gate rows PASS or delegated-with-evidence; scoped security review 0 findings; preflight GREEN; pending Allen's tag approval.**

The release preflight (`release.yml` dispatch, run 34004527568) ran the full
pre-publish path on a runner before the merge, including the DHI final stage on
the new digest; publish jobs skipped by construction.

## Fix-now items applied in cycle

None arose from the review itself. The release IS the fix for the two published
defects it was cut for (the stale hardened base and the two transitive
advisories); both landed in PR #276 before the review opened.

## Deferred (documented dispositions)

- FedRAMP CR26 schema re-vendor flagged by the schema-watch sentinel (issue
  #275; common-definitions 0.2.1 to 0.3.0, SDR 1.0.3 to 1.1.1, NOTICE-level).
- The class-level non-blank string type for the remaining `min_length=1`
  request fields; the DAST fix covered the two fields the scanner reached.
- The stateful DAST test's Hypothesis `FlakyStrategyDefinition` (a test-infra
  regression after the hypothesis 6.165 / schemathesis 4.25 bumps, not an API
  finding): stabilize `tests/dast/test_openapi_stateful.py`.
- `CODECOV_TOKEN` is past the 90-day rotation cadence (Row 16 yellow).

## The 21-row pre-push gate

| # | Row | Outcome |
|---|---|---|
| 1 | Credential pattern sweep | 0 hits (v0.12.0..HEAD) |
| 2 | Attribution sweep (diff) | 0 hits |
| 3 | Attribution sweep (commit messages) | 0 hits across 15 commits |
| 4 | .gitignore secret patterns | PASS (.env*, *.pem, *.key covered; .venv*/ added this cycle) |
| 5 | Staged secret-store files | only packages/evidentia-ui/.env.example (placeholder template, CI secret-scan covered) |
| 6 | Test gate + coverage threshold | 5125 passed, 14 skipped (0:05:31 under coverage); TOTAL coverage 86.73% vs Silver threshold 80%: reached |
| 7 | Lint + type gate | ruff clean; mypy 285 files clean |
| 8 | Build sanity | uv build 16 artifacts (8 wheels + 8 sdists) at 0.12.1; twine check 16/16 PASSED |
| 9 | Identity | Allen Byrd <125306425+allenfbyrd@users.noreply.github.com> |
| 10 | Branch sanity | main == origin/main == 04f7105, clean tree |
| 11 | Legacy long-lived secrets | repo: CODECOV_TOKEN (2026-05-17), SCORECARD_TOKEN (2026-06-24); pypi/ghcr envs: none (OIDC). No legacy PyPI token. |
| 12 | Code-scanning alert delta | 0 open alerts |
| 13 | Container CVE scan | DELEGATED: preflight 34004527568 container smoke GREEN on the new DHI digest; release.yml osv-scans the built image; post-publish rescan re-verifies Monday. grype not run locally (dhi.io requires CI credentials). |
| 14 | Vulnerability aging SLO | 0 open Dependabot alerts (transformers + browserslist auto-closed once main's locks moved) |
| 15 | License / SCA | PASS: the 'Tier-C placeholder catalog' string appears in src only as the analyzer's warning text (gap_analyzer/analyzer.py), the demo cast that records that warning (evidentia_api/static/demo.cast), and the designed placeholder text of the CIS stub (catalogs/data/stubs/cis-controls-v8.1.yaml); no licensed control text ships. SPDX/licence enforcement delegated to the required osv-scanner SBOM gate + dependency-review; pip-licenses not installed locally. |
| 16 | Secret rotation cadence | YELLOW: CODECOV_TOKEN is 111 days old (> 90); SCORECARD_TOKEN 73 days. gh api user/keys 404 (token scope) - SSH signing key managed locally. |
| 17 | CHANGELOG-presence gate | extract_changelog_block.py 0.12.1 -> 7078 bytes PASS |
| 18 | Branch-protection bypass audit | CLEAN: all pushes were feature-branch pushes (carve-out); merges via merge queue; no 'Bypassed rule violations' seen |
| 19 | Documentation freshness | doc-inventory.yaml not bootstrapped for this project (pre-existing G21 gap); substitute: check_docs_health --strict 0 FAIL, check_version_consistency PASS (anchors), README releases regenerated by gen_readme_releases.py |
| 20 | Binary-in-VCS (OSPS-QA-05) | 0 hits |
| 21 | Release-workflow first-live-run audit | FIRES (release.yml changed since v0.12.0: buildx action v4.2.0->v4.3.0 via #256, pip-compile base digest). SATISFIED by the preflight dispatch 34004527568 GREEN through build (the changed steps executed; publish jobs skipped by construction). |

## Scoped security review (`v0.12.1-delta`)

Files reviewed in full: 17 (the Python modules changed
since v0.12.0 plus the Dockerfile, the release and container workflows, and the
Dependabot config).

**No HIGH or MEDIUM findings with confidence >= 8.**

Informational notes (no action required this cycle):

- pip install pip-tools==7.6.1 inside the pip-compile container (release.yml + container-build.yml) is version-pinned but not hash-pinned; pre-existing pattern, mitigated by the digest-pinned base, TLS, and the hash-pinned + osv-gated requirements.txt it produces.
- check_doc_counts.py exec-loads scripts/check_parity.py via importlib (repo-internal trusted path; not user-controlled).
- Dependabot ignore ranges (typer >=0.27, rich >=15) only cover versions that are unresolvable under existing caps; security advisories bypass cooldown and alerts are independent of update config, so no security-update capability is lost.

## Business case (recorded at tag approval)

- **Why now**: The published v0.12.0 image carries three High openssl CVEs (DEBIAN-CVE-2026-14456/-14457/-18798) with the upstream fix (3.5.7) available; standing policy says rebuild when a fix exists, and the weekly post-publish rescan stays red until we do. Both open Dependabot advisories close in the same release.
- **Who suffers if delayed**: Everyone pulling the documented ghcr.io/polycentric-labs/evidentia:v0.12.0 path runs a base with disclosed High advisories, against SECURITY.md's supported-versions promise.
- **Rollback**: PyPI yank of the eight 0.12.1 distributions (0.12.0 stays installable); GHCR tag removal (cosign signatures immutable, v0.12.0 untouched); GitHub Release deletion; CHANGELOG correction commit. The 0.12.1 version slot is consumed, so a redo ships as 0.12.2.

## Step 7: post-tag verification

Run against release run 34007377650 (`release.yml` on tag `v0.12.1`; gate, build,
publish-pypi and publish-container all succeeded once Allen approved the `pypi`
and `ghcr` deployments). Runner: the session's `step7_verify.sh` plus a manual
clean-room rebuild for 7.4.5.

| Sub-step | Check | Result |
|---|---|---|
| 7.2 | PyPI serves all 8 wheels at 0.12.1; sha256 of each download recorded | PASS, 8/8 |
| 7.3 | PEP 740: `pypi-attestations verify pypi` per wheel, plus the PyPI integrity endpoint | PASS, 8/8 verified; 8 attestations listed |
| 7.4 | SLSA provenance: `gh attestation verify <wheel> --repo Polycentric-Labs/evidentia` | PASS, 8/8; predicate `https://slsa.dev/provenance/v1`, signer `release.yml@refs/tags/v0.12.1` |
| 7.4b | Negative control for the attestation verifier (non-matching subject) | PASS (rejected as expected) |
| 7.4.5 | Reproducible build: clean worktree at the tag, `SOURCE_DATE_EPOCH=1788659225`, `uv build --all-packages`, member-by-member diff against the PyPI wheels | PASS with documented drift: every member byte-identical except the CI-injected PEP 770 `dist-info/sboms/*.cdx.json` entries (two for evidentia-api: python + npm closure) and the `RECORD` lines listing them |
| 7.5 | Container: `cosign verify` (keyless), `gh attestation verify oci://…`, `docker run … version` | PASS; image reports 0.12.1 |
| 7.6 | Release SBOM `evidentia-sbom.cdx.json` (218,839 bytes) through osv-scanner | PASS, 0 findings |
| 7.7 | OpenSSF Scorecard | 8.4 (informational) |
| 7.8 | Fresh-install smoke: `uvx evidentia --version` | PASS, 0.12.1 |
| 7.9 | GitHub Release `v0.12.1`: body 7,743 bytes; assets `evidentia-sbom.cdx.json` and `evidentia.intoto.jsonl` | PASS |

Two notes for the next cycle. The first 7.4 pass reported 0/8 because the runner
passed `--signer-workflow` without the `owner/repo/` prefix; `--repo` is the
correct form and the runner is fixed. The wheel SBOM injection is the only
expected reproducibility drift; record it as the allowed set
(`reproducible_build_known_drift`) when the review config is bootstrapped, so
7.4.5 can assert it exactly instead of explaining it.

## Cross-references

- [`CHANGELOG.md`](../../../CHANGELOG.md) `[0.12.1]`
- [`docs/verification.md`](../../verification.md), the verify recipes Step 7 runs
- [`docs/release-checklist.md`](../../release-checklist.md)
- [`docs/deprecation-calendar.md`](../../deprecation-calendar.md), the two rows this release ships
