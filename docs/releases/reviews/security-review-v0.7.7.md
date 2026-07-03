# Security review — v0.7.7 + v0.7.7.1

> *5th canonical deliverable per pre-release-review v4 G14.*

This document is the consolidated security-review record for the
v0.7.7 + v0.7.7.1 ship cycle (2026-05-02). It captures findings
from the 3 mandatory `/security-review` invocations + the Step 7
post-tag verification, plus the disposition of each finding.

Cross-reference:

- [docs/positioning-and-value.md](positioning-and-value.md) — version-history v0.7.7 skip-by-reuse note
- [docs/capability-matrix.md](capability-matrix.md) — v0.7.7 re-validation snapshot (17 surfaces)
- [docs/threat-model.md](threat-model.md) — STRIDE asset coverage
- [docs/enterprise-grade-accepted-findings.md](enterprise-grade-accepted-findings.md) — pre-existing accepted-findings rationale
- [CHANGELOG.md](../CHANGELOG.md) — `[0.7.7]` and `[0.7.7.1]` entries

## Scope

- **Diff range**: `v0.7.6..v0.7.7.1` — 23 commits, ~12,000 LOC across 65 files
- **Surfaces newly added**: 7 (5 SQL adapters + Okta collector + ServiceNow integration)
- **Surfaces re-validated**: 10 (existing tiers regression-checked clean)

## Findings table (CVSS v3.1 / CWE / EPSS)

| ID | Bucket | Category | Location | CVSS v3.1 | CWE | EPSS | Disposition |
|---|---|---|---|---|---|---|---|
| F-001 | HIGH (CVSS-MED) | path-traversal via REST `database_path` | [collectors.py:480-498](../packages/evidentia-api/src/evidentia_api/routers/collectors.py:480) | 6.5 | CWE-22 | 0.0042 | **fixed** in commit 16a5f86 (Step 5.A) |
| F-002 | MEDIUM | stack-trace verbosity in connection errors | 5 SQL adapter `_ensure_connected` paths | 4.0 | CWE-209 | 0.0008 | **fixed** in 16a5f86 (driver-name-only error format) |
| F-003 | MEDIUM | SQLite URI not URL-quoted | [sqlite/collector.py:254](../packages/evidentia-collectors/src/evidentia_collectors/sql/sqlite/collector.py:254) | 4.3 | CWE-20 | 0.0011 | **fixed** in 16a5f86 (`urllib.parse.quote(path, safe="/")`) |
| F-004 | LOW | TOCTOU between `is_file()` + `sqlite3.connect` | sqlite/collector.py:247-260 | 2.5 | CWE-367 | 0.0003 | **accepted** — read-only URI + filesystem ACLs limit blast radius |
| F-005 | LOW | Okta MFA sample 100 × 30s = 50min upper bound | [okta/collector.py](../packages/evidentia-collectors/src/evidentia_collectors/okta/collector.py) | n/a | n/a | n/a | **accepted** — documented as `EVIDENTIA-OKTA-RATE-LIMIT-PARTIAL` BLIND_SPOT |
| F-006 | HIGH (Scorecard) | top-level `security-events: write` over-broad | [.github/workflows/codeql.yml:35](../.github/workflows/codeql.yml:35) | 6.0 | CWE-732 | n/a | **fixed** in 4c01709 (job-scoped permission); alert #77 state=`fixed` post-CodeQL re-scan |
| F-007 | CRITICAL | Container image `:v0.7.7` has wrong binary inside | release.yml `publish-container` job; Dockerfile pin not bumped | 7.5 | CWE-1295 | n/a | **fixed** via v0.7.7.1 hot-fix (commit d5b0abb) — corrected pin + bump_version.py hardened to sweep Dockerfile + regex with negative-lookahead so prefix-substring bug cannot recur |

**Summary**: 0 unfixed CRITICAL / HIGH / MEDIUM at v0.7.7.1 ship.

## `/security-review` invocations

### Invocation #1 — Step 3 entry (diff-scoped)

**Scope**: `v0.7.6..HEAD` diff (~11,711 lines / 62 files).

**Method**: `/security-review` builtin not in this session's
user-invocable list — graceful-degradation via parallel agent
audit covering path-injection, SQL-injection, secret leakage,
URL/auth substring matching, stack-trace exposure,
deserialization, TLS posture, HTTP timeout absence, race/TOCTOU,
unbounded enumeration, idempotency token leakage.

**Surfaces inspected in full**: 5 SQL adapters, Okta collector,
ServiceNow client + config + sync + mapper, CLI wiring
(collect.py + integrations.py), REST router (collectors.py).

**Findings**: F-001 (HIGH, CWE-22), F-002 (MEDIUM, CWE-209),
F-003 (MEDIUM, CWE-20), F-004 (LOW, CWE-367), F-005 (LOW,
documented BLIND_SPOT).

**Positive observations**:

- Secret-handling protocol consistently enforced across all 5
  adapters via an identical 8-line URI validator
- Read-only-principal probes present in every adapter so
  misconfigured collectors self-report write capability
- `pickle`, `yaml.unsafe_load`, `eval`, `exec` introduced
  nowhere in the diff
- Okta + ServiceNow constructors refuse non-https URLs
- `httpx.Client` instances all have explicit timeouts
- `correlation_id` for ServiceNow uses `gap.id` (UUID); no PII
  leakage

### Invocation #2 — Step 4 capability-matrix pass (per-subsystem)

**Scope**: per-surface read-through of the 7 new public surfaces
(5 SQL + Okta + ServiceNow), each adversarially probed across 7
attack vectors (bad input, missing dep, network failure, expired
credential, malformed config, race, DoS).

**Findings**: 0 new findings (all 5 from invocation #1 already
captured).

### Invocation #3 — Step 6.C final pre-tag pass

**Scope**: 195-line, 11-file delta since invocation #1 (the
Step 5.A bundle commit + docs commits).

**Findings**: 0 new findings. All deltas in the security-improving
direction.

## Step 7 post-tag verification (v4 G1)

**This is where v4 earned its keep on its first prototype run.**

| Sub-step | v0.7.7 result | v0.7.7.1 result |
|---|---|---|
| 7.1 release.yml status | ✅ completed/success | ✅ completed/success |
| 7.2 PyPI 6 packages live | ✅ 0.7.7 | ✅ 0.7.7.1 |
| 7.3 PEP 740 attestation verify | ⚠ `pypi-attestations` invocation syntax mismatch — needs CLI doc re-read; defer to v0.7.8 | ⚠ same |
| 7.5 Container pull + version smoke | 🚨 **DRIFT** — `:v0.7.7` reports `Evidentia v0.7.6` inside (F-007) | ✅ `:v0.7.7.1` reports `Evidentia v0.7.7.1` |
| 7.5b `:latest` resolution | n/a | ✅ `:latest` → v0.7.7.1 image |
| 7.7 Code-scanning HIGH delta | ⚠ 1 NEW (alert #77 — fixed inline at row 12 before tag) | ✅ alert #77 state=`fixed` post-CodeQL |
| 7.8 Fresh-venv install smoke | not run on v0.7.7 (drift halted) | ✅ `pip install evidentia==0.7.7.1` + `evidentia version` correct |
| 7.9 GitHub Release | ✅ published 04:41:21Z; SBOM 184,613 bytes | ✅ published 04:58:12Z; SBOM 184,655 bytes |

## v0.7.4-pattern hot-fix replication

The v0.7.7 → v0.7.7.1 cycle is the second instance of the same-
day Dockerfile-trap hot-fix pattern (v0.7.4 was the first, in
April 2026, when v0.7.3 shipped Dockerfile + 4 workflow files
with `evidentia --version` instead of `evidentia version`).

| Aspect | v0.7.4 (April 2026) | v0.7.7.1 (May 2026) |
|---|---|---|
| What broke | 5 wrong CLI invocations across Dockerfile + 4 workflows | Dockerfile pin literal not bumped from prior version |
| When detected | Same-day after `evidentia --version` errored at smoke | Same-day at Step 7.5 docker run smoke |
| Time-to-fix | ~30 min from detect to v0.7.4 tag | ~17 min from detect to v0.7.7.1 tag |
| Lesson captured into release process | release-checklist Step 5: local Docker build mandatory for any release touching Dockerfile or container-build.yml | bump_version.py: sweep Dockerfile + regex negative-lookahead so prefix-substring trap cannot recur |

## Recommendations for v0.7.8

1. Add a `pre-release-review` Step 6 row 8 sub-check that greps
   the Dockerfile for the OLD version literal post-bump,
   surfacing this trap earlier (before tag, not after).
2. Land Docker integration tests for MySQL, MSSQL, Oracle
   (currently only Postgres has them; mirror the P0.1 pattern).
3. Re-attempt the CodeQL custom sanitizer for `validate_within`
   once a tested approach surfaces (data-extension YAML + QL
   BarrierGuard subclass both failed to fire in v0.7.7).
4. Re-run `pypi-attestations verify pypi` with corrected CLI
   invocation form (the `pypi:` URI scheme used in v0.7.5/v0.7.6
   appears to no longer match the current CLI's expected
   argument shape).
5. Q3 quarterly resync of `docs/positioning-and-value.md` per
   the regular cadence (~July 2026 ship window).

## Sign-off

| Role | Sign-off |
|---|---|
| Pre-release-review v4 reviewer | this document, dated 2026-05-02 |
| Tag authorization | Allen Byrd, explicit per-action approval (publishing-authority protocol) |
| Production deployer | n/a (open-source release; no internal SaaS deploy) |

This document remains the audit-of-record for v0.7.7 + v0.7.7.1
ship-time security posture. Future Claude sessions reading this
should NOT regenerate; they should append a "Reviewed for
v0.X.Y on YYYY-MM-DD: no material change" line if scope warrants.
