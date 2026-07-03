# Security review — v0.10.1

> **Status**: in-cycle artifact for the v0.10.1 ship — the v4
> pre-release-review's 5th canonical deliverable.
>
> **Theme**: v0.10.x integration consolidation — close both v0.10.0
> findings (F-V100-L1 trust-boundary + F-V100-M1 release tooling),
> ship the deferred third-party OCSF ingestion collector with
> Detection Finding support, extend the v0.10.0 pilot pattern to the
> remaining 11 collectors.

## Cycle scope

v0.10.1 is the first patch on the v0.10.x line. The
[`docs/v0.10.1-plan.md`](v0.10.1-plan.md) 5 phases:

1. `finding_from_ocsf` gains `trust_unmapped: bool = True` (closes
   F-V100-L1).
2. New `evidentia_collectors.ocsf` ingestion collector + Detection
   Finding mapping (`class_uid` 2004 — what Prowler and AWS Security
   Hub emit) + `evidentia collect ocsf --input <file-or-url>` CLI verb.
3. 11 remaining collectors (okta + 4 SQL adapters + databricks +
   snowflake + 4 vendor-risk SaaS) migrated to populate
   `compliance_status` per finding semantics.
4. `Finding` alias on `SecurityFinding` (deprecation policy, target
   removal v1.0.0); `evidentia collect convert --input X --format ocsf`
   CLI verb; `EventAction.COLLECT_OCSF_EMITTED`.
5. `scripts/bump_version.py` hardened against third-party pin
   over-bumping via `[tool.uv.sources]` workspace allowlist (closes
   F-V100-M1).

## Review structure

v0.10.1 was reviewed under the v4 default pre-tag variant with the
Diff + 1-hop dep closure scope (Step 1.4 option 1). The changeset is
on `main` (local), so the `/security-review` and `/code-review`
builtins have no feature-branch diff to scope against — direct
delta inspection per the v0.9.8 / v0.9.9 / v0.10.0 precedent
sanctioned by `security-review-integration.md`.

| Pass | Scope | Verdict |
|---|---|---|
| 3 — commit re-test + 1-hop closure | 7 unpushed commits (6 v0.10.1 phases + 1 positioning skip-by-reuse). 5 importer files inspected via 1-hop closure (3 importers of `evidentia_core.ocsf` + 2 importers of the new `evidentia_collectors.ocsf`). | PROCEED-CLEAN |
| 4 — capability matrix (REUSE + delta) | v0.10.0 matrix reused for 8 unchanged subsystems (re-validated by 3332-test suite); v0.10.1 PRE-TAG section added for 8 new + 2 modified surfaces with 8-vector adversarial probe table. | PROCEED-CLEAN |
| 6.C — final pre-tag pass | Full HEAD vs `v0.10.0` direct delta inspection; 16-row pre-push gate (filled below); no new findings; 1 ruff RUF012 nit caught + fixed in-cycle (test_bump_version.py `ClassVar` annotation). | PROCEED-CLEAN |

## Findings ledger

| ID | Bucket | Category | Location | CVSS v3.1 | CWE | EPSS | Disposition |
|---|---|---|---|---|---|---|---|
| **F-V101-L1** | **LOW** | SSRF surface — URL ingest does not block private-IP / link-local ranges | `evidentia_collectors/ocsf/collector.py:collect_ocsf_url` | n/a — operator-driven URL (typed at CLI), not attacker-controlled | CWE-918 (Server-Side Request Forgery) | n/a | **Accept for v0.10.1**; v0.10.2 hardening optional. Add a `--block-private-ips` flag rejecting 10/8, 172.16/12, 192.168/16, 169.254/16, 127/8 (covers AWS metadata + local-loopback). Risk model: an operator typos a malicious internal URL and gets back data they shouldn't see. NOT exploitable by a remote attacker — there is no untrusted URL input path in the CLI surface. Tracked in `docs/v0.10.2-plan.md`. |

**Both v0.10.0 carry-forward findings CLOSED inline**:

| ID | Bucket | Closure |
|---|---|---|
| **F-V100-L1** (LOW) | trust-boundary on `unmapped["evidentia"]` | **CLOSED** by Phase 1 — `finding_from_ocsf(..., trust_unmapped=False)` ignores the block; the v0.10.1 ingestion collector uses this path; adversarial close-out test asserts a forged block cannot impersonate Evidentia-native fields. |
| **F-V100-M1** (MEDIUM) | `bump_version.py` over-bumped third-party pin | **CLOSED** by Phase 5 — workspace allowlist via `[tool.uv.sources]`; regex now requires a workspace package name to precede the version range; dry-run on hypothetical `0.10.0 → 0.11.0` confirms `py-ocsf-models` pin stays put. 6 new tests + 1 pre-existing test file aligned. |

**Net at v0.10.1**: 0 CRITICAL / 0 HIGH / 0 MEDIUM / 1 NEW LOW (accepted
with v0.10.2 follow-up); 2 prior findings closed.

## Security category sweep — direct delta inspection

| Category | v0.10.1 verdict |
|---|---|
| Injection (SQL/shell/path) | NONE in v0.10.1 code |
| Deserialization | Pydantic `model_validate` only; both Compliance Finding (2003) and Detection Finding (2004) re-validated via `py_ocsf_models` before any field read |
| Weak crypto | None added |
| Secret exposure | No new credential handling; no `__repr__` overrides |
| Authz bypass | No new auth surface |
| Trust boundary | **F-V100-L1 CLOSED**; collector dispatch uses `trust_unmapped=False` |
| Supply chain | Zero new third-party deps in v0.10.1 |
| DoS / resource exhaustion | URL ingest bounded by 50 MB cap + 10s timeout; transforms O(n_findings) |
| Regex / ReDoS | No new regex |
| **SSRF (new)** | F-V101-L1 (LOW) — no private-IP block on URL ingest; accepted operator-driven |

## `/security-review` + `/code-review`

All 4 `/code-review` auto-fire triggers activated:

| Trigger | Fired? | Detail |
|---|---|---|
| 1 — new public API/CLI/route | **YES** | 2 new `@app.command()` verbs (`collect ocsf` + `collect convert`). Both reviewed directly. |
| 2 — new file under `packages/*/src/` | **YES** | 2 new files (`evidentia_collectors/ocsf/__init__.py` + `collector.py`). Both reviewed directly (collector.py is the F-V101-L1 source). |
| 3 — >500 LOC delta | **YES** | 2145 LOC delta. Direct inspection covered every code-bearing addition. |
| 4 — security subsystem touched | **YES** (false-positive) | `audit/events.py` matches the trigger-4 path pattern, but the delta is enum-value-only (5 lines, no audit logic). Logged as false-positive. |

## 16-row pre-push gate (Step 6.C)

| # | Check | v0.10.1 outcome |
|---|---|---|
| 1 | Credential pattern sweep of `v0.10.0..HEAD` diff | PASS — 0 hits |
| 2 | Claude-attribution sweep of diff content | PASS — 0 hits |
| 3 | Commit-message attribution sweep | PASS — 0 hits |
| 4 | `.gitignore` secret-store coverage | PASS (unchanged from v0.10.0) |
| 5 | Tracked secret-shape files | PASS — only pre-existing `.env.example` placeholder |
| 6 | Test gate | PASS — 3332 passed / 14 skipped (+37 vs v0.10.0) |
| 7 | Type/lint gate | PASS — mypy strict 0/0 across 267 source files; ruff clean (RUF012 nit on `tests/unit/test_bump_version.py:PKGS` caught + fixed inline) |
| 8 | Build sanity | PASS — 7 wheels + 7 sdists at 0.10.1; `twine check` all PASSED |
| 9 | Identity | PASS — `Allen Byrd <125306425+allenfbyrd@users.noreply.github.com>` |
| 10 | Branch sanity | PASS — on `main`, 9 commits ahead of `origin/main` at chore(release) time |
| 11 | Legacy long-lived secrets | PASS — only `CODECOV_TOKEN`; no `PYPI_API_TOKEN` |
| 12 | Code-scanning alert delta since v0.10.0 | PASS — 0 new HIGH alerts |
| 13 | Container CVE scan (Trivy) | WARN-SKIP — `trivy` not installed; v0.10.1 made no Dockerfile changes; `release.yml publish-container` cosign-signs at tag (Step 7.5 verified clean) |
| 14 | Vulnerability aging SLO (`osv-scanner --sbom`) | PASS — clean; 225 packages in local dev venv |
| 15 | License / SCA enforcement | WARN-SKIP — `pip-licenses` not installed; **zero new third-party deps in v0.10.1** |
| 16 | Secret-rotation cadence | PASS — `CODECOV_TOKEN` 5 days old (<90) |

Rows 13/15 degrade gracefully on absent optional tooling — same
disposition as the prior 25 PROCEED-CLEAN cycles. Zero blocking
findings. No new MEDIUM at this gate (vs v0.10.0 which caught 2
inline); F-V100-M1's release-tooling fix was live-verified by this
release's own version bump (23 substitutions vs the buggy 28
v0.10.0 produced — the 5 missing are the py-ocsf-models pin
over-bumps the v0.10.1 Phase 5 fix now blocks).

## Step 7 post-tag verification

| Sub-step | Outcome |
|---|---|
| 7.1 `release.yml` run | ✅ **success** in 213s (~3:33 tag-to-publish); run id `26323893254` |
| 7.3 PEP 740 attestation verify (7 wheels) | ✅ **7/7 OK** via `pypi-attestations verify pypi --repository https://github.com/Polycentric-Labs/evidentia "pypi:<wheel-name>"` |
| 7.5 Cosign container verify | ✅ **VERIFIED** — `cosign verify ghcr.io/polycentric-labs/evidentia:v0.10.1` reports SLSA Provenance v1 signed by `release.yml` via Fulcio + Rekor; image digest `sha256:5f14867effb79852e4dddc70bea896b0d4f8c5116dc6ccc68f4925473fde770e` |
| 7.5 Docker smoke | ✅ `docker run … version` → `Evidentia v0.10.1 / Python 3.14.5` |
| 7.6 Published SBOM osv-scan | ✅ **CLEAN** — `evidentia-sbom.cdx.json` from the GitHub Release scanned with `osv-scanner --sbom`; 183 packages; no issues |
| 7.7 Scorecard | ✅ **success** for `ddacd53` (v0.10.1 commit); 0 open HIGH code-scanning alerts |
| 7.8 Fresh-venv install smoke | ✅ `python -m venv` + `pip install "evidentia==0.10.1"` → `Evidentia v0.10.1 / Python 3.14.2`. **Live close-out validation of F-V100-M1**: `pip install "evidentia-core[ocsf]==0.10.1"` resolves correctly — `py_ocsf_models` installs from the (preserved, NOT over-bumped) `>=0.9.0,<0.10.0` range, and `from evidentia_core.ocsf import finding_from_ocsf_detection` (the new v0.10.1 symbol) imports cleanly. |
| 7.9 Release notes audit | ✅ CHANGELOG-style summary present (auto-extracted from `[0.10.1]` block); `evidentia-sbom.cdx.json` attached as release asset |
| 7.10 Memory + audit-log update | this section; plus a fresh entry appended to `MEMORY.md` for v0.10.1 SHIPPED |

**Verdict**: PROCEED-CLEAN confirmed post-tag — **26th consecutive**
of the v0.7.x → v0.8.x → v0.9.x → v0.10.x line. v0.10.1 SHIPPED.

## Carry-over disposition

| Finding | Severity | Disposition |
|---|---|---|
| F-V100-L1 (trust_unmapped on `unmapped["evidentia"]`) | LOW | **CLOSED v0.10.1 Phase 1.** |
| F-V100-M1 (bump_version.py third-party pin over-bump) | MEDIUM | **CLOSED v0.10.1 Phase 5.** |
| F-V100-S1 (starlette PYSEC-2026-161) | MEDIUM | CLOSED at v0.10.0 ship (starlette 1.0.0 → 1.0.1). |
| paramiko CVE-2026-44405 | LOW | Stays CLOSED (compliance-trestle 4.0.3 from v0.9.9 holds). |
| pyjwt PYSEC-2025-183 | DISPUTED | Allowlisted in `osv-scanner.toml` with `ignoreUntil=2026-11-21`. Carried unchanged. |

## Standards alignment

Same as v0.10.0 — NIST SSDF PW.5 / PS.3; OpenSSF Best Practices
Silver; ISO 27001:2022 A.8.27 + SOC 2 Type II CC7.1 (test coverage
of new surfaces; CVSS / CWE scoring on findings).

## Cross-references

- [`docs/v0.10.1-plan.md`](v0.10.1-plan.md) — phase-by-phase scope.
- [`docs/v0.10.2-plan.md`](v0.10.2-plan.md) — forward-looking
  (MCP-as-backend + F-V101-L1 SSRF hardening).
- [`docs/ocsf-mapping.md`](ocsf-mapping.md) §5.1 + §7.A — trust_unmapped
  + Detection Finding mapping.
- [`docs/api-stability.md`](api-stability.md) — Finding alias + new
  EventAction value documented.
- [`docs/deprecation-calendar.md`](deprecation-calendar.md) —
  SecurityFinding deprecation entry.
- [`docs/capability-matrix.md`](capability-matrix.md) — v0.10.1
  PRE-TAG snapshot.
- [`docs/threat-model.md`](threat-model.md) — v0.10.1 attack-surface
  delta section.
- `.local/pre-release-review/runs/2026-05-23T04-36-19Z.json` — per-run
  log (26th in the series).
