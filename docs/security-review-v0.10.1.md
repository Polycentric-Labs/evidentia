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
| 6.C — final pre-tag pass | Pending (see §"16-row pre-push gate" below — filled at Step 6 entry). | TBD |

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

## 16-row pre-push gate (Step 6.C — filled at Step 6 entry)

_Filled by Step 6 when the 16-row gate runs against the final
release-prep state (post-version-bump, post-CHANGELOG-rename)._

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
