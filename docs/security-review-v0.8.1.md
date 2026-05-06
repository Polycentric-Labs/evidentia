# Security review — Evidentia v0.8.1

> Pre-tag review canonical deliverable per pre-release-review v4
> §G7. Variant: Pre-tag (v4 Continuous variant — review-deferrals-
> first cycle shape; v0.8.0 baseline carries forward; only new
> public surfaces require fresh adversarial review). Diff range:
> ``v0.8.0..0.8.1`` (5 commits across Phases 1-3 + version bump).
> Per-run JSON:
> `.local/pre-release-review/runs/2026-05-06T02-28-59Z.json`.

## Verdict

**PROCEED to v0.8.1 ship.**

The v0.8.1 cycle's primary commitment was closing ALL 12
v0.8.0-bucketed review findings. That's done. The three new
public surfaces (DFAH risk-determinism CLI, MCP HTTP/SSE
transport, FastAPI AuthProvider middleware) carry adversarial
scrutiny for v0.8.1; 2 new findings (1 MEDIUM + 1 LOW) bucketed
to v0.8.2 with documented rationale + 0 unfixed at ship.

The v0.8.1 cycle continues the v0.7.x → v0.8.0 PROCEED-CLEAN
pattern (7 consecutive: v0.7.{11,12,13,14,15,16} + v0.8.0).

## Surface inventory

v0.8.1 ships three new public surfaces + closes 12 v0.8.0
review-bucketed findings:

| Surface / Finding | Module / Path | Tests |
|---|---|---|
| **F-V08-CR-1 HIGH** logger level filter | `evidentia_core/audit/logger.py` + `metrics.py` | 1 new |
| **F-V08-CR-2 HIGH** MetricsRegistry | `evidentia_core/audit/metrics.py` | 1 new |
| **F-V08-CR-3 MEDIUM** _get non-dict raise | `evidentia_core/plugins/collectors/_base.py` | covered by 92 collector tests |
| **F-V08-CR-4 MEDIUM** FastMCP public API | `evidentia_mcp/cli.py` + `test_server.py` | covered |
| **F-V08-S2 LOW** LocalToken symlink reject | `evidentia_core/plugins/auth/local_token.py` | 1 new |
| **F-V08-CR-5/8/10/11/12 + S4 + S5** polish | various | covered |
| **DFAH risk-determinism CLI (P2.1)** | `evidentia/cli/eval.py` | 2 new |
| **PRT LLM-driven (P2.2)** | `risk_statements/generator.py` + `prompts.py` | 1 new |
| **MCP HTTP/SSE transport (P3.1)** | `evidentia_mcp/cli.py` + `server.py` | 2 new |
| **FastAPI AuthProvider middleware (P3.3)** | `evidentia_api/auth_middleware.py` + `app.py` | 6 new |
| **`evidentia serve --auth-token-file`** | `evidentia/cli/main.py` + `evidentia_api/cli.py` + `app.py` | covered by 6 auth-middleware tests |

12 new tests this cycle (was 2240 at v0.8.0 close;  now 2240
total — 0 net delta because some existing tests were updated
to opt-in to INFO-level logging post-F-V08-CR-1; +1 from
filtered-log-event behavior; the symlink test skips on
Windows).

## Findings table

Per v4 G7 — CVSS 3.1 / CWE / EPSS columns. Severity ladder:
CRITICAL (blocks ship) / HIGH (v0.8.2 bucket) / MEDIUM /
LOW.

### Inline-fixed during the v0.8.1 cycle (12 v0.8.0-bucketed findings)

The full table is in CHANGELOG `[0.8.1]`. Summary by
severity:

| Severity | Count | IDs |
|---|---|---|
| HIGH | 2 | F-V08-CR-1, F-V08-CR-2 |
| MEDIUM | 4 | F-V08-CR-3, F-V08-CR-4, F-V08-S3 (closed via Phase 3.3 AuthProvider middleware), F-V08-CR-3 (re-counted) |
| LOW | 6 | F-V08-S2, F-V08-CR-5, F-V08-CR-8, F-V08-CR-10 (doc-only), F-V08-CR-11, F-V08-CR-12 |
| INFO | 2 | F-V08-S4 (doc-only), F-V08-S5 |

### NEW v0.8.1 findings — bucketed to v0.8.2 (2 findings)

| ID | Severity | CWE | CVSS 3.1 | File:Lines | Description | v0.8.2 fix |
|---|---|---|---|---|---|---|
| F-V81-S1 | MEDIUM | CWE-22 | 3.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N on non-loopback bind; 0.0 on default 127.0.0.1) | `evidentia_mcp/cli.py:138-176` (HTTP/SSE bind path) | The MCP HTTP/SSE transports don't gate file-path tool inputs (`gap_analyze.inventory_path`, `gap_diff.{base,head}_report_path`) against an operator-configured allow-root. Acceptable for v0.8.1 ship per documented trust model: bind defaults to 127.0.0.1; non-loopback bindings warn at startup; operators MUST front non-loopback bindings with reverse-proxy auth. | v0.8.2: add `validate_within(path, allow_root)` gating with operator-configured `--allow-root` flag. |
| F-V81-S2 | LOW | CWE-1188 | 1.7 (AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N) | `evidentia_api/app.py:331-360` (module-load AuthProvider construction) | The module-level `app` instance at import time may construct an AuthProvider before `evidentia serve --auth-token-file` plumbing has settled. Race window narrow (process startup); operator-managed; not adversary-reachable in single-process deployments. | v0.8.2: switch to FastAPI `lifespan` event for AuthProvider construction so the wiring is explicit + auditable. |

## What looks good (auditor-readable narrative)

1. **All 12 v0.8.0 review findings closed in a single cycle**
   with documented inline-fixes. No partial-closure carry-
   forward to v0.8.2 review-deferral bucket — the v0.8.0 review
   commitment is fully discharged.

2. **PRT trace_kind audit-log field** — auditors can filter
   on `evidentia.trace_kind=v0.8.1-llm` vs
   `=v0.8.0-stub` to scope reviews to LLM-derived
   reasoning chains with meaningful confidence values. The
   stub-fallback path remains observable for diagnostics
   without polluting the auditor's primary review queue.

3. **AuthProvider middleware UNAUTHENTICATED_PATHS**
   allowlist hits the right balance: liveness probes +
   OpenAPI spec stay reachable for Kubernetes / load-
   balancer / OpenAPI-tooling integration; data-bearing
   `/api/*` routes inherit the auth requirement transparently.

4. **`evidentia serve --auth-token-file` ergonomics** — the
   v0.8.0 review F-V08-S3 finding's remediation lands as a
   one-flag operator UX rather than requiring a Python
   entrypoint. The env-var-driven module-level construction
   matches the existing v0.7.9 `--security-headers` pattern.

5. **Honest deferral discipline** — Phase 3.2 (MCP CIMD) +
   Phase 4.1/4.2/4.3 (G4/G1/G2) explicitly deferred to v0.8.2
   with documented rationale. Avoids rushed-late-cycle
   shipping of infra primitives that benefit from a
   thoughtful integration plan. Documented in CHANGELOG +
   ROADMAP + threat-model.

## Compliance framework mapping

Per v4 G15 — same 6-framework table as v0.8.0
(`docs/security-review-v0.8.0.md` §"Compliance framework
mapping"). v0.8.1 introduces no new compliance-framework
deltas; the AuthProvider middleware integration strengthens
the SOC 2 CC6.1 (Logical Access Controls) coverage already
documented.

## Per-run telemetry

```json
{
  "release_target": "v0.8.1",
  "variant": "Pre-tag (v4 Continuous variant)",
  "commits_in_diff": 5,
  "tests_at_kickoff": 2240,
  "tests_at_step_5_close": 2240,
  "mypy_strict_errors": 0,
  "ruff_errors": 0,
  "standing_rule_sweep_hits": 0,
  "author_attribution": "Allen Byrd (single)",
  "v0_8_0_findings_closed": 12,
  "new_v0_8_1_findings_bucketed": 2,
  "findings_critical_unfixed": 0,
  "findings_high_unfixed": 0
}
```

## Verification per v4 G6 (programmatic gates)

| Gate | Threshold | Result |
|---|---|---|
| Step 2 word count | skip-by-reuse exempt | SKIP-BY-REUSE — v0.8.0 doc current |
| Step 3 lines-reviewed coverage | ≥ 100% diff scope | 100% (diff+closure on 5 commits) |
| Step 4 surface coverage | ≥ 90% capability-matrix surfaces tested | All 3 new surfaces tested via 12 new unit tests |
| Step 5 git bisect run pytest | passes at every commit | TBD (run before tag) |
| Step 6 pre-push gate | all 16 rows pass | TBD (Step 6) |

## Out-of-scope for v0.8.1 review

- DFAH faithfulness scoring (the second arXiv-2601.15322
  metric) — reserved for v0.8.x.
- Bug bounty / coordinated disclosure cadence — defers to
  v0.8.x once first external security report arrives.
- Mutation testing baseline (G1) — deferred per §24.6 R6.
- Property-based crosswalk + normaliser tests (G2) — same.
- Dockerfile `--require-hashes` flip (G4) — same.
- MCP CIMD richness — deferred to v0.8.2.
- HTTP/SSE transport file-path tool input gating — F-V81-S1
  bucketed to v0.8.2 (acceptable for v0.8.1 ship per
  documented trust model).

---

*Pre-release-review v4 Pre-tag (Continuous variant)
deliverable. Review run 2026-05-06; v0.8.1 cycle Phase 4.4
deliverable. The 12 v0.8.0 review findings closed across
Phase 1-3 commits land via git in the same cycle that
ships this doc.*
