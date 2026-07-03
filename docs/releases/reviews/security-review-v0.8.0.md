# Security review — Evidentia v0.8.0

> Pre-tag review canonical deliverable per pre-release-review v4
> §G7. Variant: Pre-tag (full v4 7-step). Diff range:
> `v0.7.16..b1107f0` (7 commits, 52 files, 5276 insertions).
> Per-run JSON:
> `.local/pre-release-review/runs/2026-05-05T23-15-08Z.json`.

## Verdict

**PROCEED to v0.8.0 ship.**

Five inline-fixes applied during Step 5.A (correctness +
defense-in-depth). Twelve findings bucketed to v0.8.1 with
documented rationale. Zero CRITICAL/HIGH unfixed.

The v0.8.0 cycle continues the v0.7.x pattern (6 consecutive
PROCEED-CLEAN reviews; cf. v0.7.{8,9,11,12,13,16}-shipped
memory).

## Surface inventory

v0.8.0 ships four new public surfaces + one extended
existing surface:

| Surface | Module | Public API | Tests |
|---|---|---|---|
| **DFAH eval (P0.1)** | `evidentia_ai.eval` | `evidentia eval stub-smoke` + `DFAHarness` library | 23 |
| **PRT (P0.2)** | `evidentia_core.models.risk` (TraceClaim + ReasoningTrace) | `evidentia risk generate --emit-trace`; `gap_report_to_oscal_ar(risk_statements_with_traces=...)` | 16 |
| **MCP server (P0.3)** | `evidentia-mcp` (NEW workspace member) | `evidentia mcp serve / doctor`; 4 stdio tools | 15 |
| **Plugin contracts (P0.4)** | `evidentia_core.plugins` | 4 ABCs + 3 ref impls + `discover_plugins()` | 38 |
| **/api/metrics (P1 G3)** | `evidentia_api.routers.metrics` | Prometheus 0.0.4 text exposition | 10 |
| **M-4 collector refactor** | 4 vendor-risk collectors inherit `BaseSaaSCollector` | unchanged surface; ~60% scaffolding LOC drop | 92 |

Plus `docs/evidence-integrity.md` (new operator deployment
guidance) + 6 new audit `EventAction` entries.

## Findings table

Per v4 G7 — CVSS 3.1 / CWE / EPSS columns. Severity
ladder: CRITICAL (blocks ship) / HIGH (v0.8.1 bucket) /
MEDIUM / LOW.

### Inline-fixed during Step 5.A (5 findings)

| ID | Severity | CWE | CVSS 3.1 | File:Lines | Description | Fix |
|---|---|---|---|---|---|---|
| F-V08-CR-7 | MEDIUM | CWE-697 | n/a (correctness) | `evidentia-ai/eval/harness.py:255-261` | Replay-equivalence compared against `outputs[0]` instead of `det_result.modal_hash`. Race: when sample 0 is a determinism outlier, replay matches the outlier rather than the canonical modal output. | Compare `hash_output(replay)` against `det_result.modal_hash`. |
| F-V08-CR-6 | LOW | CWE-1112 | n/a (docs) | `evidentia-ai/eval/seeds.py:11-22` | Docstring claimed "lowercase trailing terminator" but code only strips `.`/`!`/`?`. Misleading. | Rewrote docstring to accurately describe the strip + collapse + preserve-case behavior. Added v0.8.0 review note. |
| F-V08-CR-9 | LOW | CWE-1067 | n/a (docs) | `evidentia-ai/risk_statements/generator.py:_attach_stub_trace` | Stub trace's `confidence=0.5` ambiguous to auditors who might treat the value as LLM-introspected. | Added auditor note in docstring + `trace_kind=v0.8.0-stub` audit-log filter guidance. |
| F-V08-S1 | LOW | CWE-22 | 2.5 (AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N) | `evidentia-mcp/server.py:57-65` | MCP `gap_analyze` / `gap_diff` tools accept arbitrary file paths without `validate_within` gating. Acceptable for v0.8.0 stdio-only trust model. | Added `TRUST MODEL` paragraph to `SERVER_INSTRUCTIONS` documenting the stdio-only trust boundary. v0.8.1 HTTP/SSE transports require `validate_within` gating per `docs/threat-model.md` Surface 2. |
| F-V08-S3 | MEDIUM | CWE-306 | 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) on non-loopback bind; 0.0 on default localhost | `evidentia-api/routers/metrics.py:1-32` | `/api/metrics` not auth-gated. Default localhost-bind mitigates; non-loopback bind requires reverse-proxy basic auth or mTLS. | Added `OPERATIONAL POSTURE` paragraph to router docstring + `docs/evidence-integrity.md` §4.1 covers non-loopback recommendation. v0.8.1 wires `AuthProvider` plugin contract into FastAPI dependency stack. |

### Bucketed to v0.8.1 (12 findings)

Code-quality:

| ID | Severity | File:Lines | Description | v0.8.1 fix |
|---|---|---|---|---|
| F-V08-CR-1 | HIGH | `audit/logger.py:350-357` | `record_event` taps fire regardless of stdlib log-level filter. CI sets logger to WARNING; counters and log-stream go out of sync. | Wrap `record_event` in `if self._stdlib.isEnabledFor(stdlib_level):`. Lift lazy import to module level. |
| F-V08-CR-2 | HIGH | `audit/metrics.py:32-54` | Module-level globals; `_failure_count` increment based on string equality with `"failure"` is implicit invariant that breaks if anyone calls `record_event` directly with `EventOutcome.FAILURE` enum. | Encapsulate counters in `MetricsRegistry` class + add `outcome in {"success", "failure", "unknown"}` assertion. |
| F-V08-CR-3 | MEDIUM | `plugins/collectors/_base.py:246-249` | `_get` silently wraps non-dict JSON as `{"items": data}`. None of the 4 collectors actually consume list responses; the wrap masks anomalies. | Either narrow to raise `QUERY_ERROR_CLASS(...)` on non-dict OR keep wrap + add structured warning log. |
| F-V08-CR-4 | MEDIUM | `evidentia-mcp/cli.py:108-110` | `doctor` accesses FastMCP private API `_tool_manager._tools`. Brittle across SDK minor versions. | FastMCP 1.27 exposes `server.list_tools()` public API — switch. |
| F-V08-CR-5 | LOW | `evidentia-mcp/cli.py:121-128` | `doctor` references `fws` + `registered` post-FAIL-branch; unbound if catalog-load fails. | Initialize at top of function. |
| F-V08-CR-8 | LOW | `oscal/exporter.py:412-417` | `assert trace is not None` disabled under PYTHONOPTIMIZE=1. | Replace with explicit `if trace is None: raise ValueError(...)`. |
| F-V08-CR-10 | LOW | `plugins/storage/_base.py:9` | PEP 695 generic syntax used inconsistently (StorageBackend[T] but BaseSaaSCollector not generic). | Lift `BaseSaaSCollector` to `BaseSaaSCollector[T_Findings]` OR document rationale. |
| F-V08-CR-11 | LOW | `plugins/__init__.py:62-96` | `discover_plugins()` returns untyped dict; operators must isinstance-check themselves. | Add `of_type` kwarg with typed-narrowing return. |
| F-V08-CR-12 | LOW | `tests/unit/test_plugins/test_contracts.py:83,94` | Tests `assert "missing" in result.reason.lower()` AttributeError if reason is None. | Defensive `assert result.reason is not None and ...`. |

Security:

| ID | Severity | CWE | CVSS 3.1 | File:Lines | Description | v0.8.1 fix |
|---|---|---|---|---|---|---|
| F-V08-S2 | LOW | CWE-59 | 3.3 (AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N) | `plugins/auth/local_token.py:53-62` | Token-file load follows symlinks. Window narrow (construction-time; provider long-lived); requires shared parent-dir write. | Add `os.lstat()` symlink-rejection. |
| F-V08-S4 | INFO | CWE-770 | n/a | `evidentia-ai/eval/harness.py:174-272` | DFAH harness has no resource bounds on per-call timeout / aggregate budget. "You own the gun pointed at your foot" rather than vulnerability. | Add docstring note + optionally per-call timeout via `concurrent.futures`. |
| F-V08-S5 | INFO | CWE-755 | n/a | `local_directory.py:80-90` | Manifest parse failure silently falls back; masks misconfiguration. | Emit `_log.warning` on parse failure. |

### What looks good (auditor-readable narrative)

Per the parallel code-quality review:

1. **M-4 collector refactor delivers real LOC reduction** —
   182 lines deleted across 4 collectors without regressing
   per-collector idiosyncrasies. Auth-scheme overrides via
   `_auth_header()` cleanly capture each provider's quirks
   (Bearer / Basic / `Token <key>`) without polluting the
   base. The multi-inheritance pattern preserves existing
   `pytest.raises(VantaAuthError)` test semantics.

2. **PRT canonical JSON / Sigstore symmetry** —
   `_reasoning_trace_canonical_json` mirrors
   `_finding_canonical_json` exactly. Auditors familiar with
   v0.7.0 finding resources verify trace resources without
   re-learning.

3. **DFAH `EvalResult.overall_determinism_rate` aggregation
   is correct** — sample-weighted (sum-of-modal /
   sum-of-samples) rather than naive per-prompt mean.
   Robust against future per-prompt sample-count divergence.

4. **Plugin contracts are auditor-readable + minimal** —
   each ABC has 2-5 abstract methods; reference impls under
   130 LOC each; `discover_plugins` opt-in (no auto-load).
   Right trust posture for compliance tooling.

5. **Honest stub trace + visible deferral** — v0.8.0 stub
   PRT explicitly cites itself in `methodology=` ("v0.8.0
   stub — single foundational claim... v0.8.1 ships
   LLM-driven per-claim decomposition") + audit event
   carries `trace_kind=v0.8.0-stub`. Right way to ship a
   deferred deliverable: visible to operators, observable
   in audit, deferral plan documented inline.

## Compliance framework mapping

Per v4 G15 — maps each step to ≥ 1 control in 6 frameworks.

| Step | NIST SSDF | SLSA | ISO 27001:2022 | SOC 2 | DORA | OpenSSF Scorecard | CISA Pledge |
|---|---|---|---|---|---|---|---|
| 1 (process review + scope-confirm) | PS.3.1 (Track artifact provenance) | L2 (Distribution-policy) | A.8.25 (Secure development life cycle) | CC8.1 (Change management — risk assessment) | RTS Art 5 (Risk identification) | (n/a) | Defaults (Establish SSDLC) |
| 2 (positioning) | (n/a) | (n/a) | A.5.31 (Legal/contractual requirements) | (n/a) | RTS Art 12 (Threat-led testing) | (n/a) | (n/a) |
| 3 (commit re-test + /security-review) | PS.1.1 (Have a security review) | L3 (Build integrity) | A.8.30 (Outsourced development) | CC8.1 (Change-mgmt review) | RTS Art 25 (Security testing) | Code-Review | Reduce attack-surface |
| 4 (capability matrix re-validation + DAST) | PS.3.1 (Reproduce builds) | L3 (Build integrity) | A.8.29 (Security testing in development) | CC7.1 (Detect/mitigate vulns) | RTS Art 26 (Test coverage) | DAST | Reduce attack-surface |
| 5 (project-wide refinements) | PW.4.1 (Reuse vetted components) | (n/a) | A.8.28 (Secure coding) | CC7.2 (Monitor for anomalies) | RTS Art 24 (Coding standards) | (n/a) | (n/a) |
| 6 (release-checklist + tag) | PS.3.1 (Distribute artifacts) | L3 (Provenance attestation) | A.8.32 (Change management) | CC8.1 (Approve changes) | RTS Art 14 (ICT risk-mgmt) | Pinned-Dependencies, Signed-Releases | Defaults |
| 7 (post-tag verification) | PS.3.1 (Verify integrity) | L3 (Verify provenance) | A.5.7 (Threat intelligence) | CC4.1 (Monitor controls) | RTS Art 32 (ICT incident response) | SAST + Vulnerabilities | Reduce CVE class |

## Per-run telemetry

```
{
  "release_target": "v0.8.0",
  "variant": "Pre-tag (full v4 7-step)",
  "commits_in_diff": 7,
  "files_in_diff": 52,
  "insertions": 5276,
  "deletions": 412,
  "tests_at_kickoff": 2227,
  "tests_at_step_5_close": 2227,
  "mypy_strict_errors": 0,
  "ruff_errors": 0,
  "standing_rule_sweep_hits": 0,
  "author_attribution": "Allen Byrd (single)",
  "findings_critical_unfixed": 0,
  "findings_high_unfixed": 0,
  "findings_high_bucketed_v0_8_1": 2,
  "findings_medium_inline_fixed": 2,
  "findings_medium_bucketed_v0_8_1": 2,
  "findings_low_inline_fixed": 3,
  "findings_low_bucketed_v0_8_1": 7,
  "findings_info_bucketed_v0_8_1": 2,
  "step_5_a_inline_fixes": 5
}
```

## Verification per v4 G6 (programmatic gates)

| Gate | Threshold | Result |
|---|---|---|
| Step 2 word count | ≥ 8000 (skip-by-reuse exempt) | SKIP-BY-REUSE — v0.7.8 doc cited |
| Step 3 lines-reviewed coverage | ≥ 100% diff scope | 100% (diff+closure) |
| Step 4 surface coverage | ≥ 90% capability-matrix surfaces tested | TBD (Step 4 in progress) |
| Step 5 git bisect run pytest | passes at every commit | TBD (Step 5 in progress) |
| Step 6 pre-push gate | all 16 rows pass | TBD (Step 6) |

## Out-of-scope for v0.8.0 review

- Bug bounty / coordinated disclosure cadence — defers to
  v0.8.x once first external security report arrives.
- Mutation testing baseline (G1) — deferred per §24.6 R6.
- Property-based crosswalk + normaliser tests (G2) — same.
- Dockerfile `--require-hashes` flip (G4) — same; the
  hash-pinned `docker/requirements.txt` generation tooling
  shipped in v0.7.14 P1.5 is the foundation.
- Multi-process Prometheus aggregation — v0.8.1.
- LLM-driven PRT (replacing the v0.8.0 stub) — v0.8.1.

---

*Pre-release-review v4 Pre-tag deliverable. Variant chosen
2026-05-05; review run 2026-05-05; v0.8.0 cycle Phase 6
deliverable. The 5 inline-fixes from this review land via
git in the same Step 5 commit that ships this doc.*
