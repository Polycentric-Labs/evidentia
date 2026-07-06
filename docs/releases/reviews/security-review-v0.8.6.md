# Security review — v0.8.6

> 5th canonical Pre-tag deliverable per the v4 pre-release-review
> skill (G7: severity bucketing with CVSS / CWE / EPSS columns).
> Variant: **Pre-tag (v4 7-step Continuous-style compression)**.
> Diff range: `v0.8.5..v0.8.6` (4 v0.8.6-cycle commits).
>
> **Note**: this document was authored at v0.8.7 backfill time
> (per §30 P1) — the actual review work happened during the
> v0.8.6 ship cycle 2026-05-07; the document was a P6 cycle-close
> artifact deferred at single-session compression. All findings +
> verdicts below reflect the v0.8.6 ship-time review state.

## Step 1 — process review + scope-confirm

**Scope**: diff+closure across the 4 v0.8.6-cycle commits per
Allen's cycle-open lock-in (§29.1: Comprehensive scope + CIMD-
enforcement-first sequencing + Aggressive ~2-3w + 3 additions
including v0.7.x retrospective + v1.0 transition narrative DRAFT
+ per-tool scope enforcement audit-trail layer).

**Bug-fix policy**: per the v3-prototyped pattern, inline-fix
CRITICAL/HIGH; bucket MEDIUM/LOW for v0.8.7 with explicit
rationale.

## Step 2 — project review (positioning + value)

**SKIP-BY-REUSE.** No market-context shifts since v0.8.0
+ v0.8.3 + v0.8.4 + v0.8.5 spot-validation. The 6-criterion
skip-by-reuse gate holds: doc < 90 days; minor bump; no new
enterprise-grade claim; no competitor categorical move;
threat-model fresh (refreshed in v0.8.5).

## Step 3 — per-commit re-test + /security-review

| Commit | Theme | Findings |
|---|---|---|
| `a117011` | P1 CIMD scope enforcement at MCP-protocol level + per-call audit trail (NEW `evidentia_mcp.scope` module + 2 new EventActions + `--default-client-id` CLI flag + 8 unit tests) | 0 unfixed |
| `222fc6f` | P2 Cohen's Kappa rater agreement script + label-quality probe (NEW `scripts/compute_inter_rater_kappa.py` + 25 unit tests + `tests/data/dfah-calibration/inter-rater-agreement.md`) | 0 unfixed |
| `a95cb8b` | P3 per-claim bootstrap-resampled confidence + framework-aware threshold defaults (`FaithfulnessResult.confidence` + `FaithfulnessResult.framework` fields + `DEFAULT_THRESHOLDS_BY_FRAMEWORK_JACCARD` map + `resolve_threshold` helper + 10 unit tests) | 0 unfixed |
| `eb0f331` | P4 + P5 docs (v0.7.x-retrospective.md + v1.0-transition.md DRAFT) + version bump to 0.8.6 + CHANGELOG | 0 unfixed |

`/code-review` auto-fire triggers per the v4 G2 protocol:

- **New public CLI surface**: `--default-client-id <slug>`
  flag on `evidentia mcp serve`. Trigger #1.
- **New file under packages/*/src/**:
  `packages/evidentia-mcp/src/evidentia_mcp/scope.py` (~250
  LOC). Trigger #2.
- **>500 LOC delta**: yes (~1500 LOC across the 4 commits
  including tests + corpus integration). Trigger #3.
- **Security-relevant subsystem touched**: MCP scope-
  enforcement (auth-adjacent metadata layer). Trigger #4.

All 4 triggers fire — comprehensive `/code-review` + `/security-
review` invocations across the diff range.

### Security findings (CVSS / CWE / EPSS)

#### Inline-fixed during cycle

None.

#### Bucketed to v0.8.7 (LOW; rationale below)

No new LOW findings. The cycle's surface additions are well-
bounded:

- **CIMD scope enforcement gate**: `enforce_cimd_scope` is
  monkey-bound to `FastMCP.call_tool` (mcp Python SDK 1.27
  has no public middleware hook); pass-through path preserves
  v0.8.5 behavior when `cimd_registry=None`; deny-by-default
  on ambiguous-caller / unregistered / out-of-scope. **CIMD is
  NOT authentication** — documented prominently in `cimd.py`
  (v0.8.5 P4) + `scope.py` (v0.8.6 P1) docstrings. Operators
  MUST wire transport-level authentication (reverse-proxy mTLS
  or bearer tokens). The threat-model section in
  `docs/threat-model.md` v0.8.6 delta documents this.
- **Cohen's Kappa script**: pure data tooling; no runtime
  surface. Rule-based jaccard rater is deterministic + reads
  corpus JSONL files only.
- **Per-claim confidence + framework fields**: additive
  Pydantic field changes; backward-compatible (default None);
  bootstrap resampling uses Python stdlib `random.Random` with
  optional seed (test-only; production callers leave None).

**No CRITICAL / HIGH / MEDIUM / LOW findings unfixed at ship.**

## Step 4 — capability-matrix re-validation

**Carry-forward from v0.8.5 + new rows**:

| Surface | v0.8.5 baseline | v0.8.6 delta |
|---|---|---|
| `evidentia mcp serve` CLI | `--cimd-registry <path>` | + `--default-client-id <slug>` |
| MCP `build_server` factory | `cimd_registry=` | + `default_client_id=` (threaded to `enforce_cimd_scope` after `_register_tools`) |
| MCP `run_stdio` / `run_sse` / `run_http` | `cimd_registry=` | + `default_client_id=` forwarded |
| `server.evidentia_cimd` server-side attribute | shipped (v0.8.5 P4); read-only by tool implementations | now consulted at runtime by `enforce_cimd_scope` gate |
| `EventAction.AI_MCP_TOOL_AUTHORIZED` | (does not exist) | NEW: per-call event when CIMD gate authorizes |
| `EventAction.AI_MCP_TOOL_DENIED` | (does not exist) | NEW: per-call event when CIMD gate denies |
| `evidentia_mcp.scope` module | (does not exist) | NEW: `enforce_cimd_scope(server, default_client_id)` + idempotency guard |
| `scripts/compute_inter_rater_kappa.py` | (does not exist) | NEW: Cohen's Kappa formula + Landis-Koch interpretation + CI-gateable exit codes |
| `tests/data/dfah-calibration/inter-rater-agreement.md` | (does not exist) | NEW: documents the v0.8.6 P2 κ probe (best κ = 0.4848 at threshold 0.85; ships as "single-rater + κ probe inconclusive" per §29 R3) |
| `FaithfulnessResult.confidence` | (does not exist) | NEW: `float | None = None`; bootstrap-resampled stddev; opt-in via `compute_confidence=True` |
| `FaithfulnessResult.framework` | (does not exist) | NEW: `str | None = None`; persisted on result for audit-trail re-derivation |
| `DEFAULT_THRESHOLDS_BY_FRAMEWORK_JACCARD` | (does not exist) | NEW: NIST 0.60 / FFIEC 0.35 / ISO27001 0.30 (per v0.8.5 P2 sweep) |
| `resolve_threshold(framework, method)` helper | (does not exist) | NEW: framework-aware default lookup with fallback to `DEFAULT_FAITHFULNESS_THRESHOLD` |
| `examples/mcp/cimd-registry-readonly.json` + `cimd-registry-power.json` | (do not exist) | NEW: operator-friendly CIMD example registries |

DAST per G11: carry-forward (no new HTTP routes; CIMD scope
enforcement is at the MCP-protocol level, not over HTTP).

## Step 5 — refinements + commit-decomposition audit

**Per-commit refinements** were inline during dev:

- ruff RUF022 `__all__` not sorted in `cimd.py` — auto-fixed (v0.8.5)
- ruff RUF059 unused tuple unpack vars in test_compute_inter_rater_kappa.py
  — auto-fixed via `--unsafe-fixes`
- caplog ecs_record access pattern: scope tests use
  `getattr(record, "ecs_record", {})` per the canonical
  audit-logger emit pattern (`extra={"ecs_record": ecs_record}`)
- mypy strict no-any-return on `_bootstrap_confidence` —
  resolved with explicit float annotations on `normalized_stddev`
  + `confidence` intermediates
- ASCII output in `compute_inter_rater_kappa.py` (Greek κ
  spelled out as "kappa") for Windows-cp1252 portability

**Commit-decomposition rubric (v4 SKILL.md)**:

- ✅ Each commit has one thematic concern (P1 CIMD; P2 kappa;
  P3 confidence/framework; P4-P5+bump)
- ✅ Each commit lands a buildable state (pytest green between
  each)
- ✅ Each commit's message follows the conventional-commit
  prefix
- ✅ Single-author attribution (Allen Byrd)
- ✅ Standing-rule keyword sweep clean across all 4 commits

## Step 6 — release-checklist final review + 16-row pre-push gate

| # | Gate | Status |
|---|---|---|
| 1 | pytest 100% green | ✅ 2383 passed / 17 skipped |
| 2 | mypy strict 0/0 | ✅ 217 source files |
| 3 | ruff clean | ✅ |
| 4 | standing-rule sweep clean | ✅ all 4 cycle commits |
| 5 | author attribution | ✅ Allen Byrd only |
| 6 | inter-package pins consistent | ✅ all `>=0.8.6,<0.9.0` |
| 7 | bump_version.py atomic | ✅ 26 subs / 9 files |
| 8 | release.yml CHANGELOG auto-populate | ✅ block authored |
| 9 | release.yml Wait-for-PyPI all 6 packages | ✅ (validated since v0.7.16) |
| 10 | container-build.yml Wait-for-PyPI all 6 packages | ✅ (validated since v0.7.14 P2.2) |
| 11 | OSV scanner clean | ✅ post-tag verified clean |
| 12 | code-scanning alert delta | ✅ 0 open at ship (G4 Path 2 stable; pip-tools pin durable) |
| 13 | container CVE scan (Trivy) | ✅ post-tag |
| 14 | vulnerability aging SLO | ✅ |
| 15 | license/SCA enforcement | ✅ |
| 16 | secret-rotation cadence | ✅ |

## Step 7 — post-tag verification (NEW v4)

**EXECUTED at v0.8.6 ship-time 2026-05-07**:

| # | Gate | Result |
|---|---|---|
| G1 | PEP 740 verify all 7 packages | ✅ 7/7 OK |
| G2 | cosign verify SLSA Provenance v1 | ✅ matching cert + Rekor inclusion at digest `sha256:583d3849b5997edd2557530c48a32f085fa22ebbc2441bbeb2e7fcf7db8799a5` |
| G3 | osv-scanner --sbom | ✅ 169 packages / 0 issues |
| G4 | docker run smoke | ✅ "Evidentia v0.8.6" + Python 3.14.4 |
| G5 | fresh-venv install | ✅ **13th consecutive pin-trap fix validation** |
| G7 | Scorecard delta | ✅ 0 open code-scanning alerts at close |
| G16 | release-body substantiveness | ✅ 6837 bytes — **12th consecutive auto-populate-from-CHANGELOG** |

release.yml first-fire on v0.8.6 tag PASSED end-to-end (G4
Path 2 5th consecutive activation; no hot-fix needed).

## Compliance framework mapping (v4 G15)

| Framework | Control | v0.8.6 evidence |
|---|---|---|
| **NIST SSDF** | PS.3.1 (artifact integrity) | G4 Path 2 hash-pinning continues working (5th consecutive release post-G4 activation) |
| **NIST SSDF** | PW.7 (review code for vulnerabilities) | This document; per-commit /security-review |
| **NIST SSDF** | RV.1.1 (track public vulnerabilities) | osv-scanner clean; 0 open code-scanning alerts |
| **SLSA** | L3 build provenance (v1) | release.yml `actions/attest-build-provenance@v4` |
| **ISO 27001:2022** | A.5.34 access control | NEW: per-tool scope enforcement at MCP-protocol level (CIMD allowlist semantics) |
| **ISO 27001:2022** | A.8.15 logging | NEW: per-call AI_MCP_TOOL_AUTHORIZED + AI_MCP_TOOL_DENIED audit events |
| **ISO 27001:2022** | A.8.25 secure development | This document; 16-row pre-push gate |
| **ISO 27001:2022** | A.8.28 secure coding | mypy strict + ruff + standing-rule sweep |
| **SOC 2 Type II** | CC6.6 (logical access) | NEW: per-client audit trail via CIMD scope enforcement |
| **SOC 2 Type II** | CC7.1 (secure baselines) | G4 Path 2 hash-pinning + Scorecard PinnedDependencies 10/10 |
| **SOC 2 Type II** | CC8.1 (change management) | Pre-release-review v4 gate; 16-row pre-push |
| **DORA (EU)** | Article 6 ICT risk management | DFAH determinism + replay + faithfulness audit trail; per-claim confidence enables triage of low-confidence below-threshold claims |
| **OpenSSF Scorecard** | PinnedDependencies | Stable 10/10 (G4 Path 2 + pip-tools pin) |
| **CISA Secure-by-Design Pledge** | Pledge 4 (vulnerability disclosure) | docs/security-review-v0.8.6.md (this doc) |

## Verdict

**PROCEED-CLEAN — 13th consecutive of v0.7.x → v0.8.x line.**

All 16 pre-push gate rows green. 0 unfixed CRITICAL / HIGH /
MEDIUM / LOW findings. The cycle's flagship items (P1 CIMD
scope enforcement at MCP-protocol level + P2 Cohen's Kappa
rater agreement + P3 per-claim confidence + framework-aware
threshold defaults) close ALL 3 v0.8.5 carry-overs cleanly +
the 3 cycle-additions (P4 v0.7.x retrospective + P5 v1.0
transition narrative DRAFT + per-tool scope enforcement
audit-trail layer).

Step 7 post-tag verification ALL PASS (executed at ship-time);
this document closes the audit loop.

---

*v0.8.6 cycle metrics: 4 cycle commits, ~1500 LOC delta
including tests + corpus integration, 45 new tests (8 scope +
25 kappa + 10 confidence/framework + 2 docs-only), 2383
passed / 17 skipped (was 2338 / 17 at v0.8.5 ship), 0 unfixed
findings at close. Comprehensive scope of the v0.8.x line —
all v0.8.5 carry-overs closed in one focused session matching
v0.8.3 + v0.8.4 + v0.8.5 single-session-compression cadence.*

*Document backfilled 2026-05-08 per v0.8.7 §30 P1 (cycle-close
artifact deferred during v0.8.6 single-session compression).*
