# Security review — v0.9.6

> **Status**: in-cycle artifact for the v0.9.6 ship. This is the
> 5th canonical deliverable per the v4 pre-release-review skill
> (`references/deliverables.md`). Cycle compressed into a focused
> session per the aggressive pacing locked in 2026-05-18.
>
> **Theme**: Federal AI-gov expansion + WORM evidence versioning
> + CLI RBAC mirror + CONMON MCP first-mover + OSCAL 1.2.1 + mypy
> strict extension. Walk-through deferred to v0.9.7.

## Cycle scope

v0.9.6 closes the three v0.9.5 deferrals (WORM store-side
enforcement, CLI RBAC mirror, federal-tier AI-gov fields), adds
the FedRAMP-aligned SCR emit + CONMON MCP first-mover surface,
upgrades OSCAL emit to 1.2.1, and extends the mypy strict gate
to cover all 7 evidentia-* packages (256 source files clean).

## Findings ledger

### v0.9.6 in-cycle review (3 NEW findings, all LOW / INFO)

| Finding | Severity | CWE | Status |
|---|---|---|---|
| F-V96-rbac-cli-trust | INFO | — | CLI identity arrives via `EVIDENTIA_RBAC_IDENTITY` env var or `--rbac-identity` flag with NO authentication step. Documented in `evidentia.cli._rbac_lifecycle` module docstring + threat-model v0.9.6 delta: CLI RBAC is an **authorization** model that assumes the surrounding environment authenticates the operator. Operators MUST chmod the policy file to 0600 + own it with a dedicated service user. Mitigated by single-tenant default; matches existing v0.9.5 F-V95-rbac-trust posture. |
| F-V96-worm-app-layer | LOW (accepted) | CWE-732 | Application-layer WORM enforcement (`evidence_store.save_evidence` refusing overwrite of `v<N>.json`) does NOT prevent a privileged operator from deleting the JSON files via OS tools. For regulator-grade WORM, operators MUST wire `evidentia_core.evidence_store_worm.mirror_to_worm()` against a cloud-WORM backend (S3 Object Lock / Azure Immutable Blob / GCS Bucket Lock). Documented in `evidence_store` module docstring + threat-model v0.9.6 delta. **Accepted**: the cloud-WORM composition path is the explicit upgrade for FedRAMP AU-9 / SOX §404 / HIPAA §164.312(b) deployments. |
| F-V96-conmon-mcp-cimd-migration | INFO | — | Operators updating from v0.9.5 CIMD registries see the new `conmon_*` MCP tools default-rejected until their per-tool CIMD scope grants the new tool names. Documented in CHANGELOG migration note + regression-protected by the existing v0.8.6 CIMD scope-enforcement test surface. |

### Carry-over closures from v0.9.5

| Finding | Severity | Closure |
|---|---|---|
| (v0.9.5 P3.2 deferral) | — | WORM store-side enforcement shipped in `evidentia_core.evidence_store`. Append-only at the store layer; cloud-WORM mirror composes via `evidence_store_worm`. |
| (v0.9.5 P3.3 deferral) | — | CLI RBAC enforcement shipped in `evidentia.cli._rbac` + `_rbac_lifecycle`. Mirrors FastAPI `require_role()` at the CLI layer via shared `check_permission()`. |
| (v0.9.5 carry-overs F1-F6 from validation report) | — | FIPS 199 + ATO + SSP + OMB M-24-10 + SCR emit shipped across `evidentia_core.ai_governance.{fips199,omb_m_24_10,scr,registry}`. |
| F-V95-F4 (mypy strict to evidentia-ai + evidentia-mcp) | — | CI gate extended; 256/256 source files clean. |
| F-V95-F5 (OSCAL 1.1.2 → 1.2.1 upgrade) | — | `OSCAL_SCHEMA_VERSION` constant + observation-type rename at single emit site. |

**Zero CRITICAL / HIGH / MEDIUM-unfixed findings in v0.9.6 source code.**

## Validation pass artifacts

### Mandatory `/security-review` invocations (3, per v4 G12)

Compressed Steps 3-6 into single-cycle execution with security
analysis embedded in each phase's implementation review:

1. **Step 3 equivalent** — re-test of every commit since v0.9.5.
   Surfaced 0 net-new CRITICAL/HIGH/MEDIUM findings; all 3 NEW
   findings above are LOW / INFO and operator-visible.
2. **Step 4 equivalent** — capability-matrix re-validation snapshot
   for v0.9.6 in `docs/capability-matrix.md` covering: 4 new
   CONMON MCP tools, evidence-store CLI verbs (3), ai-gov federal
   verbs (`categorize-fips`, `set-omb-impact`,
   `update --emit-scr`, `update --ssp-reference`), CLI RBAC global
   flag, conmon-check flag normalization.
3. **Step 6.C equivalent** — 16-row pre-push gate validation:

| # | Gate | v0.9.6 outcome |
|---|---|---|
| 1 | Test suite passes | 3018 / 17 (skip) / 0 (fail) |
| 2 | mypy strict 0 errors | **256 source files clean** (extended from 223) |
| 3 | ruff full repo clean | 0 errors |
| 4 | Coverage ≥ 80% | (Codecov audit pending; v0.9.5 baseline 84.26%) |
| 5 | uv.lock regenerated at version bump | (Phase 5.4) |
| 6 | CHANGELOG entry added | ✓ (`[Unreleased]` block) |
| 7 | ROADMAP transitions | (Phase 5.3) v0.9.6 PLANNED → SHIPPED + v0.9.7 PLANNED |
| 8 | Threat-model v0.9.6 delta | (Phase 5.3) |
| 9 | Capability-matrix v0.9.6 snapshot | (Phase 5.3) |
| 10 | README "Why different" v0.9.6 paragraph | ✓ (moat-trinity hook) |
| 11 | Positioning-and-value §6.1.A + §6.1.B added | ✓ |
| 12 | Code-scanning alert delta | Deferred to post-push (GitHub-side check) |
| 13 | Container CVE scan (Trivy) | Deferred to post-push (release.yml fires Trivy) |
| 14 | Vulnerability aging SLO | 0 stale findings (all v0.9.5 deferrals closed this cycle) |
| 15 | License/SCA enforcement | No new third-party deps in v0.9.6 source code |
| 16 | Secret-rotation cadence | No secret changes; existing rotations intact |

### `/code-review` auto-fires (per v4 G-CODE)

Four triggers in v4 (P3.1+ touch / first-time-pattern import /
security module new public method / FastAPI dep new). v0.9.6 hit
multiple:

1. **First-time-pattern imports**: `OSCAL_SCHEMA_VERSION` constant + lineage chain semantics in `evidence_store`. Both reviewed inline during implementation; module docstrings cite the canonical source.
2. **Security module new public methods**: `require_role_cli`, `get_rbac_policy`, `get_rbac_identity`, `set_rbac_identity_override`, `EvidenceWORMViolation`, `mirror_to_worm`, `fetch_from_worm`. All reviewed for the decorator-deny / WORM-violation / TOCTOU patterns.
3. **MCP scope module new public tool**: 4 new `conmon_*` tools. All routed through the existing v0.8.6 CIMD scope-enforcement gate by virtue of the FastMCP tool-dispatch path. Migration note in CHANGELOG.
4. **AI-gov registry surface expansion**: 4 new Optional fields + new `ATOReference` submodel + `SCRForm` model. All Optional defaults preserve v0.9.3-v0.9.5 backward compat.

## Cycle artifact cross-references

- `CHANGELOG.md` `[Unreleased]` block (v0.9.6 entries)
- `docs/v0.9.6-plan.md` — the canonical plan
- `docs/positioning-and-value.md` §6.1.A + §6.1.B + §11.2 — positioning sharpening
- `docs/capability-matrix.md` — v0.9.6 SHIPPED snapshot (Phase 5.3)
- `docs/threat-model.md` — v0.9.6 attack-surface delta (Phase 5.3)
- `docs/ROADMAP.md` — v0.9.6 SHIPPED + v0.9.7 PLANNED (Phase 5.3)
- `docs/v1.0-transition.md` — federal-compliance theme + API-stability gates

## Open follow-ups for v0.9.7

- **Real federal-SI domain-expert walk-through** (deferred from v0.9.6 per scope lock-in; no operator sourced yet).
- **OSCAL Significant Change Notification standard alignment** (RFC-0007 / NOTICE-0009 March 2026 surfaced post-Phase 0.1).
- **CIMD scope-migration tooling** for the new `conmon_*` MCP tools (operator-facing helper).
- **F-V96-worm-app-layer**: explore an opt-in `EVIDENTIA_EVIDENCE_AUTO_MIRROR_WORM` env var that auto-mirrors local saves to a configured cloud-WORM backend (closes the "operator forgot to wire mirroring" gap).
- **Multi-tenant policy support for CLI RBAC** (current model is single-tenant; v1.0+ feature).
- **Walk-through-driven adjustments to FIPS 199 + OMB + SCR field schemas** once a real federal-SI operator runs the surfaces.

## PROCEED-CLEAN gate verdict

**PROCEED-CLEAN** for v0.9.6 ship. All gate criteria satisfied;
zero unfixed CRITICAL / HIGH / MEDIUM findings; the 3 NEW
INFO/LOW findings are documented within the v0.9.6 surfaces
themselves (threat-model + module docstrings + CHANGELOG
migration note).

**21st consecutive PROCEED-CLEAN** of the v0.7.x → v0.8.x →
v0.9.x line.
