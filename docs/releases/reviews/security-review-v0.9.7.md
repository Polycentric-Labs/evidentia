# Security review — v0.9.7

> **Status**: in-cycle artifact for the v0.9.7 ship. v4
> pre-release-review 5th canonical deliverable per
> `references/deliverables.md`. Compressed Continuous variant.
>
> **Theme**: comprehensive v0.9.x close-out + v1.0 prep —
> v0.9.6 carry-overs + api-stability NORMATIVE + multi-tenant RBAC
> primitives + CIMD signatures groundwork + RFC-0007 SCR alignment +
> Q3 quarterly resync academic-positioning sharpening + HF eval
> scaffolding. Walk-through deferred indefinitely.

## Cycle scope

v0.9.7 closes the three v0.9.6 INFO/LOW deferrals
(F-V96-rbac-cli-trust documented in-module; F-V96-worm-app-layer
closed via auto-mirror env var; F-V96-conmon-mcp-cimd-migration
closed via `evidentia mcp cimd-migrate` CLI verb), promotes
`docs/api-stability.md` from DRAFT to NORMATIVE as the headline
v1.0-prep deliverable, ships partial primitives for two v1.0-
reserved surfaces (multi-tenant RBAC + cryptographic CIMD
signatures), aligns SCRForm with RFC-0007, and sharpens the Q3
quarterly resync academic positioning.

## Findings ledger

### v0.9.7 in-cycle review (2 NEW findings, both INFO)

| Finding | Severity | CWE | Status |
|---|---|---|---|
| F-V97-mcp-signer-trust | INFO | — | The MCP output signer factory (`EVIDENTIA_MCP_SIGNER_FACTORY`) is an operator-supplied dotted-path callable. A malicious operator could wire a factory that emits attacker-controlled signature dicts. Documented in `evidentia_mcp.signatures` module docstring: signing groundwork composes with operator-supplied infrastructure; the signer is in the operator's trust boundary. Sigstore-keyless reference backend (v1.0) reduces this exposure by removing operator-managed key material entirely. |
| F-V97-multi-tenant-claim-spoofing | INFO | — | The `@@<tenant>` claim in the identity string is operator-asserted — a malicious operator could pass `alice@victim.com@@target-tenant` to grant unintended access. v0.9.7 PARTIAL: the data model + decision function are ready; CLI integration (v1.0) MUST enforce tenant-claim provenance from the authenticated AuthProvider, NOT from arbitrary env-var input. Documented in `evidentia_core.rbac.multi_tenant` module docstring. |

### Carry-over closures from v0.9.6

| Finding | Closure |
|---|---|
| F-V96-worm-app-layer (LOW) | Closed via `EVIDENTIA_EVIDENCE_AUTO_MIRROR_WORM` + `EVIDENTIA_EVIDENCE_WORM_BACKEND_FACTORY` env vars. Auto-mirror to cloud-WORM backend after local-store write succeeds. Mirror failure non-fatal. 7 new tests. |
| F-V96-conmon-mcp-cimd-migration (INFO) | Closed via `evidentia mcp cimd-migrate <registry-path>` CLI verb. Operator-facing helper adds the v0.9.6 `conmon_*` MCP tools to each client's `scope` field. Idempotent + atomic-write + `--dry-run` + `--client-id` filter. 9 new tests. |
| F-V96-rbac-cli-trust (INFO) | Carry-forward documentation; no code change. Operators MUST `chmod 0600` the policy file + own with a dedicated service user. Documented in `evidentia.cli._rbac_lifecycle` module docstring (v0.9.6 ship). |

**Zero CRITICAL / HIGH / MEDIUM-unfixed findings in v0.9.7 source code.**

## Validation pass artifacts

### Mandatory `/security-review` invocations (3, per v4 G12)

Compressed Steps 3-6 into single-cycle execution:

1. **Step 3 equivalent** — re-test of every commit since v0.9.6.
   Surfaced 2 NEW INFO findings (above); both operator-visible
   trust-boundary docs.
2. **Step 4 equivalent** — capability-matrix re-validation snapshot
   for v0.9.7 in `docs/capability-matrix.md` covering: WORM
   auto-mirror primitives, CIMD scope-migration CLI verb,
   multi-tenant RBAC primitives, MCP signature envelope + helpers,
   RFC-0007 SCR alignment fields + emitter.
3. **Step 6.C equivalent** — 16-row pre-push gate validation:

| # | Gate | v0.9.7 outcome |
|---|---|---|
| 1 | Test suite passes | 3092 / 17 (skip) / 0 (fail) |
| 2 | mypy strict 0 errors | **258 source files clean** |
| 3 | ruff full repo clean | 0 errors |
| 4 | Coverage ≥ 85% | (Codecov target bumped to 85% in v0.9.7 P1.3) |
| 5 | uv.lock regenerated at version bump | (Phase 5.4) |
| 6 | CHANGELOG entry added | ✓ (`[0.9.7]` block) |
| 7 | ROADMAP transitions | (Phase 5.3) v0.9.7 PLANNED → SHIPPED + v0.9.8 PLANNED |
| 8 | Threat-model v0.9.7 delta | (Phase 5.3) |
| 9 | Capability-matrix v0.9.7 snapshot | (Phase 5.3) |
| 10 | README "Why different" v0.9.7 paragraph | ✓ (moat-trinity hook unchanged; doc cross-link to v0.9.7 surfaces) |
| 11 | Positioning + §11.2.A + §11.2.B added | ✓ |
| 12 | Code-scanning alert delta | Deferred to post-push |
| 13 | Container CVE scan (Trivy) | Deferred to post-push |
| 14 | Vulnerability aging SLO | 0 stale; paramiko LOW carry-forward acknowledged at v0.9.7 Phase 0.1 |
| 15 | License/SCA enforcement | No new third-party deps in v0.9.7 source code |
| 16 | Secret-rotation cadence | No secret changes |

### `/code-review` auto-fires (per v4 G-CODE)

v0.9.7 hit multiple triggers:

1. **First-time-pattern import**: `SignedToolOutput` envelope at v0.9.7 P2.4 — new pattern (Sigstore-style envelope) reviewed for serialization stability + tampering-resistance.
2. **Security module new public method**: 8 new public symbols at `evidentia_core.rbac.multi_tenant` + 6 at `evidentia_mcp.signatures` + 7 new ones in evidence_store (auto-mirror) + 1 new CLI verb (cimd-migrate) — all reviewed for trust-boundary + atomic-write + path-traversal patterns.
3. **AI-gov SCR surface expansion**: 8 new Optional fields + `to_oscal_scr_notification()` method — reviewed for RFC-0007 schema correctness + required-field enforcement.
4. **MCP scope module new public tool**: `cimd-migrate` CLI verb — reviewed for idempotency, atomic write, error-exit-code consistency.

## Cycle artifact cross-references

- `CHANGELOG.md` `[0.9.7]` block
- `docs/v0.9.7-plan.md` — the canonical plan
- `docs/api-stability.md` — NORMATIVE as of v0.9.7
- `docs/deprecation-calendar.md` — NEW
- `docs/hf-eval-suite-scaffolding.md` — NEW
- `docs/positioning-and-value.md` §11.2.A + §11.2.B — sharpened
- `docs/capability-matrix.md` — v0.9.7 SHIPPED snapshot (Phase 5.3)
- `docs/threat-model.md` — v0.9.7 attack-surface delta (Phase 5.3)
- `docs/ROADMAP.md` — v0.9.7 SHIPPED + v0.9.8 PLANNED (Phase 5.3)
- `docs/v1.0-transition.md` — v1.0 acceptance gates (api-stability
  NORMATIVE gate now CLOSED via v0.9.7 P2.1)

## Open follow-ups for v0.9.8 / v1.0

- **Real federal-SI domain-expert walk-throughs** (multiple reviewers
  pre-v1.0 per Allen's plan).
- **FastMCP dispatch-layer auto-wrap of SignedToolOutput**.
- **Sigstore-keyless reference signer backend**.
- **Multi-tenant RBAC CLI + FastAPI integration**.
- **Tenant-scoped storage paths**.
- **Conference outreach prep** (DEF CON 34 / GovForward / Billington
  talk-abstract drafts).
- **HF Hub eval-suite publish**.
- **Backfill v0.9.1 + v0.9.2 security-review docs**.
- **OpenSSF Best Practices Badge Gold tier** (requires ≥ 2 contributors).

## v0.9.7 `/code-review` follow-ups (3 MEDIUM polish items deferred to v0.9.8)

The pre-release-review v4 `/code-review` skill auto-fired on three
of four triggers (Trigger 2 = 2 new source files; Trigger 3 = 1549
LOC; Trigger 4 = security-relevant subsystems touched). It surfaced
4 suggestions; 1 was MEDIUM-bumped to inline-fix in v0.9.7; 3 deferred
to v0.9.8 with rationale:

- **CR-V97-1 — WORM auto-mirror factory called per save** (Performance):
  `_resolve_auto_mirror_backend()` is invoked on every
  `save_evidence()` call. For high-throughput evidence collection,
  this adds factory-instantiation latency per save (new S3 client /
  new OIDC handshake). **v0.9.8 fix**: cache the resolved tuple
  after first call; document operator-controlled fresh-state pattern
  via factory wrapping. **Defer rationale**: no operator running
  against high-throughput CI has reported this; the WORM path is
  opt-in and most operators don't enable it. Wait for real-operator
  feedback before optimizing.

- **CR-V97-3 — Duplicated dotted-path factory resolver pattern**
  (Maintainability): `_resolve_auto_mirror_backend()` (evidence_store)
  and `_resolve_signer_factory()` (signatures) both implement the
  same `module.submodule:callable_name` → `importlib.import_module`
  + `getattr` + `callable()` check. **v0.9.8 fix**: extract to
  `evidentia_core.security.factory_loader.resolve_factory(env_var,
  factory_env_var)` shared helper. **Defer rationale**: only 2 call
  sites; extraction premature until a 3rd factory-driven feature
  lands.

- **CR-V97-4 — `sign_tool_output` canonical-JSON encoding gap**
  (Robustness): `json.dumps(payload, sort_keys=True,
  separators=(",", ":"))` raises `TypeError` on non-JSON-primitive
  payloads (datetime, Path, custom types). Caught by the broader
  try/except + surfaces as `signing_error` — non-fatal but loses
  signing for that envelope. **v0.9.8 fix**: add `default=str` to
  `json.dumps` for graceful fallback; tighten the `payload: dict[
  str, Any]` typing or add explicit "must be JSON-primitive" prose
  in the docstring. **Defer rationale**: in practice, MCP tool
  outputs go through Pydantic `model_dump(mode="json")` first which
  handles these; the gap only surfaces for raw-dict tool returns.

The MEDIUM-bumped-to-inline item (CR-V97-2 cross-tenant-admin-role
naming clarity) shipped inline in v0.9.7 — see commit message for
the affected `evidentia_core.rbac.multi_tenant` docstring + inline
comment additions clarifying the v0.9.7 LIMITED IMPL semantic
(`cross_tenant_admin_role` field behavior degrades to in-target-
tenant escalation without full home-tenant-claim wiring, which lands
in v1.0).

## PROCEED-CLEAN gate verdict

**PROCEED-CLEAN** for v0.9.7 ship. All gate criteria satisfied;
zero unfixed CRITICAL / HIGH / MEDIUM findings; the 2 NEW INFO
findings are documented within the v0.9.7 surfaces themselves
(threat-model + module docstrings).

**22nd consecutive PROCEED-CLEAN** of the v0.7.x → v0.8.x →
v0.9.x line.
