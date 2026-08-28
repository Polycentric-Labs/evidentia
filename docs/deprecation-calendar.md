# Deprecation calendar

> **Status**: NORMATIVE (v0.9.7+).
>
> **Scope**: enumerates every active deprecation on Evidentia's
> public surface (CLI flags, env vars, library entry points, REST
> URIs, model fields, EventAction values, plugin contract methods,
> MCP tool names). Operators MAY rely on a deprecated surface
> continuing to work until the target removal release.
>
> **Canonical location**: `docs/deprecation-calendar.md`.
> **Cross-references**: [api-stability.md](api-stability.md)
> (deprecation policy section), [CHANGELOG.md](../CHANGELOG.md)
> per-release Deprecated / Removed blocks.

---

## Active deprecations

| Surface | Replacement | Deprecated since | Target removal | Notes |
|---|---|---|---|---|
| `evidentia conmon check --last-completed-file` (CLI flag) | `--state-file` | v0.9.6 (2026-05-18) | **v1.0.0** | Normalized to match `conmon watch`, `conmon health`, `conmon mark-completed`. DeprecationWarning emitted when used; specifying both flags exits with code 2. |
| `evidentia_core.models.finding.SecurityFinding` (library class name) | `evidentia_core.models.finding.Finding` (same class, new canonical name) | v0.10.1 (2026-05-23) | **v1.0.0** (earliest major bump) | The `SecurityFinding` name is kept as a backward-compatible alias for ≥ 1 minor cycle per the deprecation policy. Both names refer to the same class — no runtime difference, no behavior change, `isinstance(obj, SecurityFinding)` and `isinstance(obj, Finding)` both succeed. The rename aligns with OCSF's "Finding" terminology (Compliance Finding, Detection Finding). No `DeprecationWarning` is emitted in v0.10.1 to avoid spamming the ~50+ existing call sites — the alias is silent. Operators / integrators are encouraged to switch to `Finding` in new code; existing code keeps working unchanged. |
| `evidentia ai-gov set-omb-impact` (CLI) + `OMBImpactRequest` / `POST /api/ai-gov/systems/{system_id}/set-omb-impact` (API) — OMB **M-24-10** impact leveling | `evidentia ai-gov set-high-impact` + `HighImpactRequest` / `POST /api/ai-gov/systems/{system_id}/set-high-impact` — OMB **M-25-21** high-impact determination | v0.10.12 (2026-06-23) | **v1.0.0** | OMB M-24-10 was rescinded 2025-04-03 and superseded by M-25-21. The legacy M-24-10 surface is retained as a backward-compatible alias per the deprecation policy; new code should record the M-25-21 high-impact determination instead. **v0.12.0 made the announcement machine-readable** (step 4 of § How removals are sequenced, previously satisfied only in prose): the CLI verb emits a `DeprecationWarning`, and the REST operation is flagged `deprecated: true` in OpenAPI (so generated SDKs mark it too) and answers with the RFC 8594 `Deprecation: true` header plus a `Link: …; rel="successor-version"` pointing at `set-high-impact`. No `Sunset` header is sent: the commitment is to a removal *release*, not a date, and a fabricated timestamp would be a false machine-readable promise. |

| Framework id `occ-sr-26-02` (catalog id) | `occ-sr-26-2` | v0.13.0 (in development, 2026-08-28) | **v1.0.0** | V13-15 designator correction: the FRB letter is SR 26-2 (no leading zero, matching the SR 11-7 style) and the OCC bulletin is 2026-13 (no "a" suffix). The old id resolves through a loader alias (`evidentia_core.catalogs.loader`) with a `DeprecationWarning`; a regression test exercises the alias per process rule 5. |
| ConMon state key `occ-2026-13a-model-risk` (cadence slug in operator `--state-file` YAML) | `occ-2026-13-model-risk` | v0.13.0 (in development, 2026-08-28) | **v1.0.0** | Same designator correction, applied to the bundled cadence slug. Both state-file readers (the daemon's `load_state_file` and the CLI loader) migrate the old key to the new one on read with a `DeprecationWarning`; when both keys are present the new key's value wins so a half-migrated file cannot regress a newer completion date. Writes (`conmon mark-completed`) accept the new slug only. |

No other surfaces are currently deprecated as of the v0.13 cycle (current release v0.12.0).

---

## Recently removed (history)

Removals stay listed here for ≥ 2 minor releases past the removal
so operators searching their CHANGELOG can find the trail.

| Surface | Replacement | Deprecated since | Removed in | Notes |
|---|---|---|---|---|
| `evidentia_ai.eval` + its 7 submodules (`claim_extraction`, `faithfulness`, `faithfulness_semantic`, `harness`, `metrics`, `seeds`, `signing`) — library import path | `evidentia_eval` (same symbols, same signatures) | v0.10.5 (2026-05-25) | **v0.12.0** | The v0.10.5 P9 extraction moved the DFAH determinism + faithfulness harness to the dedicated `evidentia-eval` workspace package so air-gap installs of the production risk-statement runtime stopped pulling the dev-time eval stack. The old paths were retained as re-export shims emitting a `DeprecationWarning` at import time, with removal announced for v0.12.0 in the shim docstring, [api-stability.md](api-stability.md) §5, and the `evidentia-ai` dependency comment. v0.12.0 executes it: the shim package is deleted and the unconditional `evidentia-eval` base dependency on `evidentia-ai` goes with it. **Migration**: replace `from evidentia_ai.eval import X` with `from evidentia_eval import X`. The `evidentia-ai[eval-faithfulness]` **install extra is NOT removed** — it is a packaging alias, not an import path, and still proxies to `evidentia-eval[faithfulness-semantic]`. Note this row is backfilled: the deprecation predates this calendar's first revision (v0.9.7) in announcement but was never carried in the Active table, so the earlier "no surfaces removed yet" statement described the table, not the project's full deprecation history. |

---

## How removals are sequenced

Per the [api-stability.md](api-stability.md) deprecation policy:

1. **Announce** in release N: add `DeprecationWarning` (Python),
   `Deprecation: true` header (REST), CHANGELOG entry under
   "Deprecated". Add a row to this calendar.
2. **Maintain** through release N+1: surface continues to work
   unchanged. Warning continues to emit.
3. **Remove** in release N+2 (≥ major-bump release): drop the
   surface; CHANGELOG entry under "Removed"; move calendar row
   to "Recently removed" history.

The minimum window between announce and remove is **1 full minor
release cycle** (release N → N+1 → N+2). Practical removal
windows are typically longer to give operators time to migrate.

---

## Process for proposing a new deprecation

1. Open a PR adding the surface to the "Active deprecations"
   table above with the proposed target removal release.
2. Update [api-stability.md](api-stability.md) if the surface is
   declared frozen there.
3. Add the deprecation announcement in the implementing release's
   CHANGELOG under "Deprecated".
4. Wire the `DeprecationWarning` (Python) or `Deprecation: true`
   header (REST) in code.
5. Add a regression test that EXERCISES the deprecated surface
   AND asserts the warning fires (preserves the deprecation path's
   testability through the maintenance window).

---

## Why this calendar exists

Operators integrating Evidentia in production GRC pipelines need
predictability about when they MUST migrate code paths. Listing
every active deprecation in one canonical place — with target
removal release and replacement — closes one of the open v1.0
acceptance gates per `docs/v1.0-transition.md` ("Deprecation
calendar published for any v0.9.x → v1.0 changes").

The calendar is binding under the v0.9.7 NORMATIVE api-stability
contract: Evidentia will not remove a surface listed here earlier
than its declared target removal release. Pushing a removal later
(extending the maintenance window) is non-breaking and may happen
when operator feedback surfaces.
