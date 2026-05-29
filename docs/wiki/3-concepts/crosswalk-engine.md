# Crosswalk engine

A *crosswalk* maps controls in one framework to related controls in another — for example, which NIST SP 800-53 controls a given ISO 27001 control corresponds to. Crosswalks power Evidentia's cross-framework efficiency analysis: implement one control, and the gap analyzer can tell you which requirements it also satisfies in every other framework you care about. This page explains the crosswalk schema (including the v0.10.6 provenance fields), how the bidirectional mapping graph is built, and how the OSPS Baseline crosswalks are regenerated reproducibly.

The code lives in `packages/evidentia-core/src/evidentia_core/catalogs/crosswalk.py`; the data lives in `catalogs/data/mappings/`.

## What ships

Evidentia bundles **13 crosswalks** (864 control-to-control mapping rows in total), one JSON file per source→target framework pair in `catalogs/data/mappings/`. They span regulatory, federal, and supply-chain pairings — for example `iso-27001-2022_to_nist-800-53-mod.json`, `nist-csf-2.0_to_nist-800-53-mod.json`, `nist-ai-rmf-1.0_to_eu-ai-act.json`, and the five OpenSSF OSPS Baseline crosswalks (`osps-baseline_to_{eu-cra,nist-800-161,nist-csf-2.0,nist-ssdf-800-218,pci-dss-4.0}.json`). The authoritative, always-current inventory — with per-crosswalk row counts and verification posture — is the auto-generated [crosswalks reference page](../4-reference/crosswalks.md).

## The CrosswalkDefinition schema

> **A note on where this lives.** Both crosswalk *models* are defined in `evidentia_core/models/catalog.py`: `CrosswalkDefinition` (the full multi-mapping crosswalk document) and its per-row `FrameworkMapping`. There is no `models/crosswalk.py`. The crosswalk *engine* (`CrosswalkEngine`, described below) lives in a separate file — `evidentia_core/catalogs/crosswalk.py` — which is easy to confuse with the models; the schema is in `catalog.py`, the loading/indexing logic is in `catalogs/crosswalk.py`.

`CrosswalkDefinition` (an `EvidentiaModel`, so `extra="forbid"`) is the on-disk shape of a crosswalk file:

| Field | Type | Notes |
|---|---|---|
| `source_framework` | `str` | The "from" framework ID. |
| `target_framework` | `str` | The "to" framework ID. |
| `version` | `str` | Crosswalk version label. |
| `generated_at` | `str` | When this crosswalk was produced. |
| `source` | `str` | Authority source for the crosswalk. |
| `mappings` | `list[FrameworkMapping]` | The control-to-control rows. |
| `v0_9_3_note` | `str \| None` | Optional cycle-note documenting authoring scope. |
| `confidence_rubric` | `dict[str, str] \| None` | Optional explanation of the `confidence` vocabulary. |
| `provenance` | `str \| None` | **v0.10.6, additive.** |
| `verification` | `Literal["self-attested-via-upstream", "hand-checked"] \| None` | **v0.10.6, additive.** |
| `verification_note` | `str \| None` | **v0.10.6, additive.** |

It also exposes `get_target_controls(source_control_id)` and `get_source_controls(target_control_id)` for direct lookups (both case-insensitive and whitespace-tolerant).

Each row is a `FrameworkMapping`: `source_control_id`, `source_control_title`, `target_control_id`, `target_control_title`, `relationship: str` (the `RelationshipType` vocabulary — `equivalent` / `related` / `partial` / `superset` / `subset` / `intersects`, kept as a plain `str` for v0.1.x JSON compatibility), `notes`, and an optional `confidence` (`high` / `medium` / `low`, v0.9.3).

### The v0.10.6 provenance fields — why they exist

Some crosswalks are hand-authored concordances; others are auto-extracted verbatim from an upstream source that publishes its own mappings. Those have very different trust properties, and v0.10.6 added three optional fields so a consumer can tell them apart (verified in `catalog.py`):

- **`provenance: str | None`** — a tag for the extraction source, e.g. `"upstream-osps-guidelines"`. `None` for crosswalks predating v0.10.6.
- **`verification: Literal["self-attested-via-upstream", "hand-checked"] | None`** — the verification posture. `"self-attested-via-upstream"` means the mappings were auto-extracted from an upstream `guidelines[]` array and are **not** independently audit-verified. `"hand-checked"` means SME-reviewed.
- **`verification_note: str | None`** — free-form prose explaining the posture's scope and the path to upgrading `self-attested-via-upstream` → `hand-checked` if a consumer needs independent verification.

All three default to `None`, so the eight pre-existing in-tree crosswalks load unchanged — this is an additive, non-breaking schema evolution per the [frozen-surface contract](frozen-surfaces-and-stability.md). The five OSPS Baseline crosswalks carry `provenance="upstream-osps-guidelines"` and `verification="self-attested-via-upstream"`: a deliberate honesty signal that those 674 OSPS mapping rows are auto-extracted, not hand-verified. **Always verify a mapping before relying on it for an audit** — the verification column tells you which crosswalks especially warrant that check.

## Loading and the bidirectional mapping graph

`CrosswalkEngine` (`crosswalk.py`) loads every `*.json` file under the mappings directory and builds an in-memory mapping graph for fast lookups during gap analysis. `load_all()` globs and sorts the directory; `load_crosswalk(path)` reads one file with `json.load`, validates it into a `CrosswalkDefinition`, and indexes every mapping.

> **Implementation note.** The crosswalk loader reads JSON directly via `json.load`, which is a distinct code path from the catalog engine's `_load_catalog_data` extension-dispatch helper. Crosswalk files are JSON-only today; the catalog YAML support does not extend to the mappings directory.

The indexing is the heart of it. For each mapping the engine populates two indexes keyed on `(framework, control_id_upper, framework)` tuples:

- a **forward** index `(source_fw, source_ctl, target_fw) → [FrameworkMapping]`, and
- a **reverse** index, built by synthesizing a swapped `FrameworkMapping` (target becomes source, source becomes target, relationship and notes preserved) so that a crosswalk authored A→B is automatically queryable B→A.

That symmetry is why `get_mapped_controls(source_fw, control_id, target_fw)` checks both indexes and de-duplicates by `target_control_id`. The higher-level helpers build on it:

- `get_all_mapped_controls(framework, control_id)` returns a dict keyed by every target framework that the control maps to or from.
- `get_cross_framework_value(framework, control_id)` flattens that into a list of `"framework:control_id"` strings — exactly the data the gap analyzer uses to prioritize: a control that satisfies more frameworks is higher-value to implement.
- `available_frameworks` is the set of all framework IDs appearing in any loaded crosswalk.

The engine is wired into the system through `FrameworkRegistry.crosswalk` (lazy-loaded on first access), so most callers reach it through the registry rather than constructing it directly.

## Reproducible OSPS crosswalk generation

The five OSPS Baseline crosswalks are not hand-maintained — they are a reproducible build output. `scripts/catalogs/gen_osps_crosswalks.py` regenerates all five JSONs **byte-for-byte** from the OpenSSF OSPS Baseline `baseline/OSPS-*.yaml` family files at a pinned upstream commit (the SHA lives in the co-located `_osps_upstream.py` constant module, alongside the JSON artifacts it pins).

The script's value is eliminating manual sweeps: previously the pinned SHA and per-mapping `notes` strings had to be hand-edited across all five files (10-15 occurrences of the SHA alone) on every upstream OSPS bump. Now a bump is: (1) update `OSPS_BASELINE_COMMIT_SHA` in `_osps_upstream.py`, (2) run the regenerator, (3) review the diff and commit.

Modes:

- `gen_osps_crosswalks.py` — regenerate all five JSONs in place.
- `gen_osps_crosswalks.py --check` — exit 0 if the regenerated bytes match the committed JSONs exactly; exit 1 with a per-file first-divergence diff summary on drift. This is the CI / pre-tag drift gate.
- `--output-dir DIR` — write elsewhere for inspection; `--no-fetch` — rely solely on the gitignored `.local/` upstream cache.

Upstream YAML is fetched via the `gh` CLI (argument list, no shell — the only interpolated values are the pinned SHA and a fixed family-letter allowlist) and cached under `.local/`. The extraction is pure and unit-tested: `extract_entries_by_standard` walks family → control → guideline-block → entry in a fixed order; `build_crosswalk` assembles the payload with a stable field order; `serialize` emits `indent=2`, `ensure_ascii=False`, single trailing newline. The script never pushes, tags, or publishes — it only fetches upstream and writes the in-tree JSON artifacts.

This is why the five OSPS crosswalks honestly carry `verification="self-attested-via-upstream"`: their rows come straight from upstream's `guidelines[]` array, transformed losslessly, with zero manual massaging — which is reproducible and traceable, but not the same as independent SME verification.

## Related reading

- [Architecture](architecture.md) — where crosswalks sit in the cross-framework gap-analysis flow.
- [Catalog engine](catalog-engine.md) — the companion engine for *within*-framework control catalogs.
- [Data model](data-model.md) — the `ControlMapping` model (distinct from `FrameworkMapping`: the former lives on a finding, the latter on a crosswalk).
- [`4-reference/crosswalks.md`](../4-reference/crosswalks.md) — the auto-generated, always-current crosswalk inventory with row counts + verification posture.
- [`5-compliance/osps-baseline-mapping.md`](../5-compliance/osps-baseline-mapping.md) — the OSPS Baseline mapping detail.
