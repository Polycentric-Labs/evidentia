# Crosswalk engine

A *crosswalk* maps controls in one framework to related controls in another: which NIST SP 800-53 controls a given ISO 27001 control corresponds to, for example. Crosswalks power Evidentia's cross-framework efficiency analysis: implement one control, and the gap analyzer can tell you which requirements it also satisfies in every other framework you care about. This page explains the crosswalk schema (including the provenance fields), how the bidirectional mapping graph is built, how framework families let a baseline inherit its parent's crosswalks, how resolution is measured, and how the generated crosswalks are reproduced.

The code lives in `packages/evidentia-core/src/evidentia_core/catalogs/crosswalk.py`; the data lives in `catalogs/data/mappings/`.

## What ships

Evidentia bundles **16 crosswalks**, one JSON file per source and target framework pair in `catalogs/data/mappings/`. They span regulatory, federal, AI-governance and supply-chain pairings, for example `iso-27001-2022_to_nist-800-53-rev5.json`, `nist-csf-2.0_to_nist-800-53-rev5.json`, `nist-ai-rmf-1.0_to_eu-ai-act.json`, `fedramp-ksi-2026_to_nist-800-53-rev5.json`, and the five OpenSSF OSPS Baseline crosswalks (`osps-baseline_to_{eu-cra,nist-800-161,nist-csf-2.0,nist-ssdf-800-218,pci-dss-4.0}.json`). The authoritative, always-current inventory, with per-crosswalk row counts, verification posture and identifier resolution, is the auto-generated [crosswalks reference page](../4-reference/crosswalks.md).

## The CrosswalkDefinition schema

> **A note on where this lives.** Both crosswalk *models* are defined in `evidentia_core/models/catalog.py`: `CrosswalkDefinition` (the full multi-mapping crosswalk document) and its per-row `FrameworkMapping`. There is no `models/crosswalk.py`. The crosswalk *engine* (`CrosswalkEngine`, described below) lives in a separate file, `evidentia_core/catalogs/crosswalk.py`, which is easy to confuse with the models; the schema is in `catalog.py`, the loading and indexing logic is in `catalogs/crosswalk.py`.

`CrosswalkDefinition` (an `EvidentiaModel`, so `extra="forbid"`) is the on-disk shape of a crosswalk file:

| Field | Type | Notes |
|---|---|---|
| `source_framework` | `str` | The "from" framework id: a bundled catalog id or a crosswalk family id (see below). |
| `target_framework` | `str` | The "to" framework id: a bundled catalog id, a family id, or one of the three external targets the truth gate allows (`eu-cra`, `nist-800-161`, `pci-dss-4.0`). |
| `version` | `str` | Crosswalk version label. |
| `generated_at` | `str` | When this crosswalk was produced. |
| `source` | `str` | Authority source for the crosswalk. |
| `mappings` | `list[FrameworkMapping]` | The control-to-control rows. |
| `v0_9_3_note` | `str \| None` | Optional cycle-note documenting authoring scope. |
| `confidence_rubric` | `dict[str, str] \| None` | Optional explanation of the `confidence` vocabulary. |
| `provenance` | `str \| None` | **v0.10.6, additive.** |
| `verification` | `Literal["self-attested-via-upstream", "self-attested", "hand-checked"] \| None` | **v0.10.6, additive**; `self-attested` added in v0.10.10. |
| `verification_note` | `str \| None` | **v0.10.6, additive.** |
| `risk_model_note` | `str \| None` | **v0.10.10, additive.** How the two frameworks characterize risk differently. |

It also exposes `get_target_controls(source_control_id)` and `get_source_controls(target_control_id)` for direct lookups (both case-insensitive and whitespace-tolerant).

Each row is a `FrameworkMapping`: `source_control_id`, `source_control_title`, `target_control_id`, `target_control_title`, `relationship: str` (the `RelationshipType` vocabulary: `equivalent` / `related` / `partial` / `superset` / `subset` / `intersects`, kept as a plain `str` for v0.1.x JSON compatibility), `notes`, and an optional `confidence` (`high` / `medium` / `low`, v0.9.3).

### The provenance fields and why they exist

Some crosswalks are hand-authored concordances; others are auto-extracted verbatim from an upstream source that publishes its own mappings. Those have very different trust properties, and v0.10.6 added three optional fields so a consumer can tell them apart (verified in `catalog.py`):

- **`provenance: str | None`**: a tag for the extraction source, for example `"upstream-osps-guidelines"`. `None` for hand-authored concordances.
- **`verification`**: the verification posture. `"self-attested-via-upstream"` means the mappings were auto-extracted from an upstream cross-reference list and are **not** independently audit-verified. `"self-attested"` means Evidentia authored the rows from public control numbering and titles without the licensed text (the FDA Section 524B crosswalks and the NIST AI RMF to ISO/IEC 42001 concordance). `"hand-checked"` means SME-reviewed; no bundled crosswalk carries it yet.
- **`verification_note: str | None`**: free-form prose explaining the posture's scope and the path to upgrading it if a consumer needs independent verification.

All three default to `None`, so older crosswalks load unchanged; this is an additive, non-breaking schema evolution per the [frozen-surface contract](frozen-surfaces-and-stability.md). **Always verify a mapping before relying on it for an audit**; the verification column of the reference page tells you which crosswalks especially warrant that check.

## Loading and the bidirectional mapping graph

`CrosswalkEngine` (`crosswalk.py`) loads every `*.json` file under the mappings directory and builds an in-memory mapping graph for fast lookups during gap analysis. `load_all()` globs and sorts the directory; `load_crosswalk(path)` reads one file with `json.load`, validates it into a `CrosswalkDefinition`, and indexes every mapping.

> **Implementation note.** The crosswalk loader reads JSON directly via `json.load`, which is a distinct code path from the catalog engine's `_load_catalog_data` extension-dispatch helper. Crosswalk files are JSON-only today; the catalog YAML support does not extend to the mappings directory.

The indexing is the heart of it. For each mapping the engine populates two indexes keyed on `(framework, control_id_upper, framework)` tuples:

- a **forward** index `(source_fw, source_ctl, target_fw) -> [FrameworkMapping]`, and
- a **reverse** index, built by synthesizing a swapped `FrameworkMapping` (target becomes source, source becomes target, relationship and notes preserved) so that a crosswalk authored A to B is automatically queryable B to A.

That symmetry is why `get_mapped_controls(source_fw, control_id, target_fw)` checks both indexes and de-duplicates by `target_control_id`. The higher-level helpers build on it:

- `get_all_mapped_controls(framework, control_id)` returns a dict keyed by every target framework that the control maps to or from.
- `get_cross_framework_value(framework, control_id)` flattens that into a list of `"framework:control_id"` strings, exactly the data the gap analyzer uses to prioritize: a control that satisfies more frameworks is higher-value to implement.
- `available_frameworks` is the set of all framework ids declared by any loaded crosswalk.

The engine is wired into the system through `FrameworkRegistry.crosswalk` (lazy-loaded on first access), so most callers reach it through the registry rather than constructing it directly.

### Framework families

Several bundled catalogs are views of a larger one. The NIST SP 800-53 Rev 5 Low, Moderate, High and Privacy baselines and the FedRAMP Rev 5 Low, Moderate, High and LI-SaaS baselines all draw their controls from the full `nist-800-53-rev5` catalog (as does the legacy 16-control `nist-800-53-mod` sample), and the three OSPS Baseline maturity levels draw their assessment requirements from one baseline. The manifest records this in the `crosswalk_family` column of `frameworks.yaml`, written from a table in `scripts/catalogs/regenerate_manifest.py`.

`FrameworkRegistry` passes that mapping to the engine (`CrosswalkEngine(families=...)`), and `lookup_keys(framework_id)` returns the catalog's own id followed by its family id. Every lookup consults all keys on both the source and the target side, so a gap found against `fedramp-rev5-moderate` receives the value of every crosswalk keyed on `nist-800-53-rev5`, and `catalog crosswalk --source nist-csf-2.0 --target nist-800-53-rev5-moderate --control GV.OC-01` answers `AC-1` exactly as the full catalog does. Inheritance runs one way: a crosswalk keyed on a member (`fedramp-rev5-moderate_to_cmmc-2-l2.json`) stays specific to that member and is not shared with its siblings or its family. Through v0.12 there were no families, so every gap in the README quickstart (`nist-800-53-rev5-moderate`) carried zero cross-framework value.

## Measuring resolution

Identifier resolution measures which rows can be checked against the bundled catalogs; external targets require a separate reference. `resolve_crosswalk(crosswalk, source_ids=..., target_ids=...)` (pure, in `crosswalk.py`) counts the rows whose normalized source and target ids appear in the reference id sets and returns a `CrosswalkResolution` with the counts, the unresolved ids and a ratio per side (`None` when a side has no bundled catalog). `FrameworkRegistry.control_ids_for(framework_id)` supplies the reference sets: a bundled catalog's own ids (any category), the union over the members for a family id, or `None` for anything else. The generated crosswalks reference page prints the result for every crosswalk, and `scripts/check_catalog_truth.py` fails the `consistency` gate when a bundled side resolves below 100 percent.

## Reproducible crosswalk generation

The bundled crosswalks use several authoring paths:

- `scripts/catalogs/gen_osps_crosswalks.py` regenerates the five OSPS Baseline crosswalks from the OpenSSF `baseline/OSPS-*.yaml` family files at a pinned upstream commit (the SHA lives in the co-located `_osps_upstream.py`). Rows are keyed on the `osps-baseline` family at assessment-requirement level: each requirement inherits the guideline mappings of its parent control, six upstream target identifiers with transcription errors are normalized and named in their row notes, and SSDF practice-level references are expanded to the practice's tasks in the bundled `nist-ssdf-800-218` catalog. Upstream YAML is fetched via the `gh` CLI (argument list, no shell) and cached under `.local/`; `--check` is the drift gate (pre-push check 10).
- `scripts/catalogs/gen_crosswalks.py` regenerates the six hand-authored concordances byte for byte from tables in the script and has the same `--check` mode.
- The FedRAMP CR26 KSI crosswalk is produced by `scripts/catalogs/gen_fedramp_ksi.py` from the pinned FedRAMP rules dataset, fetched through `gh` and cached under `.local/`.

For an upstream bump, update the pin, regenerate the artifacts, review the diff, and commit. The `self-attested-via-upstream` label records a reproducible transformation of upstream data; independent SME verification remains a separate review.

## Related reading

- [Architecture](architecture.md): where crosswalks sit in the cross-framework gap-analysis flow.
- [Catalog engine](catalog-engine.md): the companion engine for *within*-framework control catalogs, and the text-depth column.
- [Data model](data-model.md): the `ControlMapping` model (distinct from `FrameworkMapping`: the former lives on a finding, the latter on a crosswalk).
- [`4-reference/crosswalks.md`](../4-reference/crosswalks.md): the auto-generated, always-current crosswalk inventory with row counts, verification posture and resolution.
- [`5-compliance/crosswalk-index.md`](../5-compliance/crosswalk-index.md): the verification-posture view.
- [`5-compliance/osps-baseline-mapping.md`](../5-compliance/osps-baseline-mapping.md): the OSPS Baseline mapping detail.
