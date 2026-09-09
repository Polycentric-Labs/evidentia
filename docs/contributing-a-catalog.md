# Contributing a new framework catalog

> v0.10.3+. Lowers the barrier to adding a new compliance framework
> to Evidentia. Catalogs can now be **YAML or JSON** — pick whichever
> is friendlier; the loader auto-detects by file extension.

## TL;DR — the 3-file PR

1. Add a catalog file at one of:
   - `packages/evidentia-core/src/evidentia_core/catalogs/data/us-federal/<framework-id>.yaml`
   - `…/data/international/<framework-id>.yaml`
   - `…/data/stubs/<framework-id>.yaml` (Tier-C, copyrighted text not bundled)
   - `…/data/state-privacy/<framework-id>.yaml`
   - `…/data/threats/<framework-id>.yaml`
   - `…/data/mappings/<framework-id>.yaml`
2. Run `python scripts/catalogs/regenerate_manifest.py` to update
   `data/frameworks.yaml` (the manifest is auto-generated from the
   files on disk — never hand-edited).
3. Open a PR with both files staged.

## Why YAML (v0.10.3+) vs. JSON

| | JSON | YAML |
|---|---|---|
| Comments | ❌ Not supported | ✅ `# inline + block` |
| Multi-line strings | Awkward (`\n` escapes) | ✅ `|` literal + `>` folded |
| Trailing commas | Forbidden | Allowed |
| Hand-edit friendliness | Brittle | Significantly better |
| Tooling | Universal | Universal (PyYAML, yamllint, etc.) |

Both formats produce the same `ControlCatalog`; YAML is just the
nicer surface for hand-authoring. Existing JSON catalogs stay JSON
— there's no auto-migration. Convert one when you next edit it if
you like.

## Required schema (Evidentia-format)

```yaml
framework_id: my-framework-id     # kebab-case; stable across versions
framework_name: "Display name"
version: "1.0"                    # framework version, not catalog version
source: "Upstream URL or citation"
tier: A | B | C | D                # redistribution tier; see "Other tier conventions"
category: control                  # control | technique | vulnerability | obligation

# Tier-C only (control text is copyrighted):
placeholder: true
license_required: true
license_terms: "© <Holder>. Brief redistribution rationale."
license_url: "URL where users can license/download the authoritative text"

families:
  - "Family 1"
  - "Family 2"
controls:
  - id: AC-1
    title: "Control title"
    description: "Control text — or '[Licensed content — see license_url]' for Tier-C stubs"
    family: "Family 1"
    # Tier-C stub controls also carry:
    placeholder: true
    tier: C
    license_required: true
    license_url: "URL where users can license/download the authoritative text"
```

The `manifest.py` model validates every field; malformed catalogs
get caught by the existing `tests/unit/test_catalogs/test_all_bundled.py`
suite (which parametrizes a smoke test per bundled framework).

## Worked examples

### 7-control stub — `iso-27017-2015.yaml` (v0.10.3 proof)

See `packages/evidentia-core/src/evidentia_core/catalogs/data/stubs/iso-27017-2015.yaml`
for the first YAML catalog in the bundled set — a 7-control
Tier-C cloud-services stub. The corresponding JSON equivalent was
removed in v0.10.3; both formats produce identical
`ControlCatalog` objects when loaded.

### 18-control stub — `cis-controls-v8.1.yaml` (v0.10.4 C3 richer proof)

See `packages/evidentia-core/src/evidentia_core/catalogs/data/stubs/cis-controls-v8.1.yaml`
for a richer hand-authored example. The 18 CIS Critical Security
Controls v8.1 are grouped by Implementation Group (IG1 / IG2 / IG3)
using `# ── ... ──` comment headers — a pattern that's impossible in
JSON. This demonstrates the actual contributor benefit of YAML for
catalogs that need browsability beyond a flat control list.

The 7-control vs 18-control pair lets contributors see both ends of
the size spectrum the YAML format is intended to serve.

## When NOT to use YAML

- **OSCAL catalogs** (e.g., NIST 800-53 Rev 5): stick with JSON.
  Upstream NIST publishes OSCAL JSON; the existing JSON files are
  byte-identical to NIST's release. Keep the chain of custody.
- **Machine-generated catalogs**: JSON is easier for tooling to
  emit + diff against the upstream.

## Other tier conventions

The tier records what may be redistributed. It does not say how much
control text the file carries; that is the derived `text_depth` below.

- **`tier: A`**: public-domain or open-licensed, redistributable
  verbatim. Two sub-categories:
  - **Public-domain works** (US federal, NIST, CISA, FedRAMP).
  - **Permissive-licensed works** (Apache-2.0, MIT, CC-BY) where
    the upstream license explicitly permits verbatim redistribution.
    The catalog's `license_terms` field MUST cite the upstream
    license; the source URL pins the upstream commit/version so the
    chain-of-custody is auditable.
  Bundle the full control bodies where the source publishes them. A
  catalog that carries only control numbering and titles is
  acceptable, and the manifest labels it `text_depth: headings`.
- **`tier: B`**: free to use with attribution (MITRE ATT&CK, CISA
  KEV).
- **`tier: C`**: copyrighted; only IDs and neutral titles bundled.
  Every control body is a placeholder (`placeholder: true`);
  operators run `evidentia catalog import` with their licensed copy
  to override.
- **`tier: D`**: government edicts (statutes, regulations);
  obligations restated in Evidentia's words, or
  heading-level references where only the structure is captured.

Each manifest entry's `license` and `source_url` columns carry the
per-catalog statement (`evidentia catalog license-info <id>` prints
them).

## Text depth (derived, never declared)

`scripts/catalogs/regenerate_manifest.py` loads every catalog and
writes a `text_depth` column into the manifest: `full` when every
non-withdrawn entry has statement text that differs from its title,
`headings` when none does, `partial` otherwise. Placeholder entries
never count. You do not set it in the catalog file; the rule lives
in `evidentia_core.models.catalog.derive_text_depth`, every catalog
model exposes it as `.text_depth`, and `scripts/check_catalog_truth.py`
fails the `consistency` gate if the manifest column disagrees with the
files. `evidentia catalog list` shows it in the `Text` column.

## Currency and source scope

Control catalogs may carry `status` (`current`, `superseded`, `retired` or
`historical`), `notes`, `verified_on` and `superseded_by`. Omit unverified facts;
absence does not mean current. Retain predecessor IDs when their controls have
historical assessment value, and do not claim a successor is equivalent.

Use independent string-valued control `properties` for publisher tags and raw
baseline or overlay labels. Priority, Existing status and applicability are
separate facts. `audit_contexts` maps a named authority jurisdiction to its
published audit version, source, verification date and optional `valid_through`.
Unlisted authorities remain unknown.

Future or pending revisions belong in `publication_notices`, outside `controls`.
Keep publication, approval, order-effective and standard-applicability dates
separate. Neither dates nor notices change gap-analysis membership. The
[catalog currency guide](catalog-currency.md) gives the verified examples and
explains the limitations. `text_depth` measures the presence of statement text;
it does not certify source accuracy or verbatim quotation.

## Source rows and spreadsheet fidelity

Attach optional `source_rows` to a `CatalogControl` when source cells need to
remain inspectable. These evidence rows do not add controls, statements or gap
requirements. Each row requires a lowercase SHA-256 claim, a literal nonblank
sheet name, a positive integer row, a scalar `source_id`, a `kind` of `aggregate`,
`clause` or `fragment`, and a `values` mapping. Optional `source_id_format` and
`interpreted_id` retain an explicitly reviewed identifier interpretation.
Surrounding whitespace in a valid sheet name is preserved.

Map exact, unique source column names to finite JSON scalars. Null, empty text,
booleans, numbers and whitespace are distinct. Dates and datetimes become ISO
text. Quote YAML values when text such as `005` must stay a string. Parsed
mappings cannot recover duplicate input keys; API YAML imports reject non-string
keys before JSON conversion could collapse them. Builders must check exact
headers and duplicate IDs before constructing mappings.

Use `resolved_values` only for reviewed spreadsheet merge-anchor projections,
with the source anchor recorded in `provenance`. Keep physical follower blanks
in `values`. Do not forward-fill arbitrary blanks or infer applicability from
priority, audit dates or another row's classification. Both optional mappings
default to empty. Source rows and their scalar mappings resist ordinary mutation,
detach input aliases and support deep copying. Invalid copied evidence fails
model serialization rather than silently changing a nonfinite value to null.

Native JSON/YAML, API imports, saved reloads and framework/control responses
retain rows, including nested enhancements. CLI control details show JSON scalar
representations; console details are read-only. Browser number handling does not
promise arbitrary numeric precision when exporting or rewriting source files.
The pinned source projections remain the regeneration inputs. SHA-256 syntax
validation establishes a provenance claim, not publisher authentication.

See `gen_cms_ars.py`, `gen_cjis_companion.py` and the corresponding JSON inputs in
`scripts/catalogs/sources/` for complete examples. Both generators have explicit
input/output paths and a `--check` mode. They preserve approved source corrections
beside their original cells and reject changed interpretation preconditions.
The [currency guide](catalog-currency.md#cms-and-cjis-source-evidence) describes
source scope, historical references and independent audit contexts.

## OSCAL sidecar artifacts (v0.10.6+)

A bundled catalog MAY ship a companion OSCAL Catalog 1.2.1
serialization alongside the Evidentia-format YAML, named
`<framework-id>.oscal.json` (or `.oscal.yaml`). Worked example:
the OpenSSF OSPS Baseline ships three Evidentia per-maturity YAMLs
(`osps-baseline-m{1,2,3}.yaml`) plus one OSCAL serialization
(`osps-baseline.oscal.json`) covering the full 41-control surface.

OSCAL sidecars are **downstream-consumption artifacts**, not
framework-manifest entries. The `scripts/catalogs/regenerate_manifest.py`
scanner skips any file matching `*.oscal.json` / `*.oscal.yaml` so
they don't register as separate frameworks. Validation: the OSCAL
JSON MUST validate against `trestle.oscal.catalog.Catalog` (Trestle
4.0.3+ pydantic models) or `oscal-cli validate`. Authoring guidance:

- Top-level: `{"catalog": {"uuid": "<stable UUID v5>", "metadata": {...}, "groups": [...]}}`
- Each upstream family → one OSCAL `group` with `class: "family"`.
- Each control → one OSCAL `control` with lowercase hyphenated `id`
  (e.g. `osps-ac-01`) and uppercase `class` preserving the canonical
  upstream ID (e.g. `OSPS-AC-01`).
- Per-control `props`: include a `maturity-level` prop where the
  upstream framework declares one (OSPS Baseline does).
- `parts`: a `statement` part for the control objective + per-
  assessment-requirement `objective` parts (with `applicability`
  prop) + an optional `guidance` part holding upstream crosswalk
  references (informative; treat as self-attested by upstream).

## Tests + CI

`tests/unit/test_catalogs/test_all_bundled.py` parametrizes a
catalog-load smoke test per bundled framework. Adding a new catalog
auto-extends the test suite — no new test file required for the
catalog itself.

`tests/unit/test_catalogs/test_yaml_loader.py` (v0.10.3+) covers
the YAML loader paths directly.

`tests/unit/test_catalogs/test_osps_baseline.py` (v0.10.6+) is a
worked-example test suite for a multi-maturity Tier-A catalog with
companion OSCAL sidecar. Mirror this pattern when contributing a
similarly-structured catalog (per-maturity / per-baseline / per-
profile slices of a single upstream source).
