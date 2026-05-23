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
tier: A | B | C | D                # see ATTRIBUTION.md
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

## Worked example — `iso-27017-2015.yaml` (v0.10.3 proof)

See `packages/evidentia-core/src/evidentia_core/catalogs/data/stubs/iso-27017-2015.yaml`
for the first YAML catalog in the bundled set — a 7-control
Tier-C cloud-services stub. The corresponding JSON equivalent was
removed in v0.10.3; both formats produce identical
`ControlCatalog` objects when loaded.

## When NOT to use YAML

- **OSCAL catalogs** (e.g., NIST 800-53 Rev 5): stick with JSON.
  Upstream NIST publishes OSCAL JSON; the existing JSON files are
  byte-identical to NIST's release. Keep the chain of custody.
- **Machine-generated catalogs**: JSON is easier for tooling to
  emit + diff against the upstream.

## Other tier conventions

- **`tier: A`** — public-domain control text (US federal, NIST,
  CISA). Catalog bundles full control bodies.
- **`tier: B`** — copyrighted but licensed for embedded distribution
  (rare).
- **`tier: C`** — copyrighted; only IDs + titles bundled. Control
  body is a placeholder; operators run `evidentia catalog import`
  with their licensed copy to override.
- **`tier: D`** — government edicts (statutes, regulations) —
  uncopyrightable; full text bundled.

See `ATTRIBUTION.md` for the redistribution rationale per tier.

## Tests + CI

`tests/unit/test_catalogs/test_all_bundled.py` parametrizes a
catalog-load smoke test per bundled framework. Adding a new catalog
auto-extends the test suite — no new test file required for the
catalog itself.

`tests/unit/test_catalogs/test_yaml_loader.py` (v0.10.3+) covers
the YAML loader paths directly.
