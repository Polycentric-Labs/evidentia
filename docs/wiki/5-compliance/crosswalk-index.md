# Crosswalk index

Evidentia bundles inter-framework crosswalks, one JSON file per source and
target pair under `catalogs/data/mappings/`. A crosswalk maps controls in a
source framework to related controls in a target framework, so a single piece
of evidence can satisfy obligations across several frameworks at once.

This page is the **verification-posture** view: the one thing you must know
before relying on a crosswalk for an audit is *how trustworthy each mapping
is*, and the second is *whether its identifiers actually exist in the catalogs
it names*. For the flat, always-current table of every crosswalk with its
source, target, row count, posture and resolution, see the auto-generated
[Reference: Crosswalks](../4-reference/crosswalks.md) page. For how the
crosswalk engine loads and applies these files, see
[Concepts: Crosswalk engine](../3-concepts/crosswalk-engine.md).

## Verification posture: read this first

Every crosswalk records a `verification` field with one of four states:

| Posture | Meaning | Trust for audit use |
|---|---|---|
| `self-attested-via-upstream` | Auto-extracted from an upstream source's own cross-references; **not independently SME-verified** | Verify each mapping before relying on it |
| `self-attested` | Authored by Evidentia from public control numbering and titles, without the licensed text | Verify each mapping against the standard before relying on it |
| *(empty / not set)* | Evidentia-authored concordance that predates the posture field | Treat as a working draft; verify before relying on it |
| `hand-checked` | SME-confirmed against both frameworks' control text | Not yet used by any bundled crosswalk |

**No crosswalk is marked `hand-checked`.** The generated reference page lists
the posture of each one. In broad strokes: the five OpenSSF OSPS Baseline
crosswalks and the FedRAMP CR26 KSI crosswalk are `self-attested-via-upstream`
(they carry a `provenance` naming the upstream source); the two FDA Section
524B illustrative crosswalks and the NIST AI RMF to ISO/IEC 42001 concordance
are `self-attested`; the remaining Evidentia-authored concordances carry no
posture. So: **always verify a mapping before relying on it for an audit.**

You can read the posture programmatically:

```python
from evidentia_core.catalogs.crosswalk import CrosswalkEngine, MAPPINGS_DIR

engine = CrosswalkEngine()
cw = engine.load_crosswalk(MAPPINGS_DIR / "osps-baseline_to_nist-ssdf-800-218.json")
print(cw.verification)  # "self-attested-via-upstream"
print(cw.provenance)  # "upstream-osps-guidelines"
print(len(cw.mappings))
```

The `provenance` / `verification` / `verification_note` fields were added
additively to `CrosswalkDefinition` in v0.10.6; older crosswalks load unchanged
with these fields defaulting to `None`.

## Resolution: do the identifiers exist?

A crosswalk row needs valid identifiers on both sides. Bundled catalogs allow
Evidentia to check those identifiers mechanically; external targets need a
separate reference. Three kinds of defect had gone unnoticed:

- Four Evidentia-authored crosswalks were keyed on `nist-800-53-mod`, the
  legacy 16-control sample, so between half and 61 percent of their rows in
  three of the four named controls outside the sample and resolved to nothing.
  They are now keyed on the full `nist-800-53-rev5` catalog, where every row
  resolves.
- The five OSPS Baseline crosswalks declared a source framework that was not a
  catalog id and carried control-level identifiers (`OSPS-AC-01`) where the
  bundled maturity catalogs hold assessment requirements (`OSPS-AC-01.01`).
  They are now keyed on the `osps-baseline` family at requirement level, and
  six upstream target identifiers with transcription errors are normalized and
  named in their row notes.
- The NIST AI RMF to ISO/IEC 42001 concordance targeted identifiers of the form
  `ISO42001.A.6.1`, which are not Annex A identifiers; it is re-targeted onto
  the published Annex A numbering.

The generated reference page shows, for every crosswalk, how many rows resolve
on each side. Three targets have no bundled catalog and show `not bundled`:
EU CRA, NIST SP 800-161 and PCI DSS 4.0 (the OSPS upstream publishes those
mappings; Evidentia keeps them for readers who hold the text). Every other side
resolves completely, and `scripts/check_catalog_truth.py` fails the
`consistency` gate if that stops being true.

## Families: baselines inherit their parent's crosswalks

Several catalogs are views of a larger one. The NIST SP 800-53 Rev 5 Low,
Moderate, High and Privacy baselines and the FedRAMP Rev 5 baselines draw
their controls from the full `nist-800-53-rev5` catalog; the three OSPS
Baseline maturity levels draw their requirements from one baseline. The
manifest records this as `crosswalk_family`, and the engine consults both a
catalog's own key and its family's on every lookup. A gap found against
`fedramp-rev5-moderate` therefore receives the cross-framework value of every
crosswalk keyed on `nist-800-53-rev5`. Before family support, it received
only mappings keyed directly on the FedRAMP baseline, including its CMMC
Level 2 crosswalk.

## Why crosswalks are not auto-generated

Crosswalks are audit-critical, so Evidentia does **not** generate them from an
LLM at runtime; that is a [deliberately rejected item](../6-project/roadmap.md)
on correctness grounds. The upstream-attested crosswalks are extracted from a
pinned upstream by a reproducible script (`scripts/catalogs/gen_osps_crosswalks.py`
and the FedRAMP KSI generator). `scripts/catalogs/gen_crosswalks.py` regenerates
six hand-authored concordances from its tables; other concordances remain
separately authored artifacts. The OSPS and legacy-crosswalk scripts each have
a `--check` mode. Any new crosswalk should be authored, reviewed, and committed,
never produced on the fly.

## See also

- [Reference: Crosswalks](../4-reference/crosswalks.md), the flat,
  always-current table (auto-generated from the mapping files).
- [Concepts: Crosswalk engine](../3-concepts/crosswalk-engine.md), how
  crosswalks load and apply, families, and the `CrosswalkDefinition` schema.
- [OSPS Baseline mapping](osps-baseline-mapping.md), the deep-dive on the five
  OSPS crosswalks and their upstream-attested posture.
- [Guides: Run gap analysis](../2-guides/run-gap-analysis.md), using
  crosswalks for cross-framework gap-analysis efficiency.
