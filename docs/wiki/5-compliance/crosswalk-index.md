# Crosswalk index

Evidentia bundles **13 inter-framework crosswalks** (864 control-to-control
mapping rows in total). A crosswalk maps controls in a source framework to
related controls in a target framework, so a single piece of evidence can
satisfy obligations across multiple frameworks at once.

This page is the **verification-posture** view: the one thing you must
know before relying on a crosswalk for an audit is *how trustworthy each
mapping is*. For the flat, always-current table of every crosswalk +
source/target + row count, see the auto-generated
[Reference → Crosswalks](../4-reference/crosswalks.md) page. For how the
crosswalk engine loads and applies these files, see
[Concepts → Crosswalk engine](../3-concepts/crosswalk-engine.md).

## Verification posture — read this first

Every crosswalk records a `verification` field. There are three possible
states; **only two are currently in use**:

| Posture | Meaning | Trust for audit use |
|---|---|---|
| `self-attested-via-upstream` | Auto-extracted from an upstream source's own cross-references; **not independently SME-verified** | Verify each mapping before relying on it |
| *(empty / not set)* | Evidentia-authored concordance; no formal verification posture declared | Treat as a working draft; verify before relying on it |
| `hand-checked` | SME-confirmed against both frameworks' control text | (not yet used — see below) |

**No crosswalk is currently marked `hand-checked`.** Of the 13:

- **5 are `self-attested-via-upstream`** — the OSPS Baseline crosswalks
  (all carry `provenance: upstream-osps-guidelines`).
- **8 have no posture set** — the pre-v0.10.6 Evidentia-authored
  concordances.

So: **always verify a mapping before relying on it for an audit.** The
v0.10.7+ roadmap targets upgrading the 5 OSPS crosswalks from
`self-attested-via-upstream` to `hand-checked` once SME review confirms
their accuracy.

You can read the posture programmatically:

```python
from evidentia_core.catalogs.crosswalk import load_crosswalk

cw = load_crosswalk("osps-baseline_to_nist-ssdf-800-218")
print(cw.verification)  # "self-attested-via-upstream"
print(cw.provenance)  # "upstream-osps-guidelines"
print(len(cw.mappings))  # 115
```

The `provenance` / `verification` / `verification_note` fields were added
additively to `CrosswalkDefinition` in v0.10.6 (the 8 older crosswalks
load unchanged with these fields defaulting to `None`).

## The 5 self-attested-via-upstream crosswalks (OSPS Baseline)

These are **mechanical extracts** of the upstream OpenSSF OSPS Baseline
`guidelines[]` array at the pinned commit `ac6bbec`. They reflect what
the OSPS Baseline *says* maps to each target framework — they are NOT an
independent SME mapping against (for example) the actual text of NIST
SSDF PO.1.1. Consumers requiring independent verification should plan a
hand-check pass.

| Source | Target | Rows | Provenance |
|---|---|---|---|
| OSPS Baseline 2026.02.19 | NIST 800-161 | 200 | upstream-osps-guidelines |
| OSPS Baseline 2026.02.19 | PCI DSS 4.0 | 200 | upstream-osps-guidelines |
| OSPS Baseline 2026.02.19 | NIST SSDF 800-218 | 115 | upstream-osps-guidelines |
| OSPS Baseline 2026.02.19 | EU CRA | 107 | upstream-osps-guidelines |
| OSPS Baseline 2026.02.19 | NIST CSF 2.0 | 52 | upstream-osps-guidelines |

See the [OSPS Baseline mapping](osps-baseline-mapping.md) showcase page
for the full verification-posture rationale (the v0.10.6 brainstorm
decision to ship these raw, with an explicit disclaimer, rather than
withhold them pending SME review).

## The 8 Evidentia-authored concordances (no posture set)

These predate the v0.10.6 posture fields and were authored as Evidentia
concordances. They have no formal `verification` posture declared, so the
same "verify before relying" guidance applies.

| Source | Target | Rows |
|---|---|---|
| NIST CSF 2.0 | NIST 800-53 (mod) | 36 |
| FedRAMP Rev 5 Moderate | CMMC 2.0 L2 | 32 |
| NIST AI RMF 1.0 | EU AI Act | 26 |
| NIST AI RMF 1.0 | ISO/IEC 42001:2023 | 23 |
| ISO/IEC 27001:2022 | NIST 800-53 (mod) | 23 |
| NIST 800-53 (mod) | HIPAA Security | 20 |
| NIST 800-53 (mod) | SOC 2 TSC | 17 |
| Virginia VCDPA | California CCPA/CPRA | 13 |

These cover the highest-traffic compliance overlaps: the AI-governance
pair (NIST AI RMF ↔ EU AI Act / ISO 42001), the federal pair (FedRAMP ↔
CMMC, CSF ↔ 800-53), the privacy pair (VCDPA ↔ CCPA), and the
audit-staple ISO 27001 / HIPAA / SOC 2 mappings onto NIST 800-53.

## Why crosswalks are not auto-generated

Crosswalks are audit-critical, so Evidentia does **not** generate them
from an LLM at runtime — that is a
[deliberately rejected item](../6-project/roadmap.md) on correctness
grounds. The 5 OSPS crosswalks are extracted from a pinned, authoritative
upstream (hence `self-attested-via-upstream`, not "LLM-generated"); the 8
concordances are committed, reviewable artifacts. Any new crosswalk
should be authored, reviewed, and committed — never produced on the fly.

## See also

- [Reference → Crosswalks](../4-reference/crosswalks.md) — the flat,
  always-current table (auto-generated from the mapping files).
- [Concepts → Crosswalk engine](../3-concepts/crosswalk-engine.md) — how
  crosswalks load + apply; the `CrosswalkDefinition` schema.
- [OSPS Baseline mapping](osps-baseline-mapping.md) — deep-dive on the 5
  OSPS crosswalks + their upstream-attested posture.
- [Guides → Run gap analysis](../2-guides/run-gap-analysis.md) — using
  crosswalks for cross-framework gap-analysis efficiency.
