# Catalog inventory

Evidentia bundles **96 framework catalogs** in-tree. This page is the
compliance-angled view: it groups those catalogs by region / standard
family and, for each group, tells you **what is production-grade
authoritative text versus a licensing placeholder**, and **what you may
redistribute**.

For the flat, sortable, always-current table of every catalog ID +
version + tier + category, see the auto-generated
[Reference → Catalogs](../4-reference/catalogs.md) page (regenerated from
the live `frameworks.yaml` manifest on every CI run). This page does not
duplicate that table; it explains the *posture* behind it. Run
`evidentia catalog list` to enumerate catalogs at runtime.

## The licensing tiers (what you can actually use)

Every catalog carries a redistribution **tier**. The tier is the single
most important fact for a compliance program, because it tells you
whether Evidentia ships the authoritative control text or only the
neutral control numbering:

| Tier | What ships | Production-grade? | Redistribution |
|---|---|---|---|
| **A** | Full authoritative control text | ✅ Yes — public-domain / open-licensed source | Bundled verbatim; freely redistributable |
| **B** | Full authoritative content (sample subset for some) | ✅ Yes — free with attribution | Bundled with attribution |
| **C** | Control IDs + neutral titles **only** (text is copyrighted) | ⚠️ Placeholder — you supply the licensed text | Not bundled; `license_url` points to where to obtain it |
| **D** | Paraphrased obligation / regulation references | ✅ Usable — statutory obligations restated | Bundled (statutes/regulations are not copyrightable) |

The current distribution across all 96 catalogs:

| Tier | Count | Meaning for your program |
|---|---|---|
| A | **50** | Drop-in. Full text bundled. Most US federal + international control frameworks. |
| B | **4** | Drop-in with attribution. MITRE ATT&CK / CAPEC / CWE + CISA KEV. |
| C | **22** | **Placeholder.** ISO, CIS, PCI DSS, COBIT, SOC 2, etc. — import your licensed copy via `evidentia catalog import`. |
| D | **20** | Usable. Privacy statutes + EU regulations, restated as obligations. |

**The Tier-C distinction is the one to internalize.** A Tier-C catalog
(e.g. `iso-27001-2022`, `pci-dss-4.0.1`, `soc2-tsc`) ships only the
public control numbering (ISO 27001 Annex A IDs, SOC 2 CC1–CC9 / A1 /
C1 / P1–P8 / PI1, etc.) and a `license_url`. It is a **scaffold, not a
finished catalog** — gap analysis against it will key off the right
control IDs, but the control text your auditors read must come from your
licensed copy. All 22 Tier-C catalogs are flagged `placeholder: true` +
`license_required: true` in the manifest, so they are unambiguous at
runtime.

See [`ATTRIBUTION.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/ATTRIBUTION.md)
at the repo root for the per-source license statements.

## By region / standard family

### US Federal (38 catalogs — all Tier-A)

The deepest coverage area, and entirely production-grade. Includes:

- **NIST SP 800-53 Rev 5** — Low / Moderate / High / Privacy baselines
  (resolved from `usnistgov/oscal-content`, CC0) plus the legacy
  16-control `nist-800-53-mod` sample retained for backward compatibility.
- **FedRAMP Rev 5** — Low / Moderate / High / LI-SaaS baselines.
- **CMMC 2.0** — Level 1 / 2 / 3.
- **NIST SP 800-171** Rev 2 + Rev 3, **800-172**, **CSF 2.0**,
  **SSDF 800-218**, **AI RMF 1.0**, **Privacy Framework 1.0**.
- **HIPAA** (Security / Privacy / Breach), **GLBA Safeguards**,
  **CJIS v6**, **IRS Pub 1075**, **CMS ARS 5.1**, **FDA 21 CFR Part 11**,
  **NERC CIP**, **NY DFS Part 500**, **CISA CPGs**.
- **The full FFIEC IT Examination Handbook stack** — Audit, Management,
  Information Security, Operations, Outsourcing booklets + the
  Cybersecurity Assessment Tool.
- **OCC Bulletin 2026-13a / FRB SR 26-02** (model risk; supersedes the
  SR 11-7 / OCC 2011-12 line).

All ship verbatim because US Government works are public domain.

### International (15 catalogs)

Mostly Tier-A; a handful of EU regulations are Tier-D obligations:

- **Tier-A control frameworks**: Australian Essential Eight + ISM,
  Canada ITSG-33, NZ NZISM, UK Cyber Essentials + NCSC CAF 3.2,
  EU AI Act, and the **3 OpenSSF OSPS Baseline maturity catalogs**
  (M1 / M2 / M3 — verbatim under upstream Apache-2.0; see the
  [OSPS Baseline mapping](osps-baseline-mapping.md) showcase page).
- **Tier-D obligations / regulations**: EU GDPR, EU NIS2, EU DORA,
  Canada PIPEDA, UK DPA 2018. (GDPR / PIPEDA / DPA are categorized
  `obligation`; NIS2 + DORA are `control`-category regulations restated
  as paraphrased references.)

### US State Privacy (15 catalogs — all Tier-D obligations)

The complete set of comprehensive US state consumer-privacy laws:
California (CCPA/CPRA), Colorado, Connecticut, Delaware, Florida, Iowa,
Maryland, Minnesota, Montana, New Hampshire, Oregon, Tennessee, Texas,
Utah, Virginia. Each is a paraphrased obligation reference (state
statutes are not copyrightable under the government-edicts doctrine), so
all 15 are bundled and usable.

### Threat Intelligence (4 catalogs — all Tier-B)

Cross-reference frameworks that ride alongside control catalogs:
MITRE **ATT&CK Enterprise**, **CAPEC**, **CWE** (2024 Top-25 sample),
and the **CISA KEV** sample. Tier-B because they are free to use with
attribution; the KEV sample is a daily-refreshable subset of the full
catalog.

### License-required placeholders (20 catalogs — all Tier-C)

These are the frameworks whose control **text** is copyrighted, so
Evidentia ships only the public numbering + a `license_url`:

- **ISO/IEC**: 27001:2022, 27002:2022, 27017:2015, 27018:2019,
  27701:2019, 42001:2023, 22301:2019.
- **CIS**: Critical Security Controls v8.1 + the AWS / Azure / GCP /
  Kubernetes / RHEL 9 Foundations Benchmarks.
- **Others**: PCI DSS v4.0.1, COBIT 2019, HITRUST CSF v11, IEC 62443,
  SCF 2024, SWIFT CSCF 2024, **SOC 2 Trust Services Criteria**.

To use one of these for a real assessment, obtain the authoritative text
from the source (`license_url` is in the manifest + on the
[Reference → Catalogs](../4-reference/catalogs.md) page) and load your
licensed copy with `evidentia catalog import`. See
[Contributing a catalog](contributing-a-catalog.md) for the catalog
schema if you are hand-authoring one.

## Adding or pinning a catalog

- **Add a new framework**: 3-file PR — see
  [Contributing a catalog](contributing-a-catalog.md).
- **Pin a catalog version** (planned): a `catalog pin <framework> <version>`
  command — so an authoritative-source refresh does not shift your assessment
  baseline — is planned (not yet available; track it on the roadmap). Catalog
  content is a non-frozen surface
  ([api-stability.md](../6-project/api-stability.md) §"Bundled catalog
  content") — it evolves as NIST / ISO / EU sources publish updates, and the
  pin will be the operator escape hatch.

## See also

- [Reference → Catalogs](../4-reference/catalogs.md) — the flat,
  always-current table (auto-generated from the manifest).
- [Crosswalk index](crosswalk-index.md) — how the bundled catalogs map
  to one another.
- [OSPS Baseline mapping](osps-baseline-mapping.md) — the showcase
  deep-dive on the 3 OSPS Baseline catalogs + their crosswalks.
- [`ATTRIBUTION.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/ATTRIBUTION.md)
  — per-source license statements.
