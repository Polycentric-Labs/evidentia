# Catalog currency and applicability

A catalog version, an audit version and a legal effective date answer different
questions. Evidentia records their sources separately. A date never activates or
removes a requirement from gap analysis. Select the catalog and applicability
scope for the assessment you are conducting.

`catalog list` marks catalog lifecycle status. `catalog show`, `catalog where`
and `catalog license-info` display available notices and verification dates.
The console shows them in the framework browser and catalog management page.
Missing metadata means unverified, not current. An imported catalog keeps its
validated currency and licensing metadata. API imports accept unquoted YAML
date values and reject unsupported YAML types before replacing an installed
catalog. CLI source and license values render as literal text.

```bash
evidentia catalog license-info ffiec-cat
evidentia catalog show nerc-cip-v7
evidentia catalog show eu-ai-act --control AIA.Art.9
```

## September 2026 source review

The following changes were checked against primary publications on 2026-09-09.
Catalog content is a [non-frozen surface](api-stability.md). Import the version
used for an assessment if it must remain fixed. Changed IDs have no implied
one-to-one mapping to their predecessors.

| Catalog | Bundled edition and scope |
|---|---|
| `cisa-cpgs` | CPG 2.0, 34 goal headings under the six CSF functions. The prior 36-row subset is replaced. |
| `swift-cscf-2026` | 2026 attestation edition, 32 headings: 26 mandatory designations and six advisory designations. Architecture qualifications still apply. |
| `swift-cscf-2024` | Historical compatibility copy. Its original source table was not verified in this review; it is not a certified archive. |
| `cmmc-2-l1` | 15 current FAR-based requirement IDs from the Level 1 assessment guide, replacing the old 17 NIST-style rows. |
| `nerc-cip-v7` | 13 current US standard headings. The legacy handle does not name a uniform v7 suite. Requirement text is excluded. |
| `fda-524b-appendix1` | The eight existing categories already refer to the 2026-02-03 guidance; source currency was rechecked. |

Primary sources: [CISA CPG 2.0](https://www.cisa.gov/sites/default/files/2025-12/CPG_Report_2.0_508c.pdf),
[Swift control editions](https://www.swift.com/myswift/customer-security-programme/understand-controls),
[DoD Level 1 guide](https://dodcio.defense.gov/Portals/0/Documents/CMMC/AssessmentGuideL1v2.pdf),
[NERC CIP index](https://www.nerc.com/standards/reliability-standards/cip), and
[FDA guidance](https://www.fda.gov/regulatory-information/search-fda-guidance-documents/cybersecurity-medical-devices-quality-management-system-considerations-and-content-premarket).
The Swift catalog is Tier C and supplies no licensed body text. NERC is also
Tier C; public availability does not establish text redistribution permission.

## FFIEC booklets and retirement

Six new catalogs complete the ten current handbook booklets. They contain 373
public body headings, with no examination procedures, appendices or narrative
statements. Published section locators are document locators, not official
assessment-control IDs. Unnumbered entries use explicitly local IDs derived from
heading URL paths. Heading counts do not establish assessment completeness.

| Catalog | Edition | Headings |
|---|---|---:|
| `ffiec-aio` | June 2021 | 104 |
| `ffiec-business-continuity-management` | November 2019 | 54 |
| `ffiec-development-acquisition-maintenance` | August 2024 | 109 |
| `ffiec-retail-payment-systems` | April 2016 | 43 |
| `ffiec-supervision-technology-service-providers` | October 2012 | 26 |
| `ffiec-wholesale-payment-systems` | July 2004 | 37 |

Each catalog links its [public handbook](https://ithandbook.ffiec.gov/) headings
and edition sources. The other four current booklets are Audit, Information
Security, Management and Outsourcing. The new heading catalogs do not enlarge
those older catalogs' text coverage claims.

`ffiec-operations` retains all 27 existing rows, marked superseded by
`ffiec-aio`. FFIEC announced the replacement on
[2021-06-30](https://www.ffiec.gov/news/press-releases/2021/pr-06-30).
`ffiec-cat` retains its historical 33-row subset, marked retired on 2025-08-31.
Its [sunset statement](https://www.ffiec.gov/sites/default/files/media/press-releases/2024/cat-sunset-statement-ffiec-letterhead.pdf)
points to alternatives such as NIST CSF and CISA CPGs; those are not equivalent
successor catalogs. Existing assessment references continue to resolve.

## NERC publication notices

`publication_notices` is separate from `controls`. It never enters the control
index, text-depth calculation or gap-analysis denominator, even after a listed
date passes. The snapshot is for US enforcement; Canadian jurisdictions,
requirement-specific phases and notified early adoption require separate review.

[Order 919](https://www.govinfo.gov/content/pkg/FR-2026-03-24/pdf/2026-05716.pdf)
approved eleven revised standards and four new plus eighteen modified glossary
terms. It was issued 2026-03-19, published 2026-03-24 and became effective
2026-05-26. These order dates do not make the revised standards generally
applicable in 2026. No glossary definitions or requirement bodies are bundled.

| Announced revisions | General US standard applicability | Qualification |
|---|---|---|
| CIP-002-7 | 2028-07-01 | Approval history; superseded by CIP-002-8. |
| CIP-002-8 | 2028-07-01 | Separate RD25-8-000 approval. |
| CIP-003-10 | 2028-07-01 | NERC inactive date 2029-06-30. |
| CIP-003-11 | 2029-07-01 | Separate Order 918 approval. |
| CIP-004-8, CIP-005-8, CIP-006-7.1, CIP-007-7.1, CIP-008-7.1, CIP-009-7.1, CIP-010-5, CIP-011-4.1, CIP-013-3 | 2028-07-01 | Order 919 revisions; errata suffixes are significant. |
| CIP-015-1 | 2028-10-01 | Approved by Order 907; NERC inactive date 2029-09-30. |
| CIP-015-2 | 2029-10-01 | Approved 2026-08-10; additional scope phases continue in 2030 and 2031. |
| CIP-014-4 | Unverified | Filed and pending approval; current CIP-014-3 remains in the control set. |

The [NERC index](https://www.nerc.com/standards/reliability-standards/cip) supplies
standard dates. Notices also link the approving orders. The CIP-002-7 page's
order-effective date conflicts with the Federal Register; the catalog records
that discrepancy and uses the final rule. No publication date is invented for
the [CIP-015-2 letter approval](https://www.nerc.com/standards/reliability-standards/cip/cip-015-2).

## Regulatory dates and authority scope

[Regulation (EU) 2026/1744](https://eur-lex.europa.eu/eli/reg/2026/1744/oj/eng)
was published on 2026-07-24 and entered into force on 2026-07-27. Its amendment
to Article 113 makes Chapter III Sections 1-3, except Article 6(5), applicable
from 2027-12-02 for Annex III systems and 2028-08-02 for Annex I systems where
the provision applies. The
general application date remains 2026-08-02. Specified new Article 5
prohibitions apply from 2026-12-02; earlier prohibitions and GPAI duties keep
their earlier dates. The bundled article summaries carry these scoped date
properties. They are not a full consolidation of the amended law or an
automatic applicability decision.

[Article 27(1)](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-27)
retains its specific Annex III and deployer scope, excluding Annex III point 2.
Its entry therefore has no Annex I date. The Commission page reproduces the
original text; the enacted amendment changes paragraphs 4 and 5, not that scope.
The [original Article 113 schedule](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-113)
supports the earlier dates; its superseded high-risk deadline is not used.

For [NYDFS Part 500](https://www.dfs.ny.gov/cybersecurity/23-NYCRR-Part-500),
the final scheduled transitions for the 2023 amendment ended on 2025-11-01.
Ongoing entity-specific periods remain, including the 180-day period after loss
of an exemption under section 500.19(h). The catalog records the distinction.
DFS labels its formatted text a convenience copy rather than the official
version. The 29 headings and selected subsection summaries now distinguish
CISO reporting from governing-body oversight, Class A detection/logging from
training, and compliance notices from extortion-payment notices. Section 500.24
is included. Review prior evidence linked to 500.4(c)/(d), 500.14(b), 500.16 or
500.17(a)/(b)/(c), whose former bundled headings misidentified their subjects.
These corrections do not migrate evidence automatically.

`audit_contexts` holds a version and dated source per named authority. It does
not turn a publisher's latest edition into every state's audit version. Only
listed authorities have verified context, and `valid_through` bounds a source's
stated coverage. The CMS and CJIS imports below retain their separate source
and audit contexts.

## CMS and CJIS source evidence

`cms-ars-5.2` retains all 1,681 data rows in the reviewed CMS workbook sheet.
Its 605 reference units comprise 243 base controls and 362 enhancements; 1,076
clause rows remain attached evidence. Baseline, MAC, HVA, FTI, priority and
frequency columns stay independent. Blank cells never inherit applicability.
The [CMS source page](https://security.cms.gov/policy-guidance/cms-acceptable-risk-safeguards-ars)
dates ARS 5.2 to 2026-07-01 and ARS 5.1 to 2023-07-26. CMS and supporting
organizations must tailor the source to their systems. Earlier applicability
decisions do not transfer automatically.

`cjis-v6.1` imports the FBI's
[Requirements Companion Document](https://le.fbi.gov/cjis-division/cjis-security-policy-resource-center/requirement-companion-document-pdf)
for the [2026-06-25 policy](https://le.fbi.gov/file-repository/cjis_security_policy_v6-1_20260625-1.pdf).
All 1,533 physical statement fragments remain in source order across 324
reference units. Three numbered CSO clauses attach to section 3.2.2.
Structural ancestors support navigation only. Roles, conditions, alternative
paths, exceptions and table fragments still require entity and scenario
review. The unit count is not an official requirement count, and the companion
is not the complete 473-page policy. Audit dates, priorities and IaaS/PaaS/SaaS
columns remain separate. Only US-TX has a verified audit context: [Texas DPS](https://www.dps.texas.gov/section/crime-records/cjis-documents)
uses version 5.9.5 through 2027-03-31. Later Texas periods and other authorities
remain unknown.

The historical `cms-ars-5.1` and `cjis-v6` catalogs retain all 19 and 24 previous
records, respectively. Their notices identify the limited coverage and point
to the new catalogs without migrating evidence or claiming equivalent IDs.

```bash
evidentia catalog show cms-ars-5.2 --control AC-01
evidentia catalog show cjis-v6.1 --control AT-3
evidentia catalog show cjis-v6.1 --control 5.20
```

Control details expose `source_rows` through CLI JSON and an expandable console
view. Each row has a source SHA-256 claim, sheet and physical row, raw identifier,
optional format and interpretation, original scalar values and provenance.
`values` preserves physical cells; `resolved_values` carries only reviewed
spreadsheet merge-anchor values. A physical blank can therefore coexist with a
known merged value. Null, empty text, numbers and booleans remain distinct.
The numeric source value `5.2` and format `0.00` remain separate from the reviewed
CJIS identifier `5.20`. Source rows never add indexed controls or gap requirements.

Pinned text projections under `scripts/catalogs/sources/` retain the reviewed
cell metadata. Regeneration needs no network or workbook parser:

```bash
uv run --no-sync python scripts/catalogs/gen_cms_ars.py --check
uv run --no-sync python scripts/catalogs/gen_cjis_companion.py --check
```

Government text is attributed to CMS, FBI and the cited NIST publications.
Workbook artwork, seals, logos and referenced third-party standards are excluded
from these text projections. The source hashes bind the reviewed inputs; they
do not authenticate a publisher or grant rights over separately cited material.
