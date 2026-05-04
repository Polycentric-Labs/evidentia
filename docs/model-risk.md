# Model Risk Management (MRM) module

Comprehensive walkthrough of Evidentia's model-risk capability
surface, introduced in v0.7.10. The module ships an SR 11-7 /
SR 26-02 / OCC Bulletin 2011-12 / OCC Bulletin 2026-13a-aligned
model inventory, doc generator, validation report, AI-feature
linkage, and Three Lines of Defense + Effective Challenge
governance primitives.

## Why MRM in Evidentia

OCC Bulletin 2011-12 / FRB SR 11-7 (active 2011-2026) and the
April 2026 supersession by OCC Bulletin 2026-13a / FRB SR 26-02
together establish the regulatory expectation that
federally-regulated financial-services institutions maintain a
formal Model Risk Management program. The framework requires:

1. A **model inventory** with each managed model documented for
   purpose, methodology, inputs, outputs, ownership, tier
   classification, and validation cadence.
2. **Independent validation** of models on a tier-driven cadence
   (typically Tier 1 = annual / Tier 2 = biennial / Tier 3 =
   triennial).
3. **Effective challenge** of model assumptions, methodology, and
   results by parties independent of model development.
4. **Three Lines of Defense** separation between business
   operations (1st line), risk + compliance oversight (2nd line),
   and internal audit (3rd line).
5. **Documented audit trail** linking every model-influenced
   decision back to the inventory entry that governs the model.

Note: the SR 26-02 / OCC 2026-13a guidance **explicitly excludes**
generative AI and agentic AI from scope. Banks deploying LLM-driven
controls operate without a regulatory framework — Evidentia's
`GenerationContext` provenance chain (v0.7.1) + the v0.7.10 P0.6.4
`RiskStatement.model_inventory_ref` linkage produce
SR-replacement-grade audit evidence for LLM-driven controls,
positioning Evidentia as the SR-11-7-replacement-framework for
the regulator-vacuum gap.

Vanta-class GRC SaaS tools don't ship MRM; commercial MRM tools
(SS&C Algorithmics, SAS Model Risk Management) are
six-figure-per-year products. Evidentia ships the OSS-native,
Apache 2.0, Sigstore-signable, OSCAL-compatible MRM primitive.

## Module surface

The MRM module ships as `evidentia model-risk` plus the
`evidentia governance` sibling (3LOD + Effective Challenge):

```
evidentia model-risk
├── model                          # Model inventory CRUD
│   ├── add                        # Add a model (atomic flags + --from-yaml)
│   ├── list                       # List models (filter by tier / methodology)
│   ├── show                       # Show one model (formatted + --json)
│   ├── edit                       # Edit (per-field flags / --from-yaml / --editor)
│   └── delete                     # Delete (prompt by default; --yes)
├── doc generate <id>              # SR 11-7-aligned model documentation (Markdown)
└── validation-report generate <id>  # Validation cycle report (Markdown)

evidentia governance
├── lines-report                   # 3LOD distribution from a YAML overlay
└── challenge                      # Effective Challenge log
    ├── add                        # Log a challenge event
    ├── list                       # List challenges (filter + --json)
    └── show                       # Show one challenge (formatted + --json)
```

REST equivalents under `/api/model-risk/models/*`:

```
GET    /api/model-risk/models                         # list + pagination + filters
POST   /api/model-risk/models                         # create
GET    /api/model-risk/models/{id}                    # fetch
PUT    /api/model-risk/models/{id}                    # full-replace
DELETE /api/model-risk/models/{id}                    # delete (204)
GET    /api/model-risk/models/{id}/next-validation-due  # cadence preview
GET    /api/model-risk/models/{id}/documentation      # Markdown doc (text/plain)
GET    /api/model-risk/models/{id}/validation-report  # Markdown report
```

## Data model

The `ModelInventory` Pydantic schema captures the SR 11-7
"Conceptual Soundness" inventory expectations:

| Field | Type | Notes |
|---|---|---|
| `id` | UUID | Auto-generated. |
| `name` | str | Human-readable model name. |
| `purpose` | str | SR 11-7 §III.A purpose narrative. |
| `methodology` | enum | `statistical` / `ml` / `rules_based` / `llm` / `expert_judgment` / `hybrid` |
| `vendor_or_internal` | enum | `internal` / `vendor` |
| `vendor_id` | str \| None | UUID cross-link to v0.7.9 TPRM `Vendor.id`. **Required** for vendor-provenance models; **must be absent** for internal. |
| `tier` | enum | `tier_1` / `tier_2` / `tier_3` (drives validation cadence) |
| `owner` | str | Internal model owner email. |
| `inputs` | list\[ModelInput\] | Each: name + source_system + optional transformation / classification / refresh_cadence. |
| `outputs` | list\[ModelOutput\] | Each: name + decision_type + downstream_consumers. |
| `last_validation_date` | date \| None | Anchor for the auto-cadence. |
| `validation_findings` | list\[ValidationFinding\] | Each: title + description + severity + status + detected_at + optional remediation. |
| `next_validation_due` | date \| None | Auto-computed from tier + last_validation_date; explicit override always wins. |
| `retirement_plan` | str \| None | Documented model retirement / replacement plan. |
| `notes` | str \| None | Free-text operator notes. |
| `evidence_refs` | list\[EvidenceRef\] | Sigstore-signed evidence chain (validation reports, back-tests, sensitivity analyses). Reuses the v0.7.9 TPRM EvidenceRef schema. |
| `created_at` / `updated_at` / `evidentia_version` | auto | Standard EvidentiaModel auto-fields. |

### Vendor-or-internal contract

A `@model_validator(mode="after")` enforces the cross-link
contract:

- Vendor-provenance models **must** set `vendor_id` (UUID) so
  the SR 11-7 §V vendor-risk overlay applies.
- Internal-provenance models **must not** set `vendor_id` (it
  has no meaning for internal models).

The post-validator pattern (vs `@field_validator`) ensures the
check fires even when `vendor_id` defaults to None.

### Auto-cadence

`compute_next_validation_due()` maps tier + last_validation_date:

- Tier 1 = 12 months (annual)
- Tier 2 = 24 months (biennial)
- Tier 3 = 36 months (triennial)

Date arithmetic is calendar-aware via stdlib `calendar`: a
Tier 1 model last-validated on Feb 29 of a leap year + 12 months
clamps to Feb 28 of the following non-leap year. Same year-roll
handling pattern as `Vendor.compute_next_review_due`.

## Quick start

### Add a model

```
$ evidentia model-risk model add \
    --name "FICO scorer v3" \
    --purpose "Score consumer credit applications" \
    --methodology ml \
    --vendor-or-internal internal \
    --tier tier_1 \
    --owner ml-team@example.com \
    --last-validation-date 2025-06-15
Added model FICO scorer v3 (id: 80e8b404-0f2b-4e29-bd8a-617275aa732c)
```

The next validation auto-computes to 2026-06-15 (Tier 1 = annual).

### List models

```
$ evidentia model-risk model list --tier tier_1
                       Model inventory (1 total)
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━┓
┃ ID       ┃ Name          ┃ Tier   ┃ Methodology ┃ Provenan ┃ Owner               ┃ Next validation┃ Findings ┃ Ev ┃
┃          ┃               ┃        ┃             ┃ ce       ┃                     ┃                ┃          ┃    ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━┩
│ 80e8b404 │ FICO scorer v3│ tier_1 │ ml          │ internal │ ml-team@example.com │ 2026-06-15     │ 0        │ 0  │
└──────────┴───────────────┴────────┴─────────────┴──────────┴─────────────────────┴────────────────┴──────────┴────┘
```

### Generate documentation

```
$ evidentia model-risk doc generate 80e8b404-0f2b-4e29-bd8a-617275aa732c \
    --output reports/fico-v3-doc.md
Wrote model documentation to reports/fico-v3-doc.md (1842 chars).
```

The generated Markdown covers 9 SR 11-7-aligned sections:
identification, purpose, methodology, inputs, outputs,
assumptions/limitations, validation history, monitoring/retirement,
audit trail.

### Generate validation report

```
$ evidentia model-risk validation-report generate \
    80e8b404-0f2b-4e29-bd8a-617275aa732c \
    --output reports/fico-v3-validation.md
Wrote validation report to reports/fico-v3-validation.md (1426 chars).
```

The validation report includes an executive summary with **HIGH
findings open warning callout**, finding-disposition table
(severity × status), detailed findings table, per-finding
remediation narrative, and tier-driven cadence context. If any
HIGH-severity finding is in OPEN status, a regulator-friendly
warning callout fires at the top of the report:

```
> ⚠️ **HIGH-severity findings open**: 1
>
> Per SR 11-7 §III.D, HIGH-severity validation findings should
> block the model from production use until remediated.
```

## AI-feature linkage (P0.6.4)

The v0.7.10 P0.6.4 feature wires
`evidentia_core.models.risk.RiskStatement.model_inventory_ref`
through `evidentia_ai.RiskStatementGenerator`:

```python
from evidentia_ai import RiskStatementGenerator

gen = RiskStatementGenerator(
    model="claude-sonnet-4",
    model_inventory_id="80e8b404-0f2b-4e29-bd8a-617275aa732c",
)
risk = gen.generate(gap, system_context)
assert risk.model_inventory_ref == "80e8b404-0f2b-4e29-bd8a-617275aa732c"
```

Every RiskStatement produced by the generator now carries the
inventory linkage. SR 11-7 / SR 26-02 audit trace-back becomes:

> "This risk statement was generated by ML model 80e8b404 tracked
> in inventory entry 80e8b404, validated on 2025-06-15 by team
> ml-team@example.com, tier 1 with annual cadence, next due
> 2026-06-15."

The linkage is **opt-in** — operators with no model-risk module
simply don't pass `model_inventory_id` and behavior matches all
pre-v0.7.10 callers.

## Three Lines of Defense (P1.5 G1)

`evidentia governance lines-report` consumes a YAML overlay
mapping owner emails to line-of-defense classifications and
produces a Markdown distribution report.

YAML overlay shape:

```yaml
- email: alice@example.com
  line_of_defense: first
  team: Loan Origination
  title: Senior Underwriter
- email: bob@example.com
  line_of_defense: second
  team: MRM
  title: Director, Model Risk
- email: carol@example.com
  line_of_defense: third
  team: Internal Audit
  title: Senior Auditor
```

```
$ evidentia governance lines-report \
    --classifications owners.yaml \
    --output reports/lines-of-defense.md
Wrote 3LOD report to reports/lines-of-defense.md (3 owner(s); 1st=1 / 2nd=1 / 3rd=1).
```

The report contains:

1. Executive summary — counts + percentages per line + total
2. **3LOD crossover warning callout** — fires when any email is
   classified across multiple lines. Per FFIEC + OCC + FRB
   regulator expectations, an individual cannot simultaneously
   perform 1st-line execution + 2nd-line oversight, or 2nd-line
   oversight + 3rd-line audit assurance, on the same activity.
3. Per-line owner listing with team + title metadata
4. Per-team breakdown — which lines each team participates in

## Effective Challenge log (P1.5 G2)

`evidentia governance challenge` logs SR 11-7 §III.D effective-
challenge events:

```
$ evidentia governance challenge add \
    --subject-model-id 80e8b404-0f2b-4e29-bd8a-617275aa732c \
    --challenger-email mrm-director@example.com \
    --challenger-role "MRM Director" \
    --challenge-date 2026-01-15 \
    --challenge-topic "Methodology — feature selection rationale" \
    --challenge-substance "Why were 5 alternative feature sets evaluated? Show comparison + criteria." \
    --outcome pending
Logged challenge Methodology — feature selection rationale (id: 47a4fdcf-c71f-4593-9c46-cc64ccd5a22f)
```

Records carry: subject_model_id (cross-link to ModelInventory.id),
challenger identity + role (substantiates independence), date,
topic, substance, optional response, outcome (accepted / rejected
/ modify / pending), outcome rationale, optional resolved_at.

## OSS license + data sovereignty

The MRM module ships under Apache 2.0 like the rest of Evidentia.
Vendor-or-internal model classifications, inventory metadata,
validation findings, and challenge logs all live in operator-side
JSON files (configurable via `EVIDENTIA_MODEL_STORE_DIR` /
`EVIDENTIA_CHALLENGE_STORE_DIR` env vars) — Evidentia never
transmits this data to external services.

## See also

- `docs/tprm.md` — Third-Party Risk Management module (v0.7.9).
  Vendor inventory cross-links to the model-risk module via
  `ModelInventory.vendor_id`.
- `docs/threat-model.md` — STRIDE threat model. Section
  v0.7.10 attack-surface delta covers the new model-risk +
  governance surfaces.
- `docs/positioning-and-value.md` — strategic context including
  the SR 26-02 GenAI-exclusion regulator-vacuum positioning.
- `docs/release-checklist.md` — per-release SOP including the
  pre-tag review gates.
