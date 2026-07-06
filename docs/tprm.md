# Third-Party Risk Management (TPRM) module

Comprehensive walkthrough of Evidentia's TPRM capability surface,
introduced in v0.7.9. The module brings vendor inventory, due-
diligence questionnaire generation + ingestion, concentration-risk
reporting, vendor-risk SaaS collectors, and OSCAL TPRM emit into
the Evidentia evidence chain.

## Why TPRM in Evidentia

OCC Bulletin 2013-29, FRB SR 13-19, FFIEC IT Examination Handbook
Outsourcing booklet, and the SR 11-7 / OCC 2011-12 / SR 26-02 /
OCC 2026-13a model-risk regulatory stack all expect financial-
services institutions to maintain a comprehensive third-party risk
program with a documented vendor inventory, scheduled due-diligence
review cadence, ongoing-monitoring posture for high-tier vendors,
4th-party (subprocessor) disclosure tracking, and concentration-
risk analysis across geographies + cloud providers + critical
service categories.

Vanta-class GRC SaaS tools cover vendor inventory + DD workflow
but don't ship the regulatory catalog crosswalks (FFIEC + OCC +
FRB). OSS GRC ecosystem tools (CISO Assistant, Eramba,
compliance-trestle) primarily focus on NIST 800-53 / ISO 27001 /
SOC 2; the financial-services regulatory stack is underserved.
Evidentia v0.7.9 fills that gap as an OSS-native, Apache 2.0,
Sigstore-signable, OSCAL-emit-capable TPRM module.

## Module surface

The TPRM module ships as `evidentia tprm` — a top-level CLI
subcommand group sibling to `evidentia gap` / `evidentia risk` /
`evidentia collect` / `evidentia oscal` / `evidentia integrations`.

```
evidentia tprm
├── vendor                      # Vendor inventory CRUD
│   ├── add                     # Add a vendor (atomic flags + --from-yaml)
│   ├── list                    # List vendors (filter by criticality / type)
│   ├── show                    # Show one vendor (human-readable + --json)
│   ├── edit                    # Edit a vendor (flags + --from-yaml + --editor)
│   └── delete                  # Delete a vendor (--yes to bypass prompt)
├── concentration-report        # Aggregate vendor exposure across dimensions
└── dd-questionnaire            # Due-diligence questionnaire generation + ingest
    ├── generate                # Pre-fill DD questionnaire for a vendor
    └── ingest                  # Load completed vendor responses back
```

REST surface mirrors the CLI — see [REST reference](#rest-reference)
below.

## Vendor inventory model

Each vendor is a `Vendor` Pydantic model (in
`evidentia_core.models.tprm`) with the following fields:

| Field | Type | Notes |
|---|---|---|
| `id` | `str` (UUID v4) | Stable identifier; auto-generated |
| `name` | `str` | Vendor name |
| `type` | `VendorType` enum | `saas` / `subservice_org` / `contractor` / `data_processor` / `cloud_provider` / `open_source` |
| `criticality_tier` | `CriticalityTier` enum | `critical` / `high` / `medium` / `low` per FFIEC criticality model |
| `relationship_owner` | `str` | Internal owner email/identifier |
| `region` | `str \| None` | Free-text geo / cloud-region label (max 128 chars) |
| `contract_start_date` | `date` | |
| `contract_end_date` | `date \| None` | |
| `last_due_diligence_review` | `date \| None` | |
| `next_review_due` | `date \| None` | Computed via `compute_next_review_due()` from criticality tier (critical/high → 12mo, medium → 24mo, low → 36mo) |
| `regulatory_classification` | `list[RegulatoryClassification]` | Multi-valued: `custody` / `clearing` / `model` / `data_processor` / `critical_third_party` |
| `fourth_parties` | `list[FourthParty]` | Disclosed sub-processors, each with name + type + relationship |
| `residual_risk_score` | `int \| None` | 1-25 inherent × control = residual matrix |
| `notes` | `str \| None` | |
| `evidence_refs` | `list[EvidenceRef]` | Sigstore-signed evidence collected per vendor; each entry must carry either `artifact_id` or `file_path`, and SHA-256 hash requires `file_path` |
| `created_at` / `updated_at` / `evidentia_version` | auto | Standard Evidentia provenance fields |

The `model` regulatory_classification flag is the cross-link to the
v0.7.9-reserved Model Risk Management module (deferred to v0.7.10
"Federal compliance" cycle per plan §19.1).

## Storage

Vendor records are persisted as JSON files under a platformdirs-
backed user directory, one file per vendor named `<vendor_id>.json`.
The default location is `evidentia_data_dir() / vendor_store/`;
operators can override via the `EVIDENTIA_VENDOR_STORE_DIR` env
var (e.g., for CI test isolation, multi-tenant separation, or
WORM-backend deployments).

Save semantics use `os.replace(tmp, out_path)` for atomicity — a
crash mid-write leaves either the prior file or the new file
intact, never a half-written record.

## CLI reference

### `evidentia tprm vendor add`

Hybrid input model — atomic flags for the common case, `--from-yaml`
for complex vendors (e.g., with 4th-party disclosures or evidence-
ref entries):

```bash
# Common case — atomic flags
evidentia tprm vendor add \
  --name "Acme SaaS Co" \
  --type saas \
  --criticality-tier high \
  --owner ciso@example.com \
  --contract-start-date 2025-01-01 \
  --residual-risk-score 12 \
  --region us-east-1

# Complex vendor — load from YAML
evidentia tprm vendor add --from-yaml acme-vendor.yaml
```

Where `acme-vendor.yaml` is:

```yaml
name: Acme SaaS Co
type: saas
criticality_tier: high
relationship_owner: ciso@example.com
contract_start_date: 2025-01-01
contract_end_date: 2026-01-01
region: us-east-1
regulatory_classification: [data_processor, critical_third_party]
fourth_parties:
  - name: AWS
    type: cloud_provider
    relationship: iaas
  - name: Stripe
    type: saas
    relationship: payments
residual_risk_score: 12
notes: |
  Initial onboarding 2025-01; contract due for renewal 2026-01.
```

### `evidentia tprm vendor list`

```bash
# Rich table by default
evidentia tprm vendor list

# JSON for piping (bare array — see CLI vs REST envelope note below)
evidentia tprm vendor list --json > vendors.json

# Filtered
evidentia tprm vendor list --criticality-tier critical
evidentia tprm vendor list --type cloud_provider
```

**CLI vs REST envelope contract** (closes v0.7.9 P0.1 H-2 carry-
over): the CLI emits a bare JSON array; the REST endpoint emits a
paginated envelope `{"vendors": [...], "total": N, "skip": N,
"limit": N}`. The CLI's bare-array shape is intentional — it
makes shell pipelines clean (`evidentia tprm vendor list --json |
jq '...'`).

### `evidentia tprm vendor show`

```bash
evidentia tprm vendor show 12345678-1234-...        # human-readable
evidentia tprm vendor show 12345678-1234-... --json # raw dump
```

### `evidentia tprm vendor edit`

Three input modes:

```bash
# Atomic flags (one-off field updates)
evidentia tprm vendor edit 12345678-1234-... --next-review-due 2026-04-01

# Scripted full-replace
evidentia tprm vendor edit 12345678-1234-... --from-yaml updated.yaml

# Interactive — opens current YAML in $EDITOR
evidentia tprm vendor edit 12345678-1234-... --editor
```

### `evidentia tprm vendor delete`

```bash
evidentia tprm vendor delete 12345678-1234-...        # prompts for confirmation
evidentia tprm vendor delete 12345678-1234-... --yes  # bypass prompt (CI-friendly)
```

### `evidentia tprm concentration-report`

Aggregates vendor exposure across configurable dimensions:

| Dimension | Source on Vendor | Use case |
|---|---|---|
| `region` | `vendor.region` (free-text) | Regulator concentration-risk thresholds |
| `cloud-provider` | direct `vendor.type==cloud_provider` PLUS `vendor.fourth_parties[].name` filtered to `type=cloud_provider` (with `(direct)`/`(4th-party)` source suffix) | Cloud concentration risk per FFIEC + OCC guidance |
| `4th-party` | `vendor.fourth_parties[].name` (any type) | Identify single points of failure |
| `service-category` | `vendor.type` | Diversification analysis |
| `criticality-tier` | `vendor.criticality_tier` | Operator scope-of-review prioritization |
| `regulatory-classification` | `vendor.regulatory_classification[]` (multi-valued) | OCC 2013-29 critical-third-party flagging |

```bash
# HTML report with sortable tables (single-file, no JS deps)
evidentia tprm concentration-report \
  --by region,cloud-provider \
  --threshold 30 \
  --format html \
  --output concentration.html

# JSON for tooling
evidentia tprm concentration-report --format json --output report.json

# CSV for spreadsheet pivot (with CSV-injection defenses applied)
evidentia tprm concentration-report --format csv --output report.csv
```

Threshold semantics: when set, every per-value distribution row
whose vendor share meets-or-exceeds the threshold gets
`exceeds_threshold=true` in the JSON shape and a flag column in
the HTML output. Operators get the concrete row to investigate.

### `evidentia tprm dd-questionnaire generate`

Pre-fills vendor metadata into a DD questionnaire so the receiving
vendor sees only control questions, not blank metadata templates.

```bash
# Generic FFIEC-aligned baseline as JSON
evidentia tprm dd-questionnaire generate \
  --vendor-id 12345678-1234-... \
  --format evidentia-generic \
  --output-format json \
  --output q.json

# CAIQ-Lite as CSV for spreadsheet workflow
evidentia tprm dd-questionnaire generate \
  --vendor-id 12345678-1234-... \
  --format caiq-lite \
  --output-format csv \
  --output q.csv

# CAIQ-Full (~50 questions) as XLSX (multi-sheet workbook)
evidentia tprm dd-questionnaire generate \
  --vendor-id 12345678-1234-... \
  --format caiq-full \
  --output-format xlsx \
  --output q.xlsx

# SIG via licensed BYO template
evidentia tprm dd-questionnaire generate \
  --vendor-id 12345678-1234-... \
  --format sig \
  --from-template path/to/SIG-2026.xlsx \
  --output sig-prefilled.xlsx
```

#### Format catalogue

| Format | License | Question count | Notes |
|---|---|---|---|
| `evidentia-generic` | Apache-2.0 (Evidentia-original) | ~20 | FFIEC-aligned baseline. 9 domains: Governance, Access Control, Data Handling, Incident Response, Business Continuity, 4th-Party Risk, Personnel, Insurance, Compliance. |
| `caiq-lite` | CC BY 4.0 (CSA CAIQ v4.0.3 derivative) | ~25 | Representative subset of CSA's 245-question CAIQ; covers 15 of the 17 CAIQ control domains. |
| `caiq-full` | CC BY 4.0 (CSA CAIQ v4.0.3 derivative) | ~50 | Expanded representative subset across all standard CSA control domains. v0.7.9 P0.2 second slice. |
| `sig` | Shared Assessments (paywalled) | n/a | BYO XLSX template via `--from-template`. Evidentia pre-fills vendor metadata into the standard SIG layout; question content stays untouched (license compliance). |
| `sig-lite` | Shared Assessments (paywalled) | n/a | Same as `sig` — BYO-only. |

#### Output formats

| Format | Notes |
|---|---|
| `json` | Full Pydantic Questionnaire model dump; machine-consumable for downstream tooling |
| `csv` | Flat, one row per question + vendor-prefill header section + blank `vendor_response` column. CSV-injection-safe (`_csv_safe` neutralizes formula vectors per CWE-1236 / OWASP single-quote prefix). |
| `xlsx` | Multi-sheet workbook: Sheet 1 = vendor metadata, Sheets 2..N = one per question domain. Requires `pip install 'evidentia-core[xlsx]'` (openpyxl, ~3 MB pure-Python). v0.7.9 P0.2 second slice. |

### `evidentia tprm dd-questionnaire ingest`

Loads completed vendor responses back into Evidentia. v0.7.9 P0.2
second slice surface:

```bash
# Ingest a completed JSON questionnaire (vendor auto-resolved
# from prefill block)
evidentia tprm dd-questionnaire ingest \
  --questionnaire completed-q.json

# Ingest CSV against an explicit vendor (override correlation)
evidentia tprm dd-questionnaire ingest \
  --questionnaire completed-q.csv \
  --vendor-id 12345678-1234-...

# Ingest XLSX
evidentia tprm dd-questionnaire ingest \
  --questionnaire completed-q.xlsx \
  --output-format json
```

Auto-detects file format from the extension. Correlation order:

1. `--vendor-id` flag if supplied
2. The questionnaire's embedded `vendor_id` (from the prefill)

Without either, the command exits with a clear error.

Persistence to `Vendor.evidence_refs[]` is queued for a follow-up
release once the audit-chain-of-custody Sigstore-signing wiring
lands. Current ingest displays the parsed responses for operator
review (table or JSON).

## Vendor-risk SaaS collectors

The v0.7.9 P0.4 quartet pulls vendor-inventory data from external
TPRM / security-rating providers into the Evidentia evidence chain
as `SecurityFinding` objects mapped to NIST 800-53 SR-2/SR-3/SR-6 +
RA-3/CA-7 + OCC Bulletin 2013-29 §III.A/§III.A.4 + FRB SR 13-19
§II/§II.D + FFIEC IT Examination Handbook Outsourcing booklet §II.

### Vanta

```bash
export VANTA_API_TOKEN=<token>
evidentia collect vanta --output vanta-findings.json
```

Auth: Vanta Personal Access Token OR OAuth 2.0 client-credentials
access token, scoped to `vendors:read`. Both pass `Authorization:
Bearer <token>`. Cursor-based pagination via `pageInfo.endCursor`
with 2000-vendor default cap (`--max-vendors`). Defensive across
4 high-risk field-shape variants (`riskTier` / `risk_tier` /
`riskLevel` / `risk_level` / nested `riskAssessment.{tier,level,
severity}`).

### Drata

```bash
export DRATA_API_TOKEN=<token>
evidentia collect drata --output drata-findings.json
```

Auth: Drata Personal API token, read-only vendor-inventory scope.
Top-level `nextPageToken` cursor pagination (with Vanta-style
nested `pageInfo` fallback for forward compatibility). Defensive
across 6 high-risk field-shape variants including numeric
`inherentRisk` / `residualRisk` on Drata's documented 1-5 / 1-25
scales.

### BitSight

```bash
export BITSIGHT_API_TOKEN=<token>
evidentia collect bitsight --rating-threshold 700 --output findings.json
```

BitSight is a continuous-rating provider; ratings are on a 250-900
scale (A: 740-900, B: 670-739, C: 600-669, D: 530-599, F: <530).
Auth: HTTP Basic with token as username + empty password (the
collector wraps internally; token never in URLs).

Emits a portfolio-inventory finding per company plus a MEDIUM-
severity low-rating finding when rating < threshold (default 700).
Cross-host pagination guard refuses to follow `next` URLs pointing
off-host or to a downgraded HTTP scheme (TLS-downgrade defense
per CWE-319).

### SecurityScorecard

```bash
export SECURITYSCORECARD_API_TOKEN=<token>
evidentia collect securityscorecard --score-threshold 70 --output findings.json
```

SSC scores 0-100 with grades A (90+), B (80-89), C (70-79), D
(60-69), F (<60). Auth: `Authorization: Token <value>` (distinct
from BitSight's HTTP Basic + Vanta/Drata's Bearer).

Optional `--portfolio-id` flag selects a specific portfolio; when
omitted, the collector lists portfolios + uses the first available.

## OSCAL TPRM emit (v0.7.9 P0.5)

Closes the loop: vendors flow inventory → DD-questionnaire →
concentration-report → vendor-risk-collector findings → OSCAL AR
artifact, all in a single Sigstore-signable evidence bundle.

```bash
# Dump the vendor inventory to JSON
evidentia tprm vendor list --json > vendors.json

# Run gap analysis with vendor-inventory back-matter embedding
evidentia gap analyze \
  --inventory my-controls.yaml \
  --frameworks nist-800-53-rev5-moderate \
  --format oscal-ar \
  --vendor-inventory vendors.json \
  --findings collector-findings.json \
  --output ar.json
```

Each vendor lands in TWO surfaces of the OSCAL Assessment Results
document:

1. **`metadata.parties[]`** as a `type=organization` party
   (standard OSCAL discovery — trestle-conformant tools navigate
   vendors via the OSCAL party model). Each carries Evidentia-
   namespaced props for `vendor-id` / `vendor-type` / `criticality-
   tier` / `relationship-owner` / `contract-start-date` /
   `contract-end-date` / `last-due-diligence-review` /
   `next-review-due` / `region` / `regulatory-classification` /
   `residual-risk-score` / `fourth-party-count` (optional fields
   surface only when present).
2. **`back-matter.resources[]`** as a tamper-evident vendor record
   with canonical-JSON `base64.value` + SHA-256 `rlinks[].hashes[]`.
   Same integrity model as the v0.7.0 finding-resource embedding —
   tampering with a vendor record changes its hash and fails
   `evidentia oscal verify`.

The vendor's party UUID and back-matter resource UUID both equal
`Vendor.id` so cross-references via `href: "#<vendor-id>"` resolve
intra-document. Top-level `metadata.props` gains an Evidentia-
namespaced `vendor-inventory-count` property for quick auditor
discovery.

The OSCAL AR artifact satisfies OCC Bulletin 2013-29 + FRB SR 13-19
+ FFIEC IT Examination Handbook Outsourcing booklet vendor-
inventory expectations in a single tool-portable, integrity-
protected, Sigstore-signable JSON document.

## REST reference

All TPRM REST endpoints follow Evidentia's standard FastAPI
conventions: open auth (token-auth-deferred-to-v0.8.0 plugin
contract), 400 for body-content errors, 503 for upstream/auth
failures, 500 for unexpected.

| Method | Path | Description |
|---|---|---|
| POST | `/api/tprm/vendors` | Create vendor (full Vendor JSON in body; server fills id / created_at / updated_at) |
| GET | `/api/tprm/vendors` | List vendors (paginated envelope; `?skip=N&limit=N`, max limit=1000; filters `?criticality_tier=critical&type=cloud_provider`) |
| GET | `/api/tprm/vendors/{vendor_id}` | Get one vendor |
| PUT | `/api/tprm/vendors/{vendor_id}` | Replace one vendor (full Vendor JSON) |
| DELETE | `/api/tprm/vendors/{vendor_id}` | Delete one vendor |
| GET | `/api/tprm/vendors/{vendor_id}/next-review-due` | Compute the next-review-due date from the vendor's criticality tier (preview helper) |
| GET | `/api/tprm/concentration` | Concentration-risk report; query params `?by=region,cloud-provider&threshold=30&skip=0&limit=100` |
| POST | `/api/tprm/vendors/{vendor_id}/dd-questionnaire?format=...` | Generate questionnaire (returns Questionnaire JSON or 501/Exit(1) for SIG/SIG-Lite without BYO) |
| POST | `/api/collectors/vanta/collect` | Run Vanta vendor-inventory collection |
| POST | `/api/collectors/drata/collect` | Run Drata vendor-inventory collection |
| POST | `/api/collectors/bitsight/collect` | Run BitSight portfolio collection |
| POST | `/api/collectors/securityscorecard/collect` | Run SecurityScorecard portfolio collection |
| GET | `/api/collectors/status` | Report which collectors are installed + which credentials are set (never returns token values) |

## End-to-end example

A complete vendor onboarding + DD round-trip + concentration-
report workflow:

```bash
# 1. Add the vendor to the inventory
evidentia tprm vendor add \
  --name "Acme SaaS Co" \
  --type saas \
  --criticality-tier high \
  --owner ciso@example.com \
  --contract-start-date 2025-01-01 \
  --region us-east-1

VID=$(evidentia tprm vendor list --json | jq -r '.[-1].id')

# 2. Generate a CAIQ-Full DD questionnaire as XLSX
evidentia tprm dd-questionnaire generate \
  --vendor-id $VID \
  --format caiq-full \
  --output-format xlsx \
  --output dd-acme.xlsx

# 3. Send dd-acme.xlsx to the vendor; receive completed-acme.xlsx back

# 4. Ingest the completed responses
evidentia tprm dd-questionnaire ingest \
  --questionnaire completed-acme.xlsx \
  --output-format json

# 5. After multiple vendor onboardings, run concentration analysis
evidentia tprm concentration-report \
  --by region,cloud-provider,4th-party \
  --threshold 30 \
  --format html \
  --output concentration.html

# 6. Pull continuous-rating evidence for ongoing monitoring
export BITSIGHT_API_TOKEN=$(cat ~/.secrets/bitsight.token)
evidentia collect bitsight \
  --rating-threshold 700 \
  --output bitsight-findings.json

# 7. Emit OSCAL AR with vendor-inventory back-matter
evidentia tprm vendor list --json > vendors.json
evidentia gap analyze \
  --inventory my-controls.yaml \
  --frameworks nist-800-53-rev5-moderate \
  --format oscal-ar \
  --vendor-inventory vendors.json \
  --findings bitsight-findings.json \
  --output ar.json
```

## Roadmap (post-v0.7.9)

- **v0.7.10 "Federal compliance + Model Risk"** — `evidentia
  model-risk` module per SR 11-7 / SR 26-02 / OCC 2026-13a + 7
  new bundled catalogs (FFIEC IT Handbook 5 booklets + OCC 2026-
  13a / SR 26-02 + FFIEC CAT) + Three Lines of Defense + Effective
  Challenge governance primitives.
- **v0.7.11 "Audit chain-of-custody"** — retention metadata + WORM
  backend support (S3 Object Lock, Azure Immutable Blob, GCS
  Bucket Lock) + KRI/KPI/KGI + Open FAIR risk quantification +
  process-as-code governance workflows. Ingested questionnaire
  responses persist to `Vendor.evidence_refs[]` with Sigstore
  signing once this lands.

See [`docs/v0.7.9-plan.md`](releases/plans/v0.7.9-plan.md) and
[`docs/ROADMAP.md`](ROADMAP.md) for the full forward plan.
