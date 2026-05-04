# Audit chain-of-custody

Comprehensive walkthrough of Evidentia's retention metadata + WORM
backend abstraction, introduced in v0.7.11 P0. Closes the audit
chain-of-custody gap that v0.7.x had been pointing at since the
v0.7.0 enterprise-grade list — collected evidence can now carry
per-record retention policies aligned with regulatory record-
retention regimes.

## Why audit chain-of-custody in Evidentia

Regulators require demonstrable retention controls on audit
evidence. Failure to retain records within mandatory windows is a
common audit finding; failure to securely purge expired records
under data-minimization regimes (GDPR / CCPA) is the inverse
finding. Evidentia v0.7.11 ships:

| Domain | Primary guidance | Default retention |
|---|---|---|
| Broker-dealer records | SEC Rule 17a-4 + FINRA Regulatory Notice 17-21 | 6 years (3 years easily accessible) |
| Tax records | IRS 1.6001-1 | 7 years |
| SOX audit evidence | Sarbanes-Oxley §404 | 7 years |
| Protected health information | HIPAA Privacy Rule §164.530(j) | 6 years |
| Bank records | GLBA + FFIEC IT Handbook + 12 CFR 30 Appendix B | 5 years (most categories) |
| Cardholder data logs | PCI DSS 10.7 | 1 year (3 months online) |
| Model documentation | OCC Bulletin 2011-12 / FRB SR 11-7 + SR 26-02 | Life of model + 7 years |
| Personal data | GDPR / CCPA | Purpose-limited (operator-set) |
| Generic | Defensive default | 7 years |

Evidentia ships the metadata + lifecycle layer in v0.7.11. Real
WORM (Write-Once-Read-Many) cloud-backed enforcement (S3 Object
Lock, Azure Immutable Blob, GCS Bucket Lock) is documented via
the `WORMBackend` abstract base class; concrete implementations
land in v0.7.12 with their respective extras.

## Module surface

```
evidentia retention
├── set                # add a retention metadata record
├── list               # show all tracked records (filterable)
├── show               # show one record's details
├── extend             # extend lock-until (WORM cannot shorten)
├── transition         # transition lifecycle stage
├── delete             # delete metadata record
└── report             # Markdown audit posture report
```

Public Python surface (`evidentia_core.retention`):

- `RetentionClassification` enum (10 regulator-aligned classes)
- `RetentionPolicy` reusable policy template
- `RetentionMetadata` per-record schema
- `RetentionLifecycleStage` state machine (active / preserved /
  expired / purged)
- `is_locked()` legal-hold-aware predicate
- `transition_lifecycle()` enforces legal transitions
- `default_retention_days()` per-classification defaults
- `generate_retention_report()` deterministic Markdown report
- `WORMBackend` ABC + `LocalFilesystemWORM` reference impl

## Lifecycle state machine

```
        ┌─────────────┐
        │   ACTIVE    │ ← record created; retention countdown
        └─────────────┘
         │           │
         ▼           ▼
  ┌──────────┐  ┌──────────┐
  │PRESERVED │←→│ EXPIRED  │ ← lock window passed (no legal hold)
  └──────────┘  └──────────┘
   (legal hold)      │
                     ▼
                ┌──────────┐
                │  PURGED  │ ← terminal; metadata retained for audit
                └──────────┘
```

Transition rules:

- **ACTIVE → PRESERVED**: always allowed (legal hold trigger,
  litigation hold, regulatory inquiry)
- **PRESERVED → ACTIVE**: legal hold released
- **ACTIVE / PRESERVED → EXPIRED**: requires lock window passed
  AND no legal hold
- **EXPIRED → PURGED**: requires no legal hold; the canonical
  purge path
- **Anything → PURGED directly (skipping EXPIRED)**: ❌ forbidden
- **PURGED → anything**: ❌ terminal state

Illegal transitions raise `RetentionTransitionError` with a clear
message describing why.

## Quick-start sequence

### Set retention on a record

```bash
$ evidentia retention set \
    --classification sox-404 \
    --record-pointer /var/audit/evidence/2026-q1-sox-package.zip \
    --notes "Q1 2026 SOX §404 control testing evidence"
Tracked retention record (id: 80e8b404-...); classification: sox-404; lock_until: 2033-05-04
```

The `lock_until` auto-populates from `created_at + retention_period_days`
(SOX-404 default = 7 years).

### List records

```bash
$ evidentia retention list --classification sox-404
                       Retention records (1 total)
┏━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ID       ┃ Class        ┃ Stage  ┃ Lock-until ┃ Locked? ┃ Hold? ┃ Pointer                   ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 80e8b404 │ sox-404      │ active │ 2033-05-04 │    ✓    │   —   │ /var/audit/evidence/...  │
└──────────┴──────────────┴────────┴────────────┴─────────┴───────┴───────────────────────────┘
```

### Apply legal hold (litigation pending)

```bash
$ evidentia retention transition 80e8b404-... --new-stage preserved
Transitioned retention id=80e8b404: active → preserved
```

Now the record is exempt from automatic expiration even if the
lock window passes.

### Extend retention (legal hold cycle)

```bash
$ evidentia retention extend 80e8b404-... --new-lock-until 2040-12-31
Extended retention id=80e8b404; lock_until: 2033-05-04 → 2040-12-31
```

WORM principle: retention can only be **extended**, never
**shortened**. The CLI rejects shortening attempts with a clear
error.

### Audit report

```bash
$ evidentia retention report --output reports/retention-2026-q2.md
Wrote retention report to reports/retention-2026-q2.md (12 record(s)).
```

Sample report excerpt:

```markdown
# Retention Posture Report

_As of 2026-05-04, 12 record(s) tracked across the audit chain-of-custody._

> ℹ️ **2 record(s) eligible for secure purge.** Review §3 below;
> documented disposal process applies.

| Stage | Count |
| --- | --- |
| ACTIVE | 8 |
| PRESERVED | 1 |
| EXPIRED | 2 |
| PURGED | 1 |
| **Locked (in retention window)** | **8** |
| **Under legal hold** | **1** |
| **Total** | **12** |
```

## WORM backend integration

The `WORMBackend` abstract base class defines the contract any
concrete WORM-storage backend implements:

```python
from evidentia_core.retention.worm import WORMBackend
from evidentia_core.retention import RetentionMetadata

class WORMBackend(ABC):
    @abstractmethod
    def put(self, record_id: str, payload: bytes,
            metadata: RetentionMetadata) -> None: ...
    @abstractmethod
    def get(self, record_id: str) -> bytes: ...
    @abstractmethod
    def get_metadata(self, record_id: str) -> RetentionMetadata: ...
    @abstractmethod
    def delete(self, record_id: str, today: date | None = None) -> None: ...
    @abstractmethod
    def extend_retention(self, record_id: str,
                         new_lock_until: date) -> RetentionMetadata: ...
```

### Reference implementation: `LocalFilesystemWORM`

```python
from evidentia_core.retention.worm import LocalFilesystemWORM
from evidentia_core.retention import (
    RetentionMetadata, RetentionClassification,
)

backend = LocalFilesystemWORM(root="/var/evidentia/worm")

metadata = RetentionMetadata(
    classification=RetentionClassification.SOX_404,
    retention_period_days=7 * 365,
    record_pointer="/path/to/evidence.zip",
)

backend.put(metadata.id, evidence_bytes, metadata)
```

The reference implementation enforces WORM semantics via
**application-level checks against the metadata** — it does NOT
provide hardware-level WORM guarantees. Suitable for development
+ testing; for regulator-grade chain-of-custody, operators must
deploy a cloud-backed WORM backend.

### Concrete cloud backends (v0.7.12)

| Backend | Cloud feature | Extra |
|---|---|---|
| `S3ObjectLockWORM` | S3 Object Lock (compliance + governance modes) | `evidentia[worm-s3]` |
| `AzureImmutableBlobWORM` | Azure Immutable Blob Storage (time-based + legal hold) | `evidentia[worm-azure]` |
| `GCSBucketLockWORM` | GCS Bucket Lock (retention policy + lock) | `evidentia[worm-gcs]` |

These ship in v0.7.12 with comprehensive tests against the
respective cloud-provider mocks (moto for S3, azure-mgmt-storage
mocks, GCS test stub).

## Cross-link to v0.7.10 financial-services overlay

The retention primitives integrate with the v0.7.9 + v0.7.10
financial-services overlay:

- **Vendor records**: tag a vendor's evidence with
  `RetentionClassification.GLBA` (5-year default) at intake time
- **Model risk artifacts**: model docs + validation reports use
  `RetentionClassification.MODEL_RISK` (life + 7-year default)
- **Effective challenge logs**: retain per the model-risk class
  for audit defensibility
- **Workflow logs**: retain per the activity classification

This composition is operator-driven — Evidentia provides the
primitives + CLI; operators wire them into their evidence-
collection pipelines per their institutional retention policy.

## Standing-rule alignment

| Standard | Coverage |
|---|---|
| SEC Rule 17a-4 | 6-year default (matches §3 paragraph (b)) |
| FINRA Regulatory Notice 17-21 | 6-year default (matches §3110.07) |
| IRS 1.6001-1 | 7-year default (general taxpayer) |
| Sarbanes-Oxley §404 | 7-year default (matches §103) |
| HIPAA Privacy Rule §164.530(j) | 6-year default |
| GLBA + FFIEC | 5-year default; FFIEC Outsourcing booklet bundled |
| PCI DSS 10.7 | 1-year default |
| OCC 2011-12 / SR 11-7 / OCC 2026-13a / SR 26-02 | "life + 7 years" — operator extends past life |
| GDPR Article 5(1)(e) | Purpose-limited (default 0; operator must set) |

## See also

- `docs/governance-metrics.md` — KRI/KPI/KGI overlay (v0.7.11 P1.5 G3)
- `docs/risk-quantification.md` — Open FAIR (v0.7.11 P1.5 G4)
- `docs/financial-sector-overlay.md` — TPRM + Model Risk + governance
- `docs/threat-model.md` — STRIDE threat model
- `docs/v0.7.11-plan.md` — release plan
