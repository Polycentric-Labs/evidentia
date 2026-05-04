# GDPR Article 17 purge flow

GDPR Article 17 ("right to erasure" / "right to be forgotten")
gives EU data subjects the right to request deletion of their
personal data. This conflicts with the WORM (Write-Once-Read-
Many) immutability that records under retention metadata enjoy
under most regulatory regimes (SEC 17a-4, FINRA 3110, SOX, IRS,
HIPAA, GLBA, etc.).

Evidentia's resolution: **GDPR records are tracked separately**
from regulator-mandated retention records via the
`RetentionClassification.GDPR` enum value, and the
`purge_immediately` operator workflow handles deletion requests
through a defined workflow with full audit-trail provenance.

---

## The data model

GDPR purpose-limited records are characterized by:

- `RetentionClassification.GDPR` (`"gdpr"`) classification
- `retention_period_days = 0` (no fixed retention period)
- `lock_until = None` (computed automatically from the above)

This is intentional. GDPR retention is **operator-managed** —
there's no calendar-driven retention floor. The operator (or
their data-protection officer) decides when the purpose has been
fulfilled and the record should be purged.

Non-GDPR records take the standard path:

- Their classification is one of SEC 17a-4 / FINRA 3110 / SOX /
  IRS / HIPAA / GLBA / PCI / model-risk / generic
- `retention_period_days > 0`
- `lock_until = created_at + retention_period_days`

---

## The functional gap (closed in v0.7.12)

Pre-v0.7.12, GDPR records had no path to transition
ACTIVE → EXPIRED via `transition_lifecycle()` because the
standard precondition required `lock_until is not None and today
>= lock_until` — an impossible condition for GDPR records (where
`lock_until` is always None).

The v0.7.11 Step-4 /security-review surfaced this; the v0.7.12
P1 fix introduces:

1. **`transition_lifecycle(force_gdpr_purge: bool = False)`** —
   when True AND the record is GDPR-shaped (`retention_period_days
   == 0`) AND no legal hold is active, the override permits the
   ACTIVE → EXPIRED transition.

2. **`WORMBackend.purge_immediately(record_id, *, gdpr_request_ref,
   operator_id)`** — operator-friendly entry point that runs the
   full purge workflow atomically (validate → transition → delete
   → return audit-trail snapshot).

The override is **scoped**: it does not apply to non-GDPR records
(those still must satisfy the standard retention-window
precondition) and it does not bypass legal hold (which trumps
GDPR per most legal frameworks).

---

## Operator workflow

### 1. Receive the GDPR request

Data subject (or their representative) sends a deletion request
via your designated DPO channel (email, web form, etc.). Capture:

- The request reference (your ticketing-system ID, email subject,
  or regulator inquiry ID)
- The data subject identity (verified per your standard process)
- The records covered (typically by data-subject ID lookup)

### 2. Verify the records are GDPR-shaped

```python
from evidentia_core.retention.metadata import RetentionClassification

for record_id in covered_records:
    md = backend.get_metadata(record_id)
    assert md.classification == RetentionClassification.GDPR.value
    assert md.retention_period_days == 0
    assert md.lock_until is None
```

If any record is **not** GDPR-shaped, surface that to legal
counsel — non-GDPR records may be subject to retention obligations
that override GDPR (the Recital 65 "compliance with a legal
obligation" exception).

### 3. Verify no legal hold is active

```python
for record_id in covered_records:
    md = backend.get_metadata(record_id)
    if md.legal_hold:
        # Legal hold trumps GDPR for litigation / regulatory
        # inquiry. Surface to legal counsel BEFORE proceeding.
        raise SystemExit(f"Legal hold on {record_id}; halt + escalate")
```

### 4. Execute the purge

```python
for record_id in covered_records:
    snapshot = backend.purge_immediately(
        record_id,
        gdpr_request_ref="GDPR-REQ-2026-001",
        operator_id="alice@evidentia.dev",
    )
    print(f"Purged {record_id}; audit snapshot: {snapshot.id}")
```

The returned `snapshot` is a `RetentionMetadata` object with
`lifecycle_stage = PURGED`. The underlying record bytes are
deleted; the snapshot exists only for the audit trail.

### 5. Persist the audit-trail snapshots

```python
import json

audit_log = "purge_audit_2026.jsonl"
with open(audit_log, "a", encoding="utf-8") as fh:
    for snapshot in snapshots:
        fh.write(snapshot.model_dump_json() + "\n")
```

This is the **legal-counsel-defensible artifact**: every purge
emits an entry with operator + GDPR-request-ref + timestamp +
record metadata (everything except the deleted payload). Persist
to durable, append-only storage (your SIEM, Splunk, append-only
audit DB, or a separate WORM bucket dedicated to compliance
tracking).

The auditing also fires `EventAction.RETENTION_GDPR_PURGE` events
through the standard audit-event channel — your SIEM / log
aggregator can correlate per-purge events with the snapshot
records.

---

## What the override does NOT permit

| Scenario | Override applies? | Why |
|---|---|---|
| Non-GDPR record (retention_period_days > 0) | No | Standard retention path required; override scoped to GDPR-shaped records only |
| GDPR record under legal hold | No | Legal hold trumps GDPR per most legal frameworks; release hold first if appropriate |
| Empty `gdpr_request_ref` | No | Audit-trail provenance required; rejected at WORMBackend level |
| Empty `operator_id` | No | Audit-trail provenance required |
| Already-purged record | No | `delete()` will reject (record not found) |

---

## Cloud-specific considerations

### S3

Records under S3 Object Lock in **Compliance** mode cannot be
deleted even with the operator override — Compliance mode means
"root cannot bypass." For GDPR purpose-limited records on S3,
use **Governance** mode + the `s3:BypassGovernanceRetention` IAM
permission on the operator principal.

For S3 records configured with `retention_period_days = 0`, the
Object Lock RetainUntilDate is never set, so the standard delete
path works without the bypass permission.

### Azure

Azure Immutable Blob Storage in **Locked** mode similarly cannot
be deleted by the account owner. Use **Unlocked** mode for GDPR
records, OR keep them in a separate container that doesn't have
immutability policies enabled.

### GCS

GCS bucket retention applies bucket-wide. For GDPR records, use
a separate GCS bucket without a locked retention policy. Apply
per-object holds (`temporary_hold`) only when legal hold is
needed; release them when GDPR purge proceeds.

### LocalFilesystemWORM

The reference implementation enforces WORM at the metadata layer
only. The operator override works as documented; useful for
development + testing but not for production regulator-grade
audit chain-of-custody.

---

## Audit-trail expectations

Every GDPR purge emits:

1. A **lifecycle-transition event** when the record moves from
   ACTIVE → EXPIRED (via the override path)
2. A **delete event** when the WORMBackend physically removes
   the payload
3. A **purge-snapshot event** capturing the operator +
   gdpr_request_ref + final metadata state

Combined, these provide the legal-counsel-defensible artifact:

> "On {date}, operator {operator_id} executed GDPR Article 17
> purge {gdpr_request_ref} covering record {record_id} of
> classification {GDPR}. The record had retention_period_days=0
> (purpose-limited per GDPR). No legal hold was active at time
> of purge."

This statement can be reconstructed from the audit-event stream
without the deleted record itself — exactly what
data-protection auditors want.

---

## Cross-references

- WORM backend operator setup: [`docs/worm-backends.md`](worm-backends.md)
- Audit chain-of-custody architecture: [`docs/audit-chain-of-custody.md`](audit-chain-of-custody.md)
- Retention metadata schema: `evidentia_core.retention.metadata`
- WORMBackend ABC + `purge_immediately`: `evidentia_core.retention.worm`
- EventAction values for the audit trail:
  `RETENTION_RECORD_PURGED`, `RETENTION_GDPR_PURGE`,
  `RETENTION_LIFECYCLE_TRANSITIONED`
