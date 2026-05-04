# WORM backends — operator setup runbook

Evidentia ships four Write-Once-Read-Many (WORM) backends for
regulator-grade audit chain-of-custody. The local-filesystem
backend is suitable for development + testing; the three
cloud-backed backends provide hardware-WORM enforcement that
even the bucket owner cannot bypass.

| Backend | Module | Extra | Cloud primitive |
|---|---|---|---|
| LocalFilesystemWORM | `evidentia_core.retention.worm` | (none) | App-level metadata checks only |
| S3ObjectLockWORM | `evidentia_core.retention.worm_s3` | `evidentia[worm-s3]` | S3 Object Lock |
| AzureImmutableBlobWORM | `evidentia_core.retention.worm_azure` | `evidentia[worm-azure]` | Azure Immutable Blob Storage |
| GCSBucketLockWORM | `evidentia_core.retention.worm_gcs` | `evidentia[worm-gcs]` | GCS Bucket Lock |

All four implement the same `WORMBackend` ABC contract (put / get
/ get_metadata / delete / extend_retention / apply_legal_hold /
release_legal_hold / purge_immediately) — switching clouds is a
constructor swap.

---

## Common contract

```python
from datetime import date, timedelta

from evidentia_core.retention.metadata import (
    RetentionClassification,
    RetentionMetadata,
)

# Every record carries metadata that drives retention enforcement
metadata = RetentionMetadata(
    classification=RetentionClassification.SOX_404,
    retention_period_days=7 * 365,  # 7 years
    notes="Q3 2026 SOX evidence pull",
)

# Put writes the payload + sets the WORM lock
backend.put("rec-12345", b"<payload bytes>", metadata)

# Get returns the payload bytes; get_metadata returns the sidecar
payload = backend.get("rec-12345")
md = backend.get_metadata("rec-12345")

# Delete is rejected during the retention window — by both the
# application-level 3-layer defense AND the cloud-side WORM enforcement
try:
    backend.delete("rec-12345")
except WORMBackendError as e:
    print(f"Delete blocked (expected): {e}")

# Operator extends retention (cannot shorten — that's a WORM violation)
new_md = backend.extend_retention(
    "rec-12345", new_lock_until=date.today() + timedelta(days=10 * 365)
)

# Operator applies legal hold (overrides retention; trumps GDPR)
backend.apply_legal_hold("rec-12345")
backend.release_legal_hold("rec-12345")
```

The `purge_immediately` operator workflow handles GDPR Article 17
(right-to-erasure) requests. See [`docs/gdpr-purge-flow.md`](gdpr-purge-flow.md)
for the dedicated runbook.

---

## S3 Object Lock setup (AWS)

### Bucket creation

S3 Object Lock **must be enabled at bucket creation time** —
it cannot be added retroactively. Use the AWS CLI:

```bash
aws s3api create-bucket \
  --bucket my-evidentia-worm \
  --region us-east-1 \
  --object-lock-enabled-for-bucket
```

For non-`us-east-1` regions, add `LocationConstraint`:

```bash
aws s3api create-bucket \
  --bucket my-evidentia-worm \
  --region us-west-2 \
  --create-bucket-configuration LocationConstraint=us-west-2 \
  --object-lock-enabled-for-bucket
```

Enable versioning (Object Lock requires it):

```bash
aws s3api put-bucket-versioning \
  --bucket my-evidentia-worm \
  --versioning-configuration Status=Enabled
```

### Compliance vs Governance mode

- **Compliance mode** (recommended for regulator-grade): even the AWS root user cannot bypass the retention period. Use this for SEC 17a-4 / FINRA 3110 / SOX records.
- **Governance mode**: holders of the `s3:BypassGovernanceRetention` IAM permission can override. Use this when GDPR Article 17 right-to-erasure flows are in scope (operator can purge purpose-limited records on demand).

### IAM policy

Minimum permissions for the principal Evidentia uses:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:HeadObject",
        "s3:DeleteObject",
        "s3:PutObjectRetention",
        "s3:PutObjectLegalHold",
        "s3:GetObjectRetention",
        "s3:GetObjectLegalHold"
      ],
      "Resource": "arn:aws:s3:::my-evidentia-worm/*"
    }
  ]
}
```

### Backend instantiation

```python
from evidentia_core.retention.worm_s3 import S3ObjectLockWORM

backend = S3ObjectLockWORM(
    bucket_name="my-evidentia-worm",
    region="us-east-1",
    lock_mode="COMPLIANCE",  # or "GOVERNANCE"
    prefix="evidentia/v1/",   # optional multi-tenant prefix
)
```

The boto3 client uses the standard credential chain
(`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars,
`~/.aws/credentials`, IAM role on EC2/ECS/Lambda, etc.).

---

## Azure Immutable Blob Storage setup

### Storage account + container

Azure Immutable Blob requires version-level immutability support
on the container. Enable via Azure CLI:

```bash
# Create storage account with hierarchical namespace
az storage account create \
  --name myevidentiaworm \
  --resource-group my-rg \
  --location eastus \
  --sku Standard_LRS \
  --enable-hierarchical-namespace false

# Create container with version-level immutability
az storage container-rm create \
  --name evidentia-worm \
  --storage-account myevidentiaworm \
  --resource-group my-rg \
  --enable-vlw  # version-level worm
```

### Locked vs Unlocked policy mode

- **Locked**: the immutability policy cannot be reduced or
  removed; canonical for regulator-grade WORM
- **Unlocked**: operator can shorten retention; useful for
  development and for GDPR right-to-erasure flows

### Backend instantiation

```python
from evidentia_core.retention.worm_azure import AzureImmutableBlobWORM

backend = AzureImmutableBlobWORM(
    account_url="https://myevidentiaworm.blob.core.windows.net",
    container_name="evidentia-worm",
    lock_mode="Locked",  # or "Unlocked"
    prefix="tenant-a/",  # optional
)
```

The default credential is `azure.identity.DefaultAzureCredential`,
which resolves managed identity → env vars → Azure CLI →
interactive browser. Pass `credential=` to override.

---

## GCS Bucket Lock setup

### Bucket creation

GCS retention is **bucket-WIDE** rather than per-object — set the
bucket-level retention policy at creation, then optionally **lock**
it for regulator-grade enforcement.

```bash
# Create bucket with retention policy
gsutil mb -c standard -l us-central1 gs://my-evidentia-worm
gsutil retention set 7y gs://my-evidentia-worm

# Lock the retention policy (irreversible — even owner cannot reduce)
gsutil retention lock gs://my-evidentia-worm
```

### Per-record retention

Per-record `lock_until` is tracked in the metadata sidecar; the
bucket-side retention policy is the **enforcement floor**. Choose
the bucket retention period to match your longest expected
per-record retention (e.g., 7 years for SOX, 10+ years for
specific regulator requests).

### Backend instantiation

```python
from evidentia_core.retention.worm_gcs import GCSBucketLockWORM

backend = GCSBucketLockWORM(
    bucket_name="my-evidentia-worm",
    prefix="evidentia/",  # optional
)
```

The default `google.auth.default()` chain resolves env vars
(`GOOGLE_APPLICATION_CREDENTIALS`), `gcloud` CLI, GCE metadata,
or Application Default Credentials.

---

## Cross-cloud comparison

| Feature | S3 | Azure | GCS |
|---|---|---|---|
| Granularity | Per-object | Per-blob | Bucket-wide + per-blob holds |
| Lock can be set retroactively | No | Limited | No |
| Compliance mode (root cannot bypass) | Yes (`COMPLIANCE`) | Yes (`Locked`) | Yes (`retention lock`) |
| Operator override (GDPR-friendly) | Yes (`GOVERNANCE` + `s3:BypassGovernanceRetention`) | Yes (`Unlocked`) | Limited (must use unlocked policy + held holds) |
| Legal hold | `ObjectLockLegalHoldStatus` | `set_legal_hold` | `temporary_hold` / `event_based_hold` |
| Best fit | SEC / FINRA / per-tenant retention | Azure-native shops | GCP-native shops with single retention period |

---

## Operator workflows

### Standard retention purge (post-window)

```python
from datetime import date

# 1. Verify the record is past its retention window
md = backend.get_metadata(record_id)
assert md.lock_until is not None and date.today() >= md.lock_until

# 2. Transition lifecycle ACTIVE → EXPIRED
from evidentia_core.retention.metadata import (
    RetentionLifecycleStage, transition_lifecycle,
)

expired = transition_lifecycle(md, RetentionLifecycleStage.EXPIRED)
backend._update_metadata(record_id, expired)

# 3. Delete (now permitted by the 3-layer defense)
backend.delete(record_id)
```

### Legal hold (litigation / regulatory inquiry)

```python
# Apply hold — record cannot be deleted regardless of retention
backend.apply_legal_hold(record_id)

# ... litigation completes ...

# Release hold
backend.release_legal_hold(record_id)
```

### Retention extension (operator deliberately holds longer)

```python
from datetime import date, timedelta

new_lock = date.today() + timedelta(days=730)  # extend 2 more years
backend.extend_retention(record_id, new_lock)
```

Backward dates (shorter retention than current) are rejected by
the application layer and by all three cloud backends in
Compliance/Locked mode.

### GDPR right-to-erasure (Article 17)

See [`docs/gdpr-purge-flow.md`](gdpr-purge-flow.md).

---

## Troubleshooting

### S3: "Object Lock configuration cannot be applied"

The bucket was created without `--object-lock-enabled-for-bucket`.
Object Lock cannot be enabled retroactively — create a new bucket
with the flag, copy data over, then delete the old bucket.

### Azure: "The blob does not have an immutability policy"

The container was created without version-level immutability.
Recreate the container with `--enable-vlw` (preview features may
need to be enabled at the subscription level).

### GCS: "Cannot set retention on locked bucket"

Once `gsutil retention lock` runs, the retention period cannot
be reduced or removed — even by the project owner. This is the
intended regulator-grade behavior. To increase retention, use
`gsutil retention set <longer-period>` (forward-only).

### "Authentication failed" on first call

Run the cloud's standard "list buckets" check to verify the
credential chain is resolving correctly:

```bash
# AWS
aws s3 ls

# Azure
az storage container list --account-name <acct>

# GCS
gsutil ls
```

If those work, Evidentia's backend will resolve the same
credentials.

---

## Cross-references

- Retention metadata schema: `evidentia_core.retention.metadata`
- WORMBackend ABC + LocalFilesystemWORM reference impl: `evidentia_core.retention.worm`
- GDPR Article 17 right-to-erasure operator workflow: [`docs/gdpr-purge-flow.md`](gdpr-purge-flow.md)
- FAIR risk quantification (drives retention-period decisions): [`docs/risk-quantification.md`](risk-quantification.md) + [`docs/fair-monte-carlo.md`](fair-monte-carlo.md)
- Audit chain-of-custody architectural overview: [`docs/audit-chain-of-custody.md`](audit-chain-of-custody.md)
