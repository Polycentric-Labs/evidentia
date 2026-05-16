# Evidence integrity — anti-tamper deployment guidance (v0.8.0)

This doc covers how to deploy Evidentia so the compliance
evidence chain-of-custody is preserved end-to-end. Auditors
+ 3PAOs reviewing your evidence artifacts ask three
questions:

1. Was the evidence collected as captured? (No tampering
   between collection and emit.)
2. Is the audit trail itself tamper-evident? (Append-only
   storage; signing; immutable backups.)
3. Can the evidence be re-derived from primary sources?
   (Reproducible build; pinned dependencies; containerized
   tooling.)

Evidentia provides primitives for all three. This doc names
the primitives, recommends combinations, and surfaces the
trade-offs.

## 1. Evidence-collection integrity

### 1.1 Audit-trail provenance

Every collector emits ECS-structured audit events through
`evidentia_core.audit`:

- `COLLECT_STARTED` / `COLLECT_COMPLETED` framing each run
  with a `run_id` (ULID).
- Per-finding `EVIDENCE_COLLECTED` events tagging the
  collector source-system + identity.
- `COLLECT_FAILED` events when partial collection fires —
  surfaces the gap rather than silently dropping evidence.

The emitted audit records embed `evidentia.run_id` so a
SIEM operator can reconstruct any complete collection run
from the audit log alone (no Evidentia state required).

### 1.2 Collector blind-spots disclosure

Each collector ships an explicit `BLIND_SPOTS` list naming
what it does NOT cover (e.g., AWS Access Analyzer ignores
custom Trust Policy patterns; Vanta vendor inventory
defers control-test evidence). The disclosures travel with
every emitted OSCAL AR so an auditor sees the explicit
limits of automated coverage inline alongside the findings.

The honesty-by-design posture is a hard requirement for
3PAO + federal SI use — auditors trust documented gaps more
than oversold coverage claims.

### 1.3 Read-only collectors

All Evidentia-shipped collectors are read-only. They
consume credentials (env-driven; never in tool arguments)
and emit findings; they NEVER mutate the source system.
The contract is enforced architecturally — the collector
base class doesn't expose write methods — and verified
through the per-collector blind-spot disclosures.

## 2. Tamper-evident audit + emit pipeline

### 2.1 Sigstore-signed OSCAL AR

`evidentia oscal export --sign` signs the OSCAL Assessment
Results bundle via Sigstore keyless OIDC. The signature
binds the AR's canonical JSON to a verifiable identity at a
specific timestamp:

- Signing identity: the OIDC issuer (Google, GitHub,
  Microsoft, etc.) the operator authenticated to. The
  certificate ties the signature to an email + auth time.
- Transparency-log entry: every Sigstore signature is
  recorded in the public Rekor transparency log. An
  auditor can reproduce the verification offline by
  consulting Rekor.

The `evidentia oscal verify` verb checks signatures, AR
integrity (per-finding SHA-256), and Sigstore certificate
validity in one call. CI gates can wire `evidentia oscal
verify` against every emitted AR to block tampered
artifacts from publishing.

### 2.2 Hashed back-matter resources

Each `SecurityFinding` + each `Vendor` (TPRM v0.7.9) +
each `ReasoningTrace` (PRT v0.8.0) embedded in an OSCAL AR
travels with:

- canonical JSON in `back-matter[].resources[].base64.value`.
- SHA-256 hash in `back-matter[].resources[].rlinks[].hashes[]`.
- Cross-reference from any matching observation via
  `relevant-evidence[].href: "#<resource-uuid>"`.

Modifying any embedded resource changes its SHA-256 and
fails `evidentia oscal verify` independent of the Sigstore
signature. The dual integrity model (Sigstore-signed
container + per-resource hash) is robust against partial
tampering.

### 2.3 Retention metadata + WORM backends

Evidentia v0.7.11 introduced retention metadata + the
`WORMBackend` ABC. v0.7.12 ships three concrete cloud-WORM
implementations:

- `S3ObjectLockWORM` (`evidentia[worm-s3]`) — S3 Object
  Lock in Compliance or Governance mode.
- `AzureImmutableBlobWORM` (`evidentia[worm-azure]`) —
  Azure Immutable Blob policies (locked or unlocked) +
  legal-hold.
- `GCSBucketLockWORM` (`evidentia[worm-gcs]`) — GCS Bucket
  Lock retention policy + per-object event-based +
  temporary holds.

The cloud-WORM backends provide HARDWARE-enforced
retention — even an operator with full write credentials
cannot delete a record while the lock is in effect.
Auditor-defensible posture for SOX, GLBA, FFIEC,
HIPAA-Security-Rule, and FedRAMP record-retention
requirements.

### 2.4 GDPR Article 17 purge flow

The retention surface includes
`WORMBackend.purge_immediately()` for GDPR right-to-erasure
+ a `transition_lifecycle(force_gdpr_purge=True)` operator
override. Both paths require the underlying record to be
GDPR-shaped (`retention_period_days=0`) AND emit a
`RETENTION_GDPR_PURGE` audit event with the operator
identity + GDPR-request-ref. The purge is the canonical
legal-counsel-defensible artifact for the erasure
execution.

## 3. Reproducibility

### 3.1 Pin everything

- `pyproject.toml` pins inter-package dependencies with
  `>=N,<N+1` ranges. The `bump_version.py` script bumps
  the lower bound atomically every release (closes the
  v0.7.10 propagation race; validated 5 consecutive
  releases through v0.7.16).
- `uv.lock` pins every transitive dependency with hashes.
  CI builds with `uv sync --frozen` so the dep set on the
  release pipeline matches the operator's `pip install`
  set bit-for-bit.
- `docker/requirements.txt` (v0.7.14 P1.5 foundation; flip
  to `pip install --require-hashes` ships in v0.8.1 G4)
  carries SHA-256 hashes for every transitive dep. The
  Dockerfile install line refuses unhashed packages,
  rendering supply-chain attacks via dependency
  confusion / typosquatting non-viable.

### 3.2 SLSA L3 build provenance

Every published wheel + container ships SLSA L3 build
provenance via GitHub Actions OIDC. The provenance
attestation:

- Ties the wheel's SHA-256 to the GitHub commit SHA + the
  workflow run that built it.
- Surfaces in `pypi-attestations verify pypi` (the
  canonical PEP 740 verifier) and `gh attestation verify`.
- Closes the Scorecard "Builds-Reproducible" check.

### 3.3 Container image cosign-signed

`ghcr.io/polycentric-labs/evidentia:vX.Y.Z` is signed via cosign
keyless OIDC. The signature binds to the same GitHub
identity as the SLSA provenance. Operators verifying the
image:

```bash
cosign verify ghcr.io/polycentric-labs/evidentia:v0.8.0 \
  --certificate-identity-regexp='^https://github.com/Polycentric-Labs/evidentia/' \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com
```

A forged image (or a tampered image distributed via a
compromised registry mirror) fails verification.

## 4. Recommended deployment patterns

### 4.1 SaaS / customer-facing deployment

- Run `evidentia serve` behind a reverse proxy with TLS
  termination + WAF. Bind to localhost; do NOT expose port
  8000 directly.
- Set `EVIDENTIA_API_SECURITY_HEADERS=1` (or pass
  `--security-headers` to `evidentia serve`).
- Configure the LLM provider env var for whichever
  models you trust.
- Mount evidence stores on a `worm-s3` / `worm-azure` /
  `worm-gcs` backend; configure retention policy per your
  regulatory regime.
- Wire `evidentia oscal export --sign` into the CI/CD
  pipeline so every emitted AR is Sigstore-signed before
  publish.
- Subscribe the SIEM to the JSON audit log
  (`--json-logs`) — every event is ECS-8.11 compliant.

### 4.2 Air-gapped / on-prem deployment

- `evidentia serve --offline` flips a process-wide
  air-gap guard. All non-loopback network calls (LLM,
  Sigstore, registries) refuse with
  `OfflineViolationError`.
- Wire LLM through a local Ollama / vLLM / TGI endpoint
  bound to 127.0.0.1.
- Use the local-filesystem WORM backend for evidence
  retention; back the WORM directory with a hardware
  WORM device or air-gapped tape.
- Sigstore signing is unavailable in offline mode; the
  AR + SBOM still ship with embedded SHA-256 hashes for
  per-resource integrity but the outer signature is
  absent. Operators wanting end-to-end signing in
  air-gapped deployments wire an internal CA + cosign
  with key-based signing (defers to v0.8.1).
- Replace the OIDC-driven LLM provider auth with
  pre-issued static tokens stored in a sealed env vault.

### 4.3 Federal SI / 3PAO deployment

- All §4.1 SaaS recommendations.
- Mount evidence stores on `worm-s3` Compliance mode (NOT
  Governance — Compliance mode prevents even root-user
  override during the retention period).
- Configure retention policy to match the relevant cycle
  cadence: FedRAMP Moderate = 3 years; FedRAMP High = 6
  years; CMMC Level 3 = 6 years; SOC 2 Type II = 1 year
  per period.
- Wire `evidentia eval risk-determinism --fail-on-determinism-rate-below
  0.95` (v0.8.1) into the CI gate so non-deterministic LLM
  output never lands in the audit artifact set. The
  v0.8.0 stub-smoke verb proves the harness is wired but
  doesn't gate on the live LLM.
- Use the v0.8.0 P0.2 PRT (`--emit-trace`) so every AI-
  generated risk statement carries auditor-reviewable
  reasoning chains. v0.8.0 ships stub traces; v0.8.1
  ships the LLM-driven per-claim decomposition.

## 5. Verification commands

After deploying, verify the end-to-end posture:

```bash
# Verify the installed wheels
pypi-attestations verify pypi --repository \
  https://github.com/polycentric-labs/evidentia \
  "pypi:evidentia-0.8.0-py3-none-any.whl"

# Verify the container image
cosign verify ghcr.io/polycentric-labs/evidentia:v0.8.0 \
  --certificate-identity-regexp='^https://github.com/Polycentric-Labs/evidentia/' \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com

# Verify a Sigstore-signed AR
evidentia oscal verify path/to/assessment-results.json

# Verify the SBOM matches the wheel set
osv-scanner --sbom path/to/cyclonedx-sbom.json

# Confirm process-wide audit logging is on
evidentia doctor --json-logs

# Smoke-test the determinism harness (v0.8.0 P0.1)
evidentia eval stub-smoke --samples-per-prompt 5

# Confirm the metrics endpoint is scraping (v0.8.0 P1 G3)
curl -fs http://127.0.0.1:8000/api/metrics | grep evidentia_app_info

# Confirm the MCP server is reachable (v0.8.0 P0.3)
evidentia mcp doctor
```

All commands should exit 0; any non-zero exit indicates a
posture regression worth investigating before publishing
audit artifacts.

## 6. Threat model alignment

`docs/threat-model.md` (refreshed every minor release per
the pre-release-review v4 G5 gate) enumerates the
adversaries the integrity primitives in this doc defend
against. Operators reviewing this doc should also read the
threat-model and confirm their deployment defends against
the relevant adversary classes.

For the v0.8.0 surface specifically:

- Adversary controlling the source system (cloud account,
  SaaS vendor) — defended by read-only collectors + blind-
  spot disclosure + multi-source corroboration.
- Adversary controlling the operator's workstation —
  defended by Sigstore signing (binds to OIDC, not local
  state) + WORM backups (immutable post-emit).
- Adversary controlling the deployment environment —
  defended by `--offline` air-gap guard + cloud-WORM
  hardware enforcement.
- Adversary controlling the LLM provider — defended by
  the determinism harness (catches non-deterministic
  output) + PRT (surfaces reasoning chain for review) +
  per-output `GenerationContext` (binds to model +
  temperature + prompt_hash).

The defense is layered. No single primitive is sufficient
on its own; the combination provides auditor-defensible
end-to-end integrity.
