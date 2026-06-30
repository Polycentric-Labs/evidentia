# Sign and verify evidence

An auditor consuming an Evidentia artifact should be able to verify,
cryptographically, that it was produced by the configured instance and has not
been tampered with. Evidentia gives you three complementary mechanisms for that:
**GPG-detached signatures on OSCAL Assessment Results**, **Sigstore-keyless
signatures on MCP tool outputs**, and an **append-only / WORM evidence store**
that attests to the *history* of an evidence chain. This guide is the operator
how-to; for the design rationale see [Concepts → Evidence integrity](../3-concepts/evidence-integrity.md).

> **Terminology — do not confuse these.** In Evidentia's codebase, **CIMD =
> Client ID Metadata Document** (an OAuth/MCP client-registration concept per
> RFC 7591). CIMD governs *which MCP client may call which tool* — it does
> **not** sign anything. The cryptographic signing primitives are
> `SignedToolOutput` (Sigstore keyless, for MCP tool output) and the
> `evidentia_core.oscal.signing` GPG path (for OSCAL documents), both described
> below. This page used to be named "sign-and-verify-cimd"; the name was a
> misnomer and has been corrected.

## Generate a signing key (air-gap DSSE)

The air-gap DSSE path requires an Ed25519 or RSA key in PEM/PKCS#8 format.
Generate one with `openssl` (standard on Linux/macOS; install
[OpenSSL for Windows](https://slproweb.com/products/Win32OpenSSL.html) or use
Git Bash / WSL on Windows):

**Bash / Linux / macOS**

```bash
# Ed25519 (recommended — constant-time, compact)
openssl genpkey -algorithm ed25519 -out signing.key
openssl pkey -in signing.key -pubout -out signing.pub
chmod 600 signing.key

# RSA-3072 (for operators whose validated FIPS module requires RSA — a standard
# RSA key; Evidentia applies RSA-PSS at sign time)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out signing.key
openssl pkey -in signing.key -pubout -out signing.pub
chmod 600 signing.key

# Optional: encrypt the private key (passphrase supplied via env var, never a flag)
openssl pkey -in signing.key -aes-256-cbc -out signing.key.enc
```

**PowerShell (Windows)**

```powershell
# Ed25519 (recommended)
openssl genpkey -algorithm ed25519 -out signing.key
openssl pkey -in signing.key -pubout -out signing.pub
# On Windows, chmod is not available; restrict access via icacls or store in a
# secrets manager

# RSA-3072
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out signing.key
openssl pkey -in signing.key -pubout -out signing.pub
```

Evidentia computes and prints the `keyId` (a SHA-256 of the public key's DER-encoded
SubjectPublicKeyInfo) at sign time — operators never derive it by hand.

### Sign and verify with the DSSE path

**Bash / Linux / macOS**

```bash
# Sign a gap-analysis OSCAL AR
evidentia gap analyze \
  --inventory inv.yaml \
  --frameworks nist-800-53-rev5-moderate \
  --format oscal-ar \
  --output audit.oscal-ar.json \
  --sign-with-key signing.key
# Writes audit.oscal-ar.json  +  audit.oscal-ar.json.dsse.json

# For an encrypted key, supply the passphrase via env (never a flag)
export EVIDENTIA_SIGNING_KEY_PASSPHRASE=<passphrase>
evidentia gap analyze --sign-with-key signing.key.enc ...

# Sign a traceability profile
evidentia traceability emit --sign-with-key signing.key --output traceability.json

# Verify (pinned key, fail-closed)
evidentia oscal verify audit.oscal-ar.json \
  --verify-key signing.pub \
  --require-signature
```

**PowerShell (Windows)**

```powershell
# Sign
evidentia gap analyze `
  --inventory inv.yaml `
  --frameworks nist-800-53-rev5-moderate `
  --format oscal-ar `
  --output audit.oscal-ar.json `
  --sign-with-key signing.key
# Writes audit.oscal-ar.json  +  audit.oscal-ar.json.dsse.json

# For an encrypted key
$env:EVIDENTIA_SIGNING_KEY_PASSPHRASE = "<passphrase>"
evidentia gap analyze --sign-with-key signing.key.enc ...

# Verify
evidentia oscal verify audit.oscal-ar.json `
  --verify-key signing.pub `
  --require-signature
```

> **What `--require-signature` checks.** With `--verify-key`, verification fails
> if the DSSE envelope is absent, malformed, or the signature does not verify
> against the pinned public key. A passing verify means the pinned key signed
> over the exact canonical-JSON content — not the filename or the signing
> timestamp. See [Concepts → Evidence integrity](../3-concepts/evidence-integrity.md)
> for the full trust-model semantics.

The DSSE path is binary-free and air-gap-clean (no `gpg` binary, no network
call to Fulcio or Rekor). It works inside distroless and minimal-base containers.
Use `--sign-with-gpg` for a detached GPG signature alongside the DSSE envelope,
or `--sign-with-sigstore` for a Sigstore keyless signature (requires network).

---

## Sign an OSCAL Assessment Results document (GPG detached)

The OSCAL emit path produces an ASCII-armored GPG detached signature (`.asc`).
GPG is a universal, air-gap-friendly install (no network, no telemetry), and
ASCII armor survives email/Slack/text-only channels without binary mangling.

Sign at emit time by passing your GPG key ID to `--sign-with-gpg`:

**Bash / Linux / macOS**

```bash
evidentia gap analyze \
  --inventory my-controls.yaml \
  --frameworks nist-800-53-rev5-moderate \
  --format oscal-ar \
  --output assessment-results.json \
  --sign-with-gpg YOUR_KEY_ID
```

**PowerShell (Windows)**

```powershell
evidentia gap analyze `
  --inventory my-controls.yaml `
  --frameworks nist-800-53-rev5-moderate `
  --format oscal-ar `
  --output assessment-results.json `
  --sign-with-gpg YOUR_KEY_ID
```

This writes `assessment-results.json` plus a detached
`assessment-results.json.asc`. The `key_id` is mandatory — unambiguous signer
identity is the whole point.

### Verify the signature

```bash
evidentia oscal verify assessment-results.json --require-signature
```

`--require-signature` fails verification if no `.asc` is present next to the
file (the default is opportunistic: verify the signature if present, pass on
digests alone if absent). A signature *mismatch* is reported as a failure, not a
crash. To verify against a specific keyring rather than `~/.gnupg`, pass
`--gnupghome`. Use `--json` for a machine-readable report (the exit code still
reflects pass/fail).

## Sign with Sigstore (keyless)

For defense-in-depth — or when you want to remove operator key material from the
trust path entirely — add a Sigstore signature. Sigstore replaces a long-lived
private key with a short-lived Fulcio certificate tied to an OIDC identity, with
inclusion recorded in the Rekor transparency log. It requires the `[sigstore]`
extra and network access to Fulcio + Rekor, so it is **refused in `--offline`
mode** (use GPG in air-gapped environments):

**Bash / Linux / macOS**

```bash
pip install "evidentia-core[sigstore]"

evidentia gap analyze \
  --inventory my-controls.yaml \
  --frameworks nist-800-53-rev5-moderate \
  --format oscal-ar \
  --output assessment-results.json \
  --sign-with-sigstore
```

**PowerShell (Windows)**

```powershell
pip install "evidentia-core[sigstore]"

evidentia gap analyze `
  --inventory my-controls.yaml `
  --frameworks nist-800-53-rev5-moderate `
  --format oscal-ar `
  --output assessment-results.json `
  --sign-with-sigstore
```

The Sigstore bundle is written to `assessment-results.json.sigstore.json` by
default. `--sign-with-sigstore` coexists with `--sign-with-gpg` — sign with both
for two independent trust paths. Verify the Sigstore bundle, pinning the
expected identity and issuer (always pin both in an audit pipeline; an unpinned
verify accepts *any* signer and warns):

**Bash / Linux / macOS**

```bash
evidentia oscal verify assessment-results.json \
  --expected-identity 'https://github.com/Polycentric-Labs/evidentia/.github/workflows/release.yml@refs/tags/v0.10.6' \
  --expected-issuer https://token.actions.githubusercontent.com
```

**PowerShell (Windows)**

```powershell
evidentia oscal verify assessment-results.json `
  --expected-identity 'https://github.com/Polycentric-Labs/evidentia/.github/workflows/release.yml@refs/tags/v0.10.6' `
  --expected-issuer https://token.actions.githubusercontent.com
```

## Sign MCP tool outputs (`SignedToolOutput`)

When you run Evidentia as an MCP server, you can wrap every tool output in a
cryptographic envelope (`SignedToolOutput`) so a downstream AI client can verify
the result was produced by the configured instance without tampering in transit.
The signing layer is **opt-in** and **signer-agnostic**: the backend is supplied
via a dotted-path factory env var. Enable it with two env vars and point the
factory at the bundled Sigstore-keyless signer:

**Bash / Linux / macOS**

```bash
export EVIDENTIA_MCP_SIGN_OUTPUTS=1
export EVIDENTIA_MCP_SIGNER_FACTORY=evidentia_mcp.sigstore_signer:make_sigstore_signer
evidentia mcp serve --transport stdio
```

**PowerShell (Windows)**

```powershell
$env:EVIDENTIA_MCP_SIGN_OUTPUTS = "1"
$env:EVIDENTIA_MCP_SIGNER_FACTORY = "evidentia_mcp.sigstore_signer:make_sigstore_signer"
evidentia mcp serve --transport stdio
```

- **Default (unset)** → tools emit raw payloads (backward-compatible). Setting
  `EVIDENTIA_MCP_SIGN_OUTPUTS` turns the wrapper on.
- Production wires the Sigstore-keyless factory above; dev/CI can wire an HMAC
  signer for determinism; air-gap wires a GPG-based signer.
- A signing **failure surfaces as a structured error, not a crash**: the
  envelope is emitted with `signature=None` + `signing_error` populated.
  Consumers requiring signed-only output check `signature is not None`.
- Configuration errors surface at **server startup**, not at first tool
  dispatch, so a misconfigured factory fails fast.

The payload is canonicalized to deterministic JSON before signing, so the same
payload yields byte-identical signing input across hosts. Tool-output signatures
defend against in-transit tampering and provide audit-trail provenance; Sigstore
keyless additionally removes key material from the trust path.

## The append-only / WORM evidence store

Signatures attest to a single artifact; the evidence store attests to the
**history** of an evidence chain. It is an append-only store — one directory per
lineage chain, one JSON file per version (`v1.json`, `v2.json`, ...). Saving a
new version never overwrites an existing one.

`evidence save` validates the file against the `EvidenceArtifact` schema, so a
bare/empty YAML errors. The four required fields are `title`, `evidence_type`,
`source_system`, and `collected_by` (everything else has a sensible default).
A minimal conforming `artifact.yaml`:

```yaml
# artifact.yaml — required fields + a couple of common optionals
title: "MFA enforced on the admin console"
evidence_type: configuration        # configuration | log | screenshot | policy_document | audit_report | api_response | test_result | attestation | repository_metadata | identity_data
source_system: okta
collected_by: jane.doe@example.com
description: "Okta admin policy requires MFA for all administrators."
content:
  policy: require-mfa
  scope: admins
control_mappings:
  - framework: nist-800-53-rev5
    control_id: IA-2
    relationship: subset-of         # OLIR relationship (hyphenated): equivalent-to | equal-to | subset-of | superset-of | intersects-with | related-to
    justification: "Okta MFA policy evidences IA-2 for admins."
```

```bash
# Persist an evidence artifact (new lineage, or a new version of an existing one)
evidentia evidence save artifact.yaml

# Walk the lineage chain — every version with timestamps
evidentia evidence history <LINEAGE_ID>

# Render one specific version
evidentia evidence show <LINEAGE_ID> --version 2
```

The store directory resolves from `--store-dir` → `EVIDENTIA_EVIDENCE_STORE_DIR`
→ a platform default.

### Hardware-enforced WORM

The local store's WORM enforcement is **application-layer** — a privileged
operator can still delete the JSON files with OS tools. For regulator-grade,
hardware-enforced Write-Once-Read-Many, wire a cloud-WORM backend (S3 Object
Lock, Azure Immutable Blob, or GCS Bucket Lock). Install the matching extra and
set the auto-mirror env vars so each local-store write is mirrored to the cloud:

**Bash / Linux / macOS**

```bash
pip install "evidentia[worm-s3]"        # or worm-azure / worm-gcs
export EVIDENTIA_EVIDENCE_AUTO_MIRROR_WORM=1
export EVIDENTIA_EVIDENCE_WORM_BACKEND_FACTORY=<module:callable>
```

**PowerShell (Windows)**

```powershell
pip install "evidentia[worm-s3]"        # or worm-azure / worm-gcs
$env:EVIDENTIA_EVIDENCE_AUTO_MIRROR_WORM = "1"
$env:EVIDENTIA_EVIDENCE_WORM_BACKEND_FACTORY = "<module:callable>"
```

You then get application-layer append-only locally *plus* hardware-enforced WORM
in the cloud, gated behind one env var. The `WORMBackend` contract enforces that
a record cannot be deleted before its lock window expires and that retention can
be extended (legal hold) but never shortened.

## A complete verification recipe

To hand an auditor a fully verifiable package:

1. Emit the OSCAL AR with **both** signatures (`--sign-with-gpg KEY`
   `--sign-with-sigstore`).
2. The auditor verifies the GPG signature offline:
   `evidentia oscal verify assessment-results.json --require-signature`.
3. The auditor verifies the Sigstore bundle with pinned identity + issuer (see
   above) to confirm *who* signed and *when*.
4. If findings were folded in (`--findings`), the auditor recomputes the SHA-256
   of each OSCAL back-matter resource and confirms it matches the embedded
   digest.
5. For chain-of-custody over time, the evidence store's `history` shows the full
   append-only lineage; the cloud-WORM backend proves no version was deleted.

## What's next

- [Concepts → Evidence integrity](../3-concepts/evidence-integrity.md) — the
  end-to-end design + threat-model boundaries.
- [Project → Verification](../6-project/verification.md) — verifying released
  artifacts (wheel PEP 740 attestations, cosign-signed container, SBOM, SLSA
  provenance).
- [Concepts → RBAC and multi-tenancy](../3-concepts/rbac-and-multi-tenancy.md) —
  the authorization layer that complements CIMD scope-gating.

## Got stuck?

- **`GPGNotAvailableError`** — `gpg` is not on your PATH. Install GnuPG 2.x.
- **`--sign-with-sigstore` errors in offline mode** — Sigstore needs Fulcio +
  Rekor; it is refused under `--offline`. Use `--sign-with-gpg` or
  `--sign-with-key` instead.
- **Sigstore verify warns "accepts ANY signer"** — you did not pass
  `--expected-identity` + `--expected-issuer`. Always pin both in an audit
  pipeline.
- **MCP server starts but outputs are unsigned** — confirm
  `EVIDENTIA_MCP_SIGN_OUTPUTS` is set *and* `EVIDENTIA_MCP_SIGNER_FACTORY`
  resolves to an importable callable; a factory error surfaces at startup.
- **`SigningKeyError: encrypted signing key requires EVIDENTIA_SIGNING_KEY_PASSPHRASE`**
  — your key was generated with AES encryption (`-aes-256-cbc`). Set the env
  var `EVIDENTIA_SIGNING_KEY_PASSPHRASE=<passphrase>` before running the sign
  command. The passphrase is never accepted as a CLI flag (prevents shell
  history exposure).
- **DSSE verify fails: "subject digest mismatch"** — the artifact file was
  modified after signing. Re-sign the current content or verify the original
  signed copy.
- **DSSE verify fails: "DSSE envelope not found"** — the `.dsse.json` sidecar
  file is missing. Ensure both `<output>.json` and `<output>.json.dsse.json`
  are co-located when passing to `oscal verify`.
