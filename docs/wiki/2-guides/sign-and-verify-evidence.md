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

## Sign an OSCAL Assessment Results document (GPG detached)

The OSCAL emit path produces an ASCII-armored GPG detached signature (`.asc`).
GPG is a universal, air-gap-friendly install (no network, no telemetry), and
ASCII armor survives email/Slack/text-only channels without binary mangling.

Sign at emit time by passing your GPG key ID to `--sign-with-gpg`:

```bash
evidentia gap analyze \
  --inventory my-controls.yaml \
  --frameworks nist-800-53-rev5-moderate \
  --format oscal-ar \
  --output assessment-results.json \
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

```bash
pip install "evidentia-core[sigstore]"

evidentia gap analyze \
  --inventory my-controls.yaml \
  --frameworks nist-800-53-rev5-moderate \
  --format oscal-ar \
  --output assessment-results.json \
  --sign-with-sigstore
```

The Sigstore bundle is written to `assessment-results.json.sigstore.json` by
default. `--sign-with-sigstore` coexists with `--sign-with-gpg` — sign with both
for two independent trust paths. Verify the Sigstore bundle, pinning the
expected identity and issuer (always pin both in an audit pipeline; an unpinned
verify accepts *any* signer and warns):

```bash
evidentia oscal verify assessment-results.json \
  --expected-identity 'https://github.com/Polycentric-Labs/evidentia/.github/workflows/release.yml@refs/tags/v0.10.6' \
  --expected-issuer https://token.actions.githubusercontent.com
```

## Sign MCP tool outputs (`SignedToolOutput`)

When you run Evidentia as an MCP server, you can wrap every tool output in a
cryptographic envelope (`SignedToolOutput`) so a downstream AI client can verify
the result was produced by the configured instance without tampering in transit.
The signing layer is **opt-in** and **signer-agnostic**: the backend is supplied
via a dotted-path factory env var. Enable it with two env vars and point the
factory at the bundled Sigstore-keyless signer:

```bash
export EVIDENTIA_MCP_SIGN_OUTPUTS=1
export EVIDENTIA_MCP_SIGNER_FACTORY=evidentia_mcp.sigstore_signer:make_sigstore_signer
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

```bash
pip install "evidentia[worm-s3]"        # or worm-azure / worm-gcs
export EVIDENTIA_EVIDENCE_AUTO_MIRROR_WORM=1
export EVIDENTIA_EVIDENCE_WORM_BACKEND_FACTORY=<module:callable>
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
  Rekor; it is refused under `--offline`. Use `--sign-with-gpg` instead.
- **Sigstore verify warns "accepts ANY signer"** — you did not pass
  `--expected-identity` + `--expected-issuer`. Always pin both in an audit
  pipeline.
- **MCP server starts but outputs are unsigned** — confirm
  `EVIDENTIA_MCP_SIGN_OUTPUTS` is set *and* `EVIDENTIA_MCP_SIGNER_FACTORY`
  resolves to an importable callable; a factory error surfaces at startup.
