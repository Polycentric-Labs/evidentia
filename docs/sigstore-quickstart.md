# Sigstore quickstart for Evidentia

> Five-minute walkthrough for signing + verifying OSCAL Assessment
> Results documents end-to-end with Sigstore. For the ten-minute
> deep dive on air-gap GPG signing instead, see
> [`docs/air-gapped.md`](air-gapped.md). For the full release-time
> verifier checklist, see [`docs/release-checklist.md`](release-checklist.md)
> Step 9.

---

## Why Sigstore for compliance evidence

Sigstore is a CNCF-graduated project that lets you sign artifacts
*without managing a long-lived signing key*. Instead of holding a
GPG private key for years (and rotating it, and protecting it), you
authenticate to Sigstore's Fulcio CA over OIDC at sign time, get a
short-lived (~10 min) X.509 certificate scoped to your identity, and
sign the artifact with that. The signature + cert + transparency-log
inclusion proof land in a single `.sigstore.json` bundle file.

For Evidentia, that means every OSCAL Assessment Results document
can carry a tamper-evident signature tied to:

- A specific GitHub Actions workflow run, or
- A specific human's verified email, or
- A specific cloud workload identity (GCP / AWS / Azure)

…with no key custody for you to get wrong.

If you cannot reach Fulcio + Rekor (air-gapped networks, classified
enclaves, FedRAMP High deployments behind a one-way diode), use the
GPG path documented in [`docs/air-gapped.md`](air-gapped.md). The
verify command (`evidentia oscal verify`) accepts either signature
type interchangeably.

---

## Install with the sigstore extra

```bash
uv tool install "evidentia[sigstore]"
# or
pip install "evidentia-core[sigstore]"
```

The `[sigstore]` extra pulls in the `sigstore` Python SDK
(maintained by the Sigstore project). Without the extra,
`--sign-with-sigstore` and `--check-sigstore` raise an `ImportError`
with an explicit "install with the [sigstore] extra" hint.

Verify the install:

```bash
evidentia doctor --check-sigstore
```

Expects: `OK: sigstore importable; Fulcio + Rekor reachable`.

---

## End-to-end: sign an AR in CI

The cleanest path is signing during a CI run that already has an
ambient OIDC identity (GitHub Actions, GCP Workload Identity,
AWS IAM Roles for Service Accounts, etc.). The composite action
ships with a one-flag toggle:

```yaml
- name: Run Evidentia gap analysis + sign AR
  uses: polycentric-labs/evidentia/.github/actions/gap-analysis@v0
  with:
    inventory: my-controls.yaml
    frameworks: nist-800-53-rev5-moderate,soc2-tsc
    github-token: ${{ secrets.GITHUB_TOKEN }}
    emit-oscal-ar: 'true'
    emit-sigstore-bundle: 'true'   # ← signs the AR with Sigstore
```

Required workflow permissions:

```yaml
permissions:
  id-token: write     # OIDC token for Fulcio
  contents: read      # actions/checkout
  pull-requests: write # composite action posts a sticky comment
```

Output:

```
.evidentia-out/
├── gap-report.json
├── oscal-ar.json
└── oscal-ar.sigstore.json     ← the bundle (cert + signature + Rekor proof)
```

The bundle is committed to the
[Rekor transparency log](https://search.sigstore.dev/) at sign time
so anyone with the AR can independently retrieve the inclusion proof
later (the bundle's cert + sig are also self-contained).

---

## End-to-end: sign locally

Without an ambient OIDC identity, Sigstore falls back to interactive
browser-based authentication (OAuth via Google / GitHub / Microsoft).
This is fine for local testing; not appropriate for production audit
pipelines.

```bash
evidentia gap analyze \
    --inventory examples/meridian-fintech-v2/my-controls.yaml \
    --frameworks nist-800-53-rev5-moderate,soc2-tsc \
    --output ar.oscal.json \
    --format oscal-ar \
    --sign-with-sigstore
```

A browser window opens. Authenticate with your preferred OIDC
provider; the bundle lands at `ar.oscal.json.sigstore.json`.

---

## End-to-end: verify

### Opportunistic verification (default)

```bash
evidentia oscal verify ar.oscal.json
```

Verifies the SHA-256 digests of every embedded evidence resource AND
opportunistically validates any GPG `.asc` or Sigstore
`.sigstore.json` bundle found alongside the AR. Exits 0 if
verification succeeds; 1 otherwise.

### Strict verification (production audit pipelines)

```bash
evidentia oscal verify ar.oscal.json \
    --require-signature \
    --expected-identity 'https://github.com/polycentric-labs/evidentia/.github/workflows/release.yml@refs/heads/main' \
    --expected-issuer 'https://token.actions.githubusercontent.com'
```

`--require-signature` fails verification if no detached signature is
present (defense against an attacker stripping the `.sigstore.json`
file). `--expected-identity` + `--expected-issuer` enforce that the
signer was the specific workflow you trust — without them, the
Sigstore verifier accepts ANY validly-signed bundle from ANY OIDC
issuer (the `UnsafeNoOp` policy), and emits a structured warning
(`evidentia.oscal.verify_signature_unsafe_noop`) so SIEM operators
can detect missing-policy verifications in audit logs.

### Common identity / issuer combinations

| Signing context | `--expected-issuer` | `--expected-identity` |
|---|---|---|
| GitHub Actions workflow | `https://token.actions.githubusercontent.com` | `https://github.com/<org>/<repo>/.github/workflows/<name>.yml@refs/heads/<branch>` |
| Google Cloud Run / Workload Identity | `https://accounts.google.com` | service-account email |
| AWS IAM Roles for Service Accounts | `https://oidc.eks.<region>.amazonaws.com/id/<cluster-id>` | role ARN |
| Local dev, browser-based OAuth (Google) | `https://accounts.google.com` | your verified email |
| Local dev, browser-based OAuth (GitHub) | `https://github.com/login/oauth` | your verified email |

The exact identity string for any signed AR is reported by
`evidentia oscal verify` even on success — run once without
`--expected-identity` to discover the string, then pin it in your
production verification command.

---

## Air-gap mode

Sigstore signing requires reaching Fulcio + Rekor on the public
internet. In air-gap mode, the signing call refuses with a clear
error and the operator gets routed to GPG:

```bash
evidentia gap analyze \
    --inventory my-controls.yaml \
    --frameworks fedramp-rev5-high \
    --output ar.oscal.json \
    --format oscal-ar \
    --offline \
    --sign-with-sigstore
# → OfflineViolationError: Sigstore requires reaching Fulcio + Rekor.
#   Use --sign-with-gpg <key-id> instead. See docs/air-gapped.md.
```

Verification can still run air-gapped if the bundle was produced
elsewhere — Sigstore's verification is offline-friendly when the
bundle includes the Rekor inclusion proof (which it does by
default). Pass `--no-check-sigstore` to skip Sigstore verification
entirely if your environment forbids the imports.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ImportError: sigstore` | `[sigstore]` extra not installed | `pip install "evidentia-core[sigstore]"` |
| `evidentia.oscal.verify_signature_unsafe_noop` warning | No `--expected-identity` set | Pin `--expected-identity` + `--expected-issuer` for production verifies |
| `OfflineViolationError` on sign | `--offline` set or air-gap doctor flagged the deployment | Use `--sign-with-gpg` instead |
| Browser doesn't open during local sign | Headless environment | Run on a workstation, OR script around `sigstore sign` directly |
| `ConnectionError` against rekor.sigstore.dev | Corporate proxy blocking the public Rekor | Set `HTTPS_PROXY` env var, OR use a Sigstore mirror, OR fall back to GPG |
| Verify fails on a freshly-signed AR | Clock skew between signer and verifier | Confirm both systems' clocks are within Fulcio's 10-min validity window |

---

## What gets signed exactly

The Sigstore signature covers the **canonical-JSON-serialised AR
document** (RFC 8785 JSON Canonicalization Scheme), not the
on-disk bytes. This makes signatures stable across OS / locale
differences and lets a verifier re-canonicalise before checking,
catching whitespace-only post-sign tampering. The AR's back-matter
also embeds a SHA-256 digest of every evidence resource, signed
implicitly by being inside the canonicalised AR.

If you need to interrogate the bundle directly (e.g., to extract the
Rekor inclusion timestamp for an audit report), the bundle is a
JSON document conforming to the Sigstore Bundle v0.3 protobuf
spec. The relevant fields:

- `verification_material.x509_certificate_chain` — the leaf cert chain
- `verification_material.tlog_entries[0].inclusion_proof` — Rekor proof
- `verification_material.tlog_entries[0].integrated_time` — Unix
  timestamp the entry landed in Rekor
- `messageSignature.signature` — base64-encoded raw signature

---

## Verifying the published container image (v0.7.5+)

Evidentia v0.7.5+ ships a signed container image to
`ghcr.io/polycentric-labs/evidentia` on every release tag. Two independent
verification paths cover the image — cosign keyless (PEP 740-equivalent
for OCI artifacts) and SLSA L3 build provenance — mirroring the
dual-path coverage on the published wheels.

### Cosign keyless verification

Verifies the signature against the OIDC identity binding the GitHub
Actions workflow used to sign:

```bash
cosign verify ghcr.io/polycentric-labs/evidentia:v0.7.5 \
  --certificate-identity-regexp 'https://github\.com/Polycentric-Labs/evidentia/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

A successful verification prints the certificate identity URL
(matching the regexp above) and the Rekor transparency-log entry
URL. Pin to a specific version for reproducibility (the example
above is `v0.7.5`); use `:latest` only for development.

### SLSA build provenance verification

Independent of cosign, the same image carries an
`actions/attest-build-provenance@v2` SLSA L3 attestation stored under
`https://github.com/polycentric-labs/evidentia/attestations` and resolvable
via:

```bash
gh attestation verify oci://ghcr.io/polycentric-labs/evidentia:v0.7.5 \
  -R Polycentric-Labs/evidentia
```

This validates the build provenance predicate (workflow run id,
commit SHA, builder identity) for the image digest — the same SLSA
L3 path the wheels use, just keyed on the OCI digest instead of the
wheel filename.

### Pinning by digest for production deployment

Tags are mutable; digests are not. For production GitOps / k8s
manifests, pin to the digest emitted in the GitHub Release notes:

```bash
docker buildx imagetools inspect ghcr.io/polycentric-labs/evidentia:v0.7.5
# prints sha256:<64-hex>; copy it into your k8s manifest like so:
#   image: ghcr.io/polycentric-labs/evidentia@sha256:abc123...
```

Both `cosign verify` and `gh attestation verify` accept a digest
reference (`@sha256:...`) and verify it identically — the signature
binding is digest-based, not tag-based.

---

## See also

- [`docs/air-gapped.md`](air-gapped.md) — the GPG path for environments
  that cannot reach Fulcio / Rekor
- [`docs/release-checklist.md`](release-checklist.md) Step 9 — the
  release-time verifier checklist (PEP 740 + SLSA L3 + container
  paths covered as of v0.7.5)
- [`docs/enterprise-grade.md`](enterprise-grade.md) BLOCKER B1 / B6 /
  H4 — the enterprise-grade quality bar Sigstore signing closes;
  v0.7.5 flipped L1 (container image distribution) to ✅
- [`docs/troubleshooting.md`](troubleshooting.md) — Sigstore TUF
  fetch failures + air-gap fallback
- [GitHub Container Registry — `evidentia` package](https://github.com/polycentric-labs/evidentia/pkgs/container/evidentia)
- [Sigstore project docs](https://docs.sigstore.dev/)
- [RFC 8785 — JSON Canonicalization Scheme](https://datatracker.ietf.org/doc/html/rfc8785)

---

*Last reviewed: v0.7.5 cycle. Container-image verification sections
added in v0.7.5. Tested against Sigstore SDK 4.x + cosign 2.4.x +
Fulcio v1 + Rekor v1.*
