# Verifying Evidentia release artifacts

Every Evidentia release produces:

- 8 PyPI wheels with PEP 740 attestations
- 1 cosign-signed container image at `ghcr.io/polycentric-labs/evidentia`
- 1 SLSA Provenance v1 attestation per the container
- 1 CycloneDX 1.7 SBOM attached to the GitHub Release

All four can be verified by consumers using standard open-source tooling.
This doc covers the recipes.

## Verifying PEP 740 attestations on PyPI wheels

**Bash / Linux / macOS**

```bash
# Install pypi-attestations (one-time)
pip install pypi-attestations

# Verify a single wheel
pypi-attestations verify pypi \
  --repository https://github.com/Polycentric-Labs/evidentia \
  pypi:evidentia_core-0.12.1-py3-none-any.whl

# Expected output:
#   OK: evidentia_core-0.12.1-py3-none-any.whl
```

**PowerShell (Windows)**

```powershell
# Install pypi-attestations (one-time)
pip install pypi-attestations

# Verify a single wheel
pypi-attestations verify pypi `
  --repository https://github.com/Polycentric-Labs/evidentia `
  pypi:evidentia_core-0.12.1-py3-none-any.whl

# Expected output:
#   OK: evidentia_core-0.12.1-py3-none-any.whl
```

Per-release sweep across all 8 packages:

**Bash / Linux / macOS**

```bash
for pkg in evidentia evidentia_ai evidentia_api evidentia_collectors \
           evidentia_core evidentia_eval evidentia_integrations evidentia_mcp; do
  pypi-attestations verify pypi \
    --repository https://github.com/Polycentric-Labs/evidentia \
    "pypi:${pkg}-0.12.1-py3-none-any.whl"
done
```

**PowerShell (Windows)**

```powershell
foreach ($pkg in 'evidentia','evidentia_ai','evidentia_api','evidentia_collectors',
                 'evidentia_core','evidentia_eval','evidentia_integrations','evidentia_mcp') {
  pypi-attestations verify pypi `
    --repository https://github.com/Polycentric-Labs/evidentia `
    "pypi:${pkg}-0.12.1-py3-none-any.whl"
}
```

## Verifying the cosign-signed container

**Bash / Linux / macOS**

```bash
# Install cosign (one-time)
# https://docs.sigstore.dev/system_config/installation/

# Verify the container's keyless OIDC signature
cosign verify ghcr.io/polycentric-labs/evidentia:v0.12.1 \
  --certificate-identity-regexp "https://github.com/Polycentric-Labs/evidentia/.github/workflows/release.yml@refs/tags/v0.12.1" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Expected output: "The cosign claims were validated" + SLSA Provenance v1 JSON.
```

**PowerShell (Windows)**

```powershell
# Install cosign (one-time)
# https://docs.sigstore.dev/system_config/installation/

# Verify the container's keyless OIDC signature
cosign verify ghcr.io/polycentric-labs/evidentia:v0.12.1 `
  --certificate-identity-regexp "https://github.com/Polycentric-Labs/evidentia/.github/workflows/release.yml@refs/tags/v0.12.1" `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Expected output: "The cosign claims were validated" + SLSA Provenance v1 JSON.
```

## Verifying the CycloneDX SBOM attached to the Release

**Bash / Linux / macOS**

```bash
# Download the SBOM
gh release download v0.12.1 --pattern 'evidentia-sbom.cdx.json' \
  --repo Polycentric-Labs/evidentia

# Scan for vulnerabilities
osv-scanner scan source -L evidentia-sbom.cdx.json

# Expected output: "No issues found" (or surfaced advisories with severities).
```

**PowerShell (Windows)**

```powershell
# Download the SBOM
gh release download v0.12.1 --pattern 'evidentia-sbom.cdx.json' `
  --repo Polycentric-Labs/evidentia

# Scan for vulnerabilities
osv-scanner scan source -L evidentia-sbom.cdx.json

# Expected output: "No issues found" (or surfaced advisories with severities).
```

## Verifying SLSA Provenance v1

The container's `cosign verify` output above includes the SLSA Provenance v1
attestation inline. To extract it:

> **Requires cosign ≥ 2.6.** The provenance attestation is stored via the
> OCI 1.1 referrers API (pushed by `actions/attest-build-provenance`); cosign
> 2.4.x can verify the image signature but returns `no matching attestations`
> for the referrer-stored attestation. If you are pinned to an older cosign,
> use the tool-native `gh attestation verify oci://ghcr.io/polycentric-labs/evidentia:v0.12.1 -R Polycentric-Labs/evidentia`
> instead (any `gh` version finds it).

**Bash / Linux / macOS**

```bash
cosign verify-attestation ghcr.io/polycentric-labs/evidentia:v0.12.1 \
  --certificate-identity-regexp "https://github.com/Polycentric-Labs/evidentia/.github/workflows/release.yml@refs/tags/v0.12.1" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --type slsaprovenance1
```

**PowerShell (Windows)**

```powershell
cosign verify-attestation ghcr.io/polycentric-labs/evidentia:v0.12.1 `
  --certificate-identity-regexp "https://github.com/Polycentric-Labs/evidentia/.github/workflows/release.yml@refs/tags/v0.12.1" `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com `
  --type slsaprovenance1
```

## Cross-references

- [`SECURITY.md`](../SECURITY.md) — vulnerability reporting policy
- [`EOL.md`](EOL.md) — version support windows
- [`docs/sigstore-quickstart.md`](sigstore-quickstart.md) — Sigstore introduction
