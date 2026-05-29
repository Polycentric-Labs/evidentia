# Evidence integrity

Evidentia's value proposition rests on a chain of custody: an auditor consuming an Evidentia output should be able to verify, cryptographically, that the artifact was produced by the configured instance and has not been tampered with. This page covers the three integrity mechanisms that make that possible — signed MCP tool outputs (Sigstore keyless), signed OSCAL Assessment Results (GPG detached), and the append-only / WORM evidence store — plus a clarification of what "CIMD" means in the codebase, because the name is easy to misread.

> **Terminology, up front.** In Evidentia's code, **CIMD = Client ID Metadata Document** (an OAuth/MCP client-registration concept, per RFC 7591), *not* a "cryptographic integrity manifest." The CIMD layer governs *which MCP client may call which tool*; the *cryptographic* integrity of tool outputs is a separate mechanism (`SignedToolOutput`). Both are described below so the distinction is unambiguous.

## Signed MCP tool outputs (`SignedToolOutput`)

The MCP server can wrap every tool output in a cryptographic envelope so a downstream consumer can verify the result was produced by the configured Evidentia instance without tampering in transit. The model is `SignedToolOutput` (`packages/evidentia-mcp/src/evidentia_mcp/signatures.py`), a NORMATIVE `EvidentiaModel` frozen against field-name changes (additions only). Verified fields:

| Field | Type | Notes |
|---|---|---|
| `schema_version` | `int` | Envelope version. v0.9.7 initial = 1. |
| `payload` | `dict[str, Any]` | The tool's raw output, unmodified. The wrapper does NOT mutate it. |
| `signed_at` | `datetime` | UTC timestamp the signature was computed. |
| `signature` | `dict[str, str] \| None` | Opaque signature metadata from the operator's signer. `None` when signing failed. |
| `signing_error` | `str \| None` | Populated when signing failed and the envelope was emitted anyway with `signature=None`. |
| `tool_name` | `str \| None` | Optional MCP tool name this envelope wraps. |

Four design rules govern the signing layer (from the `signatures.py` docstring):

1. **Signer-agnostic.** The signing backend is operator-supplied via a dotted-path factory env var (`EVIDENTIA_MCP_SIGNER_FACTORY`, format `module.submodule:callable_name`). Production wires Sigstore-keyless; dev/CI wires HMAC for determinism; air-gap wires GPG.
2. **Opt-in.** Default unset → tools emit raw payloads (backward-compatible). Setting `EVIDENTIA_MCP_SIGN_OUTPUTS` enables the wrapper.
3. **Envelope format stable.** `SignedToolOutput` is frozen; field additions are non-breaking, removals/renames require a deprecation cycle.
4. **Failure surfaces as a structured error, not a crash.** A signing failure emits a `SignedToolOutput` with `signature=None` + `signing_error` populated. Operators relying on signed-only output check `signature is not None`.

`sign_tool_output(payload, *, tool_name, signer)` canonicalizes the payload to deterministic JSON (`sort_keys=True`, no whitespace, `default=str` as a defense-in-depth fallback) before signing, so the same payload yields byte-identical signing input across hosts and Python sessions. `verify_tool_output(envelope, *, verifier)` reverses it: it returns `False` for an unsigned envelope or a failed verification, never raising. The threat-model boundary is explicit: tool-output signatures defend against in-transit tampering and provide audit-trail provenance; they do **not** defend against compromise of the signing key (which Sigstore keyless avoids by removing key material from the trust path).

### Sigstore keyless reference signer

The reference backend is `make_sigstore_signer()` in `packages/evidentia-mcp/src/evidentia_mcp/sigstore_signer.py` (v0.9.8). It removes operator key material from the trust path entirely — short-lived Fulcio certificates tied to an OIDC identity replace any long-lived private key. At factory-invocation time it:

1. Verifies the `sigstore` Python package is importable (the `[sigstore]` extra installs it).
2. Verifies the deployment is **not** in air-gap mode — Sigstore needs network access to Fulcio (the certificate authority) and Rekor (the transparency log). Air-gap deployments use a GPG-based signer instead.
3. Resolves an OIDC identity via `sigstore.oidc.detect_credential` (GitHub Actions OIDC, cloud workload identity, ambient env), once, captured in the signer's closure.
4. Returns a signer that, per call, signs the canonical JSON via a Fulcio short-lived cert and records inclusion in Rekor. The returned signature dict carries `alg: "sigstore-keyless"` and `bundle:` — the full Sigstore bundle JSON (cert chain + signature + Rekor inclusion proof), everything a verifier needs without consulting external key material.

The companion `make_sigstore_verifier(*, expected_identity, expected_issuer)` builds a verifier that checks the bundle **and** that the signing certificate matches the expected OIDC identity + issuer — pinning both prevents a valid signature from a *different* identity (or a different OIDC provider) being accepted. Failures (bad cert chain, Rekor mismatch, identity-policy violation, network outage) collapse to a `False` return; callers wanting structured diagnostics use the file-based `evidentia_core.oscal.sigstore.verify_file` instead.

Configuration errors surface at server startup, not at first tool dispatch, so operators see misconfigurations immediately:

```bash
export EVIDENTIA_MCP_SIGN_OUTPUTS=1
export EVIDENTIA_MCP_SIGNER_FACTORY=evidentia_mcp.sigstore_signer:make_sigstore_signer
evidentia mcp serve --transport stdio
```

## Signed OSCAL Assessment Results (GPG detached)

The OSCAL emit path has its own signing surface: `evidentia_core.oscal.signing` produces ASCII-armored GPG detached signatures (`.asc`) for OSCAL Assessment Results documents. It's a thin `subprocess` wrapper around the `gpg` binary (GnuPG 2.x) rather than a Python library, deliberately — the binary is a universal install, air-gap friendly (no network, no telemetry), and the authoritative reference for OpenPGP. ASCII armor means a signed bundle survives email/Slack/text-only channels without binary mangling.

- `sign_file(artifact_path, *, key_id, signature_path=None, gnupghome=None) -> Path` — runs `gpg --batch --yes --armor --detach-sign --local-user <key_id>`; defaults the signature to `<artifact>.asc`. `key_id` is mandatory because unambiguous signer identity is the whole point. Raises `GPGNotAvailableError` if `gpg` isn't on PATH, `GPGSigningError` on a non-zero exit.
- `verify_file(artifact_path, *, signature_path=None, gnupghome=None) -> VerifyResult` — runs `gpg --verify` with `--status-fd 1` and parses the machine-readable status lines. Returns a `VerifyResult` dataclass (`valid: bool`, `signer_key_id`, `signer_fingerprint`, `stderr`). A signature *mismatch* is `valid=False`, not an exception — the caller decides what to do about a broken chain; exceptions are reserved for infrastructure failures (missing files, GnuPG crash). A valid signature is meaningless without identifying the signer, so the result captures *who* signed via the `GOODSIG`/`VALIDSIG` status codes.

Both paths emit structured audit events from the frozen `EventAction` vocabulary (`SIGN_GPG_SIGNED`, `SIGN_FAILED`, `VERIFY_SIGNATURE_PASSED`, `VERIFY_SIGNATURE_FAILED`), so the signing operations themselves land in the SIEM-friendly audit trail.

## The append-only / WORM evidence store

Cryptographic signatures attest to a single artifact; the evidence store attests to the **history** of an evidence chain. `evidentia_core.evidence_store` is an append-only store with a deliberately simple layout: one directory per lineage chain, one JSON file per version within it.

```
<store_root>/
  <lineage_id_A>/
    v1.json
    v2.json
    v3.json
  <lineage_id_B>/
    v1.json
```

This layout buys three properties at once: versions are discoverable by a plain directory listing (no manifest to read); append-only enforcement is per-file (`save_evidence` refuses to overwrite an existing `v<N>.json`, and the `EvidenceArtifact.new_version()` helper always produces `v<N+1>`, so a normal "edit" is automatically a fresh file); and the directory *is* the lineage (no separate manifest to keep in sync — the largest version present is the chain head). Path resolution mirrors the POA&M store: explicit override → `EVIDENTIA_EVIDENCE_STORE_DIR` → `platformdirs` default, with UUID-shape validation and `validate_within` path-traversal protection throughout.

The store's threat-model boundary is honest: WORM enforcement *here* is **application-layer** — a privileged operator can delete the JSON files with OS tools. For regulator-grade, hardware-enforced WORM, operators also wire a cloud-WORM backend.

### The WORM backend contract

`evidentia_core.retention.worm` defines the abstract `WORMBackend` (Write-Once-Read-Many) contract that concrete cloud backends implement. The abstract methods:

- `put(record_id, payload, metadata)` — write a record + its `RetentionMetadata`. Immutable until `lock_until`.
- `get(record_id)` / `get_metadata(record_id)` — read the record / its retention metadata.
- `delete(record_id, today=None)` — allowed **only** if the record is purgeable: lifecycle stage `EXPIRED`, not under legal hold, and past its lock window. Any violation raises `WORMBackendError`.
- `extend_retention(record_id, new_lock_until)` — extends the lock (the legal-hold pattern). **Cannot shorten** retention — that would violate WORM, so a shorter date raises.
- `purge_immediately(...)` — a GDPR Article 17 (right-to-erasure) override, gated to records with `retention_period_days == 0` and not under legal hold (legal hold trumps GDPR), requiring a `gdpr_request_ref` + `operator_id` for audit provenance, and emitting the `RETENTION_GDPR_PURGE` audit event on success.

A reference `LocalFilesystemWORM` ships in the same module (records as `<root>/<record_id>.bin` + a sibling `.meta.json`, with atomic `os.replace` writes that work on POSIX and Windows). It enforces WORM via application-level metadata checks only — the filesystem provides no hardware guarantee — and is suitable for development and testing. Production-grade chain of custody uses the cloud backends in `evidentia_core.retention.worm_s3` (S3 Object Lock), `worm_azure` (Azure Immutable Blob), and `worm_gcs` (GCS Bucket Lock).

When `EVIDENTIA_EVIDENCE_AUTO_MIRROR_WORM` is set, `save_evidence` mirrors each successful local-store write to a cloud-WORM backend (resolved from the `EVIDENTIA_EVIDENCE_WORM_BACKEND_FACTORY` dotted-path env var) via `evidentia_core.evidence_store_worm.mirror_to_worm` — giving operators application-layer append-only locally *plus* hardware-enforced WORM in the cloud, gated behind one env var.

## CIMD — the MCP client-metadata layer (not a signing primitive)

`evidentia_mcp/cimd.py` implements a **Client ID Metadata Document** registry per the OAuth Dynamic Client Registration spec (RFC 7591). Each registered client has a stable `client_id`, a `client_name`, and a space-separated `scope` field that acts as an allowlist of MCP tool names the client may call. The registry (`CIMDRegistry`, loaded from a JSON file via `from_file`) supports multi-tenant MCP deployments (one server instance, multiple clients with different scopes), per-client audit trails (the calling `client_id` is logged on each tool fire), and forward-looking `policy_uri` / `tos_uri` metadata.

CIMD is **optional** and is **not authentication**: when no registry is configured the server preserves no-gating behavior (every tool callable by every client). When configured, it's a metadata + scope layer that runs *on top of* whatever authentication the transport provides (reverse-proxy auth for HTTP/SSE, UID-based trust for stdio). A client that bypasses transport auth could claim any `client_id`, so operators deploying CIMD must also wire transport authentication. Operators can evolve a deployment's CIMD via the `evidentia mcp cimd-migrate` CLI verb (v0.9.7+). Cryptographic CIMD signatures (binding `client_id` to a key the client proves it holds) are a documented future direction, separate from the metadata registry that ships today.

## Related reading

- [Architecture](architecture.md) — the end-to-end cryptographic chain (evidence → signed envelope → OSCAL → cosign-signed container → PEP 740 wheel → SBOM → SLSA provenance).
- [Frozen surfaces and stability](frozen-surfaces-and-stability.md) — `SignedToolOutput` and the env-var public contract.
- [RBAC and multi-tenancy](rbac-and-multi-tenancy.md) — the authorization layer that complements CIMD scope gating.
- [`2-guides/sign-and-verify-evidence.md`](../2-guides/sign-and-verify-evidence.md) — the operator how-to.
- [`6-project/verification.md`](../6-project/verification.md) — verifying released artifacts (wheels, container, SBOM).
