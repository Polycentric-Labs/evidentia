"""Evidence chain-of-custody verifier for OSCAL AR documents (v0.7.0).

Orchestrates up to three integrity checks applied to a signed OSCAL
Assessment Results export:

1. **Digest check.** Every embedded evidence resource in
   ``back-matter.resources[]`` carries a ``hashes[]`` entry
   (OSCAL-standard) computed by :mod:`evidentia_core.oscal.digest`.
   :func:`verify_digests` re-hashes the embedded base64 content and
   compares.

2. **GPG signature check.** If a detached GPG signature (``.asc``)
   exists alongside the AR JSON, :func:`verify_signature` runs
   ``gpg --verify`` via :mod:`evidentia_core.oscal.signing`.

3. **Sigstore signature check (v0.7.0).** If a Sigstore bundle
   (``.sigstore.json``) exists alongside the AR JSON, the bundle is
   verified via :mod:`evidentia_core.oscal.sigstore`. Optional
   ``expected_sigstore_identity`` + ``expected_sigstore_issuer`` enforce
   a strict identity policy; without both, the verifier falls back to
   ``UnsafeNoOp`` (accepts any signer) and emits a structured warning.

A "clean" AR passes every check that's applicable. A "tampered" AR
fails the digest check (someone rewrote an embedded finding). A
"forged" AR passes digests but fails the signature check (someone
regenerated the export on a different machine). A "replayed" AR
passes everything but is stale — freshness is the operator's
responsibility, not this module's.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from evidentia_core.oscal.digest import digest_bytes, parse_digest


@dataclass
class DigestCheck:
    """Per-resource outcome of the digest phase."""

    resource_uuid: str
    title: str
    expected_digest: str
    actual_digest: str
    valid: bool


@dataclass
class VerifyReport:
    """Full verification outcome for an OSCAL AR document.

    ``overall_valid`` is the top-line pass/fail. Every other field is
    there so a CLI or audit UI can drill into *why* the document failed.

    v0.7.0 added the ``sigstore_*`` fields to surface Sigstore/Rekor
    signature verification alongside the existing GPG fields. Both can
    coexist for defence-in-depth — the ``overall_valid`` property
    requires every present signature to verify.
    """

    ar_path: Path
    digest_checks: list[DigestCheck] = field(default_factory=list)
    signature_valid: bool | None = None  # None = not checked (GPG)
    signature_signer: str | None = None
    signature_fingerprint: str | None = None
    sigstore_signature_valid: bool | None = None  # None = not checked
    sigstore_signer_identity: str | None = None
    sigstore_signer_issuer: str | None = None
    sigstore_rekor_log_index: int | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def digests_valid(self) -> bool:
        """True iff every embedded resource digest matches its content.

        Returns False when ``digest_checks`` is empty. Pre-v0.7.5
        ``overall_valid`` consulted this property and conflated "no
        embedded evidence" with "digests failed" — that was the source
        of the FAIL-on-metadata-only-AR bug fixed by v0.7.5 R2.
        Semantics here are retained for JSON-consumer back-compat;
        ``overall_valid`` no longer relies on this property.
        """
        return bool(self.digest_checks) and all(
            check.valid for check in self.digest_checks
        )

    @property
    def has_verification_surface(self) -> bool:
        """True if at least one verification check ran (digest, GPG, or
        Sigstore). False means the AR is a metadata-only document with
        nothing to verify — when ``overall_valid`` is also True, the
        result is a "no-op PASS" rather than a meaningful trust assertion.
        Surfaced by the CLI so users see ``PASS (no verification surface)``
        instead of an unqualified PASS.
        """
        return (
            bool(self.digest_checks)
            or self.signature_valid is not None
            or self.sigstore_signature_valid is not None
        )

    @property
    def overall_valid(self) -> bool:
        """Top-level pass/fail.

        PASS when:
        - No errors raised during verification (the ``--require-signature``
          failure path appends to ``errors`` before this property is
          consulted, so missing-signature-when-required surfaces here)
        - Every embedded digest that was present is valid; an empty
          ``digest_checks`` list is vacuously OK ("nothing to verify,
          nothing failed")
        - Every signature that was checked verified (``None`` means not
          checked, not "missing"; ``False`` means found but invalid)

        v0.7.5 R2 fix: pre-v0.7.5 used ``if not self.digests_valid``
        which returned True only when at least one digest existed AND
        all were valid. That conflated "no verification surface" with
        "digests failed", returning FAIL on metadata-only ARs that had
        no signature or evidence to check. The current logic checks
        only for explicit failures; empty surfaces are vacuously valid.
        """
        if self.errors:
            return False
        if any(not check.valid for check in self.digest_checks):
            return False
        if self.signature_valid is False:
            return False
        # ``is not False`` covers both valid-True and not-checked-None in
        # one comparison (mirrors the ``signature_valid`` check above
        # but flattened per ruff SIM103). Returns True iff every
        # signature that was checked is valid.
        return self.sigstore_signature_valid is not False


def verify_digests(ar_doc: dict[str, Any]) -> list[DigestCheck]:
    """Re-hash every embedded evidence resource and compare to stored digests.

    Walks ``back-matter.resources[]``, decodes each resource's ``base64``
    content, and computes its SHA-256. Returns one :class:`DigestCheck`
    per resource. A resource without an embedded ``base64`` block is
    skipped (it might reference an external URL, which is out of scope
    for v0.7.0 digest verification).
    """
    checks: list[DigestCheck] = []
    back_matter = ar_doc.get("assessment-results", {}).get("back-matter", {})
    resources = back_matter.get("resources", [])

    for resource in resources:
        uuid_ = resource.get("uuid", "")
        title = resource.get("title", "")
        b64_block = resource.get("base64")
        if not b64_block or "value" not in b64_block:
            # External resource or metadata-only — no content to hash.
            continue

        rlinks = resource.get("rlinks", [])
        expected_hex = _extract_expected_digest(rlinks)
        if expected_hex is None:
            # Resource embeds content but has no hash to verify against.
            # Flag as invalid — silent pass would defeat the whole point.
            checks.append(
                DigestCheck(
                    resource_uuid=uuid_,
                    title=title,
                    expected_digest="",
                    actual_digest="",
                    valid=False,
                )
            )
            continue

        try:
            content = base64.b64decode(b64_block["value"], validate=True)
        except (ValueError, TypeError):
            checks.append(
                DigestCheck(
                    resource_uuid=uuid_,
                    title=title,
                    expected_digest=expected_hex,
                    actual_digest="<decode-error>",
                    valid=False,
                )
            )
            continue

        actual_hex = digest_bytes(content)
        checks.append(
            DigestCheck(
                resource_uuid=uuid_,
                title=title,
                expected_digest=expected_hex,
                actual_digest=actual_hex,
                valid=(actual_hex == expected_hex),
            )
        )

    return checks


def verify_ar_file(
    ar_path: str | Path,
    *,
    require_signature: bool = False,
    signature_path: str | Path | None = None,
    gnupghome: str | Path | None = None,
    check_sigstore: bool = True,
    sigstore_bundle_path: str | Path | None = None,
    expected_sigstore_identity: str | None = None,
    expected_sigstore_issuer: str | None = None,
) -> VerifyReport:
    """Verify an OSCAL AR JSON file end-to-end.

    Parameters
    ----------
    ar_path:
        Path to the ``.oscal-ar.json`` (or any ``.json``) OSCAL AR file.
    require_signature:
        If True, a missing signature is a verification failure. With
        ``check_sigstore=True`` (default), EITHER a GPG ``.asc`` OR a
        Sigstore ``.sigstore.json`` satisfies the requirement. If False
        (default), an unsigned AR passes if digests check out —
        signature checks are opportunistic.
    signature_path:
        Custom GPG signature-file path. Defaults to ``<ar_path>.asc``.
    gnupghome:
        Optional ``GNUPGHOME`` override for GPG signature verification.
        Useful when verifying against a specific keyring (e.g., a
        CI-scoped key store rather than the operator's default ``~/.gnupg``).
    check_sigstore:
        When True (default), look for a Sigstore bundle alongside the AR
        and verify it if present. Set to False to skip Sigstore checks
        entirely (e.g., for air-gap-only verification).
    sigstore_bundle_path:
        Custom Sigstore bundle path. Defaults to ``<ar_path>.sigstore.json``.
    expected_sigstore_identity:
        Required signer identity (email or OIDC subject) for Sigstore
        verification. When omitted along with ``expected_sigstore_issuer``,
        the verifier falls back to ``UnsafeNoOp`` policy (accepts any
        signer) and adds a structured warning to the report. Production
        audit pipelines should always set both this AND
        ``expected_sigstore_issuer``.
    expected_sigstore_issuer:
        Required Sigstore identity issuer (e.g.,
        ``https://token.actions.githubusercontent.com``). Required if
        ``expected_sigstore_identity`` is set; ignored otherwise.
    """
    ar_path = Path(ar_path)
    report = VerifyReport(ar_path=ar_path)

    if not ar_path.is_file():
        report.errors.append(f"AR file not found: {ar_path}")
        return report

    try:
        ar_doc = json.loads(ar_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        report.errors.append(f"Malformed JSON: {e}")
        return report

    report.digest_checks = verify_digests(ar_doc)

    # ── GPG signature path ──────────────────────────────────────────────
    sig_path = Path(signature_path) if signature_path else ar_path.with_suffix(
        ar_path.suffix + ".asc"
    )
    gpg_exists = sig_path.is_file()

    # ── Sigstore bundle path ────────────────────────────────────────────
    sigstore_path = (
        Path(sigstore_bundle_path)
        if sigstore_bundle_path
        else ar_path.with_suffix(ar_path.suffix + ".sigstore.json")
    )
    sigstore_exists = check_sigstore and sigstore_path.is_file()

    # require_signature is satisfied by EITHER GPG or Sigstore in v0.7.0+
    if require_signature and not gpg_exists and not sigstore_exists:
        report.errors.append(
            f"Signature required but neither found: {sig_path} or "
            f"{sigstore_path}"
        )
        report.signature_valid = False
        report.sigstore_signature_valid = False
        return report

    if gpg_exists:
        # Deferred import — callers that don't need signature checks get
        # loaded without touching the gpg-availability probe.
        from evidentia_core.oscal.signing import (
            GPGError,
        )
        from evidentia_core.oscal.signing import (
            verify_file as gpg_verify_file,
        )

        try:
            result = gpg_verify_file(
                ar_path, signature_path=sig_path, gnupghome=gnupghome
            )
        except GPGError as e:
            report.errors.append(f"GPG signature verification failed: {e}")
            report.signature_valid = False
        else:
            report.signature_valid = result.valid
            report.signature_signer = result.signer_key_id
            report.signature_fingerprint = result.signer_fingerprint

    if sigstore_exists:
        # Deferred import — sigstore-python is an optional extra; callers
        # that didn't install [sigstore] still get GPG + digest checks.
        try:
            from evidentia_core.oscal.sigstore import (
                SigstoreError,
                SigstoreNotAvailableError,
            )
            from evidentia_core.oscal.sigstore import (
                verify_file as sigstore_verify_file,
            )
        except ImportError as e:  # pragma: no cover — sigstore module always importable
            report.errors.append(f"Sigstore module unavailable: {e}")
            report.sigstore_signature_valid = False
            return report

        if expected_sigstore_identity is None or expected_sigstore_issuer is None:
            report.warnings.append(
                "Sigstore signature found but no --expected-identity / "
                "--expected-issuer supplied. Using UnsafeNoOp policy "
                "(accepts ANY signer). Production audit pipelines should "
                "always set both flags."
            )

        try:
            ss_result = sigstore_verify_file(
                ar_path,
                bundle_path=sigstore_path,
                expected_identity=expected_sigstore_identity,
                expected_issuer=expected_sigstore_issuer,
            )
        except SigstoreNotAvailableError as e:
            report.errors.append(f"Sigstore verification unavailable: {e}")
            report.sigstore_signature_valid = False
            return report
        except SigstoreError as e:
            report.errors.append(f"Sigstore verification failed: {e}")
            report.sigstore_signature_valid = False
            return report

        report.sigstore_signature_valid = ss_result.valid
        report.sigstore_signer_identity = ss_result.signer_identity
        report.sigstore_signer_issuer = ss_result.signer_issuer
        report.sigstore_rekor_log_index = ss_result.rekor_log_index

    return report


def _extract_expected_digest(rlinks: list[dict[str, Any]]) -> str | None:
    """Return the SHA-256 hex digest from the first matching ``rlinks[].hashes[]``.

    OSCAL hashes entries look like ``{"algorithm": "SHA-256", "value": "<hex>"}``.
    We accept the canonical ``SHA-256`` and also the compact ``sha256``
    (plus a ``sha256:<hex>`` prop-style value as a fallback for older
    v0.7.0-beta tooling that may have written the non-standard form).
    """
    for rlink in rlinks:
        for hash_entry in rlink.get("hashes", []):
            algo = str(hash_entry.get("algorithm", "")).lower().replace("-", "")
            if algo == "sha256":
                raw_value = str(hash_entry.get("value", ""))
                if ":" in raw_value:
                    try:
                        _, hex_digest = parse_digest(raw_value)
                        return hex_digest
                    except ValueError:
                        continue
                return raw_value
    return None
