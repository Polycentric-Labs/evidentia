"""Tests for :mod:`evidentia_core.oscal.verify` (v0.7.0).

Covers the digest-checking half of the verifier (the signature half is
covered by ``test_signing.py`` round-trip tests; ``test_verify_ar_file``
here exercises the orchestration that pulls them together).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from evidentia_core.models.common import Severity
from evidentia_core.models.finding import SecurityFinding
from evidentia_core.models.gap import (
    ControlGap,
    GapAnalysisReport,
    GapSeverity,
    GapStatus,
    ImplementationEffort,
)
from evidentia_core.oscal import keysign
from evidentia_core.oscal.exporter import gap_report_to_oscal_ar
from evidentia_core.oscal.verify import verify_ar_file, verify_digests

# ── fixtures ─────────────────────────────────────────────────────────────


def _make_gap(control_id: str = "AC-2") -> ControlGap:
    return ControlGap(
        framework="nist-800-53-mod",
        control_id=control_id,
        control_title=f"{control_id} title",
        control_description="desc",
        gap_severity=GapSeverity.HIGH,
        implementation_status="missing",
        gap_description="not implemented",
        remediation_guidance="implement",
        implementation_effort=ImplementationEffort.MEDIUM,
        priority_score=1.0,
        status=GapStatus.OPEN,
    )


def _make_finding(control_ids: list[str] | None = None) -> SecurityFinding:
    return SecurityFinding(
        id="22222222-2222-2222-2222-222222222222",
        title="Privileged account lacks MFA",
        description="Root account missing MFA enforcement.",
        severity=Severity.HIGH,
        source_system="aws-config",
        control_ids=control_ids or ["AC-2"],
    )


def _make_report() -> GapAnalysisReport:
    gap = _make_gap("AC-2")
    return GapAnalysisReport(
        organization="TestOrg",
        frameworks_analyzed=["nist-800-53-mod"],
        total_controls_required=1,
        total_controls_in_inventory=0,
        total_gaps=1,
        critical_gaps=0,
        high_gaps=1,
        medium_gaps=0,
        low_gaps=0,
        informational_gaps=0,
        coverage_percentage=0.0,
        gaps=[gap],
        efficiency_opportunities=[],
        prioritized_roadmap=[gap.id],
        inventory_source="test.yaml",
    )


# ── verify_digests ───────────────────────────────────────────────────────


def test_verify_digests_all_pass_for_clean_export() -> None:
    """A fresh export with no tampering should re-hash cleanly."""
    ar_doc = gap_report_to_oscal_ar(_make_report(), findings=[_make_finding()])
    checks = verify_digests(ar_doc)
    assert len(checks) == 1
    assert checks[0].valid is True
    assert checks[0].expected_digest == checks[0].actual_digest


def test_verify_digests_detects_tampered_resource_payload() -> None:
    """Re-encode a different payload under the same hash → integrity fails."""
    ar_doc = gap_report_to_oscal_ar(_make_report(), findings=[_make_finding()])
    resource = ar_doc["assessment-results"]["back-matter"]["resources"][0]

    # Tamper: replace the base64 content with something different, but
    # leave the hash value intact. This is the classic attack the feature
    # is meant to detect.
    tampered_content = b'{"malicious": "payload"}'
    resource["base64"]["value"] = base64.b64encode(tampered_content).decode("ascii")

    checks = verify_digests(ar_doc)
    assert len(checks) == 1
    assert checks[0].valid is False
    assert checks[0].expected_digest != checks[0].actual_digest


def test_verify_digests_flags_resource_with_missing_hash() -> None:
    """Embedded content with no hashes[] entry → invalid (silent pass would
    defeat the chain-of-custody claim)."""
    ar_doc = gap_report_to_oscal_ar(_make_report(), findings=[_make_finding()])
    resource = ar_doc["assessment-results"]["back-matter"]["resources"][0]
    resource["rlinks"] = [{"href": "#whatever"}]  # no hashes[]
    checks = verify_digests(ar_doc)
    assert len(checks) == 1
    assert checks[0].valid is False


def test_verify_digests_skips_external_resources_without_base64() -> None:
    """Resources that point at external files have nothing to re-hash
    locally; they should be silently skipped (not flagged)."""
    ar_doc = {
        "assessment-results": {
            "back-matter": {
                "resources": [
                    {
                        "uuid": "external-uuid",
                        "title": "External evidence",
                        "rlinks": [{"href": "https://example.com/evidence.pdf"}],
                        # No base64 block — pure metadata pointer
                    }
                ]
            }
        }
    }
    checks = verify_digests(ar_doc)
    assert checks == []


def test_verify_digests_returns_empty_when_no_back_matter() -> None:
    """An AR with no evidence resources has nothing to check — return []."""
    ar_doc = gap_report_to_oscal_ar(_make_report())  # no findings
    checks = verify_digests(ar_doc)
    assert checks == []


# ── verify_ar_file ───────────────────────────────────────────────────────


def test_verify_ar_file_passes_on_clean_export(tmp_path: Path) -> None:
    ar_doc = gap_report_to_oscal_ar(_make_report(), findings=[_make_finding()])
    ar_path = tmp_path / "audit.json"
    ar_path.write_text(json.dumps(ar_doc), encoding="utf-8")

    report = verify_ar_file(ar_path)
    assert report.overall_valid is True
    assert report.digests_valid is True
    assert report.signature_valid is None  # no sig on disk, none required


def test_verify_ar_file_fails_on_tampered_content(tmp_path: Path) -> None:
    ar_doc = gap_report_to_oscal_ar(_make_report(), findings=[_make_finding()])

    # Tamper the base64 content before writing to disk.
    resource = ar_doc["assessment-results"]["back-matter"]["resources"][0]
    resource["base64"]["value"] = base64.b64encode(b"tampered").decode("ascii")

    ar_path = tmp_path / "audit.json"
    ar_path.write_text(json.dumps(ar_doc), encoding="utf-8")

    report = verify_ar_file(ar_path)
    assert report.overall_valid is False
    assert report.digests_valid is False


def test_verify_ar_file_missing_file_returns_error(tmp_path: Path) -> None:
    report = verify_ar_file(tmp_path / "does-not-exist.json")
    assert report.overall_valid is False
    assert any("not found" in err for err in report.errors)


def test_verify_ar_file_malformed_json_returns_error(tmp_path: Path) -> None:
    path = tmp_path / "garbage.json"
    path.write_text("this is { not valid json", encoding="utf-8")
    report = verify_ar_file(path)
    assert report.overall_valid is False
    assert any("Malformed JSON" in err for err in report.errors)


def test_verify_ar_file_require_signature_without_sig_fails(
    tmp_path: Path,
) -> None:
    """--require-signature turns a missing .asc into a failure."""
    ar_doc = gap_report_to_oscal_ar(_make_report())
    ar_path = tmp_path / "unsigned.json"
    ar_path.write_text(json.dumps(ar_doc), encoding="utf-8")

    report = verify_ar_file(ar_path, require_signature=True)
    assert report.overall_valid is False
    assert report.signature_valid is False
    assert report.sigstore_signature_valid is False


def test_verify_ar_file_no_evidence_no_signature_passes_with_no_surface(
    tmp_path: Path,
) -> None:
    """v0.7.5 R2 regression: a metadata-only AR with no embedded
    evidence + no signatures + ``--require-signature`` unset must
    return overall_valid=True with has_verification_surface=False
    (a "no-op PASS"), not the misleading FAIL it returned pre-v0.7.5.

    Pre-v0.7.5 ``overall_valid`` consulted ``digests_valid`` which
    returned False when ``digest_checks`` was empty, conflating
    "no surface" with "failed surface". The fix decouples the two:
    ``overall_valid`` now uses vacuous-truth semantics on empty
    surfaces, while ``digests_valid`` retains its False-when-empty
    behavior for JSON-consumer back-compat.
    """
    ar_doc = gap_report_to_oscal_ar(_make_report())  # no findings → no evidence
    ar_path = tmp_path / "metadata-only.json"
    ar_path.write_text(json.dumps(ar_doc), encoding="utf-8")

    report = verify_ar_file(ar_path)
    # The fix: was False pre-v0.7.5, must be True post-fix.
    assert report.overall_valid is True
    # New property: distinguishes "no-op PASS" from meaningful PASS.
    assert report.has_verification_surface is False
    # Sanity-check the surface really is empty.
    assert report.digest_checks == []
    assert report.signature_valid is None
    assert report.sigstore_signature_valid is None
    # Back-compat: digests_valid still returns False when empty so JSON
    # consumers reading the boolean don't see an unexpected flip.
    assert report.digests_valid is False


def test_verify_ar_file_no_evidence_with_require_signature_still_fails(
    tmp_path: Path,
) -> None:
    """v0.7.5 R2 reverse case: --require-signature on a metadata-only
    AR must still FAIL, because signature was required and not present.
    The R2 fix only loosens overall_valid for the no-surface + no-
    require-signature case; the require-signature path is unchanged.
    """
    ar_doc = gap_report_to_oscal_ar(_make_report())  # no findings → no evidence
    ar_path = tmp_path / "metadata-only-required.json"
    ar_path.write_text(json.dumps(ar_doc), encoding="utf-8")

    report = verify_ar_file(ar_path, require_signature=True)
    assert report.overall_valid is False
    assert any("Signature required" in err for err in report.errors)


# ── Sigstore integration in verify_ar_file (v0.7.0 Step-4 fix) ──────────


def test_verify_ar_file_no_sigstore_bundle_present(tmp_path: Path) -> None:
    """When no <path>.sigstore.json exists, sigstore_* fields stay None."""
    ar_doc = gap_report_to_oscal_ar(_make_report(), findings=[_make_finding()])
    ar_path = tmp_path / "audit.json"
    ar_path.write_text(json.dumps(ar_doc), encoding="utf-8")

    report = verify_ar_file(ar_path)
    assert report.sigstore_signature_valid is None
    assert report.sigstore_signer_identity is None
    assert report.overall_valid is True  # digests pass; no signatures required


def test_verify_ar_file_sigstore_bundle_present_triggers_verification(tmp_path: Path, monkeypatch) -> None:
    """When <path>.sigstore.json exists, sigstore.verify_file is called and
    the result populates the VerifyReport's sigstore_* fields."""
    from unittest.mock import MagicMock

    from evidentia_core.oscal import sigstore as sigstore_mod
    from evidentia_core.oscal.sigstore import SigstoreVerifyResult

    ar_doc = gap_report_to_oscal_ar(_make_report(), findings=[_make_finding()])
    ar_path = tmp_path / "audit.json"
    ar_path.write_text(json.dumps(ar_doc), encoding="utf-8")
    bundle_path = ar_path.with_suffix(ar_path.suffix + ".sigstore.json")
    bundle_path.write_text('{"fake": "bundle"}', encoding="utf-8")

    fake_result = SigstoreVerifyResult(
        valid=True,
        signer_identity="ci@example.com",
        signer_issuer="https://token.actions.githubusercontent.com",
        rekor_log_index=42,
    )
    mock_verify = MagicMock(return_value=fake_result)
    monkeypatch.setattr(sigstore_mod, "verify_file", mock_verify)

    report = verify_ar_file(ar_path)
    assert mock_verify.call_count == 1
    assert report.sigstore_signature_valid is True
    assert report.sigstore_signer_identity == "ci@example.com"
    assert report.sigstore_signer_issuer == "https://token.actions.githubusercontent.com"
    assert report.sigstore_rekor_log_index == 42
    assert report.overall_valid is True


def test_verify_ar_file_sigstore_invalid_bundle_fails_overall(tmp_path: Path, monkeypatch) -> None:
    """A bundle that exists but verifies as invalid fails overall_valid."""
    from unittest.mock import MagicMock

    from evidentia_core.oscal import sigstore as sigstore_mod
    from evidentia_core.oscal.sigstore import SigstoreVerifyResult

    ar_doc = gap_report_to_oscal_ar(_make_report(), findings=[_make_finding()])
    ar_path = tmp_path / "audit.json"
    ar_path.write_text(json.dumps(ar_doc), encoding="utf-8")
    bundle_path = ar_path.with_suffix(ar_path.suffix + ".sigstore.json")
    bundle_path.write_text('{"fake": "bundle"}', encoding="utf-8")

    bad_result = SigstoreVerifyResult(valid=False, details="signature mismatch")
    monkeypatch.setattr(sigstore_mod, "verify_file", MagicMock(return_value=bad_result))

    report = verify_ar_file(ar_path)
    assert report.sigstore_signature_valid is False
    assert report.overall_valid is False


def test_verify_ar_file_check_sigstore_false_skips_bundle(tmp_path: Path, monkeypatch) -> None:
    """check_sigstore=False skips the bundle even if it's present on disk."""
    from unittest.mock import MagicMock

    from evidentia_core.oscal import sigstore as sigstore_mod

    ar_doc = gap_report_to_oscal_ar(_make_report(), findings=[_make_finding()])
    ar_path = tmp_path / "audit.json"
    ar_path.write_text(json.dumps(ar_doc), encoding="utf-8")
    bundle_path = ar_path.with_suffix(ar_path.suffix + ".sigstore.json")
    bundle_path.write_text('{"fake": "bundle"}', encoding="utf-8")

    mock_verify = MagicMock()
    monkeypatch.setattr(sigstore_mod, "verify_file", mock_verify)

    report = verify_ar_file(ar_path, check_sigstore=False)
    assert mock_verify.call_count == 0
    assert report.sigstore_signature_valid is None


def test_verify_ar_file_sigstore_warns_when_no_expected_identity(tmp_path: Path, monkeypatch) -> None:
    """Bundle present but no expected_identity → warning emitted (UnsafeNoOp)."""
    from unittest.mock import MagicMock

    from evidentia_core.oscal import sigstore as sigstore_mod
    from evidentia_core.oscal.sigstore import SigstoreVerifyResult

    ar_doc = gap_report_to_oscal_ar(_make_report(), findings=[_make_finding()])
    ar_path = tmp_path / "audit.json"
    ar_path.write_text(json.dumps(ar_doc), encoding="utf-8")
    bundle_path = ar_path.with_suffix(ar_path.suffix + ".sigstore.json")
    bundle_path.write_text('{"fake": "bundle"}', encoding="utf-8")

    monkeypatch.setattr(
        sigstore_mod,
        "verify_file",
        MagicMock(return_value=SigstoreVerifyResult(valid=True)),
    )

    report = verify_ar_file(ar_path)
    assert any("UnsafeNoOp" in w for w in report.warnings)


def test_verify_ar_file_require_signature_satisfied_by_sigstore(tmp_path: Path, monkeypatch) -> None:
    """With require_signature=True, a Sigstore bundle alone satisfies the requirement."""
    from unittest.mock import MagicMock

    from evidentia_core.oscal import sigstore as sigstore_mod
    from evidentia_core.oscal.sigstore import SigstoreVerifyResult

    ar_doc = gap_report_to_oscal_ar(_make_report(), findings=[_make_finding()])
    ar_path = tmp_path / "audit.json"
    ar_path.write_text(json.dumps(ar_doc), encoding="utf-8")
    bundle_path = ar_path.with_suffix(ar_path.suffix + ".sigstore.json")
    bundle_path.write_text('{"fake": "bundle"}', encoding="utf-8")

    monkeypatch.setattr(
        sigstore_mod,
        "verify_file",
        MagicMock(
            return_value=SigstoreVerifyResult(
                valid=True,
                signer_identity="ci@example.com",
                signer_issuer="https://token.actions.githubusercontent.com",
            )
        ),
    )

    report = verify_ar_file(ar_path, require_signature=True)
    assert report.overall_valid is True
    assert report.sigstore_signature_valid is True


def test_verify_ar_file_custom_sigstore_bundle_path(tmp_path: Path, monkeypatch) -> None:
    """sigstore_bundle_path overrides the default <path>.sigstore.json."""
    from unittest.mock import MagicMock

    from evidentia_core.oscal import sigstore as sigstore_mod
    from evidentia_core.oscal.sigstore import SigstoreVerifyResult

    ar_doc = gap_report_to_oscal_ar(_make_report(), findings=[_make_finding()])
    ar_path = tmp_path / "audit.json"
    ar_path.write_text(json.dumps(ar_doc), encoding="utf-8")
    custom_bundle = tmp_path / "custom.sigstore.json"
    custom_bundle.write_text('{"fake": "bundle"}', encoding="utf-8")

    monkeypatch.setattr(
        sigstore_mod,
        "verify_file",
        MagicMock(return_value=SigstoreVerifyResult(valid=True)),
    )

    report = verify_ar_file(ar_path, sigstore_bundle_path=custom_bundle)
    assert report.sigstore_signature_valid is True


def test_verify_ar_file_sigstore_with_expected_identity_no_warning(tmp_path: Path, monkeypatch) -> None:
    """When both expected_identity and expected_issuer are set, no UnsafeNoOp warning."""
    from unittest.mock import MagicMock

    from evidentia_core.oscal import sigstore as sigstore_mod
    from evidentia_core.oscal.sigstore import SigstoreVerifyResult

    ar_doc = gap_report_to_oscal_ar(_make_report(), findings=[_make_finding()])
    ar_path = tmp_path / "audit.json"
    ar_path.write_text(json.dumps(ar_doc), encoding="utf-8")
    bundle_path = ar_path.with_suffix(ar_path.suffix + ".sigstore.json")
    bundle_path.write_text('{"fake": "bundle"}', encoding="utf-8")

    monkeypatch.setattr(
        sigstore_mod,
        "verify_file",
        MagicMock(return_value=SigstoreVerifyResult(valid=True)),
    )

    report = verify_ar_file(
        ar_path,
        expected_sigstore_identity="ci@example.com",
        expected_sigstore_issuer="https://token.actions.githubusercontent.com",
    )
    assert not any("UnsafeNoOp" in w for w in report.warnings)


def test_verify_ar_file_sigstore_single_flag_fails_with_report_error(
    tmp_path: Path,
) -> None:
    """F-V109-1: exactly one pinning flag → clean report error, no stack trace.

    ``verify_file`` raises ValueError before touching any Sigstore
    machinery (the guard is a pure usage check), so no mocking is needed
    — the orchestrator must convert it into a report-level FAIL.
    """
    ar_doc = gap_report_to_oscal_ar(_make_report(), findings=[_make_finding()])
    ar_path = tmp_path / "audit.json"
    ar_path.write_text(json.dumps(ar_doc), encoding="utf-8")
    bundle_path = ar_path.with_suffix(ar_path.suffix + ".sigstore.json")
    bundle_path.write_text('{"fake": "bundle"}', encoding="utf-8")

    report = verify_ar_file(ar_path, expected_sigstore_identity="ci@example.com")
    assert report.sigstore_signature_valid is False
    assert report.overall_valid is False
    assert any("provided together" in e for e in report.errors)
    # The misleading any-signer warning must NOT fire on the error path.
    assert not any("UnsafeNoOp" in w for w in report.warnings)


# ── DSSE (cryptography-native) leg in verify_ar_file (Task 7) ────────────


def _signed_ar(tmp_path):  # type: ignore[no-untyped-def]
    """Create a freshly DSSE-signed AR file; return (ar_path, pub_key_path)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    priv = tmp_path / "k.key"
    pub = tmp_path / "k.pub"
    priv.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    ar = tmp_path / "audit.oscal-ar.json"
    ar.write_text(json.dumps({"assessment-results": {"uuid": "u1"}}), encoding="utf-8")
    keysign.sign_oscal_file(ar, key_path=priv)
    return ar, pub


def test_verify_ar_file_dsse_pass(tmp_path: Path) -> None:
    """A valid DSSE envelope + matching key → dsse_signature_valid=True + overall_valid=True."""
    ar, pub = _signed_ar(tmp_path)
    report = verify_ar_file(ar, verify_key_path=pub)
    assert report.dsse_signature_valid is True
    assert report.overall_valid is True


def test_verify_ar_file_dsse_present_without_key_is_error(tmp_path: Path) -> None:
    """DSSE envelope present but no verify_key_path → fail-closed: dsse_signature_valid=False."""
    ar, _ = _signed_ar(tmp_path)
    report = verify_ar_file(ar)  # no verify_key_path
    assert report.dsse_signature_valid is False
    assert report.overall_valid is False
    assert any("verify-key" in e for e in report.errors)


def test_require_signature_satisfied_by_dsse(tmp_path: Path) -> None:
    """require_signature=True is satisfied by a valid DSSE envelope alone."""
    ar, pub = _signed_ar(tmp_path)
    report = verify_ar_file(ar, require_signature=True, verify_key_path=pub)
    assert report.overall_valid is True
