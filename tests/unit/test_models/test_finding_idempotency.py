"""Deterministic finding-ID derivation tests (v0.10.5 Phase 10).

These tests cover the model layer: the
:func:`evidentia_core.models.common.deterministic_finding_id` helper and
the ``_derive_deterministic_id`` model validator on
:class:`evidentia_core.models.finding.SecurityFinding`.

The collector-layer integration tests live alongside the collectors in
``tests/unit/test_collectors/test_idempotency.py``.

Cross-references:

- ``docs/collector-idempotency-audit.md`` (the contract this test guards).
- ``docs/api-stability.md`` (the post-v1.0 frozen-surface guarantee).
"""

from __future__ import annotations

from uuid import UUID

import pytest
from evidentia_core.models.common import (
    NAMESPACE_EVIDENTIA_FINDING,
    Severity,
    deterministic_finding_id,
)
from evidentia_core.models.finding import (
    ComplianceStatus,
    FindingStatus,
    SecurityFinding,
)

# ── Helper-function level ────────────────────────────────────────────────


class TestDeterministicFindingIdHelper:
    def test_returns_canonical_uuid_string(self) -> None:
        result = deterministic_finding_id("aws-config", "s3-public:bucket-1")
        # Must be parseable as a UUID.
        parsed = UUID(result)
        # Must be version 5 (name-based SHA-1 derivation).
        assert parsed.version == 5

    def test_is_deterministic_across_calls(self) -> None:
        a = deterministic_finding_id("aws-config", "s3-public:bucket-1")
        b = deterministic_finding_id("aws-config", "s3-public:bucket-1")
        assert a == b

    def test_differentiates_by_source_system(self) -> None:
        a = deterministic_finding_id("aws-config", "x")
        b = deterministic_finding_id("aws-security-hub", "x")
        assert a != b

    def test_differentiates_by_source_finding_id(self) -> None:
        a = deterministic_finding_id("aws-config", "x")
        b = deterministic_finding_id("aws-config", "y")
        assert a != b

    def test_nul_separator_prevents_concatenation_collision(self) -> None:
        # ('aws', 'config:bucket') and ('aws-config', 'bucket') would
        # collide under naive 'source_system + ":" + source_finding_id'
        # joining. The NUL-byte separator makes that impossible.
        a = deterministic_finding_id("aws", "config:bucket")
        b = deterministic_finding_id("aws-config", "bucket")
        assert a != b

    @pytest.mark.parametrize("bad", ["", "   ", "\n", "\t"])
    def test_rejects_empty_source_system(self, bad: str) -> None:
        with pytest.raises(ValueError, match="source_system"):
            deterministic_finding_id(bad, "x")

    @pytest.mark.parametrize("bad", ["", "   ", "\n", "\t"])
    def test_rejects_empty_source_finding_id(self, bad: str) -> None:
        with pytest.raises(ValueError, match="source_finding_id"):
            deterministic_finding_id("aws-config", bad)

    def test_namespace_uuid_is_pinned(self) -> None:
        # v0.10.5 Phase 10 lock-in: rotating this UUID would re-key every
        # SecurityFinding.id ever produced. The constant MUST NEVER change
        # post-v0.10.5. This assertion guards against accidental edits.
        assert str(NAMESPACE_EVIDENTIA_FINDING) == ("c81bcb44-9b41-5b18-9f10-72b3b9b4d3d6")


# ── SecurityFinding model-validator level ────────────────────────────────


class TestSecurityFindingDeterministicIdValidator:
    def test_derives_id_when_source_keys_present(self) -> None:
        f = SecurityFinding(
            title="t",
            description="d",
            severity=Severity.MEDIUM,
            source_system="aws-config",
            source_finding_id="s3-public:bucket-1",
        )
        expected = deterministic_finding_id("aws-config", "s3-public:bucket-1")
        assert f.id == expected

    def test_idempotent_across_constructions(self) -> None:
        a = SecurityFinding(
            title="t",
            description="d",
            severity=Severity.MEDIUM,
            source_system="aws-config",
            source_finding_id="s3-public:bucket-1",
        )
        b = SecurityFinding(
            title="t",
            description="d",
            severity=Severity.MEDIUM,
            source_system="aws-config",
            source_finding_id="s3-public:bucket-1",
        )
        assert a.id == b.id

    def test_explicit_id_wins_over_derivation(self) -> None:
        # The OCSF Detection Finding ingest path (third-party input) MUST
        # be able to pass an explicit id and have it survive. Phase 10's
        # validator MUST NOT override explicit id.
        explicit = "11111111-1111-1111-1111-111111111111"
        f = SecurityFinding(
            id=explicit,
            title="t",
            description="d",
            severity=Severity.MEDIUM,
            source_system="aws-config",
            source_finding_id="s3-public:bucket-1",
        )
        assert f.id == explicit

    def test_random_id_when_no_natural_keys(self) -> None:
        # Pre-v0.7.0 legacy + synthetic-context construction sites have
        # no source_finding_id. They MUST continue to get random UUIDs
        # (no derivation, no exception).
        a = SecurityFinding(
            title="t",
            description="d",
            severity=Severity.MEDIUM,
            source_system="aws-config",
        )
        b = SecurityFinding(
            title="t",
            description="d",
            severity=Severity.MEDIUM,
            source_system="aws-config",
        )
        # Random UUIDs differ across constructions.
        assert a.id != b.id
        # And neither equals the deterministic-derivation form for the
        # natural keys (because source_finding_id was None).
        # Sanity check: the random uuids are v4.
        assert UUID(a.id).version == 4
        assert UUID(b.id).version == 4

    def test_empty_source_finding_id_falls_back_to_random(self) -> None:
        # Empty / whitespace source_finding_id must NOT trigger the
        # derivation (the helper would raise); it MUST fall back to
        # random.
        a = SecurityFinding(
            title="t",
            description="d",
            severity=Severity.MEDIUM,
            source_system="aws-config",
            source_finding_id="",
        )
        b = SecurityFinding(
            title="t",
            description="d",
            severity=Severity.MEDIUM,
            source_system="aws-config",
            source_finding_id="   ",
        )
        # Both should construct successfully without error.
        assert UUID(a.id).version == 4
        assert UUID(b.id).version == 4

    def test_ocsf_unmapped_round_trip_preserves_id(self) -> None:
        # The OCSF round-trip via unmapped["evidentia"] re-validates the
        # serialized SecurityFinding. Phase 10's validator MUST honor the
        # serialized id (explicit-id branch).
        original = SecurityFinding(
            title="t",
            description="d",
            severity=Severity.MEDIUM,
            source_system="aws-config",
            source_finding_id="s3-public:bucket-1",
        )
        round_tripped = SecurityFinding.model_validate(original.model_dump(mode="json"))
        assert round_tripped.id == original.id

    def test_compliance_and_status_do_not_affect_id(self) -> None:
        # Two findings with identical natural keys MUST share the same
        # id even if compliance_status / status / severity differ. The
        # natural key encodes "which logical thing is being measured",
        # not "what the latest measurement said".
        a = SecurityFinding(
            title="t",
            description="d",
            severity=Severity.LOW,
            status=FindingStatus.ACTIVE,
            compliance_status=ComplianceStatus.FAIL,
            source_system="aws-config",
            source_finding_id="s3-public:bucket-1",
        )
        b = SecurityFinding(
            title="t",
            description="d",
            severity=Severity.HIGH,
            status=FindingStatus.RESOLVED,
            compliance_status=ComplianceStatus.PASS,
            source_system="aws-config",
            source_finding_id="s3-public:bucket-1",
        )
        assert a.id == b.id
