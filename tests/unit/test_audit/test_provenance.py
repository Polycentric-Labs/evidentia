"""Tests for :mod:`evidentia_core.audit.provenance` (v0.7.0)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from evidentia_core.audit.provenance import (
    CollectionContext,
    CollectionManifest,
    CoverageCount,
    PaginationContext,
    new_run_id,
)


def test_new_run_id_returns_ulid_string() -> None:
    run_id = new_run_id()
    assert len(run_id) == 26
    assert set(run_id).issubset(set("0123456789ABCDEFGHJKMNPQRSTVWXYZ"))


def test_new_run_id_is_time_sortable() -> None:
    first = new_run_id()
    second = new_run_id()
    assert first <= second


def test_pagination_context_defaults_to_complete() -> None:
    p = PaginationContext()
    assert p.is_complete is True
    assert p.page_size is None
    assert p.continuation_token is None


def test_pagination_context_explicit_incomplete() -> None:
    p = PaginationContext(
        page_size=100,
        page_number=3,
        continuation_token="abc123",
        is_complete=False,
    )
    assert p.is_complete is False
    assert p.continuation_token == "abc123"


def _make_context(**overrides) -> CollectionContext:
    defaults = {
        "collector_id": "test-collector",
        "collector_version": "0.7.0",
        "run_id": new_run_id(),
        "credential_identity": "arn:aws:iam::123:role/test",
        "source_system_id": "aws-account:123:us-east-1",
    }
    defaults.update(overrides)
    return CollectionContext(**defaults)


def test_collection_context_minimal_required_fields() -> None:
    ctx = _make_context()
    assert ctx.collector_id == "test-collector"
    assert ctx.collected_at.tzinfo is not None
    assert ctx.filter_applied == {}


def test_collection_context_missing_required_field_raises() -> None:
    with pytest.raises(ValueError):
        CollectionContext(  # type: ignore[call-arg]
            collector_version="0.7.0",
            run_id=new_run_id(),
            credential_identity="arn",
            source_system_id="aws:123",
        )


def test_collection_context_serializes_roundtrip() -> None:
    ctx = _make_context(filter_applied={"region": "us-east-1"})
    dumped = ctx.model_dump(mode="json")
    restored = CollectionContext.model_validate(dumped)
    assert restored == ctx


def test_collection_context_rejects_extra_fields() -> None:
    with pytest.raises(ValueError):
        CollectionContext(  # type: ignore[call-arg]
            collector_id="test",
            collector_version="0.7.0",
            run_id=new_run_id(),
            credential_identity="arn",
            source_system_id="aws:123",
            bogus_field="should fail",
        )


def test_collection_context_carries_pagination() -> None:
    ctx = _make_context(
        pagination_context=PaginationContext(page_size=50, page_number=1, continuation_token="next", is_complete=False),
    )
    assert ctx.pagination_context is not None
    assert ctx.pagination_context.is_complete is False


def test_coverage_count_accepts_zero() -> None:
    c = CoverageCount(resource_type="x", scanned=0, matched_filter=0, collected=0)
    assert c.collected == 0


def test_coverage_count_rejects_negative() -> None:
    with pytest.raises(ValueError):
        CoverageCount(resource_type="x", scanned=-1, matched_filter=0, collected=0)


def _make_manifest(**overrides) -> CollectionManifest:
    defaults = {
        "run_id": new_run_id(),
        "collector_id": "test-collector",
        "collector_version": "0.7.0",
        "collection_started_at": datetime.now(UTC),
    }
    defaults.update(overrides)
    return CollectionManifest(**defaults)


def test_manifest_default_is_complete_zero_findings() -> None:
    m = _make_manifest()
    assert m.is_complete is True
    assert m.total_findings == 0
    assert m.empty_categories == []
    assert m.incomplete_reason is None


def test_manifest_empty_set_attestation() -> None:
    """Per B5: explicitly state which categories are scanned-and-empty."""
    m = _make_manifest(
        empty_categories=["aws-iam-role-unused", "aws-s3-external-access"],
    )
    assert "aws-iam-role-unused" in m.empty_categories


def test_manifest_incomplete_reason_populated_when_failed() -> None:
    m = _make_manifest(
        is_complete=False,
        incomplete_reason="Rate limit exhausted after 5 retries",
    )
    assert m.is_complete is False
    assert m.incomplete_reason is not None


def test_manifest_serializes_roundtrip() -> None:
    m = _make_manifest(
        coverage_counts=[
            CoverageCount(
                resource_type="aws-iam-role",
                scanned=100,
                matched_filter=42,
                collected=42,
            ),
        ],
        source_system_ids=["aws-account:123:us-east-1"],
        warnings=["KMS grant chains not analyzed"],
    )
    dumped = m.model_dump(mode="json")
    restored = CollectionManifest.model_validate(dumped)
    assert restored == m


def test_manifest_coverage_count_total_can_match_findings() -> None:
    m = _make_manifest(
        total_findings=42,
        coverage_counts=[
            CoverageCount(
                resource_type="aws-iam-role",
                scanned=100,
                matched_filter=42,
                collected=42,
            ),
        ],
    )
    assert sum(c.collected for c in m.coverage_counts) == m.total_findings
