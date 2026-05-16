"""Tests for the v0.9.3 P1.4 ContinuousEvidenceSource plugin contract."""

from __future__ import annotations

from datetime import UTC, datetime

from evidentia_core.plugins import (
    ContinuousEvidenceSource,
    EvidenceRecord,
    NoopContinuousSource,
)


class TestEvidenceRecord:
    def test_immutable_frozen(self) -> None:
        rec = EvidenceRecord(
            source="x",
            cadence_slug="y",
            observed_at=datetime(2026, 5, 16, tzinfo=UTC),
            payload={"k": "v"},
        )
        # Frozen dataclass — assignment raises.
        try:
            rec.source = "z"  # type: ignore[misc]
        except Exception as exc:
            assert "frozen" in str(exc).lower() or isinstance(
                exc, AttributeError
            )
        else:
            raise AssertionError("expected FrozenInstanceError")


class TestNoopContinuousSource:
    def test_satisfies_protocol(self) -> None:
        source = NoopContinuousSource()
        # Runtime-checkable Protocol — isinstance works.
        assert isinstance(source, ContinuousEvidenceSource)

    def test_poll_returns_empty(self) -> None:
        source = NoopContinuousSource()
        assert source.poll() == []

    def test_health_check_returns_true(self) -> None:
        source = NoopContinuousSource()
        assert source.health_check() is True

    def test_poll_count_increments(self) -> None:
        source = NoopContinuousSource()
        assert source.poll_count == 0
        source.poll()
        source.poll()
        source.poll()
        assert source.poll_count == 3

    def test_name_and_cadence_slug_default(self) -> None:
        source = NoopContinuousSource()
        assert source.name == "noop"
        assert source.cadence_slug == "noop"

    def test_name_and_cadence_slug_custom(self) -> None:
        source = NoopContinuousSource(
            name="my-source", cadence_slug="nist-800-53-rev5-ca7"
        )
        assert source.name == "my-source"
        assert source.cadence_slug == "nist-800-53-rev5-ca7"


class TestProtocolConformance:
    """Verify the Protocol does NOT allow incomplete implementations
    to pass isinstance() (runtime_checkable behavior)."""

    def test_object_without_poll_fails_isinstance(self) -> None:
        class Incomplete:
            name = "x"
            cadence_slug = "y"
            # missing poll, health_check

        assert not isinstance(Incomplete(), ContinuousEvidenceSource)

    def test_object_without_name_fails_isinstance(self) -> None:
        class NoName:
            cadence_slug = "y"

            def poll(self) -> list[EvidenceRecord]:
                return []

            def health_check(self) -> bool:
                return True

        # Python 3.12+ runtime_checkable Protocols DO check declared
        # attribute presence at isinstance time. A class missing
        # `name` fails the check — this is the stricter behavior we
        # want, and matches the v0.8.0 P0.4 contract pattern.
        assert not isinstance(NoName(), ContinuousEvidenceSource)

    def test_full_satisfaction_passes_isinstance(self) -> None:
        class Complete:
            name = "x"
            cadence_slug = "y"

            def poll(self) -> list[EvidenceRecord]:
                return []

            def health_check(self) -> bool:
                return True

        assert isinstance(Complete(), ContinuousEvidenceSource)
