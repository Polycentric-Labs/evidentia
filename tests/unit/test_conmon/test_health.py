"""Unit tests for evidentia_core.conmon.health (v0.9.3 P1.3)."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from evidentia_core.conmon import (
    FrameworkHealth,
    compute_health,
    health_from_state_file,
    save_state_file,
)


class TestFrameworkHealth:
    def test_health_score_all_current(self) -> None:
        fh = FrameworkHealth(
            framework="x", total=5, current=5, due_soon=0, overdue=0
        )
        assert fh.health_score == 1.0

    def test_health_score_due_soon_counts_as_healthy(self) -> None:
        fh = FrameworkHealth(
            framework="x", total=5, current=3, due_soon=2, overdue=0
        )
        assert fh.health_score == 1.0

    def test_health_score_with_overdue(self) -> None:
        fh = FrameworkHealth(
            framework="x", total=4, current=2, due_soon=1, overdue=1
        )
        # (2 + 1) / (2 + 1 + 1) = 3/4
        assert fh.health_score == 0.75

    def test_empty_returns_one(self) -> None:
        fh = FrameworkHealth(
            framework="x", total=0, current=0, due_soon=0, overdue=0
        )
        assert fh.health_score == 1.0

    # v0.9.3 F-V93-Q1 review fix: removed test_unknown_excluded_from_
    # denominator because the per-framework `unknown` field was dead
    # code (never populated by compute_health). Unknown-slug rollup is
    # tested at the HealthReport level via
    # test_unknown_slugs_collected_not_counted below.


class TestComputeHealth:
    def test_buckets_by_framework(self) -> None:
        state = {
            # nist-800-53-rev5 family: 1 overdue (monthly last 2025)
            "nist-800-53-rev5-ca7": date(2025, 1, 1),
            # fedramp-rev5-mod: 1 current
            "fedramp-conmon-poam": date(2026, 5, 10),
        }
        report = compute_health(
            state, today=date(2026, 5, 15), window_days=14
        )
        by_fw = {fh.framework: fh for fh in report.frameworks}
        assert by_fw["nist-800-53-rev5"].overdue == 1
        assert by_fw["fedramp-rev5-mod"].current == 1

    def test_framework_filter(self) -> None:
        state = {
            "nist-800-53-rev5-ca7": date(2025, 1, 1),
            "fedramp-conmon-poam": date(2026, 5, 10),
        }
        report = compute_health(
            state,
            today=date(2026, 5, 15),
            window_days=14,
            framework_filter="nist-800-53-rev5",
        )
        assert len(report.frameworks) == 1
        assert report.frameworks[0].framework == "nist-800-53-rev5"

    def test_unknown_slugs_collected_not_counted(self) -> None:
        state = {
            "nist-800-53-rev5-ca7": date(2026, 5, 10),
            "made-up-slug": date(2026, 5, 1),
        }
        report = compute_health(state, today=date(2026, 5, 15))
        assert "made-up-slug" in report.unknown_slugs
        assert report.total_cycles == 1  # made-up excluded

    def test_to_dict_shape(self) -> None:
        state = {"nist-800-53-rev5-ca7": date(2026, 5, 10)}
        report = compute_health(state, today=date(2026, 5, 15))
        d = report.to_dict()
        assert d["today"] == "2026-05-15"
        assert d["total_cycles"] == 1
        assert d["overall_health_score"] == 1.0
        assert isinstance(d["frameworks"], list)

    def test_negative_window_days_rejected(self) -> None:
        with pytest.raises(ValueError, match="window_days"):
            compute_health({}, today=date(2026, 5, 15), window_days=-1)

    def test_empty_state_zero_total(self) -> None:
        report = compute_health({}, today=date(2026, 5, 15))
        assert report.total_cycles == 0
        assert report.overall_health_score == 1.0
        assert report.frameworks == []


class TestHealthFromStateFile:
    def test_loads_and_computes(self, tmp_path: Path) -> None:
        state_file = tmp_path / "state.yaml"
        save_state_file(
            state_file,
            {"nist-800-53-rev5-ca7": date(2026, 5, 10)},
        )
        report = health_from_state_file(
            state_file, today=date(2026, 5, 15)
        )
        assert report.total_cycles == 1
        assert report.frameworks[0].framework == "nist-800-53-rev5"
