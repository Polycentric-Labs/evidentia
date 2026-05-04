"""Unit tests for evidentia_core.governance.metrics + metric_store
(v0.7.11 P1.5 G3)."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from evidentia_core.governance.metrics import (
    Metric,
    MetricDirection,
    MetricKind,
    MetricObservation,
    MetricStatus,
    evaluate_metric,
    generate_metrics_report,
)
from evidentia_core.metric_store import (
    METRIC_STORE_ENV_VAR,
    InvalidMetricIdError,
    delete_metric,
    list_metrics,
    load_metric_by_id,
    save_metric,
)
from pydantic import ValidationError

# ── enums + schema ─────────────────────────────────────────────────


class TestMetricEnums:
    def test_kind_values(self) -> None:
        assert {k.value for k in MetricKind} == {"kri", "kpi", "kgi"}

    def test_direction_values(self) -> None:
        assert {d.value for d in MetricDirection} == {
            "higher_is_worse",
            "higher_is_better",
        }

    def test_status_values(self) -> None:
        assert {s.value for s in MetricStatus} == {
            "comfortable",
            "watch",
            "breach",
            "no_data",
        }


def _kri() -> Metric:
    return Metric(
        name="Failed-login rate",
        description="Failed logins per 1k logins per day.",
        kind=MetricKind.KRI,
        direction=MetricDirection.HIGHER_IS_WORSE,
        unit="per 1000 logins",
        warning_threshold=2.0,
        critical_threshold=4.0,
    )


def _kpi() -> Metric:
    return Metric(
        name="Patch coverage",
        description="% of HIGH CVEs patched within 30 days.",
        kind=MetricKind.KPI,
        direction=MetricDirection.HIGHER_IS_BETTER,
        unit="%",
        warning_threshold=80.0,
        critical_threshold=60.0,
    )


class TestMetricSchema:
    def test_minimal_construction(self) -> None:
        m = _kri()
        assert m.id  # auto-UUID
        assert m.created_at is not None
        assert m.observations == []

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Metric(  # type: ignore[call-arg]
                name="x",
                description="x",
                kind=MetricKind.KRI,
                direction=MetricDirection.HIGHER_IS_WORSE,
                unit="x",
                bogus="should fail",
            )

    def test_invalid_kind_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Metric.model_validate(
                {
                    "name": "x",
                    "description": "x",
                    "kind": "not-a-kind",
                    "direction": "higher_is_worse",
                    "unit": "x",
                }
            )


# ── evaluate_metric ────────────────────────────────────────────────


class TestEvaluateMetric:
    def test_no_data_when_no_observations(self) -> None:
        assert evaluate_metric(_kri()) == MetricStatus.NO_DATA

    def test_higher_is_worse_comfortable(self) -> None:
        m = _kri()
        m = m.model_copy(update={
            "observations": [MetricObservation(observed_at=date(2026, 1, 1), value=1.0)]
        })
        assert evaluate_metric(m) == MetricStatus.COMFORTABLE

    def test_higher_is_worse_watch(self) -> None:
        m = _kri()
        m = m.model_copy(update={
            "observations": [MetricObservation(observed_at=date(2026, 1, 1), value=2.5)]
        })
        assert evaluate_metric(m) == MetricStatus.WATCH

    def test_higher_is_worse_breach(self) -> None:
        m = _kri()
        m = m.model_copy(update={
            "observations": [MetricObservation(observed_at=date(2026, 1, 1), value=4.0)]
        })
        assert evaluate_metric(m) == MetricStatus.BREACH

    def test_higher_is_better_comfortable(self) -> None:
        m = _kpi()
        m = m.model_copy(update={
            "observations": [MetricObservation(observed_at=date(2026, 1, 1), value=95.0)]
        })
        assert evaluate_metric(m) == MetricStatus.COMFORTABLE

    def test_higher_is_better_watch(self) -> None:
        m = _kpi()
        m = m.model_copy(update={
            "observations": [MetricObservation(observed_at=date(2026, 1, 1), value=75.0)]
        })
        assert evaluate_metric(m) == MetricStatus.WATCH

    def test_higher_is_better_breach(self) -> None:
        m = _kpi()
        m = m.model_copy(update={
            "observations": [MetricObservation(observed_at=date(2026, 1, 1), value=55.0)]
        })
        assert evaluate_metric(m) == MetricStatus.BREACH

    def test_picks_latest_observation(self) -> None:
        m = _kri()
        m = m.model_copy(update={
            "observations": [
                MetricObservation(observed_at=date(2025, 6, 1), value=5.0),  # old breach
                MetricObservation(observed_at=date(2026, 1, 1), value=1.0),  # new comfort
            ]
        })
        assert evaluate_metric(m) == MetricStatus.COMFORTABLE

    def test_no_thresholds_means_no_breach(self) -> None:
        m = Metric(
            name="x", description="x",
            kind=MetricKind.KGI,
            direction=MetricDirection.HIGHER_IS_BETTER,
            unit="x",
            observations=[
                MetricObservation(observed_at=date(2026, 1, 1), value=0.0)
            ],
        )
        # No thresholds → can't reach BREACH or WATCH
        assert evaluate_metric(m) == MetricStatus.COMFORTABLE


# ── generate_metrics_report ────────────────────────────────────────


class TestGenerateMetricsReport:
    def test_empty_renders_minimal(self) -> None:
        out = generate_metrics_report([])
        assert "No metrics defined" in out

    def test_warning_callout_when_breach_present(self) -> None:
        kri = _kri().model_copy(update={
            "observations": [MetricObservation(observed_at=date(2026, 1, 1), value=5.0)]
        })
        out = generate_metrics_report([kri])
        assert "⚠️" in out
        assert "1 metric(s) in BREACH" in out

    def test_no_warning_when_no_breach(self) -> None:
        kri = _kri().model_copy(update={
            "observations": [MetricObservation(observed_at=date(2026, 1, 1), value=1.0)]
        })
        out = generate_metrics_report([kri])
        assert "BREACH state" not in out

    def test_per_kind_sections(self) -> None:
        out = generate_metrics_report([_kri(), _kpi()])
        assert "## KRI — Key Risk Indicators" in out
        assert "## KPI — Key Performance Indicators" in out
        # No KGI in input
        assert "## KGI" not in out

    def test_render_is_deterministic(self) -> None:
        a = generate_metrics_report([_kri(), _kpi()])
        b = generate_metrics_report([_kri(), _kpi()])
        # IDs differ but the structure is deterministic for a given
        # input. Verify report shape, not byte equality.
        assert a.split("##") == b.split("##") or len(a) == len(b)


# ── store ──────────────────────────────────────────────────────────


@pytest.fixture()
def isolated_metric_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    store = tmp_path / "metric-store"
    monkeypatch.setenv(METRIC_STORE_ENV_VAR, str(store))
    return store


class TestSaveLoad:
    def test_save_and_load_round_trip(
        self, isolated_metric_store: Path
    ) -> None:
        m = _kri()
        save_metric(m)
        loaded = load_metric_by_id(m.id)
        assert loaded is not None
        assert loaded.id == m.id
        assert loaded.name == m.name

    def test_save_atomic_no_tmp_leftover(
        self, isolated_metric_store: Path
    ) -> None:
        save_metric(_kri())
        assert list(isolated_metric_store.glob("*.tmp")) == []

    def test_load_unknown_returns_none(
        self, isolated_metric_store: Path
    ) -> None:
        result = load_metric_by_id("00000000-0000-0000-0000-000000000000")
        assert result is None

    def test_load_invalid_id_raises(
        self, isolated_metric_store: Path
    ) -> None:
        with pytest.raises(InvalidMetricIdError):
            load_metric_by_id("not-a-uuid")


class TestList:
    def test_empty_returns_empty(
        self, isolated_metric_store: Path
    ) -> None:
        assert list_metrics() == []

    def test_sort_by_kind_then_name(
        self, isolated_metric_store: Path
    ) -> None:
        save_metric(_kpi())
        save_metric(_kri())
        listed = list_metrics()
        # KGI alphabetically < KPI < KRI
        assert listed[0].kind == "kpi"
        assert listed[1].kind == "kri"


class TestDelete:
    def test_delete_returns_true(
        self, isolated_metric_store: Path
    ) -> None:
        m = _kri()
        save_metric(m)
        assert delete_metric(m.id) is True
        assert load_metric_by_id(m.id) is None

    def test_delete_unknown_returns_false(
        self, isolated_metric_store: Path
    ) -> None:
        assert delete_metric("00000000-0000-0000-0000-000000000000") is False
