"""Contract tests for the explicit-root gap-report repository."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import evidentia_core.gap_store as gap_store
import pytest
from evidentia_core.models.gap import GapAnalysisReport


def _report(organization: str = "Explicit Root") -> GapAnalysisReport:
    return GapAnalysisReport(
        organization=organization,
        frameworks_analyzed=["nist-800-53-mod"],
        total_controls_required=1,
        total_controls_in_inventory=1,
        total_gaps=0,
        critical_gaps=0,
        high_gaps=0,
        medium_gaps=0,
        low_gaps=0,
        informational_gaps=0,
        coverage_percentage=100.0,
        gaps=[],
        efficiency_opportunities=[],
        prioritized_roadmap=[],
        inventory_source="same-inventory.yaml",
    )


def _repository_type() -> type[Any]:
    repository_type = getattr(gap_store, "GapReportRepository", None)
    assert repository_type is not None, (
        "GapReportRepository must provide the explicit-root store seam"
    )
    return cast(type[Any], repository_type)


def test_repository_root_wins_over_ambient_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changing ambient store selection must not redirect a bound repository."""
    ambient_root = tmp_path / "ambient"
    explicit_root = tmp_path / "explicit"
    ambient_path = gap_store.save_report(
        _report("Ambient Sentinel"),
        gap_store_dir=ambient_root,
    )
    explicit_path = gap_store.save_report(
        _report("Explicit Sentinel"),
        gap_store_dir=explicit_root,
    )
    assert ambient_path.stem == explicit_path.stem

    monkeypatch.setenv("EVIDENTIA_GAP_STORE_DIR", str(ambient_root))
    repository = _repository_type()(explicit_root)

    loaded = repository.load_by_key(explicit_path.stem)

    assert loaded is not None
    assert loaded.organization == "Explicit Sentinel"


@pytest.mark.parametrize(
    "operation",
    ["save", "list", "load_latest", "load_by_key"],
)
def test_repository_revalidates_immediately_before_each_operation(
    tmp_path: Path,
    operation: str,
) -> None:
    """Every repository operation must invoke the supplied root authority."""

    class RootRejected(RuntimeError):
        pass

    def reject_root() -> Path:
        raise RootRejected("synthetic operation-time rejection")

    repository = _repository_type()(
        tmp_path / "store",
        root_revalidator=reject_root,
    )

    with pytest.raises(RootRejected, match="operation-time rejection"):
        if operation == "save":
            repository.save(_report())
        elif operation == "list":
            repository.list()
        elif operation == "load_latest":
            repository.load_latest()
        else:
            repository.load_by_key("0123456789abcdef")

    assert not (tmp_path / "store").exists()


def test_repository_rejects_revalidator_root_change(
    tmp_path: Path,
) -> None:
    """A revalidator cannot silently redirect a repository to another root."""
    bound_root = tmp_path / "bound"
    different_root = tmp_path / "different"
    saved = gap_store.save_report(
        _report("Different Sentinel"),
        gap_store_dir=different_root,
    )
    repository_type = _repository_type()
    root_changed_error = getattr(
        gap_store,
        "GapStoreRootChangedError",
        None,
    )
    assert root_changed_error is not None, (
        "GapStoreRootChangedError must make root drift a typed failure"
    )
    repository = repository_type(
        bound_root,
        root_revalidator=lambda: different_root,
    )

    with pytest.raises(root_changed_error, match="root changed"):
        repository.load_by_key(saved.stem)

    assert not bound_root.exists()


def test_repository_rejects_missing_revalidated_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A broken revalidator cannot fall back through ambient configuration."""
    bound_root = tmp_path / "bound"
    monkeypatch.setenv("EVIDENTIA_GAP_STORE_DIR", str(bound_root))
    repository_type = _repository_type()
    root_changed_error = getattr(
        gap_store,
        "GapStoreRootChangedError",
        None,
    )
    assert root_changed_error is not None

    def missing_root() -> Path:
        return cast(Path, None)

    repository = repository_type(
        bound_root,
        root_revalidator=missing_root,
    )

    with pytest.raises(root_changed_error, match="root changed"):
        repository.list()
