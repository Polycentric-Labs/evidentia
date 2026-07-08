"""pytest-codspeed micro-benchmarks over Evidentia's hot paths (Horizon-A H-4).

Opt-in (excluded from the default collection via the root
``addopts --ignore=tests/benchmarks``). Run under CodSpeed in
``.github/workflows/codspeed.yml`` (non-required, observe-first) or on demand
with ``pytest tests/benchmarks/``.

CodSpeed measures via instruction counting (deterministic, hardware-
independent), so each scenario keeps setup OUTSIDE the timed callable and
isolates on-disk stores to throwaway temp dirs. Scenarios mirror
docs/benchmarks.md: gap analysis (1 + 2 frameworks), catalog load, report
serialization, and two API request paths (health + gap-reports).
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

# Isolate on-disk stores to throwaway temp dirs BEFORE the app is imported, so a
# benchmark run never reads or writes the developer's real catalog / registry /
# gap-report stores (mirrors tests/dast). Module-level: the API client and its
# app are constructed at import time, and the stores read these env vars per call.
for _env in (
    "EVIDENTIA_GAP_STORE_DIR",
    "EVIDENTIA_CATALOG_DIR",
    "EVIDENTIA_AI_REGISTRY_DIR",
):
    os.environ[_env] = tempfile.mkdtemp(prefix="evidentia-bench-")

from evidentia_core.catalogs.loader import load_catalog  # noqa: E402
from evidentia_core.gap_analyzer import GapAnalyzer, load_inventory  # noqa: E402

_REPO = Path(__file__).resolve().parents[2]
_INVENTORY = _REPO / "examples" / "meridian-fintech" / "my-controls.yaml"
_ONE_FRAMEWORK = ["nist-800-53-mod"]
_TWO_FRAMEWORKS = ["nist-800-53-mod", "soc2-tsc"]


def test_bench_gap_analysis_single_framework(benchmark) -> None:
    """End-to-end gap analysis against one framework (the common UX path)."""
    inventory = load_inventory(_INVENTORY)
    analyzer = GapAnalyzer()
    benchmark(lambda: analyzer.analyze(inventory=inventory, frameworks=_ONE_FRAMEWORK))


def test_bench_gap_analysis_two_frameworks(benchmark) -> None:
    """Gap analysis across two frameworks (crosswalk-heavier path)."""
    inventory = load_inventory(_INVENTORY)
    analyzer = GapAnalyzer()
    benchmark(lambda: analyzer.analyze(inventory=inventory, frameworks=_TWO_FRAMEWORKS))


def test_bench_catalog_load(benchmark) -> None:
    """Cold catalog hydration: JSON parse + normalization + family indexing."""
    benchmark(lambda: load_catalog("nist-800-53-rev5"))


def test_bench_report_serialization(benchmark) -> None:
    """Pure serialization of a gap report to JSON (no disk I/O)."""
    inventory = load_inventory(_INVENTORY)
    report = GapAnalyzer().analyze(inventory=inventory, frameworks=_ONE_FRAMEWORK)
    benchmark(lambda: report.model_dump_json())


def test_bench_api_health(benchmark) -> None:
    """FastAPI request overhead on the trivial health endpoint."""
    from evidentia_api.app import create_app
    from fastapi.testclient import TestClient

    client = TestClient(create_app(offline=True))
    benchmark(lambda: client.get("/api/health"))


def test_bench_api_gap_reports(benchmark) -> None:
    """Gap-report listing endpoint (isolated empty store -> handler path only)."""
    from evidentia_api.app import create_app
    from fastapi.testclient import TestClient

    client = TestClient(create_app(offline=True))
    benchmark(lambda: client.get("/api/gap/reports"))
