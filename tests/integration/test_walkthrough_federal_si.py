"""Smoke test for the federal-SI walk-through (v0.9.4 P3.1).

Runs the most operator-visible steps of the walk-through from
``docs/walkthrough-federal-si.md`` against the synthetic fixtures
in ``tests/data/walkthrough-federal-si/``. If a step's output
diverges from the documented expectation, CI catches it BEFORE the
v0.9.4 ship.

Each test is a self-contained CLI invocation — no shared state,
no real network, no real LLM. The CLI verbs exercised are:

- ``conmon check``  (Step 2 of the walk-through)
- ``conmon health`` (Step 3)
- ``ai-gov classify`` (Step 4 — both tier outputs)
- ``ai-gov register`` + ``ai-gov list`` (Steps 5-6)
- ``ai-gov update`` + ``ai-gov retire`` (Step 7)
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from evidentia.cli.main import app
from typer.testing import CliRunner

WALKTHROUGH_DIR = Path(__file__).parent.parent / "data" / "walkthrough-federal-si"


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def isolated_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    registry_dir = tmp_path / "walkthrough-registry"
    monkeypatch.setenv("EVIDENTIA_AI_REGISTRY_DIR", str(registry_dir))
    return registry_dir


def test_fixture_files_exist() -> None:
    """The walk-through doc references these files; if any go
    missing, the doc is stale + the operator gets a confusing
    file-not-found at Step 2."""
    assert (WALKTHROUGH_DIR / "state.yaml").is_file()
    assert (WALKTHROUGH_DIR / "ai-systems.yaml").is_file()
    assert (WALKTHROUGH_DIR / "ai-systems-low-risk.yaml").is_file()
    assert (WALKTHROUGH_DIR / "README.md").is_file()


def test_step2_conmon_check_surfaces_overdue(runner: CliRunner) -> None:
    """Step 2: conmon check against the synthetic state file
    surfaces the documented overdue + due-soon entries."""
    result = runner.invoke(
        app,
        [
            "conmon",
            "check",
            "--last-completed-file",
            str(WALKTHROUGH_DIR / "state.yaml"),
            "--today",
            "2026-05-18",
        ],
    )
    assert result.exit_code == 0
    # nist-800-53-rev5-ca7 monthly + last 2026-03-15 → overdue.
    # Use short substring + lowercased output since rich truncates
    # long slugs at narrow terminal widths (CI ~80 col).
    out = result.output.lower()
    assert "overdue" in out
    assert "nist-800-53-re" in out  # may truncate trailing "v5-ca7"
    # fedramp-conmon-poam → due_soon (next-due 2026-05-29, 11 days).
    assert "fedramp-conmon-" in out
    assert "due within" in out


def test_step3_conmon_health_score(runner: CliRunner) -> None:
    """Step 3: conmon health JSON output has the documented shape +
    overall health score reflects 1-overdue-of-7."""
    result = runner.invoke(
        app,
        [
            "conmon",
            "health",
            "--state-file",
            str(WALKTHROUGH_DIR / "state.yaml"),
            "--today",
            "2026-05-18",
            "--window-days",
            "14",
            "--json",
        ],
    )
    assert result.exit_code == 0
    body = json.loads(result.output)
    assert body["total_cycles"] == 7
    assert body["total_overdue"] >= 1
    # 6 not-overdue / 7 total = ~0.857. Tolerate slight variance
    # if future calendar changes shift due-soon/current bucketing.
    assert 0.75 <= body["overall_health_score"] <= 0.95


def test_step4_classify_high_risk(runner: CliRunner) -> None:
    """Step 4 first call: high-risk system classifies as
    ``EUAIActTier.HIGH`` (Annex III employment + advisory role
    affecting natural persons)."""
    result = runner.invoke(
        app,
        [
            "ai-gov",
            "classify",
            "--descriptor",
            str(WALKTHROUGH_DIR / "ai-systems.yaml"),
            "--json",
        ],
    )
    assert result.exit_code == 0
    body = json.loads(result.output)
    assert body["eu_ai_act_tier"] == "high"


def test_step4_classify_minimal_risk(runner: CliRunner) -> None:
    """Step 4 second call: minimal-risk system classifies as
    ``EUAIActTier.MINIMAL``."""
    result = runner.invoke(
        app,
        [
            "ai-gov",
            "classify",
            "--descriptor",
            str(WALKTHROUGH_DIR / "ai-systems-low-risk.yaml"),
            "--json",
        ],
    )
    assert result.exit_code == 0
    body = json.loads(result.output)
    assert body["eu_ai_act_tier"] == "minimal"


def test_steps5_6_7_register_list_update_retire(runner: CliRunner, isolated_registry: Path) -> None:
    """Steps 5-7: register + list + update + retire lifecycle
    end-to-end against the walk-through fixtures."""
    # Step 5: register
    register_result = runner.invoke(
        app,
        [
            "ai-gov",
            "register",
            "--descriptor",
            str(WALKTHROUGH_DIR / "ai-systems.yaml"),
            "--provider",
            "acme-ai",
            "--owner",
            "federal-si-hr-team",
            "--deployment-status",
            "pilot",
        ],
    )
    assert register_result.exit_code == 0, register_result.output
    match = re.search(r"system_id:\s*([0-9a-f-]{36})", register_result.output)
    assert match is not None
    system_id = match.group(1)

    # Step 6: list with tier=high filter — should contain our entry
    list_result = runner.invoke(app, ["ai-gov", "list", "--tier", "high", "--json"])
    assert list_result.exit_code == 0
    listing = json.loads(list_result.output)
    assert any(e["system_id"] == system_id for e in listing)

    # Step 7a: update pilot → production
    update_result = runner.invoke(
        app,
        [
            "ai-gov",
            "update",
            system_id,
            "--deployment-status",
            "production",
        ],
    )
    assert update_result.exit_code == 0

    # Step 7b: retire (preserves entry)
    retire_result = runner.invoke(app, ["ai-gov", "retire", system_id])
    assert retire_result.exit_code == 0

    # Verify retired status persisted.
    show_result = runner.invoke(app, ["ai-gov", "show", system_id, "--json"])
    assert show_result.exit_code == 0
    body = json.loads(show_result.output)
    assert body["deployment_status"] == "retired"
