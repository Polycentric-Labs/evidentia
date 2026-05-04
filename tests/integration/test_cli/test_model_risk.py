"""Integration tests for `evidentia model-risk model` subcommands (v0.7.10 P0.6).

Uses Typer's CliRunner against the real `evidentia.cli.main:app`.
Each test scopes the model store to ``tmp_path`` via the
``EVIDENTIA_MODEL_STORE_DIR`` env var so no state leaks across
tests or into the real user profile.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evidentia.cli.main import app
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def _isolated_model_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Point EVIDENTIA_MODEL_STORE_DIR at an isolated tmp for each test."""
    store = tmp_path / "model-store"
    monkeypatch.setenv("EVIDENTIA_MODEL_STORE_DIR", str(store))
    return store


# ── helpers ────────────────────────────────────────────────────────


def _add_minimal_model(
    runner: CliRunner,
    *,
    name: str = "Test Model",
    methodology: str = "ml",
    tier: str = "tier_2",
    last_validation_date: str | None = None,
) -> str:
    """Add a model and return its ID."""
    args = [
        "model-risk",
        "model",
        "add",
        "--name",
        name,
        "--purpose",
        "Test purpose for unit testing",
        "--methodology",
        methodology,
        "--vendor-or-internal",
        "internal",
        "--tier",
        tier,
        "--owner",
        "ml-team@example.com",
    ]
    if last_validation_date:
        args.extend(["--last-validation-date", last_validation_date])
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    # Extract ID from "(id: <uuid>)"
    import re

    match = re.search(r"id: ([0-9a-f-]{36})", result.output)
    assert match, f"Could not parse ID from: {result.output}"
    return match.group(1)


# ── add ────────────────────────────────────────────────────────────


class TestModelAdd:
    def test_atomic_happy_path(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "model-risk", "model", "add",
                "--name", "FICO scorer v3",
                "--purpose", "Score consumer credit applications",
                "--methodology", "ml",
                "--vendor-or-internal", "internal",
                "--tier", "tier_1",
                "--owner", "ml-team@example.com",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "Added" in result.output
        assert "FICO scorer v3" in result.output

    def test_missing_required_field_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "model-risk", "model", "add",
                "--name", "X",
                # Missing --purpose / --methodology / --vendor-or-internal / --tier / --owner
            ],
        )
        assert result.exit_code == 1
        assert "Missing required" in result.output

    def test_invalid_methodology_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "model-risk", "model", "add",
                "--name", "X", "--purpose", "x",
                "--methodology", "telepathy",  # invalid
                "--vendor-or-internal", "internal",
                "--tier", "tier_2", "--owner", "a@b.com",
            ],
        )
        assert result.exit_code == 1
        assert "Invalid model data" in result.output

    def test_vendor_provenance_requires_vendor_id(
        self, runner: CliRunner
    ) -> None:
        result = runner.invoke(
            app,
            [
                "model-risk", "model", "add",
                "--name", "X", "--purpose", "x",
                "--methodology", "llm",
                "--vendor-or-internal", "vendor",
                # Missing --vendor-id
                "--tier", "tier_2", "--owner", "a@b.com",
            ],
        )
        assert result.exit_code == 1
        assert "vendor_id" in result.output.lower()

    def test_vendor_provenance_with_vendor_id(
        self, runner: CliRunner
    ) -> None:
        result = runner.invoke(
            app,
            [
                "model-risk", "model", "add",
                "--name", "Vendor LLM",
                "--purpose", "Vendor-supplied LLM",
                "--methodology", "llm",
                "--vendor-or-internal", "vendor",
                "--vendor-id", "aaaa1111-2222-3333-4444-555566667777",
                "--tier", "tier_2",
                "--owner", "ai-team@example.com",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "Added" in result.output

    def test_auto_computes_next_validation_due(
        self, runner: CliRunner
    ) -> None:
        # Tier 1 + last_validation_date 2025-06-15 → next 2026-06-15
        mid = _add_minimal_model(
            runner,
            tier="tier_1",
            last_validation_date="2025-06-15",
        )
        result = runner.invoke(
            app, ["model-risk", "model", "show", mid, "--json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["next_validation_due"] == "2026-06-15"

    def test_explicit_next_validation_due_overrides_auto(
        self, runner: CliRunner
    ) -> None:
        result = runner.invoke(
            app,
            [
                "model-risk", "model", "add",
                "--name", "Override test",
                "--purpose", "x",
                "--methodology", "ml",
                "--vendor-or-internal", "internal",
                "--tier", "tier_1",
                "--owner", "a@b.com",
                "--last-validation-date", "2025-06-15",
                "--next-validation-due", "2025-12-01",  # earlier override
            ],
        )
        assert result.exit_code == 0
        import re

        mid = re.search(r"id: ([0-9a-f-]{36})", result.output).group(1)
        show = runner.invoke(
            app, ["model-risk", "model", "show", mid, "--json"]
        )
        data = json.loads(show.output)
        assert data["next_validation_due"] == "2025-12-01"


# ── list ───────────────────────────────────────────────────────────


class TestModelList:
    def test_empty(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["model-risk", "model", "list"])
        assert result.exit_code == 0
        # Empty table or empty JSON
        assert "0 total" in result.output or "[]" in result.output

    def test_json_output_is_bare_array(self, runner: CliRunner) -> None:
        _add_minimal_model(runner, name="Alpha")
        _add_minimal_model(runner, name="Beta")
        result = runner.invoke(
            app, ["model-risk", "model", "list", "--json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 2
        names = {m["name"] for m in data}
        assert names == {"Alpha", "Beta"}

    def test_filter_by_tier(self, runner: CliRunner) -> None:
        _add_minimal_model(runner, name="T1", tier="tier_1")
        _add_minimal_model(runner, name="T2", tier="tier_2")
        result = runner.invoke(
            app,
            ["model-risk", "model", "list", "--tier", "tier_1", "--json"],
        )
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["name"] == "T1"

    def test_filter_by_methodology(self, runner: CliRunner) -> None:
        _add_minimal_model(runner, name="ML model", methodology="ml")
        _add_minimal_model(runner, name="LLM model", methodology="llm")
        result = runner.invoke(
            app,
            [
                "model-risk", "model", "list",
                "--methodology", "llm", "--json",
            ],
        )
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["name"] == "LLM model"


# ── show ───────────────────────────────────────────────────────────


class TestModelShow:
    def test_show_existing(self, runner: CliRunner) -> None:
        mid = _add_minimal_model(runner, name="ShowMe")
        result = runner.invoke(app, ["model-risk", "model", "show", mid])
        assert result.exit_code == 0
        assert "ShowMe" in result.output
        assert "Methodology" in result.output

    def test_show_json(self, runner: CliRunner) -> None:
        mid = _add_minimal_model(runner)
        result = runner.invoke(
            app, ["model-risk", "model", "show", mid, "--json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["id"] == mid

    def test_show_unknown_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "model-risk", "model", "show",
                "00000000-0000-0000-0000-000000000000",
            ],
        )
        assert result.exit_code == 1
        assert "No model with ID" in result.output

    def test_show_invalid_id_shape_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app, ["model-risk", "model", "show", "not-a-uuid"]
        )
        assert result.exit_code == 1
        assert "Invalid model ID" in result.output


# ── edit ───────────────────────────────────────────────────────────


class TestModelEdit:
    def test_atomic_field_update(self, runner: CliRunner) -> None:
        mid = _add_minimal_model(runner)
        result = runner.invoke(
            app,
            [
                "model-risk", "model", "edit", mid,
                "--owner", "new-owner@example.com",
            ],
        )
        assert result.exit_code == 0, result.output
        # Verify
        show = runner.invoke(
            app, ["model-risk", "model", "show", mid, "--json"]
        )
        data = json.loads(show.output)
        assert data["owner"] == "new-owner@example.com"

    def test_edit_no_input_errors(self, runner: CliRunner) -> None:
        mid = _add_minimal_model(runner)
        result = runner.invoke(app, ["model-risk", "model", "edit", mid])
        assert result.exit_code == 1
        assert "No edit input" in result.output

    def test_edit_invalid_methodology(self, runner: CliRunner) -> None:
        mid = _add_minimal_model(runner)
        result = runner.invoke(
            app,
            [
                "model-risk", "model", "edit", mid,
                "--methodology", "telepathy",
            ],
        )
        assert result.exit_code == 1
        assert "Unknown methodology" in result.output

    def test_edit_recomputes_next_validation_due(
        self, runner: CliRunner
    ) -> None:
        mid = _add_minimal_model(
            runner,
            tier="tier_2",
            last_validation_date="2025-06-15",
        )
        # Original Tier 2 + 2025-06-15 → 2027-06-15
        # Edit last-validation-date → should re-compute
        result = runner.invoke(
            app,
            [
                "model-risk", "model", "edit", mid,
                "--last-validation-date", "2026-01-01",
            ],
        )
        assert result.exit_code == 0
        show = runner.invoke(
            app, ["model-risk", "model", "show", mid, "--json"]
        )
        data = json.loads(show.output)
        # Tier 2 + 2026-01-01 → 2028-01-01
        assert data["next_validation_due"] == "2028-01-01"

    def test_explicit_next_validation_due_takes_precedence(
        self, runner: CliRunner
    ) -> None:
        mid = _add_minimal_model(
            runner,
            tier="tier_1",
            last_validation_date="2025-06-15",
        )
        # Operator override beats auto-recompute
        result = runner.invoke(
            app,
            [
                "model-risk", "model", "edit", mid,
                "--next-validation-due", "2025-12-31",
            ],
        )
        assert result.exit_code == 0
        show = runner.invoke(
            app, ["model-risk", "model", "show", mid, "--json"]
        )
        data = json.loads(show.output)
        assert data["next_validation_due"] == "2025-12-31"


# ── delete ─────────────────────────────────────────────────────────


class TestModelDelete:
    def test_delete_with_yes_flag(self, runner: CliRunner) -> None:
        mid = _add_minimal_model(runner)
        result = runner.invoke(
            app, ["model-risk", "model", "delete", mid, "--yes"]
        )
        assert result.exit_code == 0
        assert "Deleted" in result.output
        # Confirm gone
        show = runner.invoke(
            app, ["model-risk", "model", "show", mid]
        )
        assert show.exit_code == 1

    def test_delete_unknown_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "model-risk", "model", "delete",
                "00000000-0000-0000-0000-000000000000",
                "--yes",
            ],
        )
        assert result.exit_code == 1

    def test_delete_invalid_id_shape_errors(
        self, runner: CliRunner
    ) -> None:
        result = runner.invoke(
            app, ["model-risk", "model", "delete", "not-a-uuid", "--yes"]
        )
        assert result.exit_code == 1
        assert "Invalid model ID" in result.output
