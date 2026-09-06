"""Integration tests for `evidentia governance` CLI (v0.7.10 P1.5 G1 + G2)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from textwrap import dedent

import pytest
from evidentia.cli.main import app
from evidentia_core.effective_challenge_store import (
    CHALLENGE_STORE_ENV_VAR,
)
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _write_classifications(path: Path, content: str) -> None:
    path.write_text(dedent(content).lstrip(), encoding="utf-8")


class TestLinesReport:
    def test_happy_path_to_stdout(self, runner: CliRunner, tmp_path: Path) -> None:
        cls = tmp_path / "owners.yaml"
        _write_classifications(
            cls,
            """
            - email: alice@example.com
              line_of_defense: first
              team: Loan Origination
              title: Senior Underwriter
            - email: bob@example.com
              line_of_defense: second
              team: MRM
              title: Director, Model Risk
            - email: carol@example.com
              line_of_defense: third
              team: Internal Audit
            """,
        )
        result = runner.invoke(
            app,
            [
                "governance",
                "lines-report",
                "--classifications",
                str(cls),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "Three Lines of Defense Distribution" in result.output
        # 1 owner per line; 33.3% each
        assert "| first | 1 | 33.3% |" in result.output

    def test_to_file(self, runner: CliRunner, tmp_path: Path) -> None:
        cls = tmp_path / "owners.yaml"
        _write_classifications(
            cls,
            """
            - email: a@x.com
              line_of_defense: first
            """,
        )
        out = tmp_path / "lines.md"
        result = runner.invoke(
            app,
            [
                "governance",
                "lines-report",
                "--classifications",
                str(cls),
                "--output",
                str(out),
            ],
        )
        assert result.exit_code == 0, result.output
        assert out.exists()
        body = out.read_text(encoding="utf-8")
        assert "Three Lines of Defense Distribution" in body

    def test_refuses_to_overwrite_without_force(self, runner: CliRunner, tmp_path: Path) -> None:
        cls = tmp_path / "owners.yaml"
        _write_classifications(
            cls,
            """
            - email: a@x.com
              line_of_defense: first
            """,
        )
        out = tmp_path / "lines.md"
        out.write_text("existing", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "governance",
                "lines-report",
                "--classifications",
                str(cls),
                "--output",
                str(out),
            ],
        )
        assert result.exit_code == 1
        assert "--force" in result.output
        assert out.read_text(encoding="utf-8") == "existing"

    def test_invalid_yaml_errors_clearly(self, runner: CliRunner, tmp_path: Path) -> None:
        cls = tmp_path / "broken.yaml"
        # Unbalanced brace + tab — guaranteed YAML parse failure
        cls.write_text("{key: [value\n\t}", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "governance",
                "lines-report",
                "--classifications",
                str(cls),
            ],
        )
        assert result.exit_code == 1
        assert "not valid YAML" in result.output

    def test_invalid_line_of_defense_errors(self, runner: CliRunner, tmp_path: Path) -> None:
        cls = tmp_path / "bad.yaml"
        _write_classifications(
            cls,
            """
            - email: a@x.com
              line_of_defense: fourth
            """,
        )
        result = runner.invoke(
            app,
            [
                "governance",
                "lines-report",
                "--classifications",
                str(cls),
            ],
        )
        assert result.exit_code == 1
        assert "validation" in result.output.lower()

    def test_top_level_must_be_list(self, runner: CliRunner, tmp_path: Path) -> None:
        cls = tmp_path / "scalar.yaml"
        cls.write_text("not_a_list: true", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "governance",
                "lines-report",
                "--classifications",
                str(cls),
            ],
        )
        assert result.exit_code == 1
        assert "must be a YAML list" in result.output

    def test_empty_yaml_renders_empty_report(self, runner: CliRunner, tmp_path: Path) -> None:
        cls = tmp_path / "empty.yaml"
        cls.write_text("", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "governance",
                "lines-report",
                "--classifications",
                str(cls),
            ],
        )
        assert result.exit_code == 0
        assert "No owners classified" in result.output

    def test_crossover_warning_in_output(self, runner: CliRunner, tmp_path: Path) -> None:
        cls = tmp_path / "owners.yaml"
        _write_classifications(
            cls,
            """
            - email: alice@x.com
              line_of_defense: first
            - email: alice@x.com
              line_of_defense: second
            """,
        )
        result = runner.invoke(
            app,
            [
                "governance",
                "lines-report",
                "--classifications",
                str(cls),
            ],
        )
        assert result.exit_code == 0
        assert "3LOD crossover warning" in result.output


# ── effective challenge log (P1.5 G2) ──────────────────────────────


@pytest.fixture()
def isolated_challenge_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    store = tmp_path / "challenge-store"
    monkeypatch.setenv(CHALLENGE_STORE_ENV_VAR, str(store))
    return store


def _add_minimal_challenge(
    runner: CliRunner,
    *,
    topic: str = "Methodology challenge",
    subject_id: str = "aaaa1111-2222-3333-4444-555566667777",
    outcome: str = "pending",
    challenge_date: str = "2026-01-15",
) -> str:
    result = runner.invoke(
        app,
        [
            "governance",
            "challenge",
            "add",
            "--subject-model-id",
            subject_id,
            "--challenger-email",
            "mrm-director@example.com",
            "--challenger-role",
            "MRM Director",
            "--challenge-date",
            challenge_date,
            "--challenge-topic",
            topic,
            "--challenge-substance",
            "Why was this approach chosen?",
            "--outcome",
            outcome,
        ],
    )
    assert result.exit_code == 0, result.output
    # rich may wrap the rendered console line; accept whitespace
    # between "id:" and the UUID.
    match = re.search(r"id:\s+([0-9a-f-]{36})", result.output)
    assert match, f"failed to parse id from: {result.output!r}"
    return match.group(1)


class TestChallengeAdd:
    def test_minimal_add(self, runner: CliRunner, isolated_challenge_store: Path) -> None:
        cid = _add_minimal_challenge(runner)
        assert cid

    def test_invalid_outcome_errors(self, runner: CliRunner, isolated_challenge_store: Path) -> None:
        result = runner.invoke(
            app,
            [
                "governance",
                "challenge",
                "add",
                "--subject-model-id",
                "aaaa1111-2222-3333-4444-555566667777",
                "--challenger-email",
                "x@y.com",
                "--challenger-role",
                "x",
                "--challenge-date",
                "2026-01-01",
                "--challenge-topic",
                "x",
                "--challenge-substance",
                "y",
                "--outcome",
                "definitely-not-an-outcome",
            ],
        )
        assert result.exit_code == 1
        assert "Unknown outcome" in result.output

    def test_invalid_date_errors(self, runner: CliRunner, isolated_challenge_store: Path) -> None:
        result = runner.invoke(
            app,
            [
                "governance",
                "challenge",
                "add",
                "--subject-model-id",
                "aaaa1111-2222-3333-4444-555566667777",
                "--challenger-email",
                "x@y.com",
                "--challenger-role",
                "x",
                "--challenge-date",
                "not-a-date",
                "--challenge-topic",
                "x",
                "--challenge-substance",
                "y",
            ],
        )
        assert result.exit_code == 1
        assert "ISO-8601" in result.output


class TestChallengeList:
    def test_empty_message(self, runner: CliRunner, isolated_challenge_store: Path) -> None:
        result = runner.invoke(app, ["governance", "challenge", "list"])
        assert result.exit_code == 0
        assert "No challenges" in result.output

    def test_json_array_output(self, runner: CliRunner, isolated_challenge_store: Path) -> None:
        _add_minimal_challenge(runner, topic="A")
        _add_minimal_challenge(runner, topic="B")
        result = runner.invoke(app, ["governance", "challenge", "list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 2
        topics = {c["challenge_topic"] for c in data}
        assert topics == {"A", "B"}

    def test_filter_by_subject_model_id(self, runner: CliRunner, isolated_challenge_store: Path) -> None:
        sid_a = "aaaa1111-2222-3333-4444-aaaaaaaaaaaa"
        sid_b = "bbbb1111-2222-3333-4444-bbbbbbbbbbbb"
        _add_minimal_challenge(runner, subject_id=sid_a, topic="A")
        _add_minimal_challenge(runner, subject_id=sid_b, topic="B")
        result = runner.invoke(
            app,
            [
                "governance",
                "challenge",
                "list",
                "--subject-model-id",
                sid_a,
                "--json",
            ],
        )
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["challenge_topic"] == "A"

    def test_filter_by_outcome(self, runner: CliRunner, isolated_challenge_store: Path) -> None:
        _add_minimal_challenge(runner, outcome="pending", topic="P")
        _add_minimal_challenge(runner, outcome="accepted", topic="A")
        result = runner.invoke(
            app,
            [
                "governance",
                "challenge",
                "list",
                "--outcome",
                "accepted",
                "--json",
            ],
        )
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["challenge_topic"] == "A"


class TestChallengeShow:
    def test_show_existing(self, runner: CliRunner, isolated_challenge_store: Path) -> None:
        cid = _add_minimal_challenge(runner)
        result = runner.invoke(app, ["governance", "challenge", "show", cid])
        assert result.exit_code == 0
        assert "Methodology challenge" in result.output
        assert "Outcome:" in result.output

    def test_show_json(self, runner: CliRunner, isolated_challenge_store: Path) -> None:
        cid = _add_minimal_challenge(runner)
        result = runner.invoke(app, ["governance", "challenge", "show", cid, "--json"])
        data = json.loads(result.output)
        assert data["id"] == cid

    def test_show_unknown_errors(self, runner: CliRunner, isolated_challenge_store: Path) -> None:
        result = runner.invoke(
            app,
            [
                "governance",
                "challenge",
                "show",
                "00000000-0000-0000-0000-000000000000",
            ],
        )
        assert result.exit_code == 1

    def test_show_invalid_id_errors(self, runner: CliRunner, isolated_challenge_store: Path) -> None:
        result = runner.invoke(app, ["governance", "challenge", "show", "not-a-uuid"])
        assert result.exit_code == 1
        assert "Invalid challenge ID" in result.output
