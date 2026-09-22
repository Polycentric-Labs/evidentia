"""Release audit diagnostics use fixed text and retain strict failure status."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def checker() -> Any:
    source = Path(__file__).resolve().parents[2] / "scripts" / "check_docs_health.py"
    name = "docs_health_release_under_test"
    spec = importlib.util.spec_from_file_location(name, source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("failed_call", [1, 2])
@pytest.mark.parametrize("failure", [FileNotFoundError, PermissionError, OSError])
def test_cli_launch_failure_blocks_strict_gate_without_exception_text(
    checker: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failed_call: int,
    failure: type[OSError],
) -> None:
    calls: list[list[str]] = []

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if len(calls) == failed_call:
            raise failure("synthetic-private-detail")
        return subprocess.CompletedProcess(args, 0, "", "")

    config = checker.PhraseConfig.empty()
    config.is_loaded = True
    monkeypatch.setattr(checker, "load_phrase_config", lambda: (config, None))
    monkeypatch.setattr(checker, "list_tracked_files", lambda **kwargs: set())
    for name in (
        "check_parse_validity",
        "check_cross_link_resolve",
        "check_readme_size_guard",
        "check_private_path_leak",
        "check_readme_header_titlecase",
        "check_readme_recent_releases_current",
        "check_phrase_audit",
        "check_git_commit_message_audit",
        "check_git_tag_message_audit",
    ):
        monkeypatch.setattr(checker, name, lambda *args: None)
    monkeypatch.setattr(checker.subprocess, "run", run)
    monkeypatch.setattr(sys, "argv", ["check_docs_health.py", "--strict", "--json"])

    assert checker.main() == 2
    output = capsys.readouterr()
    value = json.loads(output.out)
    assert output.err == ""
    assert "synthetic-private-detail" not in output.out
    assert value["fail_count"] == 1 and value["warn_count"] == 0
    assert value["findings"] == [
        {
            "severity": "FAIL",
            "check": "release_body_audit",
            "path": "<gh>",
            "line": None,
            "message": "Cannot start GitHub CLI; verify its installation and PATH, then rerun.",
        }
    ]
    assert (
        calls
        == [
            ["gh", "auth", "status"],
            ["gh", "release", "view", "--json", "tagName,body"],
        ][:failed_call]
    )


def test_unauthenticated_cli_retains_advisory_result(checker: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 1, "", "")

    monkeypatch.setattr(checker.subprocess, "run", run)
    result = checker.CheckResult()
    checker.check_github_release_body_audit(checker.PhraseConfig.empty(), result)
    assert result.fail_count == 0 and result.warn_count == 1
    assert calls == [["gh", "auth", "status"]]


def test_successful_cli_keeps_release_body_audit(checker: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    scans: list[tuple[str, str]] = []

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        output = "" if len(calls) == 1 else json.dumps({"tagName": "v1.2.3", "body": "Release notes."})
        return subprocess.CompletedProcess(args, 0, output, "")

    def scan(text: str, *, source: str, **kwargs: Any) -> list[Any]:
        scans.append((text, source))
        return []

    monkeypatch.setattr(checker.subprocess, "run", run)
    monkeypatch.setattr(checker, "_scan_text_for_forbidden", scan)
    result = checker.CheckResult()
    checker.check_github_release_body_audit(checker.PhraseConfig.empty(), result)
    assert result.findings == []
    assert scans == [("Release notes.", "release:v1.2.3")]
    assert len(calls) == 2
