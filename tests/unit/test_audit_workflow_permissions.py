"""Tests for ``scripts/audit_workflow_permissions.py`` (D4.1, v0.10.7).

This module is the prerequisite for promoting the workflow-permissions
audit from advisory (v0.10.6) to a blocking ``--strict`` CI gate
(v0.10.7 ``verify-workflow-perms.yml``). It pins:

* :func:`audit_workflow` status for every code path — OK / WARN / FAIL /
  JUSTIFIED / ERROR — using ``tmp_path`` fixture files (NOT the repo's
  real workflows, so the unit tests stay independent of workflow churn).
* the ``# JUSTIFIED: <reason>`` association rule (comment on the first
  non-blank line directly above the top-level ``permissions:`` key).
* the ``--strict`` exit code: 2 when an un-justified FAIL exists, 0 when
  all FAIL are JUSTIFIED.

The ``--strict`` exit-code tests monkeypatch ``WORKFLOWS_DIR`` to a
temporary directory so ``main()`` audits only the fixtures.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "audit_workflow_permissions.py"


@pytest.fixture(scope="module")
def awp() -> Any:
    """Import scripts/audit_workflow_permissions.py (it has no __init__.py)."""
    spec = importlib.util.spec_from_file_location("audit_workflow_permissions", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["audit_workflow_permissions"] = module
    spec.loader.exec_module(module)
    return module


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# --------------------------------------------------------------------------
# audit_workflow status coverage
# --------------------------------------------------------------------------


def test_empty_file_is_error(awp: Any, tmp_path: Path) -> None:
    p = _write(tmp_path, "empty.yml", "")
    status, detail = awp.audit_workflow(p)
    assert status == "ERROR"
    assert "not a YAML mapping" in detail


def test_comment_only_file_is_error(awp: Any, tmp_path: Path) -> None:
    # safe_load returns None for comment-only files too.
    p = _write(tmp_path, "comments.yml", "# just a comment\n# another\n")
    status, detail = awp.audit_workflow(p)
    assert status == "ERROR"
    assert "NoneType" in detail


def test_top_level_list_is_error(awp: Any, tmp_path: Path) -> None:
    # The isinstance(data, dict) guard catches a top-level sequence, not
    # just empty files — this is the D1-review tightening.
    p = _write(tmp_path, "list.yml", "- one\n- two\n")
    status, detail = awp.audit_workflow(p)
    assert status == "ERROR"
    assert "not a YAML mapping" in detail
    assert "list" in detail


def test_top_level_scalar_is_error(awp: Any, tmp_path: Path) -> None:
    p = _write(tmp_path, "scalar.yml", "just-a-string\n")
    status, detail = awp.audit_workflow(p)
    assert status == "ERROR"
    assert "str" in detail


def test_malformed_yaml_is_error(awp: Any, tmp_path: Path) -> None:
    p = _write(tmp_path, "bad.yml", "permissions: [unterminated\n")
    status, detail = awp.audit_workflow(p)
    assert status == "ERROR"
    assert "YAML parse" in detail


def test_read_only_top_level_perms_is_ok(awp: Any, tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        "ro.yml",
        "name: x\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n",
    )
    status, detail = awp.audit_workflow(p)
    assert status == "OK"
    assert "contents" in detail


def test_read_all_top_level_perms_is_ok(awp: Any, tmp_path: Path) -> None:
    p = _write(tmp_path, "readall.yml", "name: x\npermissions: read-all\n")
    status, _ = awp.audit_workflow(p)
    assert status == "OK"


def test_write_scope_no_justification_is_fail(awp: Any, tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        "wr.yml",
        "name: x\npermissions:\n  contents: read\n  issues: write\n",
    )
    status, detail = awp.audit_workflow(p)
    assert status == "FAIL"
    assert "grants write" in detail


def test_write_all_no_justification_is_fail(awp: Any, tmp_path: Path) -> None:
    p = _write(tmp_path, "wrall.yml", "name: x\npermissions: write-all\n")
    status, _ = awp.audit_workflow(p)
    assert status == "FAIL"


def test_write_scope_with_justification_is_downgraded(awp: Any, tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        "just.yml",
        "name: x\n"
        "# JUSTIFIED: bot opens an issue on upstream drift\n"
        "permissions:\n"
        "  contents: read\n"
        "  issues: write\n",
    )
    status, detail = awp.audit_workflow(p)
    assert status == "JUSTIFIED"
    assert "bot opens an issue on upstream drift" in detail


def test_justification_through_blank_lines(awp: Any, tmp_path: Path) -> None:
    # The comment is the first NON-BLANK line above permissions:, so a
    # blank line between the comment and the key still associates.
    p = _write(
        tmp_path,
        "just_blank.yml",
        "name: x\n"
        "# JUSTIFIED: posts a PR comment\n"
        "\n"
        "permissions:\n"
        "  pull-requests: write\n",
    )
    status, detail = awp.audit_workflow(p)
    assert status == "JUSTIFIED"
    assert "posts a PR comment" in detail


def test_justification_far_above_does_not_associate(awp: Any, tmp_path: Path) -> None:
    # A JUSTIFIED comment that is NOT the immediately-preceding non-blank
    # line (another real line sits between it and permissions:) must NOT
    # downgrade — proves the association rule is strict.
    p = _write(
        tmp_path,
        "far.yml",
        "# JUSTIFIED: this comment is too far away\n"
        "name: x\n"
        "permissions:\n"
        "  issues: write\n",
    )
    status, _ = awp.audit_workflow(p)
    assert status == "FAIL"


def test_justification_on_write_line_does_not_associate(awp: Any, tmp_path: Path) -> None:
    # A comment INSIDE the block (on the write-scope line) is NOT the
    # immediately-preceding line of the top-level `permissions:` key, so
    # it does not justify under the chosen rule.
    p = _write(
        tmp_path,
        "inside.yml",
        "name: x\n"
        "permissions:\n"
        "  contents: read\n"
        "  issues: write  # JUSTIFIED: inside the block\n",
    )
    status, _ = awp.audit_workflow(p)
    assert status == "FAIL"


def test_all_jobs_declare_perms_no_top_level_is_ok(awp: Any, tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        "jobs.yml",
        "name: x\n"
        "jobs:\n"
        "  a:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        "  b:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n",
    )
    status, detail = awp.audit_workflow(p)
    assert status == "OK"
    assert "all jobs declare explicit permissions" in detail


def test_no_perms_anywhere_is_warn(awp: Any, tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        "noperms.yml",
        "name: x\njobs:\n  a:\n    runs-on: ubuntu-latest\n",
    )
    status, _ = awp.audit_workflow(p)
    assert status == "WARN"


def test_partial_job_perms_is_warn(awp: Any, tmp_path: Path) -> None:
    # Only one of two jobs declares permissions, no top-level → WARN.
    p = _write(
        tmp_path,
        "partial.yml",
        "name: x\n"
        "jobs:\n"
        "  a:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        "  b:\n"
        "    runs-on: ubuntu-latest\n",
    )
    status, _ = awp.audit_workflow(p)
    assert status == "WARN"


# --------------------------------------------------------------------------
# find_justification direct unit coverage
# --------------------------------------------------------------------------


def test_find_justification_immediately_above(awp: Any) -> None:
    text = "name: x\n# JUSTIFIED: reason here\npermissions:\n  issues: write\n"
    assert awp.find_justification(text) == "reason here"


def test_find_justification_none_when_absent(awp: Any) -> None:
    text = "name: x\npermissions:\n  issues: write\n"
    assert awp.find_justification(text) is None


def test_find_justification_none_when_no_top_level_permissions(awp: Any) -> None:
    text = "name: x\njobs:\n  a:\n    permissions:\n      contents: read\n"
    assert awp.find_justification(text) is None


def test_find_justification_ignores_indented_permissions(awp: Any) -> None:
    # An indented (job-scoped) permissions: key must not be treated as the
    # top-level key; the comment above it does not count.
    text = (
        "name: x\n"
        "jobs:\n"
        "  a:\n"
        "    # JUSTIFIED: job-scoped, not top-level\n"
        "    permissions:\n"
        "      issues: write\n"
    )
    assert awp.find_justification(text) is None


# --------------------------------------------------------------------------
# --strict exit-code coverage (main())
# --------------------------------------------------------------------------


def test_strict_exits_2_on_unjustified_fail(
    awp: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path, "ok.yml", "name: x\npermissions:\n  contents: read\n")
    _write(tmp_path, "bad.yml", "name: x\npermissions:\n  issues: write\n")
    monkeypatch.setattr(awp, "WORKFLOWS_DIR", tmp_path)
    monkeypatch.setattr(sys, "argv", ["audit_workflow_permissions.py", "--strict"])
    assert awp.main() == 2


def test_strict_exits_0_when_all_fail_justified(
    awp: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path, "ok.yml", "name: x\npermissions:\n  contents: read\n")
    _write(
        tmp_path,
        "just.yml",
        "name: x\n# JUSTIFIED: bot posts a PR comment\npermissions:\n  pull-requests: write\n",
    )
    monkeypatch.setattr(awp, "WORKFLOWS_DIR", tmp_path)
    monkeypatch.setattr(sys, "argv", ["audit_workflow_permissions.py", "--strict"])
    assert awp.main() == 0


def test_strict_exits_2_on_error_file(
    awp: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An ERROR (empty file) is blocking under --strict, same as FAIL.
    _write(tmp_path, "empty.yml", "")
    monkeypatch.setattr(awp, "WORKFLOWS_DIR", tmp_path)
    monkeypatch.setattr(sys, "argv", ["audit_workflow_permissions.py", "--strict"])
    assert awp.main() == 2


def test_advisory_default_exits_0_despite_fail(
    awp: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Without --strict, an un-justified FAIL must still exit 0 (backward
    # compatible advisory behavior).
    _write(tmp_path, "bad.yml", "name: x\npermissions:\n  issues: write\n")
    monkeypatch.setattr(awp, "WORKFLOWS_DIR", tmp_path)
    monkeypatch.setattr(sys, "argv", ["audit_workflow_permissions.py"])
    assert awp.main() == 0


def test_json_output_shape(
    awp: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import json

    _write(tmp_path, "ok.yml", "name: x\npermissions:\n  contents: read\n")
    _write(
        tmp_path,
        "just.yml",
        "name: x\n# JUSTIFIED: reason\npermissions:\n  issues: write\n",
    )
    _write(tmp_path, "bad.yml", "name: x\npermissions:\n  pull-requests: write\n")
    monkeypatch.setattr(awp, "WORKFLOWS_DIR", tmp_path)
    monkeypatch.setattr(sys, "argv", ["audit_workflow_permissions.py", "--json"])
    rc = awp.main()
    # --json alone (no --strict) is advisory → exit 0 even with a FAIL.
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["workflows"]["ok.yml"]["status"] == "OK"
    assert payload["workflows"]["just.yml"]["status"] == "JUSTIFIED"
    assert payload["workflows"]["bad.yml"]["status"] == "FAIL"
    summary = payload["summary"]
    assert summary["total"] == 3
    assert summary["ok"] == 1
    assert summary["justified"] == 1
    assert summary["fail"] == 1
    assert summary["blocking"] == 1


def test_json_strict_compose_exit_code(
    awp: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import json

    _write(tmp_path, "bad.yml", "name: x\npermissions:\n  issues: write\n")
    monkeypatch.setattr(awp, "WORKFLOWS_DIR", tmp_path)
    monkeypatch.setattr(sys, "argv", ["audit_workflow_permissions.py", "--json", "--strict"])
    rc = awp.main()
    # --json + --strict compose: json output AND strict exit code.
    assert rc == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["strict"] is True
    assert payload["summary"]["blocking"] == 1
