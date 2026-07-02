"""Tests for ``scripts/check_workflow_tools.py`` (G8 tool-availability +
G9 extras-validity; engineering-practices lessons 8-9).

Mirrors the ``test_audit_workflow_permissions.py`` precedent: the script is
loaded via ``importlib`` (scripts/ has no ``__init__.py``), and every test
uses ``tmp_path`` fixtures — never the repo's real workflows — so the unit
tests stay independent of workflow churn. The repo-tree run happens in CI
via ``verify-workflow-perms.yml``, not here.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_workflow_tools.py"


@pytest.fixture(scope="module")
def cwt() -> Any:
    spec = importlib.util.spec_from_file_location("check_workflow_tools", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_workflow_tools"] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# extract_commands — the quote-aware first-token heuristic
# ---------------------------------------------------------------------------


def test_simple_commands_and_operators(cwt: Any) -> None:
    script = "uv sync --all-packages\ndocker pull foo && cosign verify bar | jq .\n"
    assert cwt.extract_commands(script) == ["uv", "docker", "cosign", "jq"]


def test_comments_and_blank_lines_skipped(cwt: Any) -> None:
    script = "# a comment\n\nuvx twine check dist/*\n"
    assert cwt.extract_commands(script) == ["uvx"]


def test_env_prefix_assignment_unwraps_command(cwt: Any) -> None:
    assert cwt.extract_commands("FOO=bar uv run pytest\n") == ["uv"]


def test_plain_quoted_assignment_is_not_a_command(cwt: Any) -> None:
    assert cwt.extract_commands('VERSION="${REF#v}"\n') == []


def test_command_substitution_assignment_unwraps(cwt: Any) -> None:
    script = 'pinned=$(grep -oE "x" Dockerfile || true)\n'
    assert cwt.extract_commands(script) == ["grep"]


def test_arithmetic_assignment_skipped(cwt: Any) -> None:
    script = "age_days=$(( ( $(date -u +%s) - 5 ) / 86400 ))\n"
    assert cwt.extract_commands(script) == []


def test_heredoc_body_skipped(cwt: Any) -> None:
    # `echo` is a shell builtin -> filtered; the heredoc BODY must not leak
    # a phantom `not-a-command` token.
    script = "cat >> out.md <<'STANZA'\nnot-a-command --flag\nSTANZA\necho done\n"
    assert cwt.extract_commands(script) == ["cat"]


def test_backslash_continuation_folds(cwt: Any) -> None:
    script = "curl -sSfL https://example.com \\\n  -o out.bin\nchmod +x out.bin\n"
    assert cwt.extract_commands(script) == ["curl", "chmod"]


def test_control_keywords_unwrapped_and_terminals_skipped(cwt: Any) -> None:
    script = (
        "if ! printf '%s' \"$REF\" | grep -Eq 'x'; then\n"
        "  exit 1\n"
        "fi\n"
        "until docker run --rm img; do\n"
        "  sleep 15\n"
        "done\n"
        "for i in $(seq 1 30); do\n"
        "  true\n"
        "done\n"
    )
    got = cwt.extract_commands(script)
    # printf/exit/true are builtins -> filtered; grep/docker/sleep are real
    # commands unwrapped from `if !` / `until` wrappers.
    assert "grep" in got and "docker" in got and "sleep" in got
    assert "printf" not in got
    assert "for" not in got and "fi" not in got and "done" not in got and "i" not in got


def test_sudo_and_wrappers_unwrapped(cwt: Any) -> None:
    assert cwt.extract_commands("sudo docker prune\n") == ["docker"]


def test_variable_and_path_invocations_skipped(cwt: Any) -> None:
    script = '"$HOME/.local/bin/osv-scanner" scan\n/tmp/venv/bin/pip install x\n./local-script.sh\n'
    assert cwt.extract_commands(script) == []


def test_redirect_only_tokens_skipped(cwt: Any) -> None:
    assert cwt.extract_commands("uv run x 2>/dev/null\n") == ["uv"]


# --- quote-masking regressions (the classes that false-positived on the
# --- real tree during plan verification: semicolons/pipes INSIDE strings,
# --- multi-line python -c bodies, case arms, quoted jq/sed programs) -------


def test_semicolon_inside_quotes_not_split(cwt: Any) -> None:
    script = 'gh issue create --title "No liveness findings; nothing to do."\n'
    assert cwt.extract_commands(script) == ["gh"]


def test_multiline_python_c_body_is_opaque(cwt: Any) -> None:
    script = (
        'python -c "\n'
        "import zipfile, glob, sys\n"
        "wheels = [p for p in glob.glob('dist/*.whl')]\n"
        "assert wheels, f'none: {wheels}'\n"
        '"\n'
        "uv sync\n"
    )
    assert cwt.extract_commands(script) == ["python", "uv"]


def test_case_arms_skipped_until_esac(cwt: Any) -> None:
    script = (
        'case "$GITHUB_EVENT_NAME" in\n'
        "  pull_request|merge_group) echo pr ;;\n"
        "  *) echo other ;;\n"
        "esac\n"
        "docker ps\n"
    )
    assert cwt.extract_commands(script) == ["docker"]


def test_single_quoted_program_bodies_opaque(cwt: Any) -> None:
    script = (
        "gh api x -q '.[0].number; select(.title)'\n"
        'sed -i "s|__TAG__|v1|g; s|__D__|abc|g" file.md\n'
    )
    assert cwt.extract_commands(script) == ["gh", "sed"]
