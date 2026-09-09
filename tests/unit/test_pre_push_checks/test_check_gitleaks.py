"""Gitleaks hook parity tests use synthetic workflows and tool responses."""

from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CHECK_PATH = REPO_ROOT / "scripts/pre_push/check_gitleaks.py"
PIN = "8.4.2"
PRIVATE_MARKER = "synthetic-value-that-must-stay-out-of-output"


def _workflow() -> str:
    return """name: secret-scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  merge_group:
permissions:
  contents: read
concurrency:
  group: fixture
  cancel-in-progress: false
jobs:
  gitleaks:
    name: gitleaks (default ruleset + allowlist)
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@ACTION_PIN
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Install gitleaks (pinned binary, SHA256-verified)
        run: |
          VER=8.4.2
          curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${VER}/gitleaks_${VER}_linux_x64.tar.gz" -o /tmp/gitleaks.tar.gz
          echo "CHECKSUM  /tmp/gitleaks.tar.gz" | sha256sum -c -
          tar -xzf /tmp/gitleaks.tar.gz -C /tmp gitleaks
          sudo mv /tmp/gitleaks /usr/local/bin/gitleaks
          # Comment text is not a command.
          gitleaks version
      - name: Run gitleaks (scan git history)
        run: |
          gitleaks git . --config .gitleaks.toml --redact --no-banner
""".replace("ACTION_PIN", "2" * 40).replace("CHECKSUM", "1" * 64)


@pytest.fixture(scope="module")
def mod() -> Any:
    spec = importlib.util.spec_from_file_location("check_gitleaks", CHECK_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Harness:
    """Record argv and suppression settings without running any real tools."""

    def __init__(self, module: Any, root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.module = module
        self.root = root.resolve()
        self.workflow = root / ".github/workflows/secret-scan.yml"
        self.workflow.parent.mkdir(parents=True)
        self.workflow.write_text(_workflow(), encoding="utf-8")
        self.config = root / ".gitleaks.toml"
        self.config.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
        self.tools = root / "tool directory"
        self.tools.mkdir()
        self.binaries = {name: self.tools / (name + ".exe") for name in ("git", "gitleaks")}
        for path in self.binaries.values():
            path.touch()
        self.calls: list[tuple[list[str], dict[str, object]]] = []
        self.missing: str | None = None
        self.failure_stage: str | None = None
        self.exit_code = 1
        self.exception: Exception | None = None
        self.repository_output = str(self.root) + "\nfalse\n"
        self.version_output = PIN + "\n"
        monkeypatch.setattr(module, "ROOT", self.root)
        monkeypatch.setattr(module.shutil, "which", self.which)
        monkeypatch.setattr(module.subprocess, "run", self.run)

    def which(self, name: str, *, path: str) -> str | None:
        assert isinstance(path, str)
        return None if name == self.missing else str(self.binaries[name])

    def run(self, args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        self.calls.append((args, kwargs))
        stage = "repository" if args[0] == str(self.binaries["git"]) else "version" if args[1] == "version" else "scan"
        if stage == self.failure_stage and self.exception is not None:
            raise self.exception
        output = (
            self.repository_output
            if stage == "repository"
            else self.version_output
            if stage == "version"
            else PRIVATE_MARKER
        )
        return subprocess.CompletedProcess(
            args, self.exit_code if stage == self.failure_stage else 0, stdout=output, stderr=PRIVATE_MARKER
        )

    def invoke(self) -> int:
        result: int = self.module.main([])
        return result

    def replace(self, old: str, new: str) -> None:
        raw = self.workflow.read_text(encoding="utf-8")
        assert old in raw
        self.workflow.write_text(raw.replace(old, new), encoding="utf-8")


@pytest.fixture
def harness(mod: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    return Harness(mod, tmp_path, monkeypatch)


def test_exact_ci_scan_uses_repository_root_and_withholds_output(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    nested = harness.root / "nested"
    nested.mkdir()
    monkeypatch.chdir(nested)
    assert harness.invoke() == 0
    assert [args for args, _ in harness.calls] == [
        [
            str(harness.binaries["git"]),
            "-C",
            str(harness.root),
            "rev-parse",
            "--show-toplevel",
            "--is-shallow-repository",
        ],
        [str(harness.binaries["gitleaks"]), "version"],
        [str(harness.binaries["gitleaks"]), "git", ".", "--config", ".gitleaks.toml", "--redact", "--no-banner"],
    ]
    for _, options in harness.calls:
        assert options["cwd"] == harness.root
        assert options["shell"] is False
        assert options["check"] is False
        assert options["stdin"] == subprocess.DEVNULL
        assert options["stderr"] == subprocess.DEVNULL
    assert harness.calls[-1][1]["stdout"] == subprocess.DEVNULL
    assert harness.calls[-1][1]["timeout"] == 600
    assert capsys.readouterr().out == "PASS check_gitleaks: CI-pinned history scan passed\n"


def test_repository_ci_workflow_uses_supported_contract(mod: Any) -> None:
    version = mod.pinned_version((REPO_ROOT / ".github/workflows/secret-scan.yml").read_bytes())
    assert mod.VERSION_PATTERN.fullmatch(version)


def test_version_is_derived_from_ci_without_installing(harness: Harness) -> None:
    harness.replace("VER=" + PIN, "VER=9.1.7")
    harness.version_output = "9.1.7\n"
    assert harness.invoke() == 0
    assert len(harness.calls) == 3


@pytest.mark.parametrize("missing", ["git", "gitleaks"])
def test_missing_binary_blocks_before_scan(harness: Harness, missing: str) -> None:
    harness.missing = missing
    assert harness.invoke() == 1
    assert harness.calls == []


@pytest.mark.parametrize("name", ["git", "gitleaks"])
def test_missing_executable_file_blocks(harness: Harness, name: str) -> None:
    harness.binaries[name].unlink()
    assert harness.invoke() == 1
    assert harness.calls == []


@pytest.mark.parametrize("suffix", [".cmd", ".bat", ".ps1", ".sh"])
def test_shell_shim_is_not_run(harness: Harness, suffix: str) -> None:
    shim = harness.tools / ("gitleaks" + suffix)
    shim.touch()
    harness.binaries["gitleaks"] = shim
    assert harness.invoke() == 1
    assert harness.calls == []


@pytest.mark.parametrize("missing", ["workflow", "config"])
def test_missing_contract_files_block(harness: Harness, missing: str) -> None:
    path: Path = getattr(harness, missing)
    path.unlink()
    assert harness.invoke() == 1
    assert harness.calls == []


@pytest.mark.parametrize("version", ["8.4.1\n", "v8.4.2\n", "8.4.2-dev\n", "8.4.2\nextra\n", "", PRIVATE_MARKER])
def test_wrong_or_unparseable_version_blocks_without_values(
    harness: Harness, version: str, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.version_output = version
    assert harness.invoke() == 1
    assert len(harness.calls) == 2
    output = capsys.readouterr()
    assert PRIVATE_MARKER not in output.out + output.err
    assert output.err == ""


@pytest.mark.parametrize("stage", ["repository", "version", "scan"])
@pytest.mark.parametrize("exit_code", [1, 2, 127, -1])
def test_nonzero_tool_exit_never_passes_or_prints_tool_output(
    harness: Harness, stage: str, exit_code: int, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.failure_stage = stage
    harness.exit_code = exit_code
    assert harness.invoke() == 1
    output = capsys.readouterr()
    assert output.out.startswith("BLOCK check_gitleaks:")
    assert "PASS" not in output.out
    assert PRIVATE_MARKER not in output.out + output.err
    assert len(harness.calls) == {"repository": 1, "version": 2, "scan": 3}[stage]


@pytest.mark.parametrize("stage", ["repository", "version", "scan"])
@pytest.mark.parametrize(
    "error",
    [
        OSError(PRIVATE_MARKER),
        subprocess.TimeoutExpired(PRIVATE_MARKER, 1, output=PRIVATE_MARKER),
        subprocess.CalledProcessError(1, PRIVATE_MARKER, output=PRIVATE_MARKER),
    ],
)
def test_tool_exception_is_closed_and_value_free(
    harness: Harness, stage: str, error: Exception, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.failure_stage = stage
    harness.exception = error
    assert harness.invoke() == 1
    output = capsys.readouterr()
    assert PRIVATE_MARKER not in output.out + output.err
    assert output.err == ""


@pytest.mark.parametrize("tail", ["true\n", "False\n", "0\n", "false\nextra\n", ""])
def test_shallow_or_ambiguous_repository_is_rejected(harness: Harness, tail: str) -> None:
    harness.repository_output = str(harness.root) + "\n" + tail
    assert harness.invoke() == 1
    assert len(harness.calls) == 1


def test_wrong_repository_root_is_rejected(harness: Harness) -> None:
    harness.repository_output = str(harness.root.parent) + "\nfalse\n"
    assert harness.invoke() == 1
    assert len(harness.calls) == 1


def test_git_and_gitleaks_environment_cannot_redirect_scan(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    overrides = {
        "GIT_DIR": "other-repo",
        "GIT_WORK_TREE": "other-tree",
        "GIT_CONFIG_COUNT": "1",
        "GITLEAKS_CONFIG": "other-config",
        "GITLEAKS_CONFIG_TOML": PRIVATE_MARKER,
        "GITLEAKS_SKIP": "1",
    }
    for key, value in overrides.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("PARITY_TEST_KEEP", "ordinary-setting")
    assert harness.invoke() == 0
    for _, options in harness.calls:
        environment = options["env"]
        assert isinstance(environment, dict)
        assert all(key not in environment for key in overrides)
        assert environment["PARITY_TEST_KEEP"] == "ordinary-setting"
    assert all(os.environ[key] == value for key, value in overrides.items())
    assert len(harness.calls) == 3


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("--redact --no-banner", "--no-banner"),
        ("--redact", "--redact=20"),
        ("--redact", "--redact --exit-code 0"),
        ("gitleaks git .", "gitleaks git packages"),
        ("--config .gitleaks.toml", "--config alternate.toml"),
        ("--config .gitleaks.toml", ""),
        ("--no-banner", "--no-banner --baseline-path baseline.json"),
        ("--no-banner", "--no-banner || true"),
        ("--no-banner", "--no-banner | tee result"),
        ("--no-banner", "--no-banner; exit 0"),
        ("--no-banner", "--no-banner\n          true"),
        ("gitleaks git .", "echo gitleaks git ."),
        ("gitleaks git .", "${SCANNER} git ."),
        ("fetch-depth: 0", "fetch-depth: 1"),
        ("fetch-depth: 0", "fetch-depth: false"),
        ("persist-credentials: false", "persist-credentials: true"),
        ("actions/checkout@" + "2" * 40, "actions/checkout@main"),
        ("VER=8.4.2", "VER=latest"),
        ("VER=8.4.2", "VER=${VERSION}"),
        ("VER=8.4.2", "VER=8.4.2\n          VER=8.4.1"),
        ("VER=8.4.2", "VER=8.4.2; true"),
        ("sha256sum -c -", "sha256sum -c - || true"),
        ("1" * 64, "1" * 63),
        ("curl -sSfL", "curl -sSL"),
        ("gitleaks version", "gitleaks version || true"),
        ("runs-on: ubuntu-latest", "runs-on: windows-latest"),
        ("Run gitleaks (scan git history)", "Scan a different scope"),
        ("- name: Checkout", "- name: Different checkout"),
    ],
)
def test_contract_drift_blocks_before_executing_tools(harness: Harness, before: str, after: str) -> None:
    harness.replace(before, after)
    assert harness.invoke() == 1
    assert harness.calls == []


@pytest.mark.parametrize(
    ("anchor", "indent"), [("jobs:\n", ""), ("    steps:\n", "    "), ("        run: |\n", "        ")]
)
@pytest.mark.parametrize(
    "field",
    [
        "env: {OVERRIDE: value}",
        "defaults: {run: {shell: sh}}",
        "if: false",
        "continue-on-error: true",
        "working-directory: elsewhere",
        "shell: sh",
    ],
)
def test_execution_overrides_are_not_interpreted(harness: Harness, anchor: str, indent: str, field: str) -> None:
    harness.replace(anchor, indent + field + "\n" + anchor)
    assert harness.invoke() == 1
    assert harness.calls == []


@pytest.mark.parametrize(
    "raw",
    [
        b"jobs: [",
        b"name: first\nname: second\n",
        b"jobs: &jobs {}\nother: *jobs\n",
        b"42: value\n",
        b"\xff\xfe\xff",
        b"---\n{}\n---\n{}\n",
    ],
)
def test_ambiguous_or_invalid_yaml_blocks_without_content(
    harness: Harness, raw: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.workflow.write_bytes(raw)
    assert harness.invoke() == 1
    assert harness.calls == []
    assert capsys.readouterr().err == ""


def test_duplicate_scan_step_rejected(harness: Harness) -> None:
    harness.replace(
        "      - name: Run gitleaks (scan git history)",
        "      - name: Extra step\n        run: true\n      - name: Run gitleaks (scan git history)",
    )
    assert harness.invoke() == 1
    assert harness.calls == []


def test_cli_has_no_bypass_argument(mod: Any, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as result:
        mod.main(["--skip"])
    assert result.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("missing", "not installed on PATH"),
        ("version", "does not match the CI pin"),
        ("scan", "history scan failed"),
    ],
)
def test_fixed_failure_diagnostics_distinguish_remedies(
    harness: Harness, kind: str, expected: str, capsys: pytest.CaptureFixture[str]
) -> None:
    if kind == "missing":
        harness.missing = "gitleaks"
    elif kind == "version":
        harness.version_output = PRIVATE_MARKER
    else:
        harness.failure_stage = "scan"
    assert harness.invoke() == 1
    output = capsys.readouterr()
    assert expected in output.out
    assert PRIVATE_MARKER not in output.out + output.err


@pytest.mark.parametrize("error", [OSError(PRIVATE_MARKER), ValueError(PRIVATE_MARKER)])
def test_unexpected_preflight_failure_does_not_echo_exception(
    mod: Any, monkeypatch: pytest.MonkeyPatch, error: Exception, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(root: Path) -> None:
        raise error

    monkeypatch.setattr(mod, "check", fail)
    assert mod.main([]) == 1
    output = capsys.readouterr()
    assert output.out == "BLOCK check_gitleaks: scan preflight failed; scanner output withheld\n"
    assert output.err == ""


@pytest.mark.parametrize("separator", ["\v", "\f", "\r", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"])
@pytest.mark.parametrize("step_index", [1, 2])
def test_non_shell_separators_cannot_activate_commented_commands(
    harness: Harness, separator: str, step_index: int
) -> None:
    document = harness.module.yaml.load(harness.workflow.read_bytes(), Loader=harness.module._WorkflowLoader)
    step = document["jobs"]["gitleaks"]["steps"][step_index]
    step["run"] = "# comment" + separator + step["run"]
    harness.workflow.write_text(harness.module.yaml.safe_dump(document), encoding="utf-8")
    assert harness.invoke() == 1
    assert harness.calls == []


@pytest.mark.parametrize("whitespace", ["\v", "\f", "\r", "\x1c", "\x85", "\u00a0", "\u2028", "\u2029"])
def test_non_shell_whitespace_is_not_trimmed_from_commands(harness: Harness, whitespace: str) -> None:
    document = harness.module.yaml.load(harness.workflow.read_bytes(), Loader=harness.module._WorkflowLoader)
    scan = document["jobs"]["gitleaks"]["steps"][2]
    scan["run"] = scan["run"].rstrip("\n") + whitespace + "\n"
    harness.workflow.write_text(harness.module.yaml.safe_dump(document), encoding="utf-8")
    assert harness.invoke() == 1
    assert harness.calls == []


@pytest.mark.parametrize("step_index", [1, 2])
@pytest.mark.parametrize("prefix", ["# ", ""])
@pytest.mark.parametrize(
    "expression", ["${{ 1 }}", "${{ github.event.pull_request.body }}", "${{\n github.event.pull_request.body \n}}"]
)
def test_actions_expressions_are_rejected_before_comment_filtering(
    harness: Harness, step_index: int, prefix: str, expression: str
) -> None:
    document = harness.module.yaml.load(harness.workflow.read_bytes(), Loader=harness.module._WorkflowLoader)
    step = document["jobs"]["gitleaks"]["steps"][step_index]
    step["run"] = prefix + expression + "\n" + step["run"]
    harness.workflow.write_text(harness.module.yaml.safe_dump(document), encoding="utf-8")
    assert harness.invoke() == 1
    assert harness.calls == []
