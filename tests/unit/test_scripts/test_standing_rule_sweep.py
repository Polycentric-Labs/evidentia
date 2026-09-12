"""Keep the reviewed publisher exception finite and other surfaces scanned."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _ROOT / "scripts/standing_rule_sweep.sh"
_SOURCES = (
    "packages/evidentia-collectors/src/evidentia_collectors/registries/data/fedramp/snapshot.json",
    "tests/fixtures/registries/fedramp/full-source-tuples.json",
)


def _copy_source(root: Path, relative: str) -> Path:
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(_ROOT / relative, destination)
    return destination


def _run(root: Path, paths: tuple[str, ...], *, script: Path = _SCRIPT, label: str = "scan") -> int:
    bash = shutil.which("bash")
    assert bash is not None, "Git Bash or Bash must be on PATH"
    assert shutil.which("uv") is not None, "The reviewed uv must be on PATH"
    environment = {
        key: value
        for key, value in os.environ.items()
        if key
        in {
            "PATH",
            "SystemRoot",
            "WINDIR",
            "COMSPEC",
            "PATHEXT",
            "TEMP",
            "TMP",
        }
    }
    environment.update(
        {
            "UV_OFFLINE": "1",
            "UV_NO_SYNC": "1",
            "UV_PYTHON": sys.executable,
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    process = subprocess.run(
        [bash, script.as_posix(), *paths],
        cwd=root,
        env=environment,
        capture_output=True,
        check=False,
        timeout=60,
    )
    (root / (label + ".stdout")).write_bytes(process.stdout)
    (root / (label + ".stderr")).write_bytes(process.stderr)
    return process.returncode


def test_exact_reviewed_publisher_files_pass(tmp_path: Path) -> None:
    for source in _SOURCES:
        _copy_source(tmp_path, source)
    assert _run(tmp_path, _SOURCES) == 0


@pytest.mark.parametrize("damage", ["same-size", "extra-byte", "line-endings", "binary", "missing"])
def test_approved_path_refuses_any_changed_bytes(tmp_path: Path, damage: str) -> None:
    destination = _copy_source(tmp_path, _SOURCES[1])
    raw = destination.read_bytes()
    if damage == "same-size":
        destination.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
    elif damage == "extra-byte":
        destination.write_bytes(raw + b" ")
    elif damage == "line-endings":
        destination.write_bytes(raw.replace(b"\n", b"\r\n"))
    elif damage == "binary":
        destination.write_bytes(b"\0")
    else:
        destination.unlink()
    assert _run(tmp_path, (_SOURCES[1],)) != 0


def test_same_source_at_other_path_still_fails(tmp_path: Path) -> None:
    destination = tmp_path / "publisher-copy.json"
    shutil.copyfile(_ROOT / _SOURCES[0], destination)
    assert _run(tmp_path, (destination.name,)) != 0


def test_added_rule_invalidates_finite_exception(tmp_path: Path) -> None:
    _copy_source(tmp_path, _SOURCES[0])
    script = tmp_path / "changed-script.sh"
    original = _SCRIPT.read_text(encoding="utf-8")
    assert "PATTERNS=(" in original
    script.write_text(original.replace("PATTERNS=(", 'PATTERNS=("synthetic-policy-change" ', 1), encoding="utf-8")
    assert _run(tmp_path, (_SOURCES[0],), script=script) != 0


def test_all_rules_still_reject_other_public_files_and_commit_messages(tmp_path: Path) -> None:
    source = _SCRIPT.read_text(encoding="utf-8")
    block = source.split("PATTERNS=(", 1)[1].split("\n)", 1)[0]
    patterns = re.findall(r'^\s*"([^"\n]+)"', block, flags=re.MULTILINE)
    assert len(patterns) == 21
    public = tmp_path / "public.txt"
    message = tmp_path / ".git" / "COMMIT_EDITMSG"
    message.parent.mkdir()
    for index, pattern in enumerate(patterns):
        public.write_text(pattern + "\n", encoding="utf-8")
        message.write_text(pattern + "\n", encoding="utf-8")
        assert _run(tmp_path, (public.name,), label=f"public-{index}") != 0
        assert _run(tmp_path, (".git/COMMIT_EDITMSG",), label=f"message-{index}") != 0
