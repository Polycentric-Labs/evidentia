"""Security-sensitive defaults must catch mismatched AnyIO lock pins."""

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_requirements_drift.py"


@pytest.mark.parametrize(
    ("locked", "container", "expected"),
    [("4.13.0", "4.15.1", 1), ("4.15.1", "4.13.0", 1), ("4.15.1", "4.15.1", 0)],
)
def test_strict_default_detects_anyio_drift(tmp_path, locked, container, expected):
    lock = tmp_path / "uv.lock"
    requirements = tmp_path / "requirements.txt"
    lock.write_text(f'[[package]]\nname = "anyio"\nversion = "{locked}"\n', encoding="utf8")
    requirements.write_text(f"anyio=={container}\n", encoding="utf8")
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            str(SCRIPT),
            "--strict",
            "--uv-lock",
            str(lock),
            "--requirements",
            str(requirements),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == expected
    assert result.stderr == ""
    assert "anyio" in result.stdout
    if expected:
        assert locked in result.stdout and container in result.stdout
        assert "FAIL: version drift detected" in result.stdout
    else:
        assert "PASS: no version drift detected" in result.stdout
