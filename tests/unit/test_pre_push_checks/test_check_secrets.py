"""Tests for ``scripts/pre_push/check_secrets.sh`` (D5, v0.10.7).

Pre-push gate L2 check: scans the push range for accidentally-committed
secrets (dotenv / key files by name; AWS keys / GitHub PATs / PEM blocks by
content) and BLOCKs (exit 1) on a hit.

The script is bash, so it is driven via ``subprocess`` (no importlib). Each
test builds a throwaway git repo in ``tmp_path`` with a single committed
file, then runs the script with NO range args so it falls back to scanning
all tracked files (``git ls-files``). The assertions key off the exit code
(1 = block, 0 = pass) — the no-echo protocol means the token value never
appears in output, so we never assert on it.

Focus of this suite: the value-precise AWS known-placeholder allowlist added
in v0.10.7. AWS's published documentation example keys must NOT block (they
are not real credentials), while a realistic ``AKIA`` + 16-uppercase-alnum
token MUST still block (detection intact).

NOTE: the realistic "real-looking" AWS key fixture is assembled via string
concatenation so this test FILE does not itself carry a literal ``AKIA`` + 16
token (which would trip the scanner — and GitHub secret-scanning — on the
test's own push). Same discipline as ``tests/unit/test_audit/test_logger.py``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CHECK_PATH = REPO_ROOT / "scripts" / "pre_push" / "check_secrets.sh"

# AWS's published documentation placeholders — must be allowlisted (no block).
AWS_PLACEHOLDER_PRIMARY = "AKIA" + "IOSFODNN7EXAMPLE"
AWS_PLACEHOLDER_SECONDARY = "AKIAI44QH8DHB" + "EXAMPLE"
# A realistic, non-placeholder permanent AWS access key — must still block.
REAL_LOOKING_AWS_KEY = "AKIA" + "Z9Q7K3M2X1P4T6BN"


def _usable_bash() -> str | None:
    """A bash that can actually read this repo's paths, or None to skip.

    On Windows, ``shutil.which("bash")`` can resolve to the WSL shim at
    ``System32\\bash.EXE``, which cannot open Windows-style paths (it needs
    ``/mnt/c/...``) — the script then fails with exit 127 and the suite goes
    red for an environmental reason (v0.10.9). Probe each candidate with a
    ``test -r`` against the script's own path and use the first one that can
    see it; Git-for-Windows bash (MSYS) handles ``C:/...`` natively, so it is
    tried first. On POSIX the plain ``which`` result passes the probe.
    """
    candidates: list[str] = []
    for env_var in ("ProgramFiles", "ProgramFiles(x86)"):
        pf = os.environ.get(env_var)
        if pf:
            for sub in ("bin", "usr/bin"):
                cand = Path(pf) / "Git" / sub / "bash.exe"
                if cand.is_file():
                    candidates.append(str(cand))
    which = shutil.which("bash")
    if which:
        candidates.append(which)
    probe = CHECK_PATH.as_posix()
    for cand in candidates:
        try:
            proc = subprocess.run(
                [cand, "-c", f'test -r "{probe}"'],
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode == 0:
            return cand
    return None


# Skip the whole module when no usable bash exists (the script is bash-only).
BASH = _usable_bash()
pytestmark = pytest.mark.skipif(
    BASH is None,
    reason="no bash that can read repo paths (e.g. only the WSL System32 shim)",
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    )


def _make_repo(tmp_path: Path, filename: str, content: str) -> Path:
    """A throwaway git repo containing exactly one committed file."""
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q")
    _git(r, "config", "user.email", "t@example.com")
    _git(r, "config", "user.name", "Test")
    _git(r, "config", "commit.gpgsign", "false")
    (r / filename).write_text(content, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "fixture")
    return r


def _run_check(repo: Path) -> subprocess.CompletedProcess[str]:
    """Run check_secrets.sh inside ``repo`` with no range (scan-all fallback)."""
    assert BASH is not None
    # POSIX-style path: identical on POSIX, and the form MSYS/git-bash
    # resolves natively on Windows.
    return subprocess.run(
        [BASH, CHECK_PATH.as_posix()],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=False,
    )


# ---------------------------------------------------------------------------
# Allowlist: AWS documentation placeholders must NOT block.
# ---------------------------------------------------------------------------


def test_aws_primary_placeholder_passes(tmp_path: Path) -> None:
    """A doc containing AKIAIOSFODNN7EXAMPLE passes (canonical AWS example)."""
    doc = f"See the AWS example key `{AWS_PLACEHOLDER_PRIMARY}` in the docs.\n"
    repo = _make_repo(tmp_path, "SECURITY.md", doc)
    proc = _run_check(repo)
    assert proc.returncode == 0, proc.stderr
    assert "PASS check_secrets" in proc.stdout


def test_aws_secondary_placeholder_passes(tmp_path: Path) -> None:
    """The second AWS published placeholder (AKIAI44QH8DHBEXAMPLE) also passes."""
    doc = f"Another AWS example: `{AWS_PLACEHOLDER_SECONDARY}`.\n"
    repo = _make_repo(tmp_path, "docs.md", doc)
    proc = _run_check(repo)
    assert proc.returncode == 0, proc.stderr


def test_both_placeholders_together_pass(tmp_path: Path) -> None:
    """A file whose ONLY AWS-key matches are placeholders passes."""
    doc = (
        f"Examples: {AWS_PLACEHOLDER_PRIMARY} and {AWS_PLACEHOLDER_SECONDARY}.\n"
    )
    repo = _make_repo(tmp_path, "guide.md", doc)
    proc = _run_check(repo)
    assert proc.returncode == 0, proc.stderr


# ---------------------------------------------------------------------------
# Detection intact: a real-looking AWS key must STILL block.
# ---------------------------------------------------------------------------


def test_real_aws_key_blocks(tmp_path: Path) -> None:
    """A realistic non-placeholder AKIA+16 token still blocks (exit 1)."""
    content = f"aws_access_key_id = {REAL_LOOKING_AWS_KEY}\n"
    repo = _make_repo(tmp_path, "config.txt", content)
    proc = _run_check(repo)
    assert proc.returncode == 1
    assert "AWS access key" in proc.stderr
    # No-echo protocol: the token value must NEVER appear in output.
    assert REAL_LOOKING_AWS_KEY not in proc.stdout
    assert REAL_LOOKING_AWS_KEY not in proc.stderr


def test_real_key_blocks_even_alongside_placeholder(tmp_path: Path) -> None:
    """A file mixing a placeholder AND a real key still blocks on the real one."""
    content = (
        f"# example: {AWS_PLACEHOLDER_PRIMARY}\n"
        f"aws_access_key_id = {REAL_LOOKING_AWS_KEY}\n"
    )
    repo = _make_repo(tmp_path, "mixed.txt", content)
    proc = _run_check(repo)
    assert proc.returncode == 1
    assert REAL_LOOKING_AWS_KEY not in proc.stdout
    assert REAL_LOOKING_AWS_KEY not in proc.stderr


# ---------------------------------------------------------------------------
# Sanity: a clean file passes (no AWS-key content at all).
# ---------------------------------------------------------------------------


def test_clean_file_passes(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, "README.md", "# Hello\n\nNothing secret here.\n")
    proc = _run_check(repo)
    assert proc.returncode == 0, proc.stderr
