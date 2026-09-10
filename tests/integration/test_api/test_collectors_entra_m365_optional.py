"""Run startup branches in fresh interpreters without unloading product modules."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

CHILD = Path(__file__).with_name("_entra_m365_import_child.py").resolve()


@pytest.mark.parametrize("mode", ["parent", "feature", "internal", "transitive", "symbol", "syntax"])
def test_optional_import_boundary(mode: str, tmp_path: Path) -> None:
    environment = dict(os.environ)
    for key in (
        "CUSTOM_TIKTOKEN_CACHE_DIR",
        "TIKTOKEN_CACHE_DIR",
        "DATA_GYM_CACHE_DIR",
        "EVIDENTIA_API_AUTH_TOKEN_FILE",
        "EVIDENTIA_RBAC_POLICY_FILE",
        "ENTRA_M365_ACCESS_TOKEN",
        "ENTRA_M365_RETENTION_ACCESS_TOKEN",
        "ENTRA_M365_AUTH_MODE",
    ):
        environment.pop(key, None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, str(CHILD), mode, str(tmp_path / mode)],
        text=True,
        encoding="utf-8",
        capture_output=True,
        env=environment,
        timeout=40,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["mode"] == mode
    assert report["llm_calls"] == 0
    if mode in ("parent", "feature"):
        assert report["statuses"] == [503, 403, 401] and report["body_reads"] == 0
    else:
        assert report["startup"] == "rejected"
