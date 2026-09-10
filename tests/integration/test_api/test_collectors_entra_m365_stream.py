"""Run the full ASGI cases in an import-isolated interpreter."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def test_real_api_stream_boundaries_in_isolated_child(tmp_path: Path) -> None:
    environment = dict(os.environ)
    for name in (
        "CUSTOM_TIKTOKEN_CACHE_DIR",
        "TIKTOKEN_CACHE_DIR",
        "DATA_GYM_CACHE_DIR",
        "EVIDENTIA_API_AUTH_TOKEN_FILE",
        "EVIDENTIA_RBAC_POLICY_FILE",
        "ENTRA_M365_ACCESS_TOKEN",
        "ENTRA_M365_RETENTION_ACCESS_TOKEN",
        "ENTRA_M365_AUTH_MODE",
    ):
        environment.pop(name, None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    child = Path(__file__).with_name("_entra_m365_stream_child.py")
    result = subprocess.run(
        [sys.executable, str(child), str(tmp_path / "asgi-cases")],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=environment,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    summary = json.loads(result.stdout.splitlines()[-1])
    assert summary == {
        "exit_code": 0,
        "passed": 21,
        "skipped": 0,
        "llm_calls": 0,
        "litellm_loaded": False,
        "tiktoken_loaded": False,
    }
