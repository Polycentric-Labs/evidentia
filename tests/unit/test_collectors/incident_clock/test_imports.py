"""Check cold feature imports without credentials or provider I/O."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest


@pytest.mark.parametrize(
    "missing", [None, "evidentia_collectors", "certifi", "evidentia_collectors.incident_clock._http"]
)
def test_cold_import_distinguishes_absence_from_broken_dependency(missing: str | None) -> None:
    script = r"""
import importlib.abc
import os
import socket
import subprocess
import sys

missing = sys.argv[1]
class Missing(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == missing:
            raise ModuleNotFoundError("synthetic missing module", name=missing)
        return None
sys.meta_path.insert(0, Missing())

def forbidden(*args, **kwargs):
    raise AssertionError("import performed external work")
socket.create_connection = forbidden
socket.getaddrinfo = forbidden
class GuardProcess(subprocess.Popen):
    def __init__(self, *args, **kwargs):
        forbidden()
subprocess.Popen = GuardProcess
try:
    from evidentia_collectors.incident_clock.collector import IncidentClockCollector
except ModuleNotFoundError as error:
    assert missing and error.name == missing
else:
    assert not missing
    assert IncidentClockCollector.COLLECTOR_ID == "incident-clock"
print("PASS")
"""
    environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP") if key in os.environ}
    completed = subprocess.run(
        [sys.executable, "-I", "-c", script, missing or ""],
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "PASS" and completed.stderr == ""
