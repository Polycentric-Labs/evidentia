"""Verify optional absence and broken installed providers in fresh interpreters."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

CHILD = r"""
import importlib.abc
import importlib.util
import asyncio
import json
import os
import socket
import sys
from pathlib import Path
from types import SimpleNamespace

mode, surface = sys.argv[1:]
feature = "evidentia_collectors.incident_clock"
blocked = "evidentia_collectors" if mode == "root-absent" else feature
absent = mode in {"root-absent", "feature-absent"}
delegates = tuple(sys.meta_path)

class BrokenLoader(importlib.abc.Loader):
    def create_module(self, spec):
        return None
    def exec_module(self, module):
        if mode.endswith("-missing-export"):
            return
        if mode.endswith("-noncallable-export"):
            module.collect = 42
            return
        if mode == "syntax":
            raise SyntaxError("synthetic-internal-detail")
        if mode == "symbol":
            raise ImportError("synthetic-internal-detail")
        missing = "synthetic_dependency" if mode == "transitive" else "evidentia_collectors" if mode == "spoof-root" else feature if mode == "spoof-feature" else feature + "." + mode
        raise ModuleNotFoundError("synthetic-internal-detail", name=missing)

class Finder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if absent and (fullname == blocked or fullname.startswith(blocked + ".")):
            return None
        provider = mode.split("-")[0] if mode.split("-")[0] in {"jira", "servicenow", "pagerduty"} else "jira"
        if not absent and fullname == feature + "." + provider:
            return importlib.util.spec_from_loader(fullname, BrokenLoader())
        for finder in delegates:
            found = finder.find_spec(fullname, path, target)
            if found is not None:
                return found
        return None
    def find_distributions(self, *args, **kwargs):
        for finder in delegates:
            discover = getattr(finder, "find_distributions", None)
            if discover is not None:
                yield from discover(*args, **kwargs)

sys.meta_path[:] = [Finder()]
reads = []
def forbidden(*args, **kwargs):
    reads.append("forbidden")
    raise AssertionError("unexpected work")
socket.getaddrinfo = forbidden

if surface == "api":
    try:
        from evidentia_api.routers import incident_clock
    except RuntimeError as error:
        assert not absent and str(error) == "Incident clock collection could not be loaded."
        assert error.__suppress_context__ and reads == []
        print(json.dumps({"mode": mode, "surface": surface, "startup": "refused"}))
        raise SystemExit(0)
    assert absent and not incident_clock.INCIDENT_CLOCK_AVAILABLE
    from evidentia_core.plugins.auth import AuthProvider, AuthResult
    from evidentia_core.rbac import RBACPolicy, Role
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from evidentia_api.auth_middleware import AuthProviderMiddleware
    from starlette.requests import Request
    class Actor(AuthProvider):
        def name(self):
            return "synthetic-incident-provider"
        def authenticate(self, *, authorization_header):
            return AuthResult(authorization_header == "Bearer synthetic-reader", "synthetic-reader")
    async def forbidden_stream(self):
        forbidden()
        yield b""
    Request.stream = forbidden_stream
    application = FastAPI()
    application.state.auth_provider = Actor()
    application.state.rbac_policy = RBACPolicy(default_role=Role.READER)
    application.add_middleware(AuthProviderMiddleware)
    application.include_router(incident_clock.router, prefix="/api")
    operation = application.openapi()["paths"]["/api/collectors/incident-clock"]["post"]
    assert "requestBody" not in operation and "200" not in operation["responses"]
    assert incident_clock.configuration_status() == {"installed": False, "live_validated": False, "credential_identity_verified": False}
    with TestClient(application) as client:
        response = client.post("/api/collectors/incident-clock", content=b"{", headers={"Authorization": "Bearer synthetic-reader"})
        assert response.status_code == 503
else:
    from evidentia.cli import _rbac, _incident_clock_io
    from evidentia.cli.main import app
    from evidentia_core.rbac import RBACPolicy, Role
    from typer.testing import CliRunner
    _rbac.get_rbac_policy = lambda: RBACPolicy(default_role=Role.READER)
    _rbac.get_rbac_identity = lambda: "synthetic-reader"
    _incident_clock_io.read_request_file = forbidden
    config = Path("settings.yaml")
    config.write_text("{}\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["--config", str(config), "collect", "incident-clock", "--provider", "jira", "--request-file", "not-read.json"])
    assert result.exit_code == 1 and result.stdout == ""
    expected = "Incident clock collection is not installed." if absent else "Incident clock collection could not be loaded."
    assert result.stderr.strip() == expected, result.stderr
assert reads == []
print(json.dumps({"mode": mode, "surface": surface, "unavailable": absent, "reads": len(reads)}))
"""


@pytest.mark.parametrize(
    "mode",
    [
        "root-absent",
        "feature-absent",
        "jira",
        "servicenow",
        "pagerduty",
        "transitive",
        "syntax",
        "symbol",
        "spoof-root",
        "spoof-feature",
        "jira-missing-export",
        "jira-noncallable-export",
        "servicenow-missing-export",
        "servicenow-noncallable-export",
        "pagerduty-missing-export",
        "pagerduty-noncallable-export",
    ],
)
@pytest.mark.parametrize("surface", ["api", "cli"])
def test_optional_boundaries_in_fresh_interpreter(tmp_path: Path, mode: str, surface: str) -> None:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key
        not in {
            "EVIDENTIA_RBAC_POLICY_FILE",
            "EVIDENTIA_API_AUTH_TOKEN_FILE",
            "EVIDENTIA_ENTERPRISE_RETENTION_PROFILES_FILE",
            "EVIDENTIA_INCIDENT_CLOCK_PROFILES_FILE",
        }
    }
    process = subprocess.run(
        [sys.executable, "-c", CHILD, mode, surface],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert process.returncode == 0, process.stdout + process.stderr
