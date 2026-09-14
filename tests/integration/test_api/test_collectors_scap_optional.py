"""Separate genuine optional absence from broken imports in fresh processes."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

CHILD = r"""
import asyncio
import importlib.abc
import importlib.util
import json
import socket
import sys
from pathlib import Path

mode, surface, source_name = sys.argv[1:]
source = Path(source_name)
raw = source.read_bytes().replace(b"\r\n", b"\n")
loop = asyncio.new_event_loop()
feature = "evidentia_collectors.scap"
delegates = tuple(sys.meta_path)
absent = mode in {"root-absent", "feature-absent", "scan-absent"}
blocked = "evidentia_collectors" if mode == "root-absent" else "defusedxml" if mode == "scan-absent" else feature

class Broken(importlib.abc.Loader):
    def create_module(self, spec):
        return None
    def exec_module(self, module):
        if mode == "missing-export":
            return
        if mode in {"syntax", "scan-broken"}:
            raise SyntaxError("Synthetic detail must remain private")
        if mode == "symbol":
            raise ImportError("Synthetic detail must remain private")
        missing = "synthetic_transitive_dependency" if mode == "transitive" else "evidentia_collectors" if mode == "spoof-root" else feature if mode == "spoof-feature" else feature + "._contracts"
        raise ModuleNotFoundError("Synthetic detail must remain private", name=missing)

class Finder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if absent and (fullname == blocked or fullname.startswith(blocked + ".")):
            return None
        if mode == "probe-error" and fullname == feature:
            raise ModuleNotFoundError("Synthetic failed probe", name=feature)
        if mode == "scan-probe-error" and fullname == "defusedxml":
            raise RuntimeError("Synthetic failed probe")
        broken_name = feature + ".collector" if mode == "missing-export" else "defusedxml.ElementTree" if mode == "scan-broken" else feature + "._contracts"
        if not absent and mode not in {"probe-error", "scan-probe-error"} and fullname == broken_name:
            return importlib.util.spec_from_loader(fullname, Broken())
        for delegate in delegates:
            found = delegate.find_spec(fullname, path, target)
            if found is not None:
                return found
        return None
    def find_distributions(self, *args, **kwargs):
        for delegate in delegates:
            discover = getattr(delegate, "find_distributions", None)
            if discover is not None:
                yield from discover(*args, **kwargs)

sys.meta_path[:] = [Finder()]
reads = []
def audit(event, args):
    if event == "open" and args and isinstance(args[0], str) and args[0] == str(source):
        reads.append("source-file")
        raise AssertionError("An optional failure attempted to read source bytes")
sys.addaudithook(audit)
def forbidden(*args, **kwargs):
    raise AssertionError("An optional failure attempted external I/O")
socket.getaddrinfo = forbidden
socket.socket.connect = forbidden
expected_code = "collector_unavailable" if mode in {"root-absent", "feature-absent"} else "scan_extra_unavailable" if mode == "scan-absent" else "internal_dependency_failure"
expected_message = {"collector_unavailable": "The SCAP collector is unavailable.", "scan_extra_unavailable": "The optional SCAP XML support is unavailable.", "internal_dependency_failure": "SCAP import support failed."}[expected_code]

if surface == "api":
    import httpx
    from fastapi import FastAPI
    from evidentia_api.auth_middleware import AuthProviderMiddleware
    from evidentia_api.routers import scap
    from evidentia_core.plugins.auth import AuthProvider, AuthResult
    from evidentia_core.rbac import RBACPolicy, Role
    class Actor(AuthProvider):
        def name(self):
            return "synthetic-optional-auth"
        def authenticate(self, *, authorization_header):
            return AuthResult(authorization_header == "Bearer synthetic-reader", "Synthetic reader")
    application = FastAPI()
    application.state.auth_provider = Actor()
    application.state.rbac_policy = RBACPolicy(default_role=Role.READER)
    application.add_middleware(AuthProviderMiddleware)
    application.include_router(scap.router, prefix="/api")
    async def exercise():
        async def body():
            reads.append("body")
            yield raw
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://scap.test") as client:
            url = "/api/collectors/scap/collect?source_profile=xccdf-1.2-results&assessment_index=0"
            refused = await client.post(url, content=body(), headers={"Content-Type": "application/xml"})
            assert refused.status_code == 401 and reads == []
            response = await client.post(url, content=body(), headers={"Content-Type": "application/xml", "Authorization": "Bearer synthetic-reader"})
            assert response.status_code == (503 if absent else 500), response.text
            assert response.json() == {"schema_version": "scap-error-v1", "code": expected_code, "message": expected_message}
    loop.run_until_complete(exercise())
else:
    from evidentia.cli import _rbac
    from evidentia.cli.main import app
    from evidentia_core.rbac import RBACPolicy, Role
    from typer.testing import CliRunner
    _rbac.get_rbac_policy = lambda: RBACPolicy(default_role=Role.READER)
    _rbac.get_rbac_identity = lambda: "Synthetic reader"
    config = Path("settings.yaml")
    config.write_bytes(b"{}\n")
    result = CliRunner().invoke(app, ["--config", str(config), "collect", "scap", "--file", str(source), "--source-profile", "xccdf-1.2-results", "--assessment-index", "0"])
    assert result.exit_code == 1 and result.stdout == "", result.output
    assert result.stderr.strip() == expected_message, result.stderr
assert reads == []
loop.run_until_complete(loop.shutdown_default_executor())
loop.close()
print(json.dumps({"mode": mode, "surface": surface, "code": expected_code, "source_body_reads": len(reads)}))
"""


@pytest.mark.parametrize(
    "mode",
    [
        "root-absent",
        "feature-absent",
        "child",
        "transitive",
        "symbol",
        "syntax",
        "spoof-root",
        "spoof-feature",
        "probe-error",
        "scan-absent",
        "scan-probe-error",
        "scan-broken",
        "missing-export",
    ],
)
@pytest.mark.parametrize("surface", ["api", "cli"])
def test_fresh_optional_dependency_boundary(tmp_path: Path, mode: str, surface: str) -> None:
    source = Path(__file__).resolve().parents[2] / "fixtures" / "scap" / "xccdf-1.2-native.xml"
    environment = {key: value for key, value in os.environ.items() if not key.startswith("EVIDENTIA_")}
    environment.update(PYTHONDONTWRITEBYTECODE="1", LITELLM_LOCAL_MODEL_COST_MAP="true")
    result = subprocess.run(
        [sys.executable, "-B", "-c", CHILD, mode, surface, str(source)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
