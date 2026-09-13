"""Exercise optional startup and verifier failures in fresh interpreters."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

CHILD = r"""
import importlib.abc
import importlib.util
import json
import socket
import sys
from types import SimpleNamespace

mode = sys.argv[1]
feature_modes = {"parent", "feature", "internal", "transitive", "symbol", "syntax"}
enterprise = "evidentia_collectors.enterprise_retention"
registries = "evidentia_collectors.registries"
absent_modes = {"parent", "feature", "enterprise"}
probe_modes = {"probe-error", "probe-missing-child", "probe-missing-parent", "probe-unnamed"}
parser_modes = {"enterprise-parser", "storage-parser", "parser-transitive", "parser-symbol", "parser-syntax"}
new_rejected_modes = parser_modes | probe_modes | {"enterprise-missing", "spoof-registry", "spoof-enterprise-loader"}
rejected_modes = new_rejected_modes | {"internal", "transitive", "symbol", "syntax"}
loader_calls = 0

class BrokenLoader(importlib.abc.Loader):
    def create_module(self, spec):
        return None
    def exec_module(self, module):
        global loader_calls
        loader_calls += 1
        if mode == "spoof-enterprise-loader":
            raise ModuleNotFoundError("synthetic-loader-detail", name=enterprise)
        if mode == "parser-symbol":
            return
        raise SyntaxError("synthetic-parser-detail")

class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        blocked = "evidentia_collectors" if mode == "parent" else "evidentia_collectors.registries"
        if mode in feature_modes and fullname == blocked:
            if mode == "symbol":
                raise ImportError("synthetic-internal-symbol")
            if mode == "syntax":
                raise SyntaxError("synthetic-internal-syntax")
            missing = blocked if mode in {"parent", "feature"} else (
                "evidentia_collectors.registries._contracts" if mode == "internal" else "synthetic_dependency"
            )
            raise ModuleNotFoundError("synthetic-import-detail", name=missing)
        if mode == "enterprise-missing" and fullname == enterprise:
            raise ModuleNotFoundError("synthetic-absent-detail", name=fullname)
        if (mode == "spoof-registry" or mode in probe_modes) and fullname == registries:
            raise ModuleNotFoundError("synthetic-spoof-detail", name=enterprise)
        if mode == "spoof-enterprise-loader" and fullname == enterprise:
            return importlib.util.spec_from_loader(fullname, BrokenLoader(), is_package=True)
        if mode == "enterprise-parser" and fullname == enterprise + "._parsing":
            raise ModuleNotFoundError("synthetic-child-detail", name=fullname)
        if mode == "storage-parser" and fullname == "evidentia_collectors.retention._parsing":
            raise ModuleNotFoundError("synthetic-child-detail", name=fullname)
        if mode == "parser-transitive" and fullname == enterprise + "._parsing":
            raise ModuleNotFoundError("synthetic-transitive-detail", name="synthetic_parser_dependency")
        if mode in {"parser-symbol", "parser-syntax"} and fullname == enterprise + "._parsing":
            return importlib.util.spec_from_loader(fullname, BrokenLoader())
        if mode in {"defusedxml", "signxml", "broken-signxml"}:
            selected = "signxml" if mode == "broken-signxml" else mode
            if fullname == selected:
                raise ModuleNotFoundError("synthetic-verifier-detail", name="lxml" if mode == "broken-signxml" else selected)

sys.meta_path.insert(0, Block())
if mode in {"parent", "enterprise"}:
    # Every finder sees genuine namespace absence, including the existence probe.
    absent_namespace = "evidentia_collectors" if mode == "parent" else enterprise
    delegates = tuple(sys.meta_path)
    class NamespaceAbsent(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname == absent_namespace or fullname.startswith(absent_namespace + "."):
                return None
            for finder in delegates:
                spec = finder.find_spec(fullname, path, target)
                if spec is not None:
                    return spec
            return None
        def find_distributions(self, *args, **kwargs):
            for finder in delegates:
                discover = getattr(finder, "find_distributions", None)
                if discover is not None:
                    yield from discover(*args, **kwargs)
    sys.meta_path[:] = [NamespaceAbsent()]
    from importlib.metadata import version
    assert version("email-validator")

real_find_spec = importlib.util.find_spec
probe_calls = 0
def checked_probe(name, package=None):
    global probe_calls
    if name == enterprise:
        probe_calls += 1
        if mode == "probe-error":
            raise RuntimeError("synthetic-probe-detail")
        missing = {
            "probe-missing-child": enterprise + "._parsing",
            "probe-missing-parent": "evidentia_collectors",
            "probe-unnamed": None,
        }
        if mode in missing:
            raise ModuleNotFoundError("synthetic-probe-detail", name=missing[mode])
    return real_find_spec(name, package)
importlib.util.find_spec = checked_probe

dns_calls = 0
def refuse_dns(*args, **kwargs):
    global dns_calls
    dns_calls += 1
    raise AssertionError("unexpected DNS")
socket.getaddrinfo = refuse_dns

try:
    if mode in new_rejected_modes:
        # Isolate the registry refusal before another optional router can fail first.
        from evidentia_api.routers import registry
    if mode == "enterprise":
        from evidentia_api.routers import registry
        assert registry.REGISTRY_AVAILABLE is False
        try:
            from evidentia_api.app import create_app
        except RuntimeError as error:
            assert str(error) == "Incident clock collection could not be loaded."
            assert error.__suppress_context__ and dns_calls == 0
        else:
            raise AssertionError("Installed incident feature accepted a missing transitive dependency")
        from fastapi import FastAPI
        from evidentia_api.auth_middleware import AuthProviderMiddleware
        from evidentia_core.rbac import RBACPolicy, Role
        def create_app(*, auth_provider=None, trust_proxy_headers=False):
            # Preserve the original registry route assertions independently of full-app refusal.
            assert trust_proxy_headers is False
            application = FastAPI()
            application.state.auth_provider = auth_provider
            application.state.rbac_policy = RBACPolicy(default_role=Role.READER)
            application.add_middleware(AuthProviderMiddleware)
            application.include_router(registry.router, prefix="/api")
            return application
    else:
        from evidentia_api.app import create_app
except RuntimeError as error:
    assert mode in rejected_modes
    assert str(error) == "Registry collection could not be loaded."
    assert error.__suppress_context__ and dns_calls == 0
    if mode in probe_modes | {"enterprise-missing", "spoof-registry", "spoof-enterprise-loader"}:
        assert probe_calls == 1
    if mode in {"spoof-enterprise-loader", "parser-symbol", "parser-syntax"}:
        assert loader_calls == 1
    print(json.dumps({"mode": mode, "startup": "rejected", "probe_calls": probe_calls, "loader_calls": loader_calls, "dns_calls": dns_calls}))
    raise SystemExit(0)

assert mode not in rejected_modes
from evidentia_api.routers import registry
from evidentia_core.plugins.auth import AuthProvider, AuthResult
from evidentia_core.rbac import RBACPolicy, Role
from fastapi.testclient import TestClient
from starlette.requests import Request

class Actor(AuthProvider):
    def name(self):
        return "synthetic-reader"
    def authenticate(self, *, authorization_header):
        return AuthResult(authorization_header == "Bearer synthetic-reader", "synthetic-reader")

headers = {"Authorization": "Bearer synthetic-reader", "Content-Type": "application/json"}
if mode in absent_modes:
    body_reads = 0
    config_reads = 0
    worker_calls = 0
    async def forbidden_stream(self):
        global body_reads
        body_reads += 1
        raise AssertionError("unexpected body read")
        yield b""
    Request.stream = forbidden_stream
    class NoEnvironment:
        def __contains__(self, key):
            global config_reads
            config_reads += 1
            raise AssertionError("unexpected credential presence check")
        def __getitem__(self, key):
            global config_reads
            config_reads += 1
            raise AssertionError("unexpected credential lookup")
        def get(self, key, default=None):
            global config_reads
            config_reads += 1
            raise AssertionError("unexpected credential lookup")
    async def forbidden_worker(*args, **kwargs):
        global worker_calls
        worker_calls += 1
        raise AssertionError("unexpected collection worker")
    registry.run_in_threadpool = forbidden_worker
    registry.os = SimpleNamespace(environ=NoEnvironment())
    assert registry.REGISTRY_AVAILABLE is False
    assert registry.configuration_status() == {"installed": False, "selectors": [], "live_validated": False}
    app = create_app(auth_provider=Actor(), trust_proxy_headers=False)
    schema = app.openapi()
    operation = schema["paths"]["/api/collectors/registry"]["post"]
    assert "requestBody" not in operation and "200" not in operation["responses"]
    assert "RegistryLookupResult" not in schema["components"]["schemas"]
    assert operation["responses"]["503"]["content"]["application/json"]["schema"]["$ref"].endswith("/ErrorEnvelope")
    with TestClient(app) as client:
        available = client.post("/api/collectors/registry", content=b"{", headers=headers)
        unauthorized = client.post("/api/collectors/registry", content=b"{")
        app.state.rbac_policy = RBACPolicy(default_role=Role.DENY)
        denied = client.post("/api/collectors/registry", content=b"{", headers=headers)
    with TestClient(create_app(trust_proxy_headers=False)) as client:
        unconfigured = client.post("/api/collectors/registry", content=b"{", headers=headers)
    statuses = [available.status_code, unconfigured.status_code, unauthorized.status_code, denied.status_code]
    assert statuses == [503, 403, 401, 403]
    assert available.json()["detail"]["error"] == "feature_unavailable"
    assert unconfigured.json()["detail"]["error"] == "auth_not_configured"
    assert denied.json()["detail"]["error"] == "rbac_denied"
    assert body_reads == config_reads == worker_calls == 0
    if mode == "enterprise":
        assert probe_calls == 1 and enterprise not in sys.modules
    print(json.dumps({"mode": mode, "statuses": statuses, "body_reads": body_reads, "config_reads": config_reads, "worker_calls": worker_calls, "probe_calls": probe_calls, "dns_calls": dns_calls}))
else:
    with TestClient(create_app(auth_provider=Actor(), trust_proxy_headers=False)) as client:
        schema = client.get("/api/openapi.json", headers=headers).json()
        assert "RegistryLookupResult" in schema["components"]["schemas"]
        assert len(schema["paths"]["/api/collectors/registry"]["post"]["requestBody"]["content"]["application/json"]["schema"]["oneOf"]) == 11
        response = client.post("/api/collectors/registry", json={"registry": "incommon", "target": {"entity_id": "urn:synthetic:optional-test"}}, headers=headers)
        assert response.status_code == 200
        result = response.json()
        expected = "dependency_failure" if mode == "broken-signxml" else "missing_extra"
        assert result["lookup_outcome"] == "unavailable" and result["observations"] == []
        assert [item["code"] for item in result["diagnostics"]] == [expected]
        assert "synthetic-verifier-detail" not in response.text
    print(json.dumps({"mode": mode, "diagnostic": expected, "dns_calls": dns_calls}))
assert dns_calls == 0
"""


@pytest.mark.parametrize(
    "mode",
    [
        "parent",
        "feature",
        "internal",
        "transitive",
        "symbol",
        "syntax",
        "enterprise",
        "enterprise-missing",
        "spoof-registry",
        "spoof-enterprise-loader",
        "enterprise-parser",
        "storage-parser",
        "parser-transitive",
        "parser-symbol",
        "parser-syntax",
        "probe-error",
        "probe-missing-child",
        "probe-missing-parent",
        "probe-unnamed",
        "defusedxml",
        "signxml",
        "broken-signxml",
    ],
)
def test_exact_optional_import_boundary(mode: str, tmp_path: Path) -> None:
    environment = dict(os.environ)
    for key in (
        "EVIDENTIA_API_AUTH_TOKEN_FILE",
        "EVIDENTIA_RBAC_POLICY_FILE",
        "EVIDENTIA_ENTERPRISE_RETENTION_PROFILES_FILE",
        "EVIDENTIA_REGISTRY_SAM_API_KEY",
    ):
        environment.pop(key, None)
    environment.update(
        PYTHONDONTWRITEBYTECODE="1",
        LITELLM_LOCAL_MODEL_COST_MAP="true",
        EVIDENTIA_GAP_STORE_DIR=str(tmp_path / "gaps"),
        EVIDENTIA_EVIDENCE_STORE_DIR=str(tmp_path / "evidence"),
    )
    child = subprocess.run(
        [sys.executable, "-c", CHILD, mode],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=40,
        check=False,
    )
    assert child.returncode == 0, child.stdout + child.stderr
    result = json.loads(child.stdout.strip().splitlines()[-1])
    assert result["mode"] == mode and result["dns_calls"] == 0
