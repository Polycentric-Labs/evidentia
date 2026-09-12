"""Verify model and session imports without loading optional verifier libraries."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import evidentia_collectors.registries as registries
import pytest


@pytest.mark.parametrize("mode", ["models", "session"])
def test_registry_base_imports_have_no_optional_verifier_or_runtime_io(mode: str) -> None:
    script = r"""
import importlib.abc
import json
import os
import socket
import sys

class ForbiddenOptional(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in ("defusedxml", "signxml", "lxml"):
            raise AssertionError("optional_verifier_imported")
        return None

sys.meta_path.insert(0, ForbiddenOptional())
def forbidden(*args, **kwargs):
    raise AssertionError("unexpected_runtime_operation")
socket.getaddrinfo = forbidden
socket.create_connection = forbidden
original_getenv = os.getenv
original_environ_get = os.environ.get
def checked_getenv(key, default=None):
    if "SAM" in key or key.startswith("EVIDENTIA_REGISTRY"):
        raise AssertionError("configuration_read_at_import")
    return original_getenv(key, default)
os.getenv = checked_getenv
def checked_environ_get(key, default=None):
    if "SAM" in key or key.startswith("EVIDENTIA_REGISTRY"):
        raise AssertionError("configuration_read_at_import")
    return original_environ_get(key, default)
os.environ.get = checked_environ_get
import evidentia_collectors
evidentia_collectors.__path__.insert(0, sys.argv[1])
import evidentia_collectors.registries as package
from evidentia_collectors.registries import _contracts
assert package.RegistryLookupResult is _contracts.RegistryLookupResult
assert "evidentia_collectors.registries._client" not in sys.modules
assert "evidentia_collectors.registries._credentials" not in sys.modules
assert "evidentia_collectors.registries._xml_signature" not in sys.modules
request = package.RegistryLookupRequest.model_validate_json(b'{"registry":"sam-entity","target":{"uei":"ABCDEFGHIJKL"}}')
assert request.root.target.uei == "ABCDEFGHIJKL"
assert package.RegistryLookupResult.model_json_schema()["title"] == "RegistryLookupResult"
if sys.argv[2] == "session":
    from evidentia_collectors.registries._client import RegistryReadSession
    session = RegistryReadSession(request, _sam_resolver=forbidden)
    assert session.request.root.registry == "sam-entity"
assert not any(name.split(".")[0] in ("defusedxml", "signxml", "lxml") for name in sys.modules)
print(json.dumps({"mode": sys.argv[2], "exports": package.__all__}))
"""
    namespace = Path(registries.__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script, str(namespace), mode],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == {"mode": mode, "exports": registries.__all__}
