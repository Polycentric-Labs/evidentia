"""Import and constructor boundaries in fresh isolated interpreter processes."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import evidentia_collectors.enterprise_retention as enterprise
import pytest


@pytest.mark.parametrize("mode", ["models", "session", "collector"])
def test_enterprise_base_import_needs_no_s3_sdk_or_runtime_configuration(mode: str) -> None:
    script = r"""
import importlib.abc
import json
import os
import socket
import sys

class ForbiddenOptional(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in ("botocore", "boto3", "defusedxml"):
            raise AssertionError("optional_dependency_imported")
        return None

sys.meta_path.insert(0, ForbiddenOptional())
def forbidden(*args, **kwargs):
    raise AssertionError("unexpected_runtime_operation")
socket.getaddrinfo = forbidden
socket.create_connection = forbidden
original_getenv = os.getenv
original_environ_get = os.environ.get
def checked_getenv(key, default=None):
    if key.startswith("ENTERPRISE_RETENTION_") or key == "EVIDENTIA_ENTERPRISE_RETENTION_PROFILES_FILE":
        raise AssertionError("configuration_read_at_import")
    return original_getenv(key, default)
os.getenv = checked_getenv
def checked_environ_get(key, default=None):
    if key.startswith("ENTERPRISE_RETENTION_") or key == "EVIDENTIA_ENTERPRISE_RETENTION_PROFILES_FILE":
        raise AssertionError("configuration_read_at_import")
    return original_environ_get(key, default)
os.environ.get = checked_environ_get
import evidentia_collectors
evidentia_collectors.__path__.insert(0, sys.argv[1])
import evidentia_collectors.enterprise_retention as package
from evidentia_collectors.enterprise_retention import _contracts
assert "EnterpriseRetentionCollector" in package.__all__
assert "evidentia_collectors.enterprise_retention._client" not in sys.modules
assert "evidentia_collectors.enterprise_retention._credentials" not in sys.modules
assert "evidentia_collectors.enterprise_retention._profiles" not in sys.modules
request = package.EnterpriseRetentionCollectRequest.model_validate_json(
    b'{"provider":"splunk-enterprise","profile_alias":"selected","scope_label":"synthetic","targets":[{"index":"events"}]}'
)
assert request.root.targets[0].index == "events"
assert package.EnterpriseRetentionReadResult is _contracts.EnterpriseRetentionReadResult
if sys.argv[2] in ("session", "collector"):
    from evidentia_collectors.enterprise_retention import _client, _profiles
    class Resolver:
        resolve = forbidden
    profile = _profiles.FrozenProfile(alias="selected", provider="splunk-enterprise",
        origin="https://splunk.example.invalid:8089", credential_ref="ENTERPRISE_RETENTION_SYNTHETIC_TOKEN",
        address_policy=_profiles.AddressPolicy("public"))
    capability = _profiles.AuthorizedProfile(profile, Resolver())
    if sys.argv[2] == "session":
        session = _client.EnterpriseReadSession(request, profile=capability)
        assert session.context.request.root.targets[0].index == "events"
    else:
        collector_type = package.EnterpriseRetentionCollector
        assert collector_type is package.EnterpriseRetentionCollector
        with collector_type(profile=capability) as collector:
            assert collector.COLLECTOR_ID == "enterprise-retention"
assert not any(name.split(".")[0] in ("botocore", "boto3", "defusedxml") for name in sys.modules)
print(json.dumps({"mode":sys.argv[2], "exports":package.__all__}))
"""
    namespace = Path(enterprise.__file__).resolve().parents[1]
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
    assert json.loads(result.stdout) == {"mode": mode, "exports": enterprise.__all__}
