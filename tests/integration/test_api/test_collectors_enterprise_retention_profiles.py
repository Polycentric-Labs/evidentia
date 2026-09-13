"""Exercise real app startup branches in isolated, network-free children."""

from __future__ import annotations

import json
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
import os
from pathlib import Path
import sys

sys.path.insert(0, sys.argv[3])
from _entra_m365_llm_isolation import isolate_unused_llm
llm = isolate_unused_llm()
from _entra_m365_asgi import AUTH, Provider, isolate
import pytest

mode = sys.argv[1]
directory = Path(sys.argv[2]).resolve()
directory.mkdir(parents=True, exist_ok=False)
absent = mode in ('parent', 'feature')
broken = mode in ('internal', 'transitive', 'symbol', 'syntax')

class BrokenLoader(importlib.abc.Loader):
    def create_module(self, spec):
        return None
    def exec_module(self, module):
        if mode == 'transitive':
            raise ModuleNotFoundError('synthetic-private-import', name='synthetic_transitive_dependency')
        if mode == 'symbol':
            return
        raise SyntaxError('synthetic-private-import')

class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        wanted = {'parent': 'evidentia_collectors', 'internal': 'evidentia_collectors.enterprise_retention._profiles'}.get(mode)
        if fullname == wanted:
            raise ModuleNotFoundError('synthetic-private-import', name=fullname)
        if mode in ('transitive', 'symbol', 'syntax') and fullname == 'evidentia_collectors.enterprise_retention':
            return importlib.util.spec_from_loader(fullname, BrokenLoader(), is_package=True)
        return None

class Unconsumed:
    def __getattribute__(self, name):
        raise AssertionError('Absent feature consumed injected configuration')

async def deliver(app, path, *, method='POST', authorized=True, body=b'UNREAD_BODY'):
    sent = []
    consumed = 0
    done = asyncio.Event()
    headers = [(b'content-type', b'application/json')]
    if authorized:
        headers.append((b'authorization', AUTH))
    scope = {'type': 'http', 'asgi': {'version': '3.0', 'spec_version': '2.4'}, 'http_version': '1.1', 'method': method, 'scheme': 'http', 'path': path, 'raw_path': path.encode(), 'root_path': '', 'query_string': b'', 'headers': headers, 'client': ('127.0.0.1', 42221), 'server': ('review.invalid', 80), 'state': {}}
    async def receive():
        nonlocal consumed
        if consumed == 0:
            consumed += 1
            return {'type': 'http.request', 'body': body, 'more_body': False}
        await done.wait()
        return {'type': 'http.disconnect'}
    async def send(message):
        sent.append(message)
        if message['type'] == 'http.response.body' and not message.get('more_body', False):
            done.set()
    await asyncio.wait_for(app(scope, receive, send), 20)
    status = next(value['status'] for value in sent if value['type'] == 'http.response.start')
    data = b''.join(value.get('body', b'') for value in sent if value['type'] == 'http.response.body')
    return status, json.loads(data), consumed

async def run(patch):
    patch.delenv('EVIDENTIA_ENTERPRISE_RETENTION_PROFILES_FILE', raising=False)
    configured = directory / 'synthetic-profiles.json'
    input_value = None
    env_get = os.environ.get
    phase = {'startup': False, 'profile_reads': 0}
    def guarded_get(key, default=None):
        if key == 'EVIDENTIA_ENTERPRISE_RETENTION_PROFILES_FILE':
            phase['profile_reads'] += 1
            if absent or not phase['startup']:
                raise AssertionError('Profile path read outside installed startup')
        if key.startswith('ENTERPRISE_RETENTION_'):
            raise AssertionError('Credential resolved during startup or denial')
        return env_get(key, default)
    if absent:
        input_value = Unconsumed()
        patch.setenv('EVIDENTIA_ENTERPRISE_RETENTION_PROFILES_FILE', str(directory / 'must-not-open.json'))
    elif not broken:
        from evidentia_collectors.enterprise_retention import _profiles as profiles
        class Resolver:
            def resolve(self, profile):
                raise AssertionError('Credential resolution forbidden')
        profile = profiles.FrozenProfile(alias='synthetic-profile', provider='splunk-enterprise', origin='https://splunk.example.invalid:8089', credential_ref='ENTERPRISE_RETENTION_SYNTHETIC_TOKEN', address_policy=profiles.AddressPolicy('public'), api_principals=frozenset({'reviewer'}))
        if mode in ('injected', 'precedence'):
            input_value = profiles.ProfileRegistry((profile,), Resolver())
        elif mode == 'invalid-injected':
            input_value = object()
        if mode in ('file', 'malformed-file'):
            payload = {'schema_version': profiles.PROFILE_SCHEMA, 'profiles': [{'alias': 'synthetic-profile', 'provider': 'splunk-enterprise', 'origin': 'https://splunk.example.invalid:8089', 'credential_ref': 'ENTERPRISE_RETENTION_SYNTHETIC_TOKEN', 'address_policy': {'mode': 'public', 'cidrs': []}, 'api_principals': ['reviewer'], 'allow_local_cli': False}]}
            configured.write_text(json.dumps(payload) if mode == 'file' else '{"synthetic-private":', encoding='utf-8', newline='\n')
            patch.setenv('EVIDENTIA_ENTERPRISE_RETENTION_PROFILES_FILE', str(configured))
        elif mode in ('missing-file', 'precedence'):
            patch.setenv('EVIDENTIA_ENTERPRISE_RETENTION_PROFILES_FILE', str(configured))
    patch.setattr(os.environ, 'get', guarded_get)
    try:
        from evidentia_api.app import create_app
        app = create_app(auth_provider=Provider(), enterprise_retention_profiles=input_value, trust_proxy_headers=False)
    except RuntimeError as error:
        assert broken
        assert str(error) == 'Enterprise retention collection could not be loaded.'
        assert error.__suppress_context__
        return {'startup': 'rejected-import', 'profile_reads': phase['profile_reads']}
    assert not broken
    schema = app.openapi()
    assert phase['profile_reads'] == 0
    operation = schema['paths']['/api/collectors/enterprise-retention/collect']['post']
    if absent:
        assert 'requestBody' not in operation and '200' not in operation['responses']
        assert operation['responses']['503']['content']['application/json']['schema']['$ref'].endswith('/ErrorEnvelope')
    else:
        assert 'requestBody' in operation and '200' in operation['responses']
        assert 'EnterpriseRetentionCollectResult' in schema['components']['schemas']
    phase['startup'] = True
    try:
        async with app.router.lifespan_context(app):
            assert mode not in ('invalid-injected', 'malformed-file', 'missing-file')
            if absent:
                assert app.state.enterprise_retention_profiles is None
            else:
                actual = app.state.enterprise_retention_profiles
                assert type(actual) is profiles.ProfileRegistry
                assert len(actual.profiles) == (0 if mode == 'empty' else 1)
                if input_value is not None:
                    assert actual is not input_value
                    object.__setattr__(input_value, 'profiles', ())
                    assert len(actual.profiles) == 1
            before = phase['profile_reads']
            status, health, reads = await deliver(app, '/api/health', method='GET', authorized=False, body=b'')
            assert status == 200 and reads == 0
            assert 'synthetic-profile' not in json.dumps(health) and 'splunk.example.invalid' not in json.dumps(health)
            status, body, reads = await deliver(app, '/api/collectors/enterprise-retention/collect', authorized=False)
            assert status == 401 and reads == 0
            raw = json.dumps({'provider': 'splunk-enterprise', 'profile_alias': 'unknown', 'scope_label': 'synthetic', 'targets': [{'index': 'events'}]}).encode()
            status, body, reads = await deliver(app, '/api/collectors/enterprise-retention/collect', body=raw)
            assert status == (503 if absent else 403) and reads == (0 if absent else 1)
            assert body['detail']['error'] == ('feature_unavailable' if absent else 'profile_unavailable')
            from evidentia_core.rbac import RBACPolicy, Role
            app.state.rbac_policy = RBACPolicy(default_role=Role.DENY)
            status, body, reads = await deliver(app, '/api/collectors/enterprise-retention/collect')
            assert status == 403 and body['detail']['error'] == 'rbac_denied' and reads == 0
            assert phase['profile_reads'] == before
    except RuntimeError as error:
        assert mode in ('invalid-injected', 'malformed-file', 'missing-file')
        assert str(error) == 'Enterprise retention profile configuration could not be loaded.'
        assert error.__suppress_context__
        return {'startup': 'rejected-config', 'profile_reads': phase['profile_reads']}
    assert phase['profile_reads'] == (0 if absent or mode in ('injected', 'precedence') else 1)
    return {'startup': 'accepted', 'profile_reads': phase['profile_reads'], 'absence': absent, 'denial_body_reads': 0}

sys.meta_path.insert(0, Block())
if absent:
    # Parent absence is genuine. An absent enterprise feature also excludes its dependent incident feature.
    delegates = tuple(sys.meta_path)
    class EnterpriseAbsent(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            namespaces = ('evidentia_collectors',) if mode == 'parent' else (
                'evidentia_collectors.enterprise_retention', 'evidentia_collectors.incident_clock',
            )
            if any(fullname == namespace or fullname.startswith(namespace + '.') for namespace in namespaces):
                return None
            for finder in delegates:
                spec = finder.find_spec(fullname, path, target)
                if spec is not None:
                    return spec
            return None
        def find_distributions(self, *args, **kwargs):
            for finder in delegates:
                discover = getattr(finder, 'find_distributions', None)
                if discover is not None:
                    yield from discover(*args, **kwargs)
    sys.meta_path[:] = [EnterpriseAbsent()]
    namespace = 'evidentia_collectors' if mode == 'parent' else 'evidentia_collectors.enterprise_retention'
    assert importlib.util.find_spec(namespace) is None
    if mode == 'feature':
        assert importlib.util.find_spec('evidentia_collectors.incident_clock') is None
    from importlib.metadata import version
    assert version('email-validator')
with asyncio.Runner() as runner:
    runner.get_loop()
    with pytest.MonkeyPatch.context() as patch:
        isolate(patch, directory)
        report = runner.run(run(patch))
llm.assert_unused()
print(json.dumps({'mode': mode, 'llm_calls': llm.calls, **report}))
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
        "empty",
        "injected",
        "precedence",
        "file",
        "malformed-file",
        "missing-file",
        "invalid-injected",
    ],
)
def test_real_startup_and_protected_profile_branches(mode: str, tmp_path: Path) -> None:
    environment = dict(os.environ)
    for key in (
        "CUSTOM_TIKTOKEN_CACHE_DIR",
        "TIKTOKEN_CACHE_DIR",
        "DATA_GYM_CACHE_DIR",
        "EVIDENTIA_API_AUTH_TOKEN_FILE",
        "EVIDENTIA_RBAC_POLICY_FILE",
        "EVIDENTIA_ENTERPRISE_RETENTION_PROFILES_FILE",
        "ENTERPRISE_RETENTION_SYNTHETIC_TOKEN",
    ):
        environment.pop(key, None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    helper_directory = Path(__file__).resolve().parent
    result = subprocess.run(
        [sys.executable, "-B", "-c", CHILD, mode, str(tmp_path / mode), str(helper_directory)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=environment,
        timeout=45,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["mode"] == mode and report["llm_calls"] == 0
    if mode in {"internal", "transitive", "symbol", "syntax"}:
        assert report["startup"] == "rejected-import" and report["profile_reads"] == 0
    elif mode in {"invalid-injected", "malformed-file", "missing-file"}:
        assert report["startup"] == "rejected-config"
    else:
        assert report["startup"] == "accepted" and report["denial_body_reads"] == 0
