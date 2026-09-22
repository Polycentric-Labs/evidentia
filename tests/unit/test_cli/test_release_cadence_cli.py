"""Actual release commands preserve permission, clock, and exact output boundaries."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from evidentia.cli import _rbac_lifecycle, collect
from evidentia_core.rbac import RBACPolicy, Role, TenantRBACPolicy
from typer.testing import CliRunner

RUNNER = CliRunner()
ARGS = ["release-cadence", "--owner", "Example", "--repository", "Synthetic", "--channel", "full_releases"]


@pytest.fixture(autouse=True)
def isolated_authority(monkeypatch):
    import socket

    for name in ("EVIDENTIA_RBAC_POLICY_FILE", "EVIDENTIA_RBAC_IDENTITY", "EVIDENTIA_RBAC_TENANT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("EVIDENTIA_EVIDENCE_AUTO_MIRROR_WORM", raising=False)
    monkeypatch.delenv("EVIDENTIA_EVIDENCE_WORM_BACKEND_FACTORY", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("unexpected DNS"))
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("unexpected socket"))
    _rbac_lifecycle._reset_rbac_cache()
    yield
    _rbac_lifecycle._reset_rbac_cache()


def policy(value):
    _rbac_lifecycle._CACHED_POLICY = value
    _rbac_lifecycle._CACHED_POLICY_LOADED = True


def pages(monkeypatch, rows=None):
    from evidentia_collectors.release_cadence import _traversal

    raw = json.dumps([] if rows is None else rows, separators=(",", ":")).encode()
    calls = []

    def fetch(attempt, owner, repository, number, *, budget, totals):
        calls.append((owner, repository, number, budget.deadline))
        attempt.status_code = 200
        attempt.raw = attempt.decoded = len(raw)
        totals.raw += len(raw)
        totals.decoded += len(raw)
        attempt.raw_body_complete = attempt.body_complete = True
        attempt.raw_body_sha256 = attempt.body_sha256 = hashlib.sha256(raw).hexdigest()
        attempt.links = ()
        attempt.links_available = True
        return raw

    monkeypatch.setattr(_traversal.HttpAttempt, "fetch", fetch)
    return calls


def test_poll_default_exact_wire_and_no_store(monkeypatch):
    from evidentia_core import evidence_store
    from evidentia_core.release_cadence import _store

    calls = pages(monkeypatch)
    monkeypatch.setattr(_store, "lexical_store_root", lambda *a, **k: pytest.fail("observation resolved a store"))
    monkeypatch.setattr(evidence_store, "save_evidence_version_one", lambda *a, **k: pytest.fail("implicit save"))
    result = RUNNER.invoke(collect.app, ARGS)
    assert result.exit_code == 0, result.output
    raw = result.stdout_bytes
    value = json.loads(raw)
    assert value["request"] == {
        "schema_version": "release-poll-request-v1",
        "source_profile": "github-public-releases-2026-03-10",
        "owner": "Example",
        "repository": "Synthetic",
        "channel": "full_releases",
        "persist": False,
    }
    canonical = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    assert raw == canonical
    assert (
        value["request_sha256"]
        == hashlib.sha256(json.dumps(value["request"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    )
    assert value["collection_state"] == "complete"
    assert len(calls) == 1
    assert not result.stderr_bytes


@pytest.mark.parametrize("persist", [False, True])
def test_read_denial_precedes_adapter_import(monkeypatch, persist):
    import builtins

    policy(RBACPolicy(default_role=Role.DENY))
    original = builtins.__import__
    imports = []

    def guarded(name, *args, **kwargs):
        if "_release_cadence_io" in name or name.startswith("evidentia_collectors.release_cadence"):
            imports.append(name)
            raise AssertionError("denied command imported its adapter")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    result = RUNNER.invoke(collect.app, ARGS + (["--persist"] if persist else []))
    assert result.exit_code == 77
    assert not result.stdout_bytes
    assert imports == []


def test_write_denial_before_provider_and_store(monkeypatch):
    from evidentia_core.release_cadence import _store

    policy(RBACPolicy(default_role=Role.READER))
    calls = pages(monkeypatch)
    monkeypatch.setattr(_store, "lexical_store_root", lambda *a, **k: pytest.fail("denied store"))
    result = RUNNER.invoke(collect.app, [*ARGS, "--persist"])
    assert result.exit_code == 77
    assert not result.stdout_bytes
    assert calls == []


@pytest.mark.parametrize("extra", [["--channel", "unknown"], ["--owner", "../bad"], ["--repository", "a/b"]])
def test_usage_refusal_without_provider(monkeypatch, extra):
    calls = pages(monkeypatch)
    result = RUNNER.invoke(collect.app, ARGS + extra)
    assert result.exit_code == 2
    assert not result.stdout_bytes
    assert calls == []


def test_explicit_persistence_reuses_frozen_artifact_facts(monkeypatch, tmp_path):
    fixtures = Path(__file__).parents[2] / "fixtures" / "release_cadence"
    source = json.loads((fixtures / "page-1.json").read_bytes())
    calls = pages(monkeypatch, source[:1])
    result = RUNNER.invoke(collect.app, [*ARGS, "--persist", "--evidence-store", str(tmp_path)])
    assert result.exit_code == 0, result.output
    value = json.loads(result.stdout_bytes)
    assert value["request"]["persist"] is True
    assert len(calls) == 1
    assert value["outcomes"][0]["outcome"] == "created"
    identifier = value["outcomes"][0]["candidate_id"]
    stored = json.loads((tmp_path / identifier / "v1.json").read_bytes())
    assert stored["id"] == identifier
    assert stored["content"]["selected_facts"] == source[0]


@pytest.mark.parametrize("tenants,default", [({"Example": {}, "example": {}}, "Example"), ({"Example": {}}, "example")])
def test_tenant_alias_and_default_refusal_before_store(monkeypatch, tmp_path, tenants, default):
    value = TenantRBACPolicy.model_construct(
        tenants={name: RBACPolicy(default_role=Role.ADMIN) for name in tenants},
        default_tenant=default,
        cross_tenant_admin_role=Role.ADMIN,
    )
    policy(value)
    monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "operator")
    calls = pages(monkeypatch)
    result = RUNNER.invoke(collect.app, [*ARGS, "--persist", "--evidence-store", str(tmp_path)])
    assert result.exit_code in (1, 77)
    assert not result.stdout_bytes
    assert not list(tmp_path.iterdir())
    assert calls == []


def test_complete_partial_response_exits_one_without_losing_result(monkeypatch):
    from evidentia_collectors.release_cadence import _traversal
    from evidentia_core.release_cadence._limits import ReleaseFailure

    def unavailable(*args, **kwargs):
        raise ReleaseFailure("connection_failure")

    monkeypatch.setattr(_traversal.HttpAttempt, "fetch", unavailable)
    result = RUNNER.invoke(collect.app, ARGS)
    assert result.exit_code == 1
    value = json.loads(result.stdout_bytes)
    assert value["collection_state"] == "unavailable"
    assert value["terminal_reason"] == "connection_failure"
    assert value["persistence"]["attempted_calls"] == 0
    assert not result.stderr_bytes


def test_tenant_claim_selects_exact_suffixed_store(monkeypatch, tmp_path):
    fixtures = Path(__file__).parents[2] / "fixtures" / "release_cadence"
    pages(monkeypatch, json.loads((fixtures / "page-1.json").read_bytes())[:1])
    policy(TenantRBACPolicy(tenants={"Acme": RBACPolicy(default_role=Role.ADMIN)}, default_tenant="Acme"))
    monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "operator@@Acme")
    result = RUNNER.invoke(collect.app, [*ARGS, "--persist", "--evidence-store", str(tmp_path)])
    assert result.exit_code == 0, result.output
    value = json.loads(result.stdout_bytes)
    identifier = value["outcomes"][0]["candidate_id"]
    assert (tmp_path / "tenants" / "Acme" / identifier / "v1.json").is_file()
    assert not (tmp_path / identifier).exists()


def test_stdout_failure_preserves_saved_record_without_retry(monkeypatch, tmp_path):
    from evidentia.cli import _release_cadence_io as io

    fixtures = Path(__file__).parents[2] / "fixtures" / "release_cadence"
    calls = pages(monkeypatch, json.loads((fixtures / "page-1.json").read_bytes())[:1])
    accepted = []

    def broken_stdout(wire, clock):
        accepted.append(wire)
        raise OSError("synthetic internal publication detail")

    monkeypatch.setattr(io, "_publish", broken_stdout)
    result = RUNNER.invoke(collect.app, [*ARGS, "--persist", "--evidence-store", str(tmp_path)])
    assert result.exit_code == 1
    assert result.stdout_bytes == b""
    assert result.stderr == "The release operation failed.\n"
    value = json.loads(accepted[0])
    assert value["outcomes"][0]["outcome"] == "created"
    assert (tmp_path / value["outcomes"][0]["candidate_id"] / "v1.json").is_file()
    assert len(calls) == len(accepted) == 1


def test_original_clock_includes_lazy_adapter_import(monkeypatch):
    import builtins

    from evidentia_core.release_cadence import _limits

    now = [100.0]
    monkeypatch.setattr(_limits.time, "monotonic", lambda: now[0])
    original_import = builtins.__import__
    original_start = collect._start_invocation
    clocks = []

    def start():
        clock = original_start()
        clocks.append(clock)
        return clock

    def delayed(name, *args, **kwargs):
        if name == "evidentia.cli._release_cadence_io":
            now[0] = 161.0
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(collect, "_start_invocation", start)
    monkeypatch.setattr(builtins, "__import__", delayed)
    calls = pages(monkeypatch)
    result = RUNNER.invoke(collect.app, ARGS)
    assert result.exit_code == 1
    assert not result.stdout_bytes
    assert result.stderr == "The release operation failed.\n"
    assert len(clocks) == 1 and clocks[0].budget.deadline == 160.0
    assert calls == []


def test_post_save_deadline_reports_owned_uncertainty(monkeypatch, tmp_path):
    from evidentia.cli import _release_cadence_io as io
    from evidentia_core.release_cadence import _limits

    fixtures = Path(__file__).parents[2] / "fixtures" / "release_cadence"
    calls = pages(monkeypatch, json.loads((fixtures / "page-1.json").read_bytes())[:1])
    now = [100.0]
    monkeypatch.setattr(_limits.time, "monotonic", lambda: now[0])
    completed = []

    def delayed_stdout(wire, clock):
        completed.append(wire)
        now[0] = 161.0
        clock.check()

    monkeypatch.setattr(io, "_publish", delayed_stdout)
    result = RUNNER.invoke(collect.app, [*ARGS, "--persist", "--evidence-store", str(tmp_path)])
    assert result.exit_code == 1
    assert not result.stdout_bytes
    assert result.stderr == _limits.ERRORS["persistence_outcome_unavailable"][1] + "\n"
    value = json.loads(completed[0])
    assert (tmp_path / value["outcomes"][0]["candidate_id"] / "v1.json").is_file()
    assert len(calls) == 1


def test_unowned_uncertainty_code_is_not_accepted(monkeypatch):
    from evidentia.cli import _release_cadence_io as io
    from evidentia_core.release_cadence._limits import ReleaseFailure

    def forged():
        raise ReleaseFailure("persistence_outcome_unavailable")

    monkeypatch.setattr(io, "_load_poll", forged)
    result = RUNNER.invoke(collect.app, ARGS)
    assert result.exit_code == 1
    assert result.stdout_bytes == b""
    assert result.stderr == "The release operation failed.\n"


@pytest.mark.parametrize("change", ["request", "suffix", "type"])
def test_output_must_match_exact_captured_request_and_wire(monkeypatch, change):
    from types import SimpleNamespace

    from evidentia.cli import _release_cadence_io as io

    pages(monkeypatch)
    real = io._load_poll()

    def prepared(clock):
        actual = real(clock)

        def begin(value, **kwargs):
            wire = actual.begin(value, **kwargs).output_bytes()
            if change == "suffix":
                wire += b"\n"
            elif change == "type":
                wire = bytearray(wire)
            else:
                decoded = json.loads(wire)
                decoded["request"]["owner"] = "EXAMPLE"
                canonical = json.dumps(decoded["request"], sort_keys=True, separators=(",", ":")).encode()
                decoded["request_sha256"] = hashlib.sha256(canonical).hexdigest()
                wire = json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode()
            return SimpleNamespace(output_bytes=lambda: wire)

        return SimpleNamespace(begin=begin)

    monkeypatch.setattr(io, "_load_poll", lambda: prepared)
    result = RUNNER.invoke(collect.app, ARGS)
    assert result.exit_code == 1
    assert not result.stdout_bytes


def test_primary_cancellation_is_not_converted(monkeypatch):
    from evidentia_collectors.release_cadence import _traversal

    class Cancelled(BaseException):
        pass

    original = Cancelled()

    def cancel(*args, **kwargs):
        raise original

    monkeypatch.setattr(_traversal.HttpAttempt, "fetch", cancel)
    with pytest.raises(Cancelled) as caught:
        RUNNER.invoke(collect.app, ARGS)
    assert caught.value is original


@pytest.mark.parametrize("returned", [None, True, 0, 2])
def test_stdout_refuses_short_or_noninteger_write(monkeypatch, returned):
    from types import SimpleNamespace

    from evidentia.cli import _release_cadence_io as io
    from evidentia_core.release_cadence._limits import ReleaseFailure, _start_invocation

    calls = []

    def write(chunk):
        calls.append(chunk)
        return returned

    with monkeypatch.context() as scoped:
        scoped.setattr(io.sys, "stdout", SimpleNamespace(buffer=SimpleNamespace(write=write, flush=lambda: None)))
        with pytest.raises(ReleaseFailure):
            io._publish(b"{}", _start_invocation()) if returned != 2 else io._publish(b"123", _start_invocation())
    assert len(calls) == 1


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("absent", "Release support is unavailable."),
        ("transitive", "Release support failed."),
        ("export", "Release support failed."),
    ],
)
def test_fresh_process_optional_support_without_editable_collector(tmp_path, mode, expected):
    import subprocess
    import sys
    import sysconfig

    checkout = Path(__file__).parents[3]
    fake = tmp_path / "modules"
    if mode != "absent":
        package = fake / "evidentia_collectors" / "release_cadence"
        package.mkdir(parents=True)
        (package.parent / "__init__.py").write_text("", encoding="utf-8")
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "collector.py").write_text(
            "import absent_synthetic_dependency\n" if mode == "transitive" else "_prepare_poll_from_clock = None\n",
            encoding="utf-8",
        )
    sources = [str(fake), sysconfig.get_path("purelib")]
    sources += [str(checkout / "packages" / name / "src") for name in ("evidentia-core", "evidentia", "evidentia-ai")]
    script = tmp_path / "optional_probe.py"
    script.write_text(
        "import json, os, socket, sys\n"
        f"sys.path[:0] = {sources!r}\n"
        "for name in ('EVIDENTIA_RBAC_POLICY_FILE','EVIDENTIA_RBAC_IDENTITY','EVIDENTIA_RBAC_TENANT'):\n"
        "    os.environ.pop(name, None)\n"
        "def refused(*args, **kwargs):\n    raise AssertionError('unexpected network')\n"
        "socket.getaddrinfo = socket.create_connection = refused\n"
        "from importlib.util import find_spec\n"
        f"assert (find_spec('evidentia_collectors') is None) == {mode == 'absent'!r}\n"
        "from typer.testing import CliRunner\nfrom evidentia.cli.collect import app\n"
        f"result = CliRunner().invoke(app, {ARGS!r})\n"
        "print(json.dumps({'exit': result.exit_code, 'stdout': result.stdout, 'stderr': result.stderr}))\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(script)], capture_output=True, text=True, timeout=30
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result == {"exit": 1, "stdout": "", "stderr": expected + "\n"}
