"""Prove bounded owned DNS cleanup without making a resolver or provider call."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from evidentia_collectors.incident_clock import _dns as dns
from evidentia_core import network_guard


def owned_processes(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[subprocess.Popen[bytes]], list[threading.Thread], list[dict[str, Any]]]:
    processes: list[subprocess.Popen[bytes]] = []
    readers: list[threading.Thread] = []
    launches: list[dict[str, Any]] = []
    real_process = subprocess.Popen
    real_thread = threading.Thread

    def spawn(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        child = real_process(*args, **kwargs)
        processes.append(child)
        launches.append({"args": args, "kwargs": kwargs})
        return child

    def thread(*args: Any, **kwargs: Any) -> threading.Thread:
        reader = real_thread(*args, **kwargs)
        readers.append(reader)
        return reader

    monkeypatch.setattr(dns.subprocess, "Popen", spawn)
    monkeypatch.setattr(dns.threading, "Thread", thread)
    return processes, readers, launches


def assert_reaped(processes: list[subprocess.Popen[bytes]], readers: list[threading.Thread]) -> None:
    assert all(child.returncode is not None and child.stdout is not None and child.stdout.closed for child in processes)
    assert all(not reader.is_alive() for reader in readers)
    if os.name == "nt":
        assert all(child._handle.closed for child in processes)


def test_native_direct_worker_and_launch_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    processes, readers, launches = owned_processes(monkeypatch)
    monkeypatch.setattr(dns, "_WORKER_PROGRAM", "import json,os; print(json.dumps(sorted(os.environ)))")
    monkeypatch.setenv("INCIDENT_CLOCK_SYNTHETIC_TEST_TOKEN", "synthetic-not-an-authentication-value")
    monkeypatch.setenv("PYTHONPATH", "unused-synthetic-path")
    result = dns._run_worker("fixture.example.org", time.monotonic() + 3)
    allowed = {"SYSTEMROOT", "WINDIR"} if os.name == "nt" else {"LC_CTYPE"}
    assert {key.upper() for key in json.loads(result)} <= allowed
    options = launches[0]["kwargs"]
    arguments = launches[0]["args"][0]
    assert Path(arguments[0]).samefile(Path(sys._base_executable))
    assert arguments[1:4] == ["-I", "-S", "-c"] and arguments[-1] == "fixture.example.org"
    assert (
        options["close_fds"] is True
        and options["stdin"] == subprocess.DEVNULL
        and options["stderr"] == subprocess.DEVNULL
    )
    assert "INCIDENT_CLOCK_SYNTHETIC_TEST_TOKEN" not in options["env"] and "PYTHONPATH" not in options["env"]
    if os.name == "nt":
        assert options["creationflags"] == subprocess.CREATE_NO_WINDOW
    assert_reaped(processes, readers)


@pytest.mark.parametrize(
    "case", ["blocked", "oversized", "worker-error", "reader-constructor", "reader-start", "cancelled", "cleanup-error"]
)
def test_native_worker_failures_reap_every_created_resource(case: str, monkeypatch: pytest.MonkeyPatch) -> None:
    processes, readers, _ = owned_processes(monkeypatch)
    monkeypatch.setattr(dns, "_WORKER_PROGRAM", "import time; time.sleep(60)")
    deadline = time.monotonic() + (0.2 if case in ("blocked", "cleanup-error") else 3)
    if case == "oversized":
        monkeypatch.setattr(dns, "_WORKER_PROGRAM", "import sys; sys.stdout.write('x'*1048576); sys.stdout.flush()")
    elif case == "worker-error":
        monkeypatch.setattr(dns, "_WORKER_PROGRAM", "raise RuntimeError('synthetic worker failure')")
    elif case == "reader-constructor":

        def fail_constructor(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("synthetic reader construction failure")

        monkeypatch.setattr(dns.threading, "Thread", fail_constructor)
    elif case == "reader-start":
        real_factory = dns.threading.Thread

        def fail_start_factory(*args: Any, **kwargs: Any) -> threading.Thread:
            reader = real_factory(*args, **kwargs)

            def fail_start() -> None:
                raise RuntimeError("synthetic reader start failure")

            monkeypatch.setattr(reader, "start", fail_start)
            return reader

        monkeypatch.setattr(dns.threading, "Thread", fail_start_factory)
    elif case == "cancelled":
        original_remaining = dns._remaining
        calls = 0

        def cancel(cutoff: float) -> float:
            nonlocal calls
            calls += 1
            if calls >= 3:
                raise KeyboardInterrupt()
            return original_remaining(cutoff)

        monkeypatch.setattr(dns, "_remaining", cancel)
    elif case == "cleanup-error":
        real_factory = dns.subprocess.Popen

        def failed_kill_ack(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
            child = real_factory(*args, **kwargs)
            original_kill = child.kill

            def kill_then_fail() -> None:
                original_kill()
                raise OSError("synthetic cleanup acknowledgement failure")

            monkeypatch.setattr(child, "kill", kill_then_fail)
            return child

        monkeypatch.setattr(dns.subprocess, "Popen", failed_kill_ack)
    expected = KeyboardInterrupt if case == "cancelled" else dns.DNSError
    with pytest.raises(expected) as error:
        dns._run_worker("fixture.example.org", deadline)
    if case != "cancelled":
        code = error.value.code
        assert code == (
            "dns_timeout" if case == "blocked" else "cleanup_failure" if case == "cleanup-error" else "dns_failure"
        )
    assert len(processes) == 1
    assert_reaped(processes, readers)


def test_process_creation_failure_is_separate_from_reader_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[str] = []

    def failed_process(*_args: object, **_kwargs: object) -> None:
        called.append("process")
        raise OSError("synthetic CreateProcess failure")

    def forbidden_thread(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Reader creation reached after process failure")

    monkeypatch.setattr(dns.subprocess, "Popen", failed_process)
    monkeypatch.setattr(dns.threading, "Thread", forbidden_thread)
    with pytest.raises(dns.DNSError, match=r"^dns_failure$"):
        dns._run_worker("fixture.example.org", time.monotonic() + 3)
    assert called == ["process"]


@pytest.mark.parametrize("value", [None, "python", "missing/python.exe", "//server/share/python.exe"])
def test_nonlocal_or_unsupported_base_interpreter_is_refused(value: object, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "_base_executable", value)
    with pytest.raises(dns.DNSError):
        dns._base_interpreter()


def test_venv_redirector_is_not_accepted_as_direct_base(monkeypatch: pytest.MonkeyPatch) -> None:
    if Path(sys.executable).resolve() == Path(sys._base_executable).resolve():
        candidate = Path(sys.prefix) / "Scripts" / "python.exe"
    else:
        candidate = Path(sys.executable)
    monkeypatch.setattr(sys, "_base_executable", str(candidate))
    with pytest.raises(dns.DNSError):
        dns._base_interpreter()


@pytest.mark.parametrize(
    "values",
    [
        [],
        ["93.184.216.34", "127.0.0.1"],
        ["169.254.169.254"],
        ["100.64.0.1"],
        ["10.0.0.1"],
        ["::1"],
        ["::ffff:93.184.216.34"],
        ["fe80::1%1"],
        ["bad"],
        [None],
        ["93.184.216.34"] * 2,
        ["93.184.216.34"] * 129,
    ],
    ids=[
        "empty",
        "mixed",
        "metadata",
        "cgnat",
        "private",
        "loopback-v6",
        "mapped-v6",
        "scoped-v6",
        "malformed",
        "non-text",
        "duplicate",
        "too-many",
    ],
)
def test_every_dns_answer_must_be_public_native_and_unique(values: object) -> None:
    with pytest.raises(dns.DNSError, match=r"^destination_refused$"):
        dns.checked_answers(values)


def test_accepted_answer_set_is_immutable_and_detached() -> None:
    raw = ["93.184.216.34", "2606:4700:4700::1111"]
    answers = dns.checked_answers(raw)
    raw[0] = "127.0.0.1"
    assert answers == ("93.184.216.34", "2606:4700:4700::1111")


@pytest.mark.parametrize(
    "content",
    [
        b"{}",
        b'{"addresses":[]}',
        b'{"addresses":["127.0.0.1"]}',
        b'{"addresses":["93.184.216.34"],"extra":true}',
        b'{"addresses":null}',
        b'"not an object"',
    ],
)
def test_worker_output_schema_is_closed(content: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(network_guard, "is_offline", lambda: False)
    monkeypatch.setattr(dns, "_run_worker", lambda *_args: content)
    with pytest.raises(dns.DNSError):
        dns.resolve_public("fixture.example.org", time.monotonic() + 3)


def test_public_guard_runs_under_pin_without_second_uncontrolled_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def forbidden(host: str, *_args: object, **_kwargs: object) -> None:
        calls.append(host)
        raise AssertionError("Uncontrolled parent DNS reached")

    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", network_guard._GETADDRINFO_DELEGATE)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(network_guard, "is_offline", lambda: False)
    monkeypatch.setattr(dns, "_run_worker", lambda *_args: b'{"addresses":["93.184.216.34"]}')
    assert dns.resolve_public("fixture.example.org", time.monotonic() + 3) == ("93.184.216.34",)
    assert calls == []
    with dns.pinned_public_host("fixture.example.org", ("93.184.216.34",)):
        assert {row[4][0] for row in socket.getaddrinfo("fixture.example.org", 443)} == {"93.184.216.34"}
    assert calls == []


def test_offline_and_expired_budget_refuse_before_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object) -> None:
        raise AssertionError("Worker reached after local refusal")

    monkeypatch.setattr(dns, "_run_worker", forbidden)
    monkeypatch.setattr(network_guard, "is_offline", lambda: True)
    with pytest.raises(dns.DNSError, match=r"^offline_refused$"):
        dns.resolve_public("fixture.example.org", time.monotonic() + 3)
    monkeypatch.setattr(network_guard, "is_offline", lambda: False)
    with pytest.raises(dns.DNSError, match=r"^deadline_exceeded$"):
        dns.resolve_public("fixture.example.org", time.monotonic() - 1)


@pytest.mark.parametrize("phase", ["poll", "kill", "wait", "join"])
def test_cleanup_cancellation_is_retained_until_owned_resources_close(
    phase: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    native_process = subprocess.Popen
    native_join = threading.Thread.join
    processes, readers, _ = owned_processes(monkeypatch)
    monkeypatch.setattr(dns, "_WORKER_PROGRAM", "import time; time.sleep(0.5)")
    original_cleanup = dns._cleanup
    injected: list[str] = []

    def interrupted_cleanup(child: Any, reader: Any, stream: Any) -> Any:
        owner = reader if phase == "join" else child
        operation = getattr(owner, phase)

        def interrupted(*args: Any, **kwargs: Any) -> Any:
            if not injected:
                injected.append(phase)
                raise KeyboardInterrupt()
            return operation(*args, **kwargs)

        monkeypatch.setattr(owner, phase, interrupted)
        return original_cleanup(child, reader, stream)

    monkeypatch.setattr(dns, "_cleanup", interrupted_cleanup)
    try:
        with pytest.raises(KeyboardInterrupt):
            dns._run_worker("fixture.example.org", time.monotonic() + 0.1)
        assert injected == [phase]
        assert_reaped(processes, readers)
    finally:
        # Test rescue uses only the exact native resources returned by this test.
        for child in processes:
            if child.returncode is None:
                native_process.kill(child)
                native_process.wait(child, timeout=2)
        for reader in readers:
            native_join(reader, timeout=2)
        for child in processes:
            if child.stdout is not None:
                child.stdout.close()
            if os.name == "nt" and not child._handle.closed:
                child._handle.Close()


@pytest.mark.parametrize("value", [10**1000, -(10**1000)], ids=["huge-positive", "huge-negative"])
def test_native_integer_deadline_overflow_is_refused_before_worker(value: int, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def forbidden(*args: Any) -> bytes:
        calls.append("worker")
        raise AssertionError("worker_after_invalid_deadline")

    monkeypatch.setattr(dns.network_guard, "is_offline", lambda: False)
    monkeypatch.setattr(dns, "_run_worker", forbidden)
    with pytest.raises(dns.DNSError, match=r"^dns_failure$"):
        dns.resolve_public("fixture.example.org", value)
    assert calls == []
