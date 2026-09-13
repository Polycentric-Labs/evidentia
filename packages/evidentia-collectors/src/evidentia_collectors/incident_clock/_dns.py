"""Own bounded DNS workers and freeze every accepted public address."""

from __future__ import annotations

import ipaddress
import math
import os
import re
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Literal, cast

from evidentia_core import network_guard

from ._parsing import parse_strict_json

DNS_SECONDS = 5.0
WORKER_OUTPUT_BYTES = 32768
MAX_ANSWERS = 128
PROCESS_CLEANUP_SECONDS = 1.0
READER_CLEANUP_SECONDS = 1.0
DNSCode = Literal[
    "offline_refused", "destination_refused", "dns_failure", "dns_timeout", "deadline_exceeded", "cleanup_failure"
]
_WORKER_PROGRAM = """import json, socket, sys
rows = socket.getaddrinfo(sys.argv[1], 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
if not 1 <= len(rows) <= 128:
    raise ValueError()
addresses = []
for family, kind, protocol, canonical, address in rows:
    if family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM or protocol != socket.IPPROTO_TCP:
        raise ValueError()
    if type(address) is not tuple or len(address) not in (2, 4) or address[1] != 443:
        raise ValueError()
    if len(address) == 4 and (address[2] != 0 or address[3] != 0):
        raise ValueError()
    text = address[0]
    if type(text) is not str or not 1 <= len(text) <= 45:
        raise ValueError()
    addresses.append(text)
sys.stdout.write(json.dumps({"addresses": addresses}, separators=(",", ":")))
"""


class DNSError(ValueError):
    """Expose a finite failure without a hostname, path or worker output."""

    def __init__(self, code: DNSCode = "dns_failure") -> None:
        if type(code) is not str or code not in (
            "offline_refused",
            "destination_refused",
            "dns_failure",
            "dns_timeout",
            "deadline_exceeded",
            "cleanup_failure",
        ):
            code = "dns_failure"
        self.code = code
        super().__init__(code)


def _hostname(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= 253 or not value.isascii() or value != value.lower():
        raise DNSError("destination_refused")
    labels = value.split(".")
    if len(labels) < 2 or not re.search(r"[a-z]", labels[-1]):
        raise DNSError("destination_refused")
    if any(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) is None for part in labels):
        raise DNSError("destination_refused")
    return value


def _base_interpreter() -> str:
    """Resolve only this CPython runtime's direct base executable."""
    try:
        executable = getattr(sys, "_base_executable", None)
        if sys.implementation.name != "cpython" or type(executable) is not str or not Path(executable).is_absolute():
            raise DNSError()
        if not 1 <= len(executable) <= 32768 or type(sys.base_prefix) is not str:
            raise DNSError()
        supplied = Path(executable)
        if str(supplied).startswith(("\\\\", "//")) or (os.name == "nt" and ":" in str(supplied)[2:]):
            raise DNSError()
        source = supplied.resolve(strict=True)
        base = Path(sys.base_prefix).resolve(strict=True)
        if not base.is_absolute() or not source.is_relative_to(base):
            raise DNSError()
        names = {
            "python",
            "python3",
            "Python",
            "python.exe",
            "python3.exe",
            f"python{sys.version_info.major}.{sys.version_info.minor}",
        }
        if source.name not in names or (os.name == "nt" and source.parent != base):
            raise DNSError()
        info = source.stat()
        if not stat.S_ISREG(info.st_mode) or not os.access(source, os.X_OK):
            raise DNSError()
        return str(source)
    except (AttributeError, OSError, TypeError, ValueError):
        raise DNSError() from None


def _worker_environment() -> dict[str, str]:
    if os.name != "nt":
        return {}
    return {key: os.environ[key] for key in ("SystemRoot", "WINDIR") if key in os.environ}


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DNSError("dns_timeout")
    return remaining


def _cleanup(
    child: subprocess.Popen[bytes] | None, reader: threading.Thread | None, stream: BinaryIO | None
) -> tuple[bool, BaseException | None]:
    failed = False
    cancellation: BaseException | None = None
    process_cutoff = time.monotonic() + PROCESS_CLEANUP_SECONDS

    def finish(action: Callable[[], object]) -> None:
        nonlocal failed, cancellation
        # A cancellation can arrive before an owned operation takes effect.
        # Retry that operation once, preserving the original phase deadline.
        for _ in range(2):
            try:
                action()
                return
            except BaseException as error:
                if isinstance(error, Exception):
                    failed = True
                    return
                if cancellation is None:
                    cancellation = error
        failed = True

    if child is not None:

        def stop_child() -> None:
            if child.poll() is None:
                child.kill()

        finish(stop_child)
        finish(lambda: child.wait(timeout=max(0.0, process_cutoff - time.monotonic())))
        if os.name == "nt":

            def close_handle() -> None:
                handle = getattr(child, "_handle", None)
                if handle is not None:
                    handle.Close()

            finish(close_handle)
    if reader is not None and reader.ident is not None:
        reader_cutoff = time.monotonic() + READER_CLEANUP_SECONDS
        finish(lambda: reader.join(max(0.0, reader_cutoff - time.monotonic())))
        if reader.is_alive():
            failed = True
    if stream is not None and (reader is None or not reader.is_alive()):
        finish(stream.close)
    return failed, cancellation


def _run_worker(host: str, deadline: float) -> bytes:
    child: subprocess.Popen[bytes] | None = None
    reader: threading.Thread | None = None
    stream: BinaryIO | None = None
    output = bytearray()
    read_failed: list[bool] = []
    primary: BaseException | None = None
    result: bytes | None = None

    def consume() -> None:
        assert stream is not None
        try:
            while len(output) <= WORKER_OUTPUT_BYTES:
                chunk = stream.read(min(4096, WORKER_OUTPUT_BYTES + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > WORKER_OUTPUT_BYTES:
                    break
        except BaseException:
            read_failed.append(True)
        finally:
            try:
                stream.close()
            except OSError:
                read_failed.append(True)

    try:
        executable = _base_interpreter()
        _remaining(deadline)
        child = subprocess.Popen(
            [executable, "-I", "-S", "-c", _WORKER_PROGRAM, host],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            env=_worker_environment(),
            bufsize=0,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        stream = cast(BinaryIO | None, child.stdout)
        if stream is None:
            raise DNSError()
        reader = threading.Thread(target=consume, name="incident-clock-dns-reader", daemon=False)
        reader.start()
        while reader.is_alive():
            reader.join(min(0.025, _remaining(deadline)))
        if read_failed or len(output) > WORKER_OUTPUT_BYTES:
            raise DNSError()
        try:
            status = child.wait(timeout=_remaining(deadline))
        except subprocess.TimeoutExpired:
            raise DNSError("dns_timeout") from None
        if status != 0:
            raise DNSError()
        _remaining(deadline)
        result = bytes(output)
    except BaseException as error:
        primary = error
    cleanup_failed, cleanup_cancellation = _cleanup(child, reader, stream)
    if cleanup_cancellation is not None and (primary is None or isinstance(primary, Exception)):
        primary = cleanup_cancellation
    if cleanup_failed:
        if primary is not None and not isinstance(primary, Exception):
            raise primary from DNSError("cleanup_failure")
        raise DNSError("cleanup_failure") from None
    if primary is not None:
        if isinstance(primary, DNSError) or not isinstance(primary, Exception):
            raise primary
        raise DNSError() from None
    if result is None:
        raise DNSError()
    return result


def checked_answers(value: object) -> tuple[str, ...]:
    if type(value) is not list and type(value) is not tuple:
        raise DNSError("destination_refused")
    if not 1 <= len(value) <= MAX_ANSWERS:
        raise DNSError("destination_refused")
    addresses: list[str] = []
    for item in value:
        if type(item) is not str or not 1 <= len(item) <= 45 or not item.isascii() or "%" in item:
            raise DNSError("destination_refused")
        try:
            address = ipaddress.ip_address(item)
        except ValueError:
            raise DNSError("destination_refused") from None
        if network_guard._ip_is_non_public(address) or (
            isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None
        ):
            raise DNSError("destination_refused")
        canonical = str(address)
        if canonical in addresses:
            raise DNSError("destination_refused")
        addresses.append(canonical)
    return tuple(addresses)


@contextmanager
def pinned_public_host(host: str, addresses: tuple[str, ...]) -> Iterator[tuple[str, ...]]:
    """Reapply the central public-host guard under the already validated DNS pin."""
    selected = _hostname(host)
    if network_guard.is_offline():
        raise DNSError("offline_refused")
    checked = checked_answers(addresses)
    try:
        with network_guard.pin_resolved_host(selected, list(checked)):
            admitted = network_guard.enforce_public_host(selected, subsystem="incident-clock")
            if type(admitted) is not list or tuple(admitted) != checked:
                raise DNSError("destination_refused")
            yield checked
    except (network_guard.SSRFBlockedError, network_guard.OfflineViolationError):
        raise DNSError("destination_refused") from None


def resolve_public(host: str, deadline: float) -> tuple[str, ...]:
    """Resolve within five seconds and the caller's remaining useful-work budget."""
    selected = _hostname(host)
    if network_guard.is_offline():
        raise DNSError("offline_refused")
    if (
        (type(deadline) is not float and type(deadline) is not int)
        or (type(deadline) is int and deadline.bit_length() > 1023)
        or not math.isfinite(deadline)
    ):
        raise DNSError()
    started = time.monotonic()
    if deadline <= started:
        raise DNSError("deadline_exceeded")
    cutoff = min(deadline, started + DNS_SECONDS)
    content = _run_worker(selected, cutoff)
    try:
        data = parse_strict_json(content, max_bytes=WORKER_OUTPUT_BYTES)
        if type(data) is not dict or set(data) != {"addresses"}:
            raise DNSError()
        answers = checked_answers(data["addresses"])
        _remaining(cutoff)
        with pinned_public_host(selected, answers):
            return answers
    except DNSError:
        raise
    except (TypeError, ValueError):
        raise DNSError() from None
