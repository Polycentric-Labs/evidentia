"""Approve complete DNS answers and create verified, non-keylogging TLS contexts."""

from __future__ import annotations

import hashlib
import ipaddress
import math
import socket
import ssl
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

import certifi
from evidentia_core import network_guard

from ._contracts import canonical_hostname
from ._source_fields import validate_fields


class TransportError(ValueError):
    def __init__(
        self,
        code: Literal[
            "offline_refused",
            "destination_refused",
            "dns_failure",
            "tls_failure",
            "connection_failure",
            "timeout",
            "invalid_response",
            "cleanup_failure",
        ],
    ) -> None:
        self.code = code
        super().__init__(code)


def tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=certifi.where())
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname or context.keylog_filename is not None:
        raise TransportError("tls_failure")
    return context


def public_url(value: object) -> tuple[str, str]:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 8192
        or not value.isascii()
        or any(char < "!" or char > "~" for char in value)
    ):
        raise TransportError("destination_refused")
    try:
        parts = urlsplit(value)
        if (
            parts.scheme != "https"
            or parts.username is not None
            or parts.password is not None
            or parts.fragment
            or parts.port not in (None, 443)
        ):
            raise ValueError()
        host = canonical_hostname(parts.hostname)
        if parts.hostname != host or "\\" in value:
            raise ValueError()
    except ValueError:
        raise TransportError("destination_refused") from None
    return value, host


def _public_address(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= 45 or not value.isascii() or "%" in value:
        raise TransportError("dns_failure")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise TransportError("dns_failure") from None
    if not address.is_global or address.is_multicast or address.is_unspecified or address.is_reserved:
        raise TransportError("destination_refused")
    return str(address)


def resolver_addresses(value: object) -> tuple[str, ...]:
    """Every native row must be admissible before any address is used."""
    if type(value) is not list or not value:
        raise TransportError("dns_failure")
    result: list[str] = []
    for item in value:
        if type(item) is not tuple or len(item) != 5:
            raise TransportError("dns_failure")
        family, kind, protocol, canonical_name, sockaddr = item
        if (
            type(family) not in (int, socket.AddressFamily)
            or family not in (socket.AF_INET, socket.AF_INET6)
            or type(kind) not in (int, socket.SocketKind)
            or kind != socket.SOCK_STREAM
            or type(protocol) is not int
            or protocol != socket.IPPROTO_TCP
            or type(canonical_name) is not str
            or type(sockaddr) is not tuple
            or len(sockaddr) != (2 if family == socket.AF_INET else 4)
        ):
            raise TransportError("dns_failure")
        address, port = sockaddr[:2]
        if type(port) is not int or port != 443:
            raise TransportError("dns_failure")
        if family == socket.AF_INET6 and (
            type(sockaddr[2]) is not int
            or not 0 <= sockaddr[2] <= 0xFFFFF
            or type(sockaddr[3]) is not int
            or sockaddr[3] != 0
        ):
            raise TransportError("dns_failure")
        normalized = _public_address(address)
        if (":" in normalized) != (family == socket.AF_INET6):
            raise TransportError("dns_failure")
        if normalized not in result:
            result.append(normalized)
    return tuple(result)


@dataclass(frozen=True)
class ApprovedHost:
    url: str
    host: str
    addresses: tuple[str, ...]
    thread_id: int


@contextmanager
def approved_destination(url: str) -> Iterator[ApprovedHost]:
    clean_url, host = public_url(url)
    failure: Literal["offline_refused", "destination_refused", "dns_failure"] | None = None
    try:
        network_guard.check_url(clean_url, subsystem="public_registries")
    except network_guard.OfflineViolationError:
        failure = "offline_refused"
    if failure is not None:
        raise TransportError(failure)
    answers: object = None
    try:
        # Bytes deliberately delegate past an outer same-host string pin.
        answers = socket.getaddrinfo(
            host.encode("ascii"), 443, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP
        )
    except OSError:
        failure = "dns_failure"
    if failure is not None:
        raise TransportError(failure)
    addresses = resolver_addresses(answers)
    with network_guard.pin_resolved_host(host, list(addresses)):
        guarded: object = None
        try:
            guarded = network_guard.enforce_public_host(clean_url, subsystem="public_registries", block_private=True)
        except network_guard.SSRFBlockedError:
            failure = "destination_refused"
        if failure is not None or type(guarded) is not list or not guarded:
            raise TransportError("destination_refused")
        checked = tuple(_public_address(item) for item in guarded)
        if set(checked) != set(addresses):
            raise TransportError("destination_refused")
        yield ApprovedHost(clean_url, host, addresses, threading.get_ident())


def _first_socket(approved: ApprovedHost) -> tuple[socket.socket, tuple[Any, ...]]:
    """Retain resolver order and connect only to its first approved address."""
    if approved.thread_id != threading.get_ident():
        raise TransportError("destination_refused")
    rows = socket.getaddrinfo(approved.host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    if resolver_addresses(rows) != approved.addresses:
        raise TransportError("destination_refused")
    family, kind, protocol, _, address = rows[0]
    return socket.socket(family, kind, protocol), address


def _certificate_fields(value: object) -> dict[str, Any] | None:
    if value is None:
        return None
    if type(value) is not dict:
        raise TransportError("invalid_response")

    def native(item: object) -> Any:
        if type(item) is tuple:
            return [native(part) for part in item]
        if type(item) is str:
            return item
        raise TransportError("invalid_response")

    return {
        name: native(value[name])
        for name in ("subject", "issuer", "subjectAltName", "notBefore", "notAfter")
        if name in value
    }


class TLSAttempt:
    """One certificate-verified handshake, with no address or protocol fallback."""

    def __init__(self) -> None:
        self.cleanup_failed = False
        self._used = False
        self._callback_error: BaseException | None = None
        self._cleanup_cancellation: BaseException | None = None

    def _remaining(self, callback: Callable[[], float]) -> float:
        try:
            value = callback()
        except BaseException as error:
            self._callback_error = error
            raise
        if (type(value) is not int and type(value) is not float) or not math.isfinite(value) or value <= 0:
            raise TransportError("timeout")
        return min(5.0, value)

    def _close(self, resource: socket.socket | None) -> None:
        if resource is None:
            return
        try:
            resource.close()
        except BaseException as error:
            self.cleanup_failed = True
            if not isinstance(error, Exception) and self._cleanup_cancellation is None:
                self._cleanup_cancellation = error

    def fetch(self, hostname: str, *, remaining: Callable[[], float]) -> dict[str, Any]:
        if self._used:
            raise TransportError("invalid_response")
        self._used = True
        host = canonical_hostname(hostname)
        raw: socket.socket | None = None
        secured: ssl.SSLSocket | None = None
        primary: BaseException | None = None
        failure: Literal["tls_failure", "connection_failure", "timeout", "invalid_response"] | None = None
        result: dict[str, Any] | None = None
        try:
            self._remaining(remaining)
            with approved_destination("https://" + host + "/") as approved:
                context = tls_context()
                self._remaining(remaining)
                raw, address = _first_socket(approved)
                raw.settimeout(self._remaining(remaining))
                raw.connect(address)
                raw.settimeout(self._remaining(remaining))
                secured = context.wrap_socket(raw, server_hostname=host, do_handshake_on_connect=False)
                secured.settimeout(self._remaining(remaining))
                secured.do_handshake()
                self._remaining(remaining)
                der = secured.getpeercert(binary_form=True)
                if type(der) is not bytes or not 1 <= len(der) <= 65_536:
                    raise TransportError("invalid_response")
                cipher = secured.cipher()
                if cipher is not None and (type(cipher) is not tuple or len(cipher) != 3):
                    raise TransportError("invalid_response")
                peer = secured.getpeername()
                if type(peer) is not tuple or not peer or type(peer[0]) is not str:
                    raise TransportError("invalid_response")
                result = validate_fields(
                    "tls",
                    "verified_tls_adapter",
                    {
                        "protocol": secured.version(),
                        "cipher": None
                        if cipher is None
                        else {"name": cipher[0], "protocol": cipher[1], "secret_bits": cipher[2]},
                        "peer_address": str(ipaddress.ip_address(peer[0])),
                        "der_sha256": hashlib.sha256(der).hexdigest(),
                        "certificate": _certificate_fields(secured.getpeercert()),
                    },
                )
                self._remaining(remaining)
        except BaseException as error:
            if error is self._callback_error or not isinstance(error, Exception) or isinstance(error, TransportError):
                primary = error
            elif isinstance(error, ssl.SSLError):
                failure = "tls_failure"
            elif isinstance(error, TimeoutError):
                failure = "timeout"
            elif isinstance(error, OSError):
                failure = "connection_failure"
            else:
                failure = "invalid_response"
        finally:
            self._close(secured)
            self._close(raw)
        if primary is not None and not isinstance(primary, Exception):
            raise primary
        if self._cleanup_cancellation is not None:
            raise self._cleanup_cancellation
        if primary is not None:
            raise primary
        if failure is not None:
            raise TransportError(failure)
        if self.cleanup_failed or result is None:
            raise TransportError("cleanup_failure" if self.cleanup_failed else "invalid_response")
        return result
