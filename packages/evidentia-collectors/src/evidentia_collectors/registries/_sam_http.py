"""Read fixed SAM endpoints through owned, silent standard-library HTTPS."""

from __future__ import annotations

import http.client
import math
import socket
import ssl
from collections.abc import Callable, Iterator
from datetime import datetime
from functools import partial
from typing import Any, BinaryIO, cast
from urllib.parse import urlencode

import httpx

from evidentia_collectors.retention._client import ClientFault, read_bounded_body

from ._contracts import RegistryInputError, RegistryLookupRequest, SAMOrganizationTarget, UEITarget, validated_request
from ._credentials import CredentialError, SamCredentialCache
from ._tls import TransportError, approved_destination, tls_context

_ORIGIN = "https://api.sam.gov"
_ERRORS = frozenset(
    {
        "offline_refused",
        "destination_refused",
        "dns_failure",
        "tls_failure",
        "connection_failure",
        "timeout",
        "invalid_response",
        "redirect_refused",
        "http_error",
        "body_limit",
        "cleanup_failure",
    }
)


class SamTransportError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in _ERRORS else "invalid_response"
        super().__init__(self.code)


_TOKEN = frozenset(b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def _header_line(line: bytes) -> None:
    if len(line) > 65_536 or not line.endswith(b"\r\n"):
        raise SamTransportError("invalid_response")
    name, separator, value = line[:-2].partition(b":")
    if (
        not separator
        or not name
        or any(char not in _TOKEN for char in name)
        or any((char < 32 and char != 9) or char == 127 for char in value)
    ):
        raise SamTransportError("invalid_response")


def _chunk_extensions(value: bytes) -> None:
    position = 0
    while position < len(value):
        if value[position] != 59:
            raise SamTransportError("invalid_response")
        position += 1
        start = position
        while position < len(value) and value[position] in _TOKEN:
            position += 1
        if position == start:
            raise SamTransportError("invalid_response")
        if position == len(value) or value[position] == 59:
            continue
        if value[position] != 61:
            raise SamTransportError("invalid_response")
        position += 1
        if position < len(value) and value[position] == 34:
            position += 1
            while position < len(value) and value[position] != 34:
                if value[position] == 92:
                    position += 1
                    if position == len(value):
                        raise SamTransportError("invalid_response")
                char = value[position]
                if (char < 32 and char != 9) or char == 127:
                    raise SamTransportError("invalid_response")
                position += 1
            if position == len(value):
                raise SamTransportError("invalid_response")
            position += 1
        else:
            start = position
            while position < len(value) and value[position] in _TOKEN:
                position += 1
            if position == start:
                raise SamTransportError("invalid_response")
        if position < len(value) and value[position] != 59:
            raise SamTransportError("invalid_response")


def _template(request: RegistryLookupRequest, page: int) -> tuple[str, str]:
    selected = validated_request(request).root
    if type(page) is not int or not 0 <= page <= 999:
        raise RegistryInputError()
    if selected.registry == "sam-entity":
        if page != 0:
            raise RegistryInputError()
        path = "/entity-information/v4/entities"
        query = [
            ("sensitivity", "public"),
            ("samRegistered", "Yes"),
            ("includeSections", "entityRegistration"),
            ("size", "10"),
            ("ueiSAM", selected.target.uei),
        ]
    elif selected.registry == "sam-exclusions":
        path = "/entity-information/v4/exclusions"
        query = [
            ("classification", "Firm"),
            ("recordStatus", "Active"),
            ("size", "10"),
            ("page", str(page)),
            ("includeSections", "exclusionDetails,exclusionIdentification,exclusionActions,exclusionOtherInformation"),
        ]
        target = selected.target
        query.append(
            ("ueiSAM", target.uei)
            if type(target) is UEITarget
            else ("exclusionName", cast(SAMOrganizationTarget, target).organization_name)
        )
    else:
        raise RegistryInputError()
    return path, urlencode(query)


class _Callbacks:
    def __init__(
        self, remaining: Callable[[], float], utc_now: Callable[[], datetime], consume: Callable[[int, int], None]
    ) -> None:
        self.remaining = remaining
        self.utc_now = utc_now
        self.consume = consume
        self.error: BaseException | None = None

    def timeout(self, maximum: float) -> float:
        try:
            value = self.remaining()
        except BaseException as error:
            self.error = error
            raise
        if (type(value) is not int and type(value) is not float) or not math.isfinite(value) or value <= 0:
            raise SamTransportError("timeout")
        return min(maximum, value)

    def now(self) -> datetime:
        try:
            return self.utc_now()
        except BaseException as error:
            self.error = error
            raise

    def charge(self, raw: int, decoded: int) -> None:
        try:
            self.consume(raw, decoded)
        except BaseException as error:
            self.error = error
            raise


class _Closure:
    def __init__(self) -> None:
        self.failed = False
        self.cancellation: BaseException | None = None

    def close(self, operation: Callable[[], Any]) -> None:
        try:
            operation()
        except BaseException as error:
            self.failed = True
            if not isinstance(error, Exception) and self.cancellation is None:
                self.cancellation = error


class _GuardedFile:
    """Check scheduling time around each native status/header/body/framing read."""

    def __init__(self, stream: BinaryIO, sock: socket.socket, callbacks: _Callbacks, closure: _Closure) -> None:
        self.stream, self.sock, self.callbacks, self.closure = stream, sock, callbacks, closure
        self.headers_open = False

    def _read(self, method: str, argument: Any) -> Any:
        self.sock.settimeout(self.callbacks.timeout(10.0))
        result = getattr(self.stream, method)(argument)
        if method != "read1":
            self.callbacks.timeout(10.0)
        return result

    def read(self, size: int = -1) -> bytes:
        return cast(bytes, self._read("read", size))

    def read1(self, size: int = -1) -> bytes:
        return cast(bytes, self._read("read1", size))

    def readline(self, size: int = -1) -> bytes:
        line = cast(bytes, self._read("readline", size))
        if self.headers_open:
            if line == b"\r\n":
                self.headers_open = False
            else:
                _header_line(line)
        return line

    def flush(self) -> None:
        self.stream.flush()

    def readinto(self, buffer: Any) -> int:
        return cast(int, self._read("readinto", buffer))

    def close(self) -> None:
        self.closure.close(self.stream.close)


class _FileSource:
    def __init__(self, sock: socket.socket, callbacks: _Callbacks, closure: _Closure) -> None:
        self.sock, self.callbacks, self.closure = sock, callbacks, closure

    def makefile(self, mode: str) -> _GuardedFile:
        if type(mode) is not str or mode != "rb":
            raise SamTransportError("invalid_response")
        return _GuardedFile(self.sock.makefile("rb"), self.sock, self.callbacks, self.closure)


class _Response(http.client.HTTPResponse):
    def __init__(
        self,
        sock: socket.socket,
        debuglevel: int = 0,
        method: str | None = None,
        url: str | None = None,
        *,
        callbacks: _Callbacks,
        closure: _Closure,
    ) -> None:
        self._closure = closure
        # Each instance stays silent even if an operator changed the class default.
        super().__init__(cast(socket.socket, _FileSource(sock, callbacks, closure)), debuglevel=0, method=method)

    def _read_status(self) -> tuple[str, int, str]:
        line = self.fp.readline(65_537)
        if len(line) > 65_536 or not line.endswith(b"\r\n"):
            raise SamTransportError("invalid_response")
        version, separator, rest = line[:-2].partition(b" ")
        status, reason_separator, reason = rest.partition(b" ")
        if (
            version not in (b"HTTP/1.0", b"HTTP/1.1")
            or not separator
            or not reason_separator
            or len(status) != 3
            or any(char < 48 or char > 57 for char in status)
            or any((char < 32 and char != 9) or char == 127 for char in reason)
        ):
            raise SamTransportError("invalid_response")
        code = int(status)
        if not 100 <= code <= 599:
            raise SamTransportError("invalid_response")
        cast(_GuardedFile, self.fp).headers_open = True
        return version.decode("ascii"), code, reason.decode("latin-1")

    def _read_next_chunk_size(self) -> int:
        line = self.fp.readline(65_537)
        if len(line) > 65_536 or not line.endswith(b"\r\n"):
            raise SamTransportError("invalid_response")
        digits, separator, extensions = line[:-2].partition(b";")
        if separator:
            _chunk_extensions(b";" + extensions)
        if not digits or any(value not in b"0123456789abcdefABCDEF" for value in digits):
            raise SamTransportError("invalid_response")
        return int(digits, 16)

    def _read_and_discard_trailer(self) -> None:
        for _ in range(101):
            line = self.fp.readline(65_537)
            if line == b"\r\n":
                return
            if len(line) > 65_536 or not line.endswith(b"\r\n"):
                raise SamTransportError("invalid_response")
            _header_line(line)
        raise SamTransportError("invalid_response")

    def _get_chunk_left(self) -> int | None:
        left = self.chunk_left
        if left is None or left == 0:
            if left == 0 and self.fp.read(2) != b"\r\n":
                raise SamTransportError("invalid_response")
            left = self._read_next_chunk_size()
            if left == 0:
                self._read_and_discard_trailer()
                self.close()
                left = None
            self.chunk_left = left
        return left

    def close(self) -> None:
        self._closure.close(super().close)


class _Body(httpx.SyncByteStream):
    def __init__(self, response: http.client.HTTPResponse) -> None:
        self._response = response

    def __iter__(self) -> Iterator[bytes]:
        while True:
            part = b""
            incomplete = False
            try:
                part = self._response.read1(65_536)
            except http.client.IncompleteRead as error:
                part = error.partial
                incomplete = True
            if type(part) is not bytes or len(part) > 65_536:
                raise SamTransportError("invalid_response")
            if part:
                yield part
            if incomplete or (not part and self._response.length not in (None, 0)):
                raise SamTransportError("invalid_response")
            if not part:
                return

    def close(self) -> None:
        # The attempt owns response closure; HTTPX only adapts the decoded body.
        pass


class SamAttempt:
    """One connection and one request, with only fixed public failure metadata."""

    def __init__(self) -> None:
        self.status_code: int | None = None
        self.retry_after: tuple[str, ...] = ()
        self.cleanup_failed = False
        self._used = False

    def fetch(
        self,
        request: RegistryLookupRequest,
        *,
        page: int,
        credentials: SamCredentialCache,
        remaining: Callable[[], float],
        utc_now: Callable[[], datetime],
        consume: Callable[[int, int], None],
    ) -> bytes:
        if self._used or type(credentials) is not SamCredentialCache:
            raise RegistryInputError()
        self._used = True
        path, query = _template(request, page)
        public_template = _ORIGIN + path + "?" + query
        callbacks, closure = _Callbacks(remaining, utc_now, consume), _Closure()
        connection: http.client.HTTPSConnection | None = None
        response: http.client.HTTPResponse | None = None
        bridge: httpx.Response | None = None
        result: bytes | None = None
        primary: BaseException | None = None
        fixed_error: str | None = None
        stage = "connect"
        try:
            callbacks.timeout(5.0)
            with approved_destination(public_template) as approved:
                context = tls_context()
                connection = http.client.HTTPSConnection(
                    approved.host, 443, timeout=callbacks.timeout(5.0), context=context
                )
                connection.set_debuglevel(0)
                connection.auto_open = 0
                # response_class is an instance-owned callable with the native constructor signature.
                connection.response_class = cast(
                    type[http.client.HTTPResponse], partial(_Response, callbacks=callbacks, closure=closure)
                )
                connection.connect()
                callbacks.timeout(5.0)
                if connection.sock is None:
                    raise SamTransportError("connection_failure")
                credential = credentials.resolve(callbacks.now)
                connection.sock.settimeout(callbacks.timeout(10.0))
                observed = callbacks.now()
                connection.set_debuglevel(0)
                target = path + "?" + query + "&" + urlencode({"api_key": credential._for_query(observed)})
                stage = "response"
                connection.request(
                    "GET",
                    target,
                    headers={"Accept": "application/json", "Accept-Encoding": "gzip", "Connection": "close"},
                )
                response = connection.getresponse()
                if type(response.status) is not int or not 100 <= response.status <= 599:
                    raise SamTransportError("invalid_response")
                self.status_code = response.status
                if 300 <= response.status < 400:
                    raise SamTransportError("redirect_refused")
                if response.status != 200:
                    # Only the retry parser sees this bounded header. SAM still has one attempt.
                    self.retry_after = tuple(response.headers.get_all("Retry-After", []))
                    raise SamTransportError("http_error")
                encodings = response.headers.get_all("Content-Encoding", [])
                lengths = response.headers.get_all("Content-Length", [])
                transfers = response.headers.get_all("Transfer-Encoding", [])
                if (
                    len(encodings) > 1
                    or len(lengths) > 1
                    or len(transfers) > 1
                    or (lengths and transfers)
                    or (transfers and transfers[0].strip().lower() != "chunked")
                    or (lengths and (not lengths[0].isascii() or not lengths[0].isdigit()))
                ):
                    raise SamTransportError("invalid_response")
                # This synthetic request has no query credential. No HTTPX client, transport or cookie extraction runs.
                bridge = httpx.Response(
                    200,
                    headers={"content-encoding": encodings[0] if encodings else "identity"},
                    stream=_Body(response),
                    request=httpx.Request("GET", _ORIGIN + path),
                )
                result = read_bounded_body(bridge, consume=callbacks.charge)
                callbacks.timeout(10.0)
        except BaseException as error:
            if error is callbacks.error or not isinstance(error, Exception) or isinstance(error, CredentialError):
                primary = error
            elif isinstance(error, (SamTransportError, TransportError)):
                fixed_error = error.code
            elif isinstance(error, ClientFault):
                fixed_error = "body_limit" if error.code == "response_limit" else "invalid_response"
            elif isinstance(error, ssl.SSLError):
                fixed_error = "tls_failure"
            elif isinstance(error, TimeoutError):
                fixed_error = "timeout"
            else:
                fixed_error = "connection_failure" if stage == "connect" else "invalid_response"
        finally:
            if bridge is not None:
                closure.close(bridge.close)
            if response is not None:
                closure.close(response.close)
            if connection is not None:
                closure.close(connection.close)
            self.cleanup_failed = closure.failed
        if primary is not None and not isinstance(primary, Exception):
            raise primary
        if closure.cancellation is not None:
            raise closure.cancellation
        if primary is not None:
            raise primary
        if fixed_error is not None:
            raise SamTransportError(fixed_error)
        if self.cleanup_failed or result is None:
            raise SamTransportError("cleanup_failure" if self.cleanup_failed else "invalid_response")
        return result
