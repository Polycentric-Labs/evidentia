"""Own each non-SAM socket through HTTP and TLS cleanup."""

from __future__ import annotations

import math
import select
import socket
import ssl
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from functools import partial
from typing import Any, TypeVar

import httpcore
import httpx

from ._tls import ApprovedHost, TransportError, _first_socket

_T = TypeVar("_T")


class OwnedState:
    def __init__(self, remaining: Callable[[], float]) -> None:
        self.remaining = remaining
        self.primary: BaseException | None = None
        self.cleanup_cancellation: BaseException | None = None
        self.cleanup_failed = False
        self.callback_error: BaseException | None = None
        self.streams: list[OwnedStream] = []

    def call(self, operation: Callable[[], _T]) -> _T:
        try:
            return operation()
        except BaseException as error:
            if not isinstance(error, Exception) and self.primary is None:
                self.primary = error
            raise

    def timeout(self, ceiling: float, requested: float | None = None) -> float:
        try:
            available = self.call(self.remaining)
        except BaseException as error:
            self.callback_error = error
            raise
        if (
            (type(available) is not int and type(available) is not float)
            or not math.isfinite(available)
            or available <= 0
        ):
            raise TransportError("timeout")
        if requested is not None:
            if (
                (type(requested) is not int and type(requested) is not float)
                or not math.isfinite(requested)
                or requested <= 0
            ):
                raise TransportError("invalid_response")
            ceiling = min(ceiling, requested)
        return min(ceiling, available)

    def close(self, operation: Callable[[], Any]) -> None:
        try:
            operation()
        except BaseException as error:
            self.cleanup_failed = True
            if not isinstance(error, Exception) and self.cleanup_cancellation is None:
                self.cleanup_cancellation = error

    def close_all(self) -> None:
        for stream in reversed(self.streams):
            stream.close()


class OwnedStream(httpcore.NetworkStream):
    def __init__(self, raw: socket.socket, approved: ApprovedHost, context: ssl.SSLContext, state: OwnedState) -> None:
        self._socket: socket.socket = raw
        self._resources: list[socket.socket] = [raw]
        self._secured: ssl.SSLSocket | None = None
        self._approved = approved
        self._context = context
        self._state = state
        self._closed = False
        state.streams.append(self)

    def connect(self, address: tuple[Any, ...], timeout: float | None) -> None:
        try:
            self._state.call(lambda: self._socket.settimeout(self._state.timeout(5.0, timeout)))
            self._state.call(lambda: self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1))
            self._state.call(lambda: self._socket.connect(address))
            self._state.timeout(5.0, timeout)
        except BaseException as error:
            self.close()
            if error is self._state.callback_error:
                raise
            if isinstance(error, socket.timeout):
                raise httpcore.ConnectTimeout("timeout") from error
            if isinstance(error, OSError):
                raise httpcore.ConnectError("connection_failure") from error
            raise

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        if self._closed or type(max_bytes) is not int or not 0 < max_bytes <= 65_536:
            raise httpcore.ReadError("invalid_response")
        try:
            self._state.call(lambda: self._socket.settimeout(self._state.timeout(10.0, timeout)))
            value = self._state.call(lambda: self._socket.recv(max_bytes))
        except TimeoutError as error:
            if error is self._state.callback_error:
                raise
            raise httpcore.ReadTimeout("timeout") from error
        except OSError as error:
            if error is self._state.callback_error:
                raise
            raise httpcore.ReadError("connection_failure") from error
        if type(value) is not bytes or len(value) > max_bytes:
            raise httpcore.ReadError("invalid_response")
        # The decoder charges delivered bytes before it checks the deadline.
        return value

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        if self._closed or type(buffer) is not bytes:
            raise httpcore.WriteError("invalid_response")
        while buffer:
            try:
                self._state.call(lambda: self._socket.settimeout(self._state.timeout(10.0, timeout)))
                sent = self._state.call(partial(self._socket.send, buffer))
            except TimeoutError as error:
                if error is self._state.callback_error:
                    raise
                raise httpcore.WriteTimeout("connection_failure") from error
            except OSError as error:
                if error is self._state.callback_error:
                    raise
                raise httpcore.WriteError("connection_failure") from error
            if type(sent) is not int or not 0 < sent <= len(buffer):
                raise httpcore.WriteError("invalid_response")
            buffer = buffer[sent:]
            self._state.timeout(10.0, timeout)

    def _wrap(self, ssl_context: ssl.SSLContext) -> ssl.SSLSocket:
        previous = ssl_context.sslsocket_class
        if previous is not ssl.SSLSocket:
            raise TransportError("destination_refused")
        state = self._state

        class AttemptSSLSocket(ssl.SSLSocket):
            def close(self) -> None:
                state.close(super().close)

        try:
            ssl_context.sslsocket_class = AttemptSSLSocket
            return ssl_context.wrap_socket(
                self._socket, server_hostname=self._approved.host, do_handshake_on_connect=False
            )
        finally:
            state.close(lambda: setattr(ssl_context, "sslsocket_class", previous))

    def start_tls(
        self, ssl_context: ssl.SSLContext, server_hostname: str | None = None, timeout: float | None = None
    ) -> httpcore.NetworkStream:
        if (
            self._closed
            or self._secured is not None
            or ssl_context is not self._context
            or server_hostname != self._approved.host
        ):
            raise TransportError("destination_refused")
        try:
            self._state.call(lambda: self._socket.settimeout(self._state.timeout(5.0, timeout)))
            secured = self._state.call(lambda: self._wrap(ssl_context))
            self._resources.append(secured)
            self._secured = secured
            self._socket = secured
            self._state.call(lambda: secured.settimeout(self._state.timeout(5.0, timeout)))
            self._state.call(secured.do_handshake)
            self._state.timeout(5.0, timeout)
            return self
        except BaseException as error:
            self.close()
            if error is self._state.callback_error:
                raise
            if isinstance(error, socket.timeout):
                raise httpcore.ConnectTimeout("timeout") from error
            if isinstance(error, OSError):
                raise httpcore.ConnectError("tls_failure") from error
            raise

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            for resource in reversed(self._resources):
                self._state.close(resource.close)

    def get_extra_info(self, info: str) -> Any:
        if info == "ssl_object":
            return self._secured
        if info == "socket":
            return self._socket
        if info == "is_readable":
            if self._closed:
                return True
            return self._state.call(lambda: bool(select.select([self._socket], [], [], 0)[0]))
        if info == "client_addr":
            return self._state.call(self._socket.getsockname)
        if info == "server_addr":
            return self._state.call(self._socket.getpeername)
        return None


class OwnedBackend(httpcore.NetworkBackend):
    def __init__(self, approved: ApprovedHost, context: ssl.SSLContext, state: OwnedState) -> None:
        self._approved, self._context, self._state = approved, context, state
        self._used = False

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        if (
            self._used
            or type(host) is not str
            or host != self._approved.host
            or type(port) is not int
            or port != 443
            or local_address is not None
            or socket_options is not None
        ):
            raise TransportError("destination_refused")
        if host == "sam.gov" or host.endswith(".sam.gov"):
            raise TransportError("destination_refused")
        self._used = True
        self._state.timeout(5.0, timeout)
        raw, address = self._state.call(lambda: _first_socket(self._approved))
        try:
            stream = self._state.call(lambda: OwnedStream(raw, self._approved, self._context, self._state))
        except BaseException:
            self._state.close(raw.close)
            raise
        stream.connect(address, timeout)
        return stream

    def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None
    ) -> httpcore.NetworkStream:
        raise TransportError("destination_refused")

    def sleep(self, seconds: float) -> None:
        raise TransportError("invalid_response")


_CORE_ERRORS = (
    (httpcore.ConnectTimeout, httpx.ConnectTimeout, "timeout"),
    (httpcore.ReadTimeout, httpx.ReadTimeout, "timeout"),
    (httpcore.WriteTimeout, httpx.WriteTimeout, "connection_failure"),
    (httpcore.PoolTimeout, httpx.PoolTimeout, "connection_failure"),
    (httpcore.ConnectError, httpx.ConnectError, "connection_failure"),
    (httpcore.ReadError, httpx.ReadError, "invalid_response"),
    (httpcore.WriteError, httpx.WriteError, "invalid_response"),
    (httpcore.LocalProtocolError, httpx.LocalProtocolError, "invalid_response"),
    (httpcore.RemoteProtocolError, httpx.RemoteProtocolError, "invalid_response"),
    (httpcore.UnsupportedProtocol, httpx.UnsupportedProtocol, "invalid_response"),
    (httpcore.ProxyError, httpx.ProxyError, "connection_failure"),
)


@contextmanager
def core_errors() -> Iterator[None]:
    try:
        yield
    except Exception as error:
        for core_type, client_type, message in _CORE_ERRORS:
            if isinstance(error, core_type):
                raise client_type(message) from error
        raise


class OwnedResponseStream(httpx.SyncByteStream):
    def __init__(self, response: httpcore.Response, state: OwnedState) -> None:
        self._response, self._state = response, state
        self._closed = False

    def __iter__(self) -> Iterator[bytes]:
        stream = self._response.stream
        if not isinstance(stream, Iterable):
            raise TransportError("invalid_response")
        with core_errors():
            yield from stream

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._state.close(self._response.close)


class OwnedHTTPTransport(httpx.BaseTransport):
    def __init__(self, context: ssl.SSLContext, approved: ApprovedHost, state: OwnedState) -> None:
        self._state = state
        self._closed = False
        self._pool = httpcore.ConnectionPool(
            ssl_context=context,
            proxy=None,
            max_connections=1,
            max_keepalive_connections=0,
            http1=True,
            http2=False,
            retries=0,
            local_address=None,
            uds=None,
            socket_options=None,
            network_backend=OwnedBackend(approved, context, state),
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if self._closed or not isinstance(request.stream, httpx.SyncByteStream):
            raise TransportError("invalid_response")
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        with core_errors():
            response = self._pool.handle_request(core_request)
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=OwnedResponseStream(response, self._state),
            extensions=response.extensions,
        )

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._state.close(self._pool.close)
            self._state.close_all()
