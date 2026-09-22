"""Release HTTP contract examples; all transport is synthetic and local."""

from __future__ import annotations

import gzip
from contextlib import contextmanager

import httpx
import pytest
from evidentia_collectors.release_cadence import _http
from evidentia_core.release_cadence._limits import ReleaseFailure, start_budget


def link(page: str, relation: str = "next") -> bytes:
    return f"<https://api.github.com/repos/Allen/Example/releases?per_page=100&page={page}>; rel={relation}".encode()


@pytest.mark.parametrize(
    "raw, expected",
    [
        ((), None),
        ((link("2"),), 2),
        ((link("1", '"first"') + b", " + link("2", '"next"'),), 2),
        ((link("1", "last"),), None),
        ((b' \t<https://api.github.com/repos/allen/example/releases?page=2&per_page=100>\t; rel = "next" ',), 2),
    ],
)
def test_complete_link_grammar(raw, expected):
    assert _http.next_page(raw, "allen", "example", 1) == expected


@pytest.mark.parametrize(
    "raw",
    [
        (b"",),
        (link("02"),),
        (link("+2"),),
        (link("3"),),
        (link("1", "prev"),),
        (link("2", "last"),),
        (link("2"), link("2")),
        (link("2") + b",",),
        (link("2").replace(b"rel=", b"REL="),),
        (link("2").replace(b"next", b'"next last"'),),
        (link("2") + b"; title=x",),
        (link("2").replace(b"api.github.com", b"api.github.com:443"),),
        (link("2").replace(b"Allen", b"Other"),),
        (link("2").replace(b"page=2", b"page=2&page=2"),),
        (link("2").replace(b"Example/releases", b"Example/releases/"),),
        (link("2").replace(b"Example", b"%45xample"),),
        (link("2").replace(b"page=2", b"page=9007199254740992"),),
        (link("2") + b"\r\n",),
    ],
)
def test_link_refusals(raw):
    with pytest.raises(ReleaseFailure, match="release operation") as found:
        _http.next_page(raw, "allen", "example", 1)
    assert found.value.reason == "unsupported_link"


class Stream(httpx.SyncByteStream):
    def __init__(self, chunks, *, failure=None, cleanup=None):
        self.chunks = chunks
        self.failure = failure
        self.cleanup = cleanup
        self.reads = 0
        self.closed = 0

    def __iter__(self):
        for item in self.chunks:
            self.reads += 1
            yield item
        if self.failure is not None:
            raise self.failure

    def close(self):
        self.closed += 1
        if self.cleanup is not None:
            raise self.cleanup


def install(monkeypatch, stream, headers=None, status=200, *, cleanup=None):
    calls = []
    response = httpx.Response(status, headers=headers or [(b"content-type", b"application/json")], stream=stream)

    @contextmanager
    def approved(url):
        calls.append(("approved", url))
        yield object()

    class Transport:
        def __init__(self, **kwargs):
            calls.append(("transport", kwargs))

        def handle_request(self, request):
            calls.append(("request", request))
            return response

        def close(self):
            calls.append(("close",))
            if cleanup is not None:
                raise cleanup

    monkeypatch.setattr(_http, "approved_destination", approved)
    monkeypatch.setattr(_http, "tls_context", lambda: object())
    monkeypatch.setattr(_http, "OwnedHTTPTransport", Transport)
    return calls


def fetch():
    attempt = _http.HttpAttempt()
    totals = _http.EntityTotals()
    value = attempt.fetch("Allen", "Example", 1, budget=start_budget(), totals=totals)
    return attempt, totals, value


def test_identity_capture_and_fixed_request(monkeypatch):
    stream = Stream([b"[", b"]"])
    calls = install(monkeypatch, stream)
    attempt, totals, body = fetch()
    assert body == b"[]" and attempt.body_complete
    assert attempt.body_sha256 == "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
    assert (totals.raw, totals.decoded, attempt.raw, attempt.decoded) == (2, 2, 2, 2)
    assert stream.closed == 1
    request = next(row[1] for row in calls if row[0] == "request")
    assert str(request.url) == "https://api.github.com/repos/allen/example/releases?per_page=100&page=1"
    assert dict(request.headers) == {
        "host": "api.github.com",
        "accept": "application/vnd.github+json",
        "x-github-api-version": "2026-03-10",
        "user-agent": "evidentia-collectors",
        "accept-encoding": "gzip, identity",
        "connection": "close",
    }
    assert request.method == "GET"
    assert request.extensions["timeout"]["connect"] <= 5.0
    assert request.extensions["timeout"]["read"] <= 10.0


@pytest.mark.parametrize(
    "status,reason",
    [
        (301, "redirect_refused"),
        (401, "upstream_unauthorized"),
        (403, "upstream_forbidden"),
        (404, "upstream_not_found"),
        (429, "upstream_rate_limited"),
        (503, "upstream_server_error"),
        (204, "upstream_http_error"),
    ],
)
def test_non200_never_reads_body(monkeypatch, status, reason):
    stream = Stream([b"uninterpreted"])
    install(monkeypatch, stream, status=status)
    with pytest.raises(ReleaseFailure) as found:
        fetch()
    assert found.value.reason == reason
    assert stream.reads == 0 and stream.closed == 1


@pytest.mark.parametrize(
    "headers,reason",
    [
        ([(b"content-type", b"text/plain")], "unsupported_media"),
        ([(b"content-type", b"application/json"), (b"content-type", b"application/json")], "unsupported_media"),
        ([(b"content-type", b"application/json; charset=utf-8; q=1")], "unsupported_media"),
        ([(b"content-type", b"application/json"), (b"content-encoding", b"br")], "unsupported_encoding"),
        ([(b"content-type", b"application/json"), (b"content-length", b"+2")], "invalid_response"),
        (
            [(b"content-type", b"application/json"), (b"content-length", b"2"), (b"transfer-encoding", b"chunked")],
            "invalid_response",
        ),
        ([(b"content-type", b"application/json")] + [(b"x", b"y")] * 64, "invalid_response"),
    ],
)
def test_header_refusal_precedes_body(monkeypatch, headers, reason):
    stream = Stream([b"[]"])
    install(monkeypatch, stream, headers)
    with pytest.raises(ReleaseFailure) as found:
        fetch()
    assert found.value.reason == reason
    assert stream.reads == 0 and stream.closed == 1


@pytest.mark.parametrize("mode", ["single", "truncated", "trailing", "concatenated", "bad-trailer"])
def test_one_complete_gzip_member(monkeypatch, mode):
    raw = gzip.compress(b"[]", mtime=0)
    if mode == "truncated":
        raw = raw[:-1]
    elif mode == "trailing":
        raw += b"x"
    elif mode == "concatenated":
        raw += gzip.compress(b"[]", mtime=0)
    elif mode == "bad-trailer":
        raw = raw[:-1] + bytes([raw[-1] ^ 1])
    stream = Stream([raw[:7], raw[7:]])
    install(
        monkeypatch, stream, [(b"content-type", b'Application/Json; Charset="UTF-8"'), (b"content-encoding", b"gzip")]
    )
    if mode == "single":
        attempt, totals, body = fetch()
        assert body == b"[]" and attempt.body_complete
        assert totals.decoded == 2 and totals.raw == len(raw)
    else:
        with pytest.raises(ReleaseFailure) as found:
            fetch()
        assert found.value.reason == "invalid_response"
    assert stream.closed == 1


@pytest.mark.parametrize("gzip_mode", [False, True])
def test_exact_body_limit_and_plus_one(monkeypatch, gzip_mode):
    # Exercise the real 4 MiB cap without a giant allocation or source fixture.
    cap = 4_194_304
    for extra in (0, 1):
        payload = b" " * cap + b"x" * extra
        wire = gzip.compress(payload, mtime=0) if gzip_mode else payload
        headers = [(b"content-type", b"application/json")]
        if gzip_mode:
            headers.append((b"content-encoding", b"gzip"))
        stream = Stream([wire[pos : pos + 65536] for pos in range(0, len(wire), 65536)])
        install(monkeypatch, stream, headers)
        attempt, totals = _http.HttpAttempt(), _http.EntityTotals()
        if extra:
            with pytest.raises(ReleaseFailure) as found:
                attempt.fetch("allen", "example", 1, budget=start_budget(), totals=totals)
            assert found.value.reason == ("decoded_limit" if gzip_mode else "raw_limit")
            assert totals.decoded == cap + 1
            assert not attempt.body_complete
        else:
            assert attempt.fetch("allen", "example", 1, budget=start_budget(), totals=totals) == payload
            assert attempt.body_complete
        assert stream.closed == 1


def test_delivered_chunk_is_charged_before_deadline(monkeypatch):
    budget = start_budget()

    class Expiring(Stream):
        def __iter__(self):
            object.__setattr__(budget, "deadline", 0.0)
            yield b"[]"

    stream = Expiring([])
    install(monkeypatch, stream)
    attempt, totals = _http.HttpAttempt(), _http.EntityTotals()
    with pytest.raises(ReleaseFailure) as found:
        attempt.fetch("allen", "example", 1, budget=budget, totals=totals)
    assert found.value.reason == "clock_invalid"
    assert (totals.raw, totals.decoded) == (2, 2)
    assert stream.closed == 1


def test_cancellation_identity_survives_cleanup(monkeypatch):
    primary, secondary = KeyboardInterrupt(), SystemExit()
    stream = Stream([], failure=primary, cleanup=secondary)
    install(monkeypatch, stream, cleanup=RuntimeError())
    with pytest.raises(KeyboardInterrupt) as found:
        fetch()
    assert found.value is primary and stream.closed == 1


def test_cleanup_cancellation_on_success_is_visible(monkeypatch):
    secondary = SystemExit()
    stream = Stream([b"[]"], cleanup=secondary)
    install(monkeypatch, stream)
    with pytest.raises(SystemExit) as found:
        fetch()
    assert found.value is secondary


def test_refused_oversize_chunk_and_one_use(monkeypatch):
    stream = Stream([b" " * 65537])
    calls = install(monkeypatch, stream)
    attempt, totals = _http.HttpAttempt(), _http.EntityTotals()
    with pytest.raises(ReleaseFailure) as found:
        attempt.fetch("allen", "example", 1, budget=start_budget(), totals=totals)
    assert found.value.reason == "invalid_response" and totals.raw == 0
    with pytest.raises(ReleaseFailure):
        attempt.fetch("allen", "example", 1, budget=start_budget(), totals=totals)
    assert sum(row[0] == "request" for row in calls) == 1


@pytest.mark.parametrize("length", [1, 3])
def test_incomplete_framing_never_labels_prefix_digest_complete(monkeypatch, length):
    stream = Stream([b"[]"])
    install(monkeypatch, stream, [(b"content-type", b"application/json"), (b"content-length", str(length).encode())])
    attempt, totals = _http.HttpAttempt(), _http.EntityTotals()
    with pytest.raises(ReleaseFailure) as found:
        attempt.fetch("Allen", "Example", 1, budget=start_budget(), totals=totals)
    assert found.value.reason == "invalid_response"
    assert attempt.raw == totals.raw == 2 and attempt.decoded == totals.decoded == 2
    assert not attempt.raw_body_complete and attempt.raw_body_sha256 is None
    assert not attempt.body_complete and attempt.body_sha256 is None
    assert stream.closed == 1


@pytest.mark.parametrize(
    "mode", ["complete", "mixed_dns", "handshake_cancel", "read_cancel", "close_cancel", "tls_failure", "dns_deadline"]
)
def test_actual_composed_transport_pins_and_cleans_owned_resources(monkeypatch, mode):
    import socket
    import ssl

    from evidentia_collectors.registries import _http_backend
    from evidentia_core import network_guard

    monkeypatch.delenv("EVIDENTIA_OFFLINE", raising=False)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    clock = [100.0]
    if mode == "dns_deadline":
        from evidentia_core.release_cadence import _limits

        monkeypatch.setattr(_limits.time, "monotonic", lambda: clock[0])
    primary = KeyboardInterrupt("Synthetic composed transport interruption.")
    observations = []
    connections = []
    requests = []
    dns = []
    answer = ["8.8.8.8", "127.0.0.1" if mode == "mixed_dns" else "1.1.1.1"]

    def resolver(host, port, family=0, kind=0, protocol=0, flags=0):
        dns.append((host, port))
        if mode == "dns_deadline" and host == b"api.github.com":
            clock[0] = 146.0
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443)) for address in answer]

    class WireSocket:
        def __init__(self, secured=False):
            self.secured = secured
            self.closed = 0
            self.reply = (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]"
            )

        def settimeout(self, timeout):
            assert 0 < timeout <= 10

        def setsockopt(self, *args):
            assert args == (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        def connect(self, address):
            assert address == ("8.8.8.8", 443)
            connections.append(address)

        def do_handshake(self):
            observations.append("handshake")
            if mode == "handshake_cancel":
                raise primary
            if mode == "tls_failure":
                raise ssl.SSLCertVerificationError("Synthetic hostname verification refusal.")

        def selected_alpn_protocol(self):
            return "http/1.1"

        def send(self, data):
            requests.append(data)
            return len(data)

        def recv(self, maximum):
            if mode == "read_cancel":
                raise primary
            value, self.reply = self.reply[:maximum], self.reply[maximum:]
            return value

        def close(self):
            self.closed += 1
            if self.secured and mode == "close_cancel":
                raise primary

    raw, secured = WireSocket(), WireSocket(True)
    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", network_guard._GETADDRINFO_DELEGATE)
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: raw)

    def wrap(stream, context):
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        assert context.minimum_version >= ssl.TLSVersion.TLSv1_2 and context.keylog_filename is None
        assert stream._approved.host == "api.github.com"
        observations.append("verified_context")
        return secured

    monkeypatch.setattr(_http_backend.OwnedStream, "_wrap", wrap)
    # The real approve/pin/backend/httpcore/HTTPX/attempt composition remains active.
    with network_guard.pin_resolved_host("api.github.com", ["9.9.9.9"]):
        before = socket.getaddrinfo("api.github.com", 443, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        if mode == "mixed_dns":
            with pytest.raises(ReleaseFailure) as found:
                fetch()
            assert found.value.reason == "destination_refused"
        elif mode in {"tls_failure", "dns_deadline"}:
            with pytest.raises(ReleaseFailure) as found:
                fetch()
            assert found.value.reason == ("tls_failure" if mode == "tls_failure" else "deadline_exceeded")
        elif mode == "complete":
            attempt, totals, value = fetch()
            assert value == b"[]" and attempt.body_complete and totals.raw == totals.decoded == 2
        else:
            with pytest.raises(KeyboardInterrupt) as found:
                fetch()
            assert found.value is primary
        after = socket.getaddrinfo("api.github.com", 443, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        assert before == after
    # The installed wrapper is permanent; only thread-local pin state is restored.
    restored = socket.getaddrinfo("api.github.com", 443, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    assert [row[4][0] for row in restored] == answer
    assert dns == [(b"api.github.com", 443), ("api.github.com", 443)]
    if mode in {"mixed_dns", "dns_deadline"}:
        assert connections == [] and observations == [] and raw.closed == secured.closed == 0
    else:
        assert connections == [("8.8.8.8", 443)] and raw.closed == secured.closed == 1
        assert observations == ["verified_context", "handshake"]
    if requests:
        sent = b"".join(requests).lower()
        assert sent.startswith(b"get /repos/allen/example/releases?per_page=100&page=1 http/1.1\r\n")
        assert b"authorization:" not in sent and b"proxy-authorization:" not in sent and b"cookie:" not in sent


@pytest.mark.parametrize(
    "raw",
    [
        link("2").replace(b"per_page=100", b"per_page=100&per_page=100"),
        link("2") + b", " + link("2"),
        link("2").replace(b"rel=next", b'rel="ne\\xt"'),
        link("2").replace(b"https://", b"http://"),
        link("2").replace(b"api.github.com", b"other.example"),
        link("2").replace(b"api.github.com", b"api.github.com:444"),
        link("2").replace(b"Example/releases", b"Other/releases"),
        link("2").replace(b"/repos/", b"/other/"),
        link("2").replace(b">", b"#fragment>"),
    ],
)
def test_remaining_declared_link_grammar_refusals(raw):
    with pytest.raises(ReleaseFailure) as found:
        _http.next_page((raw,), "allen", "example", 1)
    assert found.value.reason == "unsupported_link"
