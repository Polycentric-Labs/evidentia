"""Synthetic enterprise session timing, retry and cancellation boundaries."""

from __future__ import annotations

import json
import socket
import ssl
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from evidentia_collectors.enterprise_retention import _client as c
from evidentia_collectors.enterprise_retention import _contracts as m
from evidentia_collectors.enterprise_retention import _credentials as cred
from evidentia_collectors.enterprise_retention import _profiles as p
from evidentia_core import network_guard as guard

CA_PEM = b"""-----BEGIN CERTIFICATE-----
MIIC8zCCAdugAwIBAgIBATANBgkqhkiG9w0BAQsFADAxMS8wLQYDVQQDDCZTeW50
aGV0aWMgZW50ZXJwcmlzZSByZXRlbnRpb24gdGVzdCBDQTAeFw0yMDAxMDEwMDAw
MDBaFw00MDAxMDEwMDAwMDBaMDExLzAtBgNVBAMMJlN5bnRoZXRpYyBlbnRlcnBy
aXNlIHJldGVudGlvbiB0ZXN0IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAkZGoJHyq1fQRP8YESGQQLc43CubPRNeTjcFXV8Feh2U41PoiKktKHpzT
y5H+QE3ucyv4ub5IWPY2N8/rRjrRGxqZfHnjyUGg89bLG+xlauUMHnNmPnCZ+KcU
o6r7tLYcK3sGo0QnpjapcCF4GHY9UxYFCyxWy4zfKE0PeoWtvphsqz9JN9UkDBV7
0+GUFp+FnihH5RjSbtvIZA1z8N45z5YRIYePFOHDs3HARbGfg2xydaRDxhzhCN/H
CI0qIf5sm8ym/Vd2MwQvgpoUtfFG8axDShSLCV5nyFPXWO6Ddb/l9xH6HDgbjh1O
00rmDMvQ3Alzrgj4IWUMd6nXFq9qcQIDAQABoxYwFDASBgNVHRMBAf8ECDAGAQH/
AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQAqAbmeqJAcJTtxWWTUVtph0SxvaUAZ0y/G
DRrvrAcKLjZXpAwIXgwXe5VPRIh3BrBPcykUG7PWN8ZDXoMy3vLAVj3DJV3dnH65
cG16cak+5yfhmQynUbKicq4K/LMzOeyBqXOFFsZQwkkhPPwmTb2sbtlogNaqL7DD
bYdAXN9WHJq60/HVDhLP9y6Cysyd2I850PuuaVLzaEbjsK+L1SReBqkS47zLULqZ
vrfO+wJy7nagkqZWVU57PaTp5w08uKYcVS5AbeHtYpP6th5Tb2y4TOvxLFFXPvk+
12VdBQqF0WyRlg5Rk6Kbd2UXfGUgH0CDnT5Qur9FOHr/ctpPq35F
-----END CERTIFICATE-----
"""

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


class Body(httpx.SyncByteStream):
    def __init__(
        self, chunks: tuple[bytes, ...], error: BaseException | None = None, close_error: BaseException | None = None
    ) -> None:
        self.chunks = chunks
        self.error = error
        self.close_error = close_error
        self.closes = 0

    def __iter__(self) -> Iterator[bytes]:
        yield from self.chunks
        if self.error is not None:
            raise self.error

    def close(self) -> None:
        self.closes += 1
        if self.close_error is not None:
            raise self.close_error


class Transport(httpx.MockTransport):
    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        super().__init__(handler)
        self.closes = 0

    def close(self) -> None:
        self.closes += 1


class Wire:
    def __init__(self, patch: pytest.MonkeyPatch, count: int = 1) -> None:
        self.seconds = 0.0
        self.wall = 0.0
        self.after_request = False
        self.late_utc: Callable[[], None] | None = None
        self.expires: datetime | None = None
        self.lookups = 0
        self.resolutions = 0
        self.sleeps: list[float] = []
        self.requests: list[httpx.Request] = []
        self.transports: list[Transport] = []
        self.bodies: list[Body] = []
        self.handler: Callable[[httpx.Request], httpx.Response] = self.success
        self.request = m.validated_request(
            {
                "provider": "splunk-enterprise",
                "profile_alias": "review",
                "scope_label": "synthetic",
                "targets": [{"index": f"index-{n}"} for n in range(count)],
            }
        )
        self.profile = p.FrozenProfile(
            alias="review",
            provider="splunk-enterprise",
            origin="https://splunk.example.invalid:8089",
            credential_ref="ENTERPRISE_RETENTION_SYNTHETIC_TOKEN",
            address_policy=p.AddressPolicy("public"),
            ca_bytes=CA_PEM,
        )
        patch.setattr(socket, "getaddrinfo", self.dns)
        patch.setattr(guard, "_GETADDRINFO_DELEGATE", self.dns)
        patch.setattr(guard._pin_state, "hosts", {}, raising=False)
        patch.setattr(guard, "_offline_enabled", False)

    def dns(self, host: Any, port: Any, *args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        self.lookups += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port))]

    def utc(self) -> datetime:
        if self.after_request and self.late_utc is not None:
            effect, self.late_utc = (self.late_utc, None)
            effect()
        return EPOCH + timedelta(seconds=self.wall)

    def tick(self) -> float:
        return self.seconds

    def resolve(self, profile: p.FrozenProfile) -> cred.CredentialMaterial:
        assert self.lookups > 0
        self.resolutions += 1
        return cred.CredentialMaterial(profile.provider, "synthetic-credential", self.expires)

    def sleep(self, delay: float) -> None:
        self.sleeps.append(delay)
        self.seconds += delay
        self.wall += delay

    def success(self, request: httpx.Request) -> httpx.Response:
        data = {"entry": [{"name": request.url.path.rsplit("/", 1)[-1], "content": {"datatype": "event"}}]}
        body = Body((json.dumps(data).encode(),))
        self.bodies.append(body)
        return httpx.Response(200, stream=body)

    def send(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.handler(request)

    def factory(self, context: ssl.SSLContext) -> httpx.BaseTransport:
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        transport = Transport(self.send)
        self.transports.append(transport)
        return transport

    def session(self) -> c.EnterpriseReadSession:
        return c.EnterpriseReadSession(
            self.request,
            profile=p.AuthorizedProfile(self.profile, self),
            transport_factory=self.factory,
            utc_clock=self.utc,
            monotonic_clock=self.tick,
            sleep=self.sleep,
            run_id_factory=lambda: "01K00000000000000000000000",
        )

    def collect(self, session: c.EnterpriseReadSession | None = None) -> m.EnterpriseRetentionCollectResult:
        selected = self.session() if session is None else session
        resources = []
        with selected:
            for target in self.request.root.targets:
                assert isinstance(target, m.SplunkIndexTarget)
                handle = selected.read_splunk_index(target, project)
                resources.append(selected.finish_resource(target, reads=(handle,)))
            return selected.finish(tuple(resources))


def project(response: c.ParsedResponse, subject: c.ReadSubject) -> c.ProjectedPage:
    entries = response.data["entry"]
    assert isinstance(entries, list) and isinstance(entries[0], dict)
    expected = m.expected_fields(subject.kind, entries[0])
    return c.ProjectedPage(
        (c.ProjectedRecord(0, subject.source_id, "index", expected.fields, expected.coverage, expected.diagnostics),)
    )


def mark_request_construction(patch: pytest.MonkeyPatch, wire: Wire) -> None:
    original = httpx.Request

    def constructed(*args: Any, **kwargs: Any) -> httpx.Request:
        result = original(*args, **kwargs)
        wire.after_request = True
        return result

    patch.setattr(httpx, "Request", constructed)


class Cancelled(BaseException):
    pass


@pytest.mark.parametrize("failure", [httpx.ReadTimeout, httpx.ReadError, httpx.ConnectTimeout, httpx.ConnectError])
def test_transport_exception_subclasses_are_not_retry_authority(
    monkeypatch: pytest.MonkeyPatch, failure: type[httpx.TransportError]
) -> None:
    wire = Wire(monkeypatch)
    different_failure = type("DifferentFailure", (failure,), {})

    def fail(request: httpx.Request) -> httpx.Response:
        raise different_failure("synthetic private transport detail")

    wire.handler = fail
    result = wire.collect()
    read = result.root.source_reads[0]
    assert read.terminal_reason == ("timeout" if issubclass(failure, httpx.TimeoutException) else "transport_failed")
    assert read.attempts == 1 and wire.sleeps == []
    assert all(t.closes == 1 for t in wire.transports)
    assert b"synthetic private transport detail" not in result.publication_bytes()


def test_401_latch_precedes_invalid_encoding_and_retry_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = Wire(monkeypatch, count=2)
    body = Body((b"{invalid",))
    wire.handler = lambda request: httpx.Response(
        401,
        headers=[("Content-Encoding", "br"), ("Content-Encoding", "gzip"), ("Retry-After", "1"), ("Retry-After", "2")],
        stream=body,
    )
    result = wire.collect()
    assert result.root.source_reads[0].terminal_reason == "credential_rejected"
    assert result.root.source_reads[0].raw_bytes == 0
    assert result.root.source_reads[1].attempts == 0
    assert wire.resolutions == wire.lookups == len(wire.requests) == 1
    assert wire.sleeps == [] and body.closes == 1
    assert all(t.closes == 1 for t in wire.transports)
    assert {d.code for d in result.root.diagnostics} == {"credential_rejected"}


def test_known_expiry_during_retry_wait_never_refreshes_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = Wire(monkeypatch, count=2)
    wire.expires = EPOCH + timedelta(seconds=1)
    body = Body((b"retry",))
    wire.handler = lambda request: httpx.Response(503, stream=body)
    result = wire.collect()
    assert len(wire.requests) == 1 and wire.resolutions == 1
    assert wire.sleeps == [1.0] and wire.lookups == 2
    assert any(d.code == "credential_expired" for d in result.root.diagnostics)
    assert result.root.source_reads[1].attempts == 0
    assert all(t.closes == 1 for t in wire.transports)


@pytest.mark.parametrize(
    "elapsed,expires,expected_send", [(2.0, 2.0, False), (1.0, 0.5, False), (1.5, 2.0, True), (0.0, 1e-06, True)]
)
def test_final_monotonic_sample_accounts_for_coherent_elapsed_expiry(
    monkeypatch: pytest.MonkeyPatch, elapsed: float, expires: float, expected_send: bool
) -> None:
    wire = Wire(monkeypatch)
    wire.expires = EPOCH + timedelta(seconds=expires)
    post_request_utc = 0
    pending_elapsed = False

    def utc() -> datetime:
        nonlocal post_request_utc, pending_elapsed
        if wire.after_request:
            post_request_utc += 1
            if post_request_utc == 2:
                pending_elapsed = True
        return EPOCH + timedelta(seconds=wire.wall)

    def tick() -> float:
        nonlocal pending_elapsed
        if pending_elapsed:
            pending_elapsed = False
            wire.seconds += elapsed
            wire.wall += elapsed
        return wire.seconds

    monkeypatch.setattr(wire, "utc", utc)
    monkeypatch.setattr(wire, "tick", tick)
    mark_request_construction(monkeypatch, wire)
    result = wire.collect()
    assert bool(wire.requests) is expected_send
    if expected_send:
        assert result.root.status == "complete"
    else:
        assert {d.code for d in result.root.diagnostics} == {"credential_expired"}
        assert result.root.source_reads[0].responses_received == 0
    assert wire.resolutions == 1 and all(t.closes == 1 for t in wire.transports)


def test_each_retry_uses_its_own_fresh_timeout_and_destination(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = Wire(monkeypatch)
    calls = 0

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            wire.seconds = wire.wall = 117.0
            raise httpx.ConnectTimeout("synthetic delayed connect")
        return wire.success(request)

    wire.handler = handle
    result = wire.collect()
    assert result.root.status == "complete"
    assert wire.requests[0].extensions["timeout"] == {"connect": 5.0, "pool": 5.0, "read": 20.0, "write": 20.0}
    assert wire.requests[1].extensions["timeout"] == {"connect": 2.0, "pool": 2.0, "read": 2.0, "write": 2.0}
    assert wire.resolutions == 1 and wire.lookups == 2 and (len(wire.transports) == 2)
    assert wire.sleeps == [1.0] and all(t.closes == 1 for t in wire.transports)


def test_retry_sleep_cancellation_restores_attempt_and_marks_session_broken(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = Wire(monkeypatch)
    primary = Cancelled("synthetic sleep cancellation")
    body = Body((b"retry",))
    wire.handler = lambda request: httpx.Response(503, stream=body)

    def cancelled_sleep(delay: float) -> None:
        assert delay == 1.0
        raise primary

    monkeypatch.setattr(wire, "sleep", cancelled_sleep)
    session = wire.session()
    target = wire.request.root.targets[0]
    assert isinstance(target, m.SplunkIndexTarget)
    with pytest.raises(Cancelled) as caught:
        session.read_splunk_index(target, project)
    assert caught.value is primary
    assert body.closes == 1 and all(t.closes == 1 for t in wire.transports)
    assert wire.lookups == wire.resolutions == len(wire.requests) == 1
    assert guard._pin_state.hosts == {}
    with pytest.raises(c.EnterpriseRetentionOperationalError):
        session.read_splunk_index(target, project)
    session.__exit__(None, None, None)
    assert session._credential is None
