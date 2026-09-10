"""Synthetic controls for bounded shared HTTP processing."""

from __future__ import annotations

import gzip
import importlib
import logging
import socket
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

client = importlib.import_module("evidentia_collectors.retention._client")


class Stream(httpx.SyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        yield from self.chunks

    def close(self) -> None:
        self.closed = True


def read(chunks: list[bytes], encoding: str = "identity", ceiling: int = 1024) -> tuple[bytes, list[int], Stream]:
    counts = [0, 0]
    stream = Stream(chunks)
    response = httpx.Response(200, headers={"Content-Encoding": encoding}, stream=stream)

    def consume(raw: int, decoded: int) -> None:
        counts[0] += raw
        counts[1] += decoded

    try:
        result = client.read_bounded_body(response, consume=consume, max_bytes=ceiling)
    finally:
        response.close()
    return result, counts, stream


@pytest.mark.parametrize("encoding", ["identity", "gzip"])
def test_full_body_exact_bytes_and_measured_counts(encoding: str) -> None:
    payload = b'{"selected":true,"duration":7}'
    encoded = gzip.compress(payload, mtime=0) if encoding == "gzip" else payload
    result, counts, stream = read([encoded[:3], encoded[3:11], encoded[11:]], encoding)
    assert result == payload
    assert counts == [len(encoded), len(payload)]
    assert stream.closed


def test_exact_byte_ceiling_and_zero_length() -> None:
    assert read([b"abcd"], ceiling=4)[0] == b"abcd"
    assert read([], ceiling=1)[0] == b""


def test_refused_raw_chunk_is_counted_before_any_prefix_admission() -> None:
    counts = [0, 0]
    response = httpx.Response(200, stream=Stream([b"12", b"3456"]))

    def consume(raw: int, decoded: int) -> None:
        counts[0] += raw
        counts[1] += decoded

    with pytest.raises(client.ClientFault) as caught:
        client.read_bounded_body(response, consume=consume, max_bytes=5)
    assert caught.value.code == "response_limit"
    assert counts == [6, 6]
    response.close()


@pytest.mark.parametrize("encoding", ["br", "deflate", "gzip, identity", "gzip,gzip", ""])
def test_unsupported_encodings_refuse(encoding: str) -> None:
    with pytest.raises(client.ClientFault) as caught:
        read([b"x"], encoding)
    assert caught.value.code == "invalid_response"


@pytest.mark.parametrize("variant", ["truncated", "trailing", "concatenated", "invalid"])
def test_gzip_requires_exactly_one_complete_member(variant: str) -> None:
    encoded = gzip.compress(b"test", mtime=0)
    payload = {
        "truncated": encoded[:-1],
        "trailing": encoded + b"x",
        "concatenated": encoded + encoded,
        "invalid": b"invalid",
    }[variant]
    with pytest.raises(client.ClientFault) as caught:
        read([payload[:10], payload[10:]], "gzip")
    assert caught.value.code == "invalid_response"


def test_gzip_expansion_is_bounded_and_counted() -> None:
    encoded = gzip.compress(b"x" * 4096, mtime=0)
    with pytest.raises(client.ClientFault) as caught:
        read([encoded], "gzip", ceiling=64)
    assert caught.value.code == "response_limit"


@pytest.mark.parametrize(
    "header",
    [
        None,
        "1",
        "00001",
        "Thu, 10 Sep 2026 00:00:01 GMT",
        "Thursday, 10-Sep-26 00:00:01 GMT",
        "Thu Sep 10 00:00:01 2026",
    ],
)
def test_retry_delay_all_supported_forms(header: str | None) -> None:
    assert client.retry_delay(header, attempt=1, now=datetime(2026, 9, 10, tzinfo=UTC), remaining=10.0) == 1


@pytest.mark.parametrize(
    "header",
    ["", "-1", "+1", "1.0", "1e1", "tomorrow", "31", "999999999999999999999999", "Mon, 01 Jan 10000 00:00:00 GMT"],
)
def test_retry_delay_rejects_invalid_or_over_budget(header: str) -> None:
    with pytest.raises(client.ClientFault):
        client.retry_delay(header, attempt=1, now=datetime(2026, 9, 10, tzinfo=UTC), remaining=30.0)


def test_retry_budget_never_retries_early() -> None:
    with pytest.raises(client.ClientFault) as caught:
        client.retry_delay("3", attempt=1, now=datetime(2026, 9, 10, tzinfo=UTC), remaining=2.0)
    assert caught.value.code == "run_budget_exhausted"
    assert (
        client.retry_delay(
            "Thu, 10 Sep 2026 00:00:00 GMT", attempt=1, now=datetime(2026, 9, 10, 0, 0, 1, tzinfo=UTC), remaining=2.0
        )
        == 0
    )


def test_transport_filter_is_context_local_and_nested(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("httpx")
    caplog.set_level(logging.INFO, logger="httpx")
    with client.quiet_transport_logs():
        logger.info("local-synthetic-marker")
        with client.quiet_transport_logs():
            logger.info("nested-synthetic-marker")
        thread = threading.Thread(target=lambda: logger.info("other-thread-marker"))
        thread.start()
        thread.join(timeout=2)
        assert not thread.is_alive()
        logger.info("restored-nested-marker")
    logger.info("outside-marker")
    assert [item.message for item in caplog.records] == ["other-thread-marker", "outside-marker"]


def test_transport_filter_restores_after_exception(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("httpcore.connection")
    caplog.set_level(logging.INFO, logger=logger.name)
    with pytest.raises(RuntimeError), client.quiet_transport_logs():
        logger.info("hidden-marker")
        raise RuntimeError("synthetic-failure")
    logger.info("visible-marker")
    assert [item.message for item in caplog.records] == ["visible-marker"]


def test_invalid_provider_request_is_rejected_before_credentials() -> None:
    calls = []
    provider = type("Provider", (), {"resolve": lambda self, name: calls.append(name)})()
    with pytest.raises(ValueError):
        client.StorageReadSession({"provider": "s3", "scope_label": "test", "targets": []}, credentials=provider)
    assert calls == []


@pytest.mark.parametrize("value", [float("nan"), float("inf"), True, "1"])
def test_nonfinite_and_invalid_clocks_never_start_io(value: Any) -> None:
    with pytest.raises(ValueError):
        client.StorageRunContext(
            {"provider": "gcs", "scope_label": "test", "targets": [{"bucket": "unit-example"}]},
            monotonic_clock=lambda: value,
        )


def test_run_context_isolated_budget_and_exact_boundary() -> None:
    clock = [0.0]
    request = {"provider": "gcs", "scope_label": "test", "targets": [{"bucket": "unit-example"}]}
    first = client.StorageRunContext(request, monotonic_clock=lambda: clock[0])
    second = client.StorageRunContext(request, monotonic_clock=lambda: clock[0])
    first.consume(4, 6)
    assert (first.raw_bytes, first.decoded_bytes) == (4, 6)
    assert (second.raw_bytes, second.decoded_bytes) == (0, 0)
    assert first.remaining() == 120.0
    clock[0] = 120.0
    with pytest.raises(client.ClientFault) as caught:
        first.remaining()
    assert caught.value.code == "run_budget_exhausted"


def test_run_counter_preserves_refused_overshoot() -> None:
    request = {"provider": "gcs", "scope_label": "test", "targets": [{"bucket": "unit-example"}]}
    context = client.StorageRunContext(request, monotonic_clock=lambda: 0.0)
    with pytest.raises(client.ClientFault) as caught:
        context.consume(client.RUN_MAX_BYTES + 3, 17)
    assert caught.value.code == "run_budget_exhausted"
    assert context.raw_bytes == client.RUN_MAX_BYTES + 3 and context.decoded_bytes == 17


contracts = importlib.import_module("evidentia_collectors.retention._contracts")
materials = importlib.import_module("evidentia_collectors.retention._credentials")


class FakeClock:
    def __init__(self) -> None:
        self.seconds = 0.0
        self.sleeps: list[float] = []

    def utc(self) -> datetime:
        return datetime(2026, 9, 10, tzinfo=UTC) + timedelta(seconds=self.seconds)

    def tick(self) -> float:
        return self.seconds

    def sleep(self, delay: float) -> None:
        self.sleeps.append(delay)
        self.seconds += delay


class FakeCredentials:
    def __init__(self, provider: str, events: list[str]) -> None:
        material = (
            materials.AwsCredentials("SYNTHETIC_ACCESS", "SYNTHETIC_SECRET", "SYNTHETIC_SESSION")
            if provider == "s3"
            else materials.BearerCredentials("SYNTHETIC_BEARER")
        )
        self.resolution = materials.CredentialResolution(material, None)
        self.events = events
        self.calls = 0

    def resolve(self, provider: str) -> Any:
        self.events.append("credentials")
        self.calls += 1
        return self.resolution


class ReplyStream(Stream):
    def __init__(self, reply: dict[str, Any], clock: FakeClock) -> None:
        super().__init__(reply.get("chunks", [reply.get("body", b"{}")]))
        self.reply = reply
        self.clock = clock
        self.close_calls = 0

    def __iter__(self) -> Iterator[bytes]:
        advances = self.reply.get("chunk_seconds", [])
        for index, chunk in enumerate(self.chunks):
            if index < len(advances):
                self.clock.seconds += advances[index]
            yield chunk
        if "read_failure" in self.reply:
            raise self.reply["read_failure"]

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True
        self.clock.seconds += self.reply.get("close_seconds", 0.0)
        if self.reply.get("close_failure"):
            raise RuntimeError("SYNTHETIC_CLOSE_DETAIL")


class Scenario(httpx.BaseTransport):
    def __init__(self, replies: list[Any], events: list[str], clock: FakeClock) -> None:
        self.replies = list(replies)
        self.events = events
        self.clock = clock
        self.requests: list[httpx.Request] = []
        self.streams: list[ReplyStream] = []
        self.close_calls = 0
        self.close_failure = False

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.events.append("send")
        self.requests.append(request)
        addresses = socket.getaddrinfo(request.url.host, 443)
        assert {row[4][0] for row in addresses} == {"8.8.8.8"}
        assert self.replies, "Unexpected synthetic request"
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        self.clock.seconds += reply.get("send_seconds", 0.0)
        stream = ReplyStream(reply, self.clock)
        self.streams.append(stream)
        return httpx.Response(reply.get("status", 200), headers=reply.get("headers", {}), stream=stream)

    def close(self) -> None:
        self.events.append("client_close")
        self.close_calls += 1
        if self.close_failure:
            raise RuntimeError("SYNTHETIC_CLIENT_CLOSE_DETAIL")


@pytest.fixture(autouse=True)
def isolate_synthetic_resolver(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    guard = client.network_guard
    monkeypatch.setattr(guard, "_GETADDRINFO_DELEGATE", guard._GETADDRINFO_DELEGATE)
    monkeypatch.setattr(guard, "_offline_enabled", False)

    def no_network(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Synthetic controls cannot resolve or open a socket")

    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    yield


def session(
    monkeypatch: pytest.MonkeyPatch, replies: list[Any], provider: str = "gcs"
) -> tuple[Any, Scenario, FakeCredentials, FakeClock, list[str]]:
    events: list[str] = []
    clock = FakeClock()
    credential = FakeCredentials(provider, events)
    scenario = Scenario(replies, events, clock)
    if provider == "s3":
        targets = [{"bucket": "unit-example", "region": "us-east-1", "expected_owner": "123456789012"}]
    elif provider == "azure":
        targets = [
            {
                "subscription_id": "11111111-2222-4333-8444-555555555555",
                "resource_group": "rg.test",
                "account": "unitexample",
                "container": "retention",
            }
        ]
    else:
        targets = [{"bucket": "unit-example"}, {"bucket": "next-example"}]

    def public(url: str, *, subsystem: str, block_private: bool = True) -> list[str]:
        assert subsystem == "storage-retention" and block_private
        events.append("dns")
        return ["8.8.8.8"]

    monkeypatch.setattr(client.network_guard, "enforce_public_host", public)
    value = client.StorageReadSession(
        {"provider": provider, "scope_label": "synthetic", "targets": targets},
        credentials=credential,
        transport_factory=lambda: scenario,
        utc_clock=clock.utc,
        monotonic_clock=clock.tick,
        sleep=clock.sleep,
        run_id_factory=lambda: "SYNTHETIC_RUN",
    )
    return value, scenario, credential, clock, events


def project(response: Any, target: Any) -> Any:
    return contracts.ProjectedComponent(
        "synthetic-v1", "configuration", {"observed": True}, source_etag=response.source_etag
    )


def first_read(value: Any, projector: Any = project) -> Any:
    request = value.context.request.root
    return value.read_component(contracts.component_ids(request.provider)[0], request.targets[0], projector)


def codes(result: Any) -> list[str]:
    return [item.code for item in result.diagnostics]


def test_request_snapshot_cannot_change_read_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    value, scenario, _, _, _ = session(monkeypatch, [{}])
    original = value.context.request.root.targets[0]
    leaked = value.context.request
    leaked.root.targets.clear()
    leaked.root.scope_label = "modified"
    assert value.context.request.root.scope_label == "synthetic"
    result = value.read_component("gcs-bucket", original, project)
    assert result.status == "complete"
    assert scenario.requests[0].url.path.endswith("unit-example")
    value.close()


def test_out_of_order_read_refuses_before_dns_or_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    value, _, credential, _, events = session(monkeypatch, [{}])
    target = value.context.request.root.targets[1]
    with pytest.raises(client.ClientFault):
        value.read_component("gcs-bucket", target, project)
    assert credential.calls == 0 and events == []
    assert first_read(value).status == "complete"
    value.close()


@pytest.mark.parametrize("provider", ["s3", "azure", "gcs"])
def test_owned_wire_send_uses_exact_routes_and_no_ambient_state(monkeypatch: pytest.MonkeyPatch, provider: str) -> None:
    value, scenario, credential, _, events = session(
        monkeypatch,
        [
            {
                "body": b"<Synthetic/>" if provider == "s3" else b"{}",
                "headers": {"Set-Cookie": "synthetic=marker; Path=/"},
            }
        ],
        provider,
    )
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    assert first_read(value).status == "complete"
    request = scenario.requests[0]
    assert request.method == "GET" and request.content == b""
    assert request.url == contracts.build_component_url(
        contracts.component_ids(provider)[0], value.context.request.root.targets[0]
    )
    assert request.headers["host"] == request.url.host
    assert "cookie" not in request.headers
    assert set(request.extensions) == {"timeout"}
    assert max(request.extensions["timeout"].values()) <= 20
    assert events[:3] == ["dns", "credentials", "send"] and credential.calls == 1
    if provider == "s3":
        assert request.headers["x-amz-expected-bucket-owner"] == "123456789012"
        assert request.headers["x-amz-security-token"] == "SYNTHETIC_SESSION"
        assert request.headers["authorization"].startswith("AWS4-HMAC-SHA256 ")
    else:
        assert request.headers["authorization"] == "Bearer SYNTHETIC_BEARER"
    value.close()
    value.close()
    assert scenario.close_calls == 1 and all(stream.closed for stream in scenario.streams)


@pytest.mark.parametrize("refusal", ["offline", "private", "empty"])
def test_guards_precede_credential_resolution(monkeypatch: pytest.MonkeyPatch, refusal: str) -> None:
    value, scenario, credential, _, _ = session(monkeypatch, [])
    if refusal == "offline":
        monkeypatch.setattr(client.network_guard, "_offline_enabled", True)
    elif refusal == "empty":
        monkeypatch.setattr(client.network_guard, "enforce_public_host", lambda *args, **kwargs: [])
    else:

        def refuse(*args: Any, **kwargs: Any) -> Any:
            raise client.network_guard.SSRFBlockedError(
                subsystem="synthetic", host="synthetic", resolved_ip="127.0.0.1"
            )

        monkeypatch.setattr(client.network_guard, "enforce_public_host", refuse)
    result = first_read(value)
    assert result.status == "unavailable" and result.attempts == 0
    assert codes(result) == ["offline_refused" if refusal == "offline" else "unsafe_destination"]
    assert scenario.requests == [] and credential.calls == 0
    value.close()


@pytest.mark.parametrize("status", [300, 301, 302, 303, 304, 307, 308, 399])
def test_redirect_never_follows_or_admits(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    value, scenario, _, clock, _ = session(
        monkeypatch, [{"status": status, "headers": {"Location": "https://example.com/redirect"}}]
    )
    result = first_read(value)
    assert codes(result) == ["redirect_refused"] and result.projection is None
    assert len(scenario.requests) == 1 and clock.sleeps == []
    value.close()
    assert scenario.streams[0].closed


@pytest.mark.parametrize("status,code", [(400, "ExpiredToken"), (400, "InvalidToken"), (403, "InvalidAccessKeyId")])
def test_s3_credential_error_latches_before_next_dns(monkeypatch: pytest.MonkeyPatch, status: int, code: str) -> None:
    payload = (
        "<Error><Code>" + code + "</Code><Message>SYNTHETIC_DETAIL</Message><RequestId>synthetic</RequestId></Error>"
    ).encode()
    value, scenario, credential, _, events = session(monkeypatch, [{"status": status, "body": payload}], "s3")
    result = first_read(value)
    count = len(events)
    remaining = value.read_component("s3-versioning", value.context.request.root.targets[0], project)
    assert codes(result) == codes(remaining) == ["credential_rejected"]
    assert remaining.attempts == 0 and len(events) == count
    assert len(scenario.requests) == 1 and credential.calls == 1
    assert "SYNTHETIC_DETAIL" not in result.model_dump_json()
    value.close()


@pytest.mark.parametrize(
    "status,code,expected",
    [
        (403, "AccessDenied", "forbidden"),
        (404, "NoSuchBucket", "resource_not_found"),
        (400, "RequestTimeTooSkewed", "upstream_error"),
        (403, "SignatureDoesNotMatch", "forbidden"),
    ],
)
def test_s3_resource_errors_never_become_evidence_or_invalidate_credentials(
    monkeypatch: pytest.MonkeyPatch, status: int, code: str, expected: str
) -> None:
    body = f"<Error><Code>{code}</Code></Error>".encode()
    value, scenario, credential, _, _ = session(
        monkeypatch, [{"status": status, "body": body}, {"body": b"<VersioningConfiguration/>"}], "s3"
    )
    first = first_read(value)
    second = value.read_component("s3-versioning", value.context.request.root.targets[0], project)
    assert codes(first) == [expected] and first.projection is None
    assert second.status == "complete" and len(scenario.requests) == 2 and credential.calls == 1
    value.close()


@pytest.mark.parametrize(
    "body,admitted",
    [
        (b"<Error><Code>ObjectLockConfigurationNotFoundError</Code></Error>", True),
        (b"<Error><Code>NoSuchBucket</Code></Error>", False),
        (b"<Error><Code>ObjectLockConfigurationNotFoundError</Code><Code>NoSuchBucket</Code></Error>", False),
        (b"<Error><Code><Nested/></Code></Error>", False),
        (b"<Error xmlns='urn:unexpected'><Code>ObjectLockConfigurationNotFoundError</Code></Error>", False),
    ],
)
def test_only_exact_s3_absence_may_reach_projector(
    monkeypatch: pytest.MonkeyPatch, body: bytes, admitted: bool
) -> None:
    value, scenario, _, _, _ = session(monkeypatch, [{"status": 404, "body": body}], "s3")
    calls: list[Any] = []

    def observe(response: Any, target: Any) -> Any:
        calls.append(response)
        return project(response, target)

    result = first_read(value, observe)
    assert bool(calls) is admitted
    assert (result.status == "complete") is admitted
    assert len(scenario.requests) == 1
    value.close()


def test_401_and_cached_missing_material_stop_later_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    for missing in (False, True):
        value, scenario, credential, _, events = session(monkeypatch, [{"status": 401}])
        if missing:
            credential.resolution = materials.CredentialResolution(None, "configuration_missing")
        first = first_read(value)
        before = list(events)
        second = value.read_component("gcs-bucket", value.context.request.root.targets[1], project)
        assert codes(first) == codes(second) == ["configuration_missing" if missing else "credential_rejected"]
        assert events == before and second.attempts == 0 and credential.calls == 1
        assert len(scenario.requests) == (0 if missing else 1)
        value.close()


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
def test_retry_counts_failed_response_bytes_and_resolves_once(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    value, scenario, credential, clock, _ = session(
        monkeypatch, [{"status": status, "body": b"xx"}, {"status": status, "body": b"xxx"}, {"body": b"{}"}]
    )
    result = first_read(value)
    assert result.status == "complete" and result.attempts == 3
    assert result.raw_bytes == result.decoded_bytes == 7
    assert clock.sleeps == [1.0, 2.0] and credential.calls == 1 and len(scenario.requests) == 3
    value.close()
    assert all(stream.closed for stream in scenario.streams)


def test_full_projection_counts_and_cleanup_failure_preserves_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    value, scenario, _, _, _ = session(monkeypatch, [{"close_failure": True}])
    projection = contracts.ProjectedComponent("synthetic-v1", "configuration", {"observed": True})
    result = first_read(value, lambda response, target: projection)
    assert result.status == "partial" and codes(result) == ["cleanup_failed"]
    assert result.projection is not None
    assert value.context.projection_bytes == contracts.projection_size(projection)
    value.close()
    assert scenario.close_calls == 1


def test_projection_failure_is_atomic(monkeypatch: pytest.MonkeyPatch) -> None:
    value, _, _, _, _ = session(monkeypatch, [{}])

    def failed(response: Any, target: Any) -> Any:
        raise ValueError("SYNTHETIC_SOURCE_DETAIL")

    result = first_read(value, failed)
    assert result.status == "unavailable" and result.projection is None
    assert value.context.projection_bytes == 0
    assert "SYNTHETIC_SOURCE_DETAIL" not in result.model_dump_json()
    value.close()


@pytest.mark.parametrize("failure", [httpx.ConnectTimeout, httpx.ReadTimeout])
def test_timeout_retries_are_bounded(monkeypatch: pytest.MonkeyPatch, failure: Any) -> None:
    value, scenario, credential, clock, _ = session(
        monkeypatch, [failure("synthetic"), failure("synthetic"), failure("synthetic")]
    )
    result = first_read(value)
    assert codes(result) == ["timeout"] and result.attempts == 3 and result.projection is None
    assert result.raw_bytes == result.decoded_bytes == 0 and clock.sleeps == [1.0, 2.0]
    assert len(scenario.requests) == 3 and credential.calls == 1
    value.close()


def test_partial_timeout_bytes_are_counted_but_never_admitted(monkeypatch: pytest.MonkeyPatch) -> None:
    value, _, _, _, _ = session(
        monkeypatch, [{"chunks": [b"{", b'"x":'], "read_failure": httpx.ReadTimeout("synthetic")}, {"body": b"{}"}]
    )
    result = first_read(value)
    assert result.status == "complete" and result.attempts == 2
    assert result.raw_bytes == result.decoded_bytes == 7
    assert result.projection.fields == {"observed": True}
    value.close()


@pytest.mark.parametrize(
    "failure", [httpx.ConnectError, httpx.RemoteProtocolError, httpx.WriteTimeout, httpx.PoolTimeout]
)
def test_other_transport_failures_do_not_retry(monkeypatch: pytest.MonkeyPatch, failure: Any) -> None:
    value, scenario, _, clock, _ = session(monkeypatch, [failure("SYNTHETIC_FAILURE")])
    result = first_read(value)
    assert codes(result) == ["upstream_error"] and result.attempts == 1 and result.projection is None
    assert len(scenario.requests) == 1 and clock.sleeps == []
    assert "SYNTHETIC_FAILURE" not in result.model_dump_json()
    value.close()


@pytest.mark.parametrize(
    "header,expected", [("5", None), ("31", "run_budget_exhausted"), ("tomorrow", "retry_after_invalid")]
)
def test_retry_after_controls_actual_sleep(monkeypatch: pytest.MonkeyPatch, header: str, expected: str | None) -> None:
    value, scenario, _, clock, _ = session(monkeypatch, [{"status": 429, "headers": {"Retry-After": header}}, {}])
    result = first_read(value)
    assert codes(result) == ([] if expected is None else [expected])
    assert clock.sleeps == ([5.0] if expected is None else [])
    assert len(scenario.requests) == (2 if expected is None else 1)
    value.close()


@pytest.mark.parametrize("status", [400, 403, 404, 409, 418, 422, 501, 505])
def test_nonretry_status_keeps_other_targets_usable(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    value, scenario, credential, clock, _ = session(monkeypatch, [{"status": status}, {}])
    first = first_read(value)
    second = value.read_component("gcs-bucket", value.context.request.root.targets[1], project)
    assert codes(first) == [
        "forbidden" if status == 403 else "resource_not_found" if status == 404 else "upstream_error"
    ]
    assert first.projection is None and second.status == "complete"
    assert len(scenario.requests) == 2 and credential.calls == 1 and clock.sleeps == []
    value.close()


def test_rejected_response_chunk_counts_without_prefix_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = b"x" * client.RESPONSE_MAX_BYTES
    value, _, _, _, _ = session(monkeypatch, [{"chunks": [payload, b"x"]}])
    result = first_read(value)
    assert codes(result) == ["response_limit"] and result.projection is None
    assert result.raw_bytes == result.decoded_bytes == client.RESPONSE_MAX_BYTES + 1
    assert value.context.raw_bytes == result.raw_bytes and value.context.projection_bytes == 0
    value.close()


def test_run_byte_budget_latches_and_preserves_actual_overshoot(monkeypatch: pytest.MonkeyPatch) -> None:
    value, scenario, _, _, events = session(monkeypatch, [{"chunks": [b"12345"]}])
    value.context.raw_bytes = client.RUN_MAX_BYTES - 2
    result = first_read(value)
    assert codes(result) == ["run_budget_exhausted"] and result.raw_bytes == result.decoded_bytes == 5
    assert value.context.raw_bytes == client.RUN_MAX_BYTES + 3
    before = list(events)
    second = value.read_component("gcs-bucket", value.context.request.root.targets[1], project)
    assert codes(second) == ["run_budget_exhausted"] and second.attempts == 0
    assert events == before and len(scenario.requests) == 1
    value.close()


@pytest.mark.parametrize("remaining,admitted", [(0, True), (-1, False)])
def test_projection_aggregate_boundary_is_atomic(
    monkeypatch: pytest.MonkeyPatch, remaining: int, admitted: bool
) -> None:
    value, _, _, _, _ = session(monkeypatch, [{}])
    projection = contracts.ProjectedComponent("synthetic-v1", "configuration", {"observed": True})
    size = contracts.projection_size(projection)
    before = client.PROJECTION_RUN_MAX_BYTES - size - remaining
    value.context.projection_bytes = before
    result = first_read(value, lambda response, target: projection)
    assert (result.projection is not None) is admitted
    assert codes(result) == ([] if admitted else ["projection_limit"])
    assert value.context.projection_bytes == (client.PROJECTION_RUN_MAX_BYTES if admitted else before)
    value.close()


def test_deadline_refuses_before_dns_and_caps_remaining_io(monkeypatch: pytest.MonkeyPatch) -> None:
    value, scenario, credential, clock, events = session(monkeypatch, [{}])
    clock.seconds = 120.0
    result = first_read(value)
    assert codes(result) == ["run_budget_exhausted"] and result.attempts == 0
    assert credential.calls == 0 and events == []
    value.close()
    value, scenario, _, clock, _ = session(monkeypatch, [{}])
    clock.seconds = 119.0
    assert first_read(value).status == "complete"
    assert set(scenario.requests[0].extensions["timeout"].values()) == {1.0}
    value.close()


@pytest.mark.parametrize(
    "reply,expected_bytes",
    [({"chunks": [b"{", b"}"], "chunk_seconds": [0, 121]}, 2), ({"body": b"{}", "close_seconds": 121}, 2)],
)
def test_deadline_after_blocking_read_or_close_never_admits(
    monkeypatch: pytest.MonkeyPatch, reply: dict[str, Any], expected_bytes: int
) -> None:
    value, scenario, _, _, _ = session(monkeypatch, [reply])
    result = first_read(value)
    assert result.projection is None and codes(result) == ["run_budget_exhausted"]
    assert result.raw_bytes == result.decoded_bytes == expected_bytes
    assert scenario.streams[0].closed
    value.close()


def test_expiry_is_rechecked_before_retry_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    value, scenario, credential, clock, events = session(monkeypatch, [{"status": 503}])
    credential.resolution = materials.CredentialResolution(
        materials.BearerCredentials("SYNTHETIC_BEARER", clock.utc() + timedelta(seconds=1)), None
    )
    result = first_read(value)
    assert codes(result) == ["credential_unavailable"] and result.attempts == 1
    assert clock.sleeps == [1.0] and credential.calls == 1
    assert events.count("dns") == 1 and len(scenario.requests) == 1
    value.close()


def test_client_close_failure_is_observable_and_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    value, scenario, _, _, _ = session(monkeypatch, [{}])
    result = first_read(value)
    scenario.close_failure = True
    value.close()
    value.close()
    assert value.cleanup_failed and scenario.close_calls == 1 and result.status == "complete"
    with pytest.raises(client.ClientFault):
        value.read_component("gcs-bucket", value.context.request.root.targets[1], project)


def test_response_cookies_are_never_reused(monkeypatch: pytest.MonkeyPatch) -> None:
    value, scenario, credential, _, _ = session(
        monkeypatch, [{"headers": {"Set-Cookie": "synthetic=marker; Domain=storage.googleapis.com; Path=/"}}, {}]
    )
    assert first_read(value).status == "complete"
    assert value.read_component("gcs-bucket", value.context.request.root.targets[1], project).status == "complete"
    assert credential.calls == 1
    assert all("cookie" not in request.headers for request in scenario.requests)
    value.close()


def test_duplicate_etag_is_not_collapsed_into_invented_source_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    value, _, _, _, _ = session(monkeypatch, [{"headers": [("ETag", '"first"'), ("ETag", '"second"')]}])
    result = first_read(value)
    assert codes(result) == ["invalid_response"] and result.projection is None
    value.close()


def test_retry_uses_detached_selected_target(monkeypatch: pytest.MonkeyPatch) -> None:
    value, scenario, _, _, _ = session(monkeypatch, [{"status": 503}, {}])
    target = value.context.request.root.targets[0]
    original = scenario.handle_request

    def mutate_after_send(request: httpx.Request) -> httpx.Response:
        response = original(request)
        target.bucket = "outside-example"
        return response

    monkeypatch.setattr(scenario, "handle_request", mutate_after_send)
    result = value.read_component("gcs-bucket", target, project)
    assert result.status == "complete" and result.attempts == 2
    assert all(request.url.path.endswith("/unit-example") for request in scenario.requests)
    value.close()


def test_slow_factory_recomputes_io_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    value, scenario, _, clock, _ = session(monkeypatch, [{}])

    def slow() -> httpx.BaseTransport:
        clock.seconds += 119
        return scenario

    value._transport_factory = slow
    assert first_read(value).status == "complete"
    assert set(scenario.requests[0].extensions["timeout"].values()) == {1.0}
    value.close()


def test_slow_factory_rechecks_credential_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    value, scenario, credential, clock, _ = session(monkeypatch, [])
    credential.resolution = materials.CredentialResolution(
        materials.BearerCredentials("SYNTHETIC_BEARER", clock.utc() + timedelta(seconds=1)), None
    )

    def slow() -> httpx.BaseTransport:
        clock.seconds += 2
        return scenario

    value._transport_factory = slow
    result = first_read(value)
    assert codes(result) == ["credential_unavailable"] and result.attempts == 0
    assert scenario.requests == []
    value.close()
    assert scenario.close_calls == 1


@pytest.mark.parametrize(
    "location", ["http://[", "http://example.com:wrong", "\x00"], ids=["brackets", "port", "control"]
)
def test_malformed_redirect_is_refused_before_location_processing(
    monkeypatch: pytest.MonkeyPatch, location: str
) -> None:
    value, scenario, _, _, _ = session(monkeypatch, [{"status": 307, "headers": {"Location": location}}])
    result = first_read(value)
    assert codes(result) == ["redirect_refused"] and result.http_status == 307
    assert len(scenario.requests) == 1 and scenario.streams[0].closed
    value.close()


def test_projector_cannot_relabel_observed_resource(monkeypatch: pytest.MonkeyPatch) -> None:
    value, scenario, _, _, _ = session(monkeypatch, [{}])

    def mutate(response: Any, target: Any) -> Any:
        target.bucket = "outside-example"
        return project(response, target)

    result = first_read(value, mutate)
    assert result.canonical_resource_id == "gcs:unit-example"
    assert scenario.requests[0].url.path.endswith("/unit-example")
    value.close()


@pytest.mark.parametrize("expiry", [False, True], ids=["deadline", "expiry"])
def test_final_clock_callback_precedes_last_validity_check(monkeypatch: pytest.MonkeyPatch, expiry: bool) -> None:
    value, scenario, credential, clock, _ = session(monkeypatch, [{}])
    if expiry:
        credential.resolution = materials.CredentialResolution(
            materials.BearerCredentials("SYNTHETIC_BEARER", clock.utc() + timedelta(seconds=1)), None
        )
    calls = 0

    def slow_clock() -> datetime:
        nonlocal calls
        calls += 1
        if not expiry or calls == 4:
            clock.seconds = 2 if expiry else 120
        return clock.utc()

    value.context._utc_clock = slow_clock
    result = first_read(value)
    assert scenario.requests == [] and result.attempts == 0
    assert result.started_at is None and result.finished_at is None
    assert codes(result) == ["credential_unavailable" if expiry else "run_budget_exhausted"]
    value.close()
