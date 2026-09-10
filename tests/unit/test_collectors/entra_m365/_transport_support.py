"""Synthetic clocks, streams, and transport guard helpers."""

from __future__ import annotations

import json
import logging
import threading
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx
from evidentia_core import network_guard

ORIGIN = "https://graph.microsoft.com"
CA_PATH = "/v1.0/identity/conditionalAccess/policies"
SIGN_PATH = "/v1.0/auditLogs/signIns"
DEVICE_PATH = "/v1.0/deviceManagement/managedDevices"
RETENTION_PATH = "/v1.0/security/labels/retentionLabels"
NOW = datetime(2026, 9, 10, tzinfo=UTC)
PRIMARY = "SYNTHETIC_PRIMARY_READER_TOKEN"
RETENTION = "SYNTHETIC_RETENTION_READER_TOKEN"
OPAQUE = "SYNTHETIC_OPAQUE%2f%2F+a%20b%26$expand%3Ddata"
SOURCE_MARKER = "SYNTHETIC_UPSTREAM_PRIVATE_MARKER"
PAGE_LIMIT = 4_194_304


def encode_page(rows, continuation=None, *, include_next=False):
    value = {"value": rows}
    if continuation is not None or include_next:
        value["@odata.nextLink"] = continuation
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sign_in(identifier, when="2026-09-09T00:00:00Z", **fields):
    return {"id": identifier, "createdDateTime": when, "appliedConditionalAccessPolicies": [], **fields}


class Clock:
    def __init__(self):
        self.value = 0.0
        self.wall = NOW
        self.sleeps = []

    def utc(self):
        return self.wall

    def monotonic(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds
        self.wall += timedelta(seconds=seconds)

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.advance(seconds)


class Guards:
    def reset(self):
        self.calls = []
        self.refusal = None
        self.local = threading.local()

    def check_url(self, url, *, subsystem, remediation=""):
        self.calls.append(("offline", url))
        assert url == ORIGIN
        if self.refusal == "offline":
            raise network_guard.OfflineViolationError(subsystem=subsystem, target=SOURCE_MARKER)

    def enforce_public_host(self, url_or_host, *, subsystem, block_private=True):
        self.calls.append(("public", url_or_host))
        assert block_private is True
        assert url_or_host in {"graph.microsoft.com", ORIGIN}
        if self.refusal == "private":
            raise network_guard.SSRFBlockedError(subsystem=subsystem, host=SOURCE_MARKER, resolved_ip="169.254.169.254")
        return ["8.8.8.8"]

    @contextmanager
    def pin_resolved_host(self, host, public_ips):
        assert host == "graph.microsoft.com"
        assert public_ips == ["8.8.8.8"]
        self.calls.append(("pin_enter", host))
        self.local.depth = getattr(self.local, "depth", 0) + 1
        try:
            yield
        finally:
            self.local.depth -= 1
            self.calls.append(("pin_exit", host))

    def before_send(self, request):
        assert getattr(self.local, "depth", 0) > 0
        assert request.method == "GET"
        assert request.url.scheme == "https"
        assert request.url.host == "graph.microsoft.com"
        self.calls.append(("send", request.url.path))


def refuse_real_network(*args, **kwargs):
    raise AssertionError("The synthetic suite must never perform DNS or socket IO")


@dataclass
class Reply:
    body: bytes = b'{"value":[]}'
    status: int = 200
    headers: object = field(default_factory=dict)
    chunks: object = None
    failure: object = None
    before_chunk: object = None
    on_send: object = None
    close_failure: bool = False


class TrackingStream(httpx.SyncByteStream):
    def __init__(self, reply):
        self.reply = reply
        self.reads = 0
        self.closed = 0

    def __iter__(self):
        chunks = self.reply.chunks if self.reply.chunks is not None else [self.reply.body]
        for chunk in chunks:
            self.reads += 1
            if self.reply.before_chunk:
                self.reply.before_chunk(self.reads)
            logging.getLogger("httpcore.http11").debug("body %s", SOURCE_MARKER)
            yield chunk
        if self.reply.failure is not None:
            raise self.reply.failure

    def close(self):
        self.closed += 1
        logging.getLogger("httpcore.http11").debug("close %s", SOURCE_MARKER)
        if self.reply.close_failure:
            raise RuntimeError(SOURCE_MARKER)


class Scenario:
    def __init__(self, guards, replies):
        self.guards = guards
        self.replies = deque(replies)
        self.requests = []
        self.streams = []

    def handle(self, request):
        self.guards.before_send(request)
        self.requests.append(request)
        assert self.replies, "Unexpected extra request"
        reply = self.replies.popleft()
        if isinstance(reply, Exception):
            raise reply
        if reply.on_send:
            reply.on_send(request)
        stream = TrackingStream(reply)
        self.streams.append(stream)
        return httpx.Response(reply.status, headers=reply.headers, stream=stream)


class Provider:
    def __init__(self, target, values=None):
        self.calls = []
        self.values = values or {
            "primary": target._CredentialResolution(token=PRIMARY, declared_auth_mode="application"),
            "retention": target._CredentialResolution(token=RETENTION, declared_auth_mode="delegated"),
        }

    def resolve(self, group):
        assert group in {"primary", "retention"}
        self.calls.append(group)
        return self.values[group]


@dataclass
class Run:
    reader: object
    request: object
    context: object
    clock: Clock
    provider: Provider
    client: httpx.Client
    scenario: Scenario

    def read(self, capability=None):
        return self.reader.read_collection(capability or self.request.capabilities[0], self.request, self.context)


def codes(source):
    return {item.code for item in source.capability.diagnostics}


def assert_summary(source, *, state, pages, attempts, scanned, ids):
    result = source.capability
    assert result.state == state
    assert result.pages_completed == pages
    assert result.requests_attempted == attempts
    assert result.scanned == scanned
    assert result.matched_filter == len(ids)
    assert result.collected == 0
    assert [row.source_id for row in source.records] == ids


def assert_closed(run):
    assert all(stream.closed == 1 for stream in run.scenario.streams)
    assert not run.client.is_closed


def assert_safe(source, caplog=None):
    payload = json.dumps(
        {
            "capability": source.capability.model_dump(mode="json"),
            "records": [row.fields for row in source.records],
        },
        ensure_ascii=True,
    )
    logs = "" if caplog is None else "\n".join(record.getMessage() for record in caplog.records)
    for marker in (PRIMARY, RETENTION, "SYNTHETIC_OPAQUE", SOURCE_MARKER):
        assert marker not in payload
        assert marker not in logs
    assert all(set(item.model_dump()) == {"code", "count", "http_status"} for item in source.capability.diagnostics)


class Stream(httpx.SyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.closed = 0
        self.reads = 0

    def __iter__(self):
        for chunk in self.chunks:
            self.reads += 1
            yield chunk

    def close(self):
        self.closed += 1
