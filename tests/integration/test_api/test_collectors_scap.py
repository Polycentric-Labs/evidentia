"""Exercise complete API results through real authenticated ASGI handling."""

from __future__ import annotations

import asyncio
import hashlib
import json
import socket
from collections.abc import Awaitable, Callable, Iterator
from typing import Any, cast

import pytest
from evidentia_collectors.scap import collector
from evidentia_collectors.scap._contracts import ScapCollectionResult
from evidentia_collectors.scap._limits import ErrorCode, ScapFailure
from fastapi import FastAPI

from ..test_cli.test_scap_io import PROFILES, assertion_bytes, source_bytes
from .test_collectors_scap_stream import _AUTH, _application, _deliver

application = cast(Callable[..., FastAPI], _application)
deliver = cast(Callable[..., Awaitable[tuple[int, dict[str, Any], int, bytes]]], _deliver)


@pytest.fixture
def local_loop(monkeypatch: pytest.MonkeyPatch) -> Iterator[asyncio.AbstractEventLoop]:
    loop = asyncio.new_event_loop()

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("In-process SCAP API checks must not contact a network")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    try:
        yield loop
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.run_until_complete(loop.shutdown_default_executor())
        loop.close()


def request(
    loop: asyncio.AbstractEventLoop,
    raw: bytes,
    profile: str,
    *,
    index: int = 0,
    claim: bytes | None = None,
) -> tuple[int, dict[str, Any], int, bytes]:
    headers = [(b"authorization", _AUTH), (b"content-type", b"application/xml")]
    if claim is not None:
        headers.append((b"x-evidentia-scap-completion-assertion", claim))
    query = f"source_profile={profile}&assessment_index={index}".encode("ascii")
    return loop.run_until_complete(deliver(application(), [raw], query=query, headers=headers))


@pytest.mark.parametrize("profile,filename", PROFILES)
def test_complete_profile_result_and_exact_accepted_wire(
    local_loop: asyncio.AbstractEventLoop,
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
    filename: str,
) -> None:
    raw = source_bytes(filename)
    original = collector._Accepted.output_bytes
    published: list[bytes] = []

    def capture(self: collector._Accepted, view: str = "result") -> bytes:
        wire = original(self, view)
        published.append(wire)
        return wire

    monkeypatch.setattr(collector._Accepted, "output_bytes", capture)
    status, body, consumed, wire = request(local_loop, raw, profile)
    assert status == 200 and consumed == 1 and published == [wire]
    ScapCollectionResult.model_validate(body)
    assert body["source"] == {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "profile": profile,
        "projection_version": "scap-native-document-v1",
    }
    assert len(body["findings"]) == 1
    assert body["findings"][0]["severity"] == "informational"
    assert body["findings"][0]["compliance_status"] == "unknown"
    artifact = body["evidence_artifact"]
    if profile.startswith("oval-"):
        assert artifact is None
    else:
        assert artifact["content"]["native_document"] == body["native_document"]
        assert artifact["content"]["assessment"] == body["assessment"]


@pytest.mark.parametrize("profile,filename", PROFILES[1:])
def test_asserted_oval_api_actor_is_request_authenticated(
    local_loop: asyncio.AbstractEventLoop,
    profile: str,
    filename: str,
) -> None:
    raw = source_bytes(filename)
    status, body, consumed, _ = request(local_loop, raw, profile, claim=assertion_bytes(raw, profile))
    assert status == 200 and consumed == 1
    assert body["completion"]["assertion"]["actor"] == {
        "basis": "api_authenticated",
        "subject": "Synthetic principal",
        "provider": "synthetic-auth",
    }
    assert body["evidence_artifact"]["content"]["completion"]["assertion"] == body["completion"]["assertion"]


@pytest.mark.parametrize(
    "mode,expected_status,code",
    [
        ("wrong-profile", 400, "source_contract_invalid"),
        ("selection", 422, "assessment_not_found"),
        ("claim-binding", 422, "completion_assertion_binding_mismatch"),
    ],
)
def test_source_failure_does_not_return_partial_native_result(
    local_loop: asyncio.AbstractEventLoop,
    mode: str,
    expected_status: int,
    code: ErrorCode,
) -> None:
    raw = source_bytes("oval-5.8-native.xml")
    claim = assertion_bytes(raw, source_sha256="0" * 64) if mode == "claim-binding" else None
    status, body, _, wire = request(
        local_loop,
        raw,
        "xccdf-1.2-results" if mode == "wrong-profile" else "oval-5.8-core-results",
        index=255 if mode == "selection" else 0,
        claim=claim,
    )
    assert status == expected_status and body == ScapFailure(code).as_dict()
    assert json.loads(wire) == body and "native_document" not in body


def test_api_has_no_output_view_or_persistence_switch(local_loop: asyncio.AbstractEventLoop) -> None:
    raw = source_bytes("xccdf-1.2-native.xml")
    for option in (b"output_view=artifact", b"save=true"):
        result = local_loop.run_until_complete(
            deliver(
                application(),
                [raw],
                query=b"source_profile=xccdf-1.2-results&assessment_index=0&" + option,
            )
        )
        assert result[0] == 422 and result[2] == 0
        assert result[1] == ScapFailure("invalid_request").as_dict()
