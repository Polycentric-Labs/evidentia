"""Actual ASGI authentication, bounded streams and complete SCAP response contracts."""

from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from evidentia_api.auth_middleware import AuthProviderMiddleware
from evidentia_api.routers import scap
from evidentia_collectors.scap import collector
from evidentia_collectors.scap._contracts import ScapCollectionResult, ScapError
from evidentia_collectors.scap._limits import RAW_LIMIT, ScapFailure, start_budget
from evidentia_core.plugins.auth import AuthProvider, AuthResult
from evidentia_core.rbac import RBACPolicy, Role
from fastapi import FastAPI
from jsonschema import Draft202012Validator
from starlette.requests import Request

_ROUTE = "/api/collectors/scap/collect"
_AUTH = b"Bearer synthetic-scap-reader"
_TEST_LOOP = None
_QUERY = b"source_profile=xccdf-1.2-results&assessment_index=0"
_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "scap"
_XCCDF = (_FIXTURES / "xccdf-1.2-native.xml").read_bytes().replace(b"\r\n", b"\n")
_OVAL = (_FIXTURES / "oval-5.8-native.xml").read_bytes().replace(b"\r\n", b"\n")


class Actor(AuthProvider):
    def __init__(self, principal="Synthetic principal"):
        self.principal = principal

    def authenticate(self, *, authorization_header):
        return AuthResult(authorization_header == _AUTH.decode("ascii"), self.principal, "Synthetic refusal")

    def name(self):
        return "synthetic-auth"


@pytest.fixture(autouse=True)
def no_external_network(monkeypatch):
    # Initialize Windows local event-loop IPC before blocking network calls.
    loop = asyncio.new_event_loop()
    monkeypatch.setattr(sys.modules[__name__], "_TEST_LOOP", loop)

    def denied(*args, **kwargs):
        raise AssertionError("Synthetic SCAP API tests cannot contact a network")

    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    try:
        yield
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.run_until_complete(loop.shutdown_default_executor())
        loop.close()


def _application(provider=True, deny=False):
    app = FastAPI()
    app.state.auth_provider = Actor() if provider is True else None if provider is False else provider
    app.state.rbac_policy = RBACPolicy(identities={}, default_role=Role.DENY if deny else Role.READER)
    app.add_middleware(AuthProviderMiddleware)
    app.include_router(scap.router, prefix="/api")
    return app


async def _deliver(app, chunks, *, query=_QUERY, headers=None, tail=None, route=_ROUTE):
    consumed = 0
    done = asyncio.Event()
    sent = []
    actual_headers = [(b"content-type", b"application/xml"), (b"authorization", _AUTH)] if headers is None else headers
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": route,
        "raw_path": route.encode(),
        "root_path": "",
        "query_string": query,
        "headers": actual_headers,
        "client": ("127.0.0.1", 42311),
        "server": ("scap.test", 80),
        "state": {},
    }

    async def receive():
        nonlocal consumed
        if consumed < len(chunks):
            index = consumed
            consumed += 1
            await asyncio.sleep(0)
            return {
                "type": "http.request",
                "body": chunks[index],
                "more_body": index < len(chunks) - 1 or tail is not None,
            }
        if tail is not None:
            consumed += 1
            if isinstance(tail, BaseException):
                raise tail
            return tail
        await done.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)
        if message["type"] == "http.response.body" and not message.get("more_body", False):
            done.set()

    await asyncio.wait_for(app(scope, receive, send), timeout=20)
    status = next(message["status"] for message in sent if message["type"] == "http.response.start")
    wire = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
    return status, json.loads(wire), consumed, wire


def _run(chunks=(_XCCDF,), **kwargs):
    app = kwargs.pop("application", None) or _application()
    return _TEST_LOOP.run_until_complete(_deliver(app, list(chunks), **kwargs))


def _fixed(result, status, code):
    assert result[0] == status
    ScapError.model_validate(result[1])
    assert result[1] == ScapFailure(code).as_dict()


@pytest.mark.parametrize("case,status", [("missing", 403), ("invalid", 401), ("empty", 403), ("denied", 403)])
def test_authentication_and_read_role_precede_all_input(monkeypatch, case, status):
    def forbidden(*args, **kwargs):
        raise AssertionError("No SCAP option, claim, dependency or body work before authentication")

    monkeypatch.setattr(scap, "_begin", forbidden)
    monkeypatch.setattr(scap, "_claim", forbidden)
    monkeypatch.setattr(scap, "_options", forbidden)
    app = _application(
        provider=False if case == "missing" else Actor("") if case == "empty" else True, deny=case == "denied"
    )
    headers = [(b"content-type", b"text/plain"), (b"authorization", b"invalid" if case == "invalid" else _AUTH)]
    result = _run([b"invalid input"], application=app, headers=headers, query=b"?invalid")
    assert result[0] == status and result[2] == 0


@pytest.mark.parametrize(
    "query",
    [
        b"",
        b"source_profile=xccdf-1.2-results",
        _QUERY + b"&assessment_index=1",
        _QUERY + b"&actor=forged",
        _QUERY + b"&cadence_slug=unknown",
        _QUERY.replace(b"=0", b"=00"),
        _QUERY.replace(b"=0", b"=+0"),
        _QUERY.replace(b"=0", b"=-1"),
        _QUERY.replace(b"=0", b"=256"),
        _QUERY.replace(b"=0", b"=1.0"),
        _QUERY.replace(b"=0", b"=%GG"),
        _QUERY.replace(b"=0", b"=%FF"),
        _QUERY + b"&cadence_slug=" + b"x" * 1024,
    ],
)
def test_closed_query_refusals_happen_before_body(query):
    result = _run(query=query)
    _fixed(result, 422, "invalid_request")
    assert result[2] == 0


@pytest.mark.parametrize(
    "media,encoding",
    [
        (b"text/xml", None),
        (b"application/json", None),
        (b"application/xml", b"gzip"),
        (b"application/xml; charset=utf-16", None),
    ],
)
def test_unsupported_media_consumes_no_body(media, encoding):
    headers = [(b"content-type", media), (b"authorization", _AUTH)]
    if encoding is not None:
        headers.append((b"content-encoding", encoding))
    result = _run(headers=headers)
    _fixed(result, 415, "unsupported_media")
    assert result[2] == 0


@pytest.mark.parametrize(
    "claim", [b"null", b"[]", b"{}", b"{", b'{"a":1,"a":2}', b'{"reference":NaN}', b" " * 2049, bytes([255]), b"{\t}"]
)
def test_invalid_claim_header_consumes_no_body(claim):
    headers = [(b"authorization", _AUTH), (b"content-type", b"application/xml"), (scap._CLAIM_HEADER, claim)]
    result = _run(headers=headers, query=_QUERY.replace(b"xccdf-1.2-results", b"oval-5.8-core-results"))
    _fixed(result, 422, "completion_assertion_invalid")
    assert result[2] == 0


def _claim_bytes(**changes):
    value = {
        "schema_version": "scap-completion-assertion-v1",
        "source_sha256": hashlib.sha256(_OVAL).hexdigest(),
        "source_profile": "oval-5.8-core-results",
        "assessment_index": 0,
        "completed_at": "2024-03-01T00:00:00.000000Z",
        "reference": "Synthetic local observation",
        **changes,
    }
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def test_duplicate_claim_and_xccdf_claim_are_refused_before_body():
    headers = [(b"authorization", _AUTH), (b"content-type", b"application/xml"), (scap._CLAIM_HEADER, _claim_bytes())]
    duplicate = _run(headers=[*headers, (scap._CLAIM_HEADER.upper(), _claim_bytes())])
    _fixed(duplicate, 422, "completion_assertion_invalid")
    assert duplicate[2] == 0
    prohibited = _run(headers=headers)
    _fixed(prohibited, 422, "completion_assertion_not_permitted")
    assert prohibited[2] == 0


def test_actor_is_only_the_authenticated_native_principal():
    headers = [(b"authorization", _AUTH), (b"content-type", b"application/xml"), (scap._CLAIM_HEADER, _claim_bytes())]
    query = _QUERY.replace(b"xccdf-1.2-results", b"oval-5.8-core-results")
    result = _run([_OVAL], headers=headers, query=query)
    assert result[0] == 200
    ScapCollectionResult.model_validate(result[1])
    assertion = result[1]["completion"]["assertion"]
    assert assertion["actor"] == {
        "basis": "api_authenticated",
        "subject": "Synthetic principal",
        "provider": "synthetic-auth",
    }
    assert assertion["completed_at"] == "2024-03-01T00:00:00.000000Z"
    forged = _run(
        [_OVAL], headers=[*headers[:-1], (scap._CLAIM_HEADER, _claim_bytes(actor={"subject": "forged"}))], query=query
    )
    _fixed(forged, 422, "completion_assertion_invalid")
    assert forged[2] == 0


@pytest.mark.parametrize("length", [None, b"1", b"999999999", b"invalid"])
@pytest.mark.parametrize("extra", [0, 1])
def test_actual_transport_limit_ignores_declared_content_length(monkeypatch, length, extra):
    """Measure transport admission separately from semantic maximum-shape tests."""
    consumed = []

    def consume(raw):
        consumed.append(len(raw))
        raise ScapFailure("malformed_xml")

    monkeypatch.setattr(scap, "_begin", lambda *args: SimpleNamespace(budget=start_budget(), consume=consume))
    headers = [(b"content-type", b"application/xml"), (b"authorization", _AUTH)]
    if length is not None:
        headers.append((b"content-length", length))
    result = _run([b"x" * 8192, b"x" * (RAW_LIMIT - 8192 + extra)], headers=headers)
    _fixed(result, 413 if extra else 400, "source_limit_exceeded" if extra else "malformed_xml")
    assert result[2] == 2
    assert consumed == ([] if extra else [RAW_LIMIT])


def test_oversized_first_chunk_stops_before_next_read():
    result = _run([b"x" * (RAW_LIMIT + 1), b"unread"])
    _fixed(result, 413, "source_limit_exceeded")
    assert result[2] == 1


@pytest.mark.parametrize(
    "tail,status,code",
    [
        ({"type": "http.disconnect"}, 400, "source_read_failed"),
        (OSError("Synthetic source-read detail"), 400, "source_read_failed"),
        (ExceptionGroup("Synthetic wrapper", [OSError("Synthetic source-read detail")]), 400, "source_read_failed"),
        (ExceptionGroup("Synthetic mixed wrapper", [OSError(), RuntimeError()]), 500, "invalid_internal_result"),
    ],
)
def test_incomplete_stream_is_fixed_without_source_values(tail, status, code):
    result = _run([_XCCDF[:40]], tail=tail)
    _fixed(result, status, code)
    assert b"Synthetic source-read detail" not in result[3]


def test_fragmented_source_uses_one_worker_parse_and_full_native_graph(monkeypatch):
    original = collector.parse_xml
    calls = []
    caller = threading.get_ident()

    def counted(raw, budget):
        calls.append((threading.get_ident(), hashlib.sha256(raw).hexdigest()))
        return original(raw, budget)

    monkeypatch.setattr(collector, "parse_xml", counted)
    result = _run([_XCCDF[:1], _XCCDF[1:31], _XCCDF[31:]])
    assert result[0] == 200 and result[2] == 3
    wire = ScapCollectionResult.model_validate(result[1])
    expected = json.loads((_FIXTURES / "xccdf-1.2-native.expected.json").read_text(encoding="utf-8"))
    assert wire.native_document.model_dump() == expected["native_document"]
    assert wire.assessment.model_dump() == expected["assessment"]
    assert calls == [(calls[0][0], hashlib.sha256(_XCCDF).hexdigest())]
    assert calls[0][0] != caller
    assert wire.evidence_artifact is not None


def test_undated_oval_returns_full_success_with_required_null_artifact():
    result = _run([_OVAL], query=_QUERY.replace(b"xccdf-1.2-results", b"oval-5.8-core-results"))
    assert result[0] == 200
    ScapCollectionResult.model_validate(result[1])
    assert "evidence_artifact" in result[1] and result[1]["evidence_artifact"] is None
    assert len(result[1]["assessment"]["outcomes"]) == 4


@pytest.mark.parametrize("failure,status", [("scan_extra_unavailable", 503), ("internal_dependency_failure", 500)])
def test_optional_parser_failure_is_distinct_and_before_body(monkeypatch, failure, status):
    def unavailable():
        raise ScapFailure(failure)

    monkeypatch.setattr(collector, "_dependency", unavailable)
    result = _run()
    _fixed(result, status, failure)
    assert result[2] == 0


def test_original_stream_deadline_and_external_cancellation(monkeypatch):
    async def run(cancel):
        entered = asyncio.Event()
        app = _application()
        scope = {
            "type": "http",
            "method": "POST",
            "path": _ROUTE,
            "app": app,
            "headers": [(b"content-type", b"application/xml")],
            "query_string": _QUERY,
            "state": {"auth_principal": "Synthetic principal", "auth_provider": app.state.auth_provider},
        }

        async def receive():
            entered.set()
            await asyncio.Event().wait()
            raise AssertionError("The stalled receive cannot complete")

        if not cancel:
            monkeypatch.setattr(
                scap,
                "_begin",
                lambda *args: SimpleNamespace(
                    budget=SimpleNamespace(deadline=scap.time.monotonic() + scap.PUBLICATION_RESERVE + 0.02)
                ),
            )
        task = asyncio.create_task(scap.collect_scap(Request(scope, receive)))
        await entered.wait()
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            response = await task
            assert response.status_code == 503
            assert json.loads(response.body)["code"] == "processing_deadline_exceeded"

    _TEST_LOOP.run_until_complete(run(True))
    _TEST_LOOP.run_until_complete(run(False))


def test_openapi_has_raw_request_closed_result_and_required_nullable_artifact():
    document = _application().openapi()
    operation = document["paths"][_ROUTE]["post"]
    assert operation["operationId"] == "collect_scap"
    assert set(operation["requestBody"]["content"]) == {"application/xml"}
    assert {row["name"] for row in operation["parameters"]} == {
        "source_profile",
        "assessment_index",
        "cadence_slug",
        "X-Evidentia-SCAP-Completion-Assertion",
    }
    assert set(operation["responses"]) == {"200", "400", "401", "403", "413", "415", "422", "500", "503"}
    result = document["components"]["schemas"]["ScapCollectionResult"]
    assert result["additionalProperties"] is False
    assert "evidence_artifact" in result["required"]
    assert {part.get("type") for part in result["properties"]["evidence_artifact"]["anyOf"]} >= {"null"}
    Draft202012Validator.check_schema(document)


def test_completion_provider_is_the_one_that_authenticated_before_rotation(monkeypatch):
    first = Actor()

    class Replacement(Actor):
        def name(self):
            return "synthetic-replacement"

    second = Replacement()
    app = _application(provider=first)
    authenticate = first.authenticate

    def rotate(*, authorization_header):
        result = authenticate(authorization_header=authorization_header)
        app.state.auth_provider = second
        return result

    monkeypatch.setattr(first, "authenticate", rotate)
    headers = [(b"authorization", _AUTH), (b"content-type", b"application/xml"), (scap._CLAIM_HEADER, _claim_bytes())]
    result = _run(
        [_OVAL],
        application=app,
        headers=headers,
        query=_QUERY.replace(b"xccdf-1.2-results", b"oval-5.8-core-results"),
    )
    assert result[0] == 200
    assert app.state.auth_provider is second
    assert result[1]["completion"]["assertion"]["actor"] == {
        "basis": "api_authenticated",
        "subject": "Synthetic principal",
        "provider": "synthetic-auth",
    }


def test_missing_request_bound_provider_refuses_without_app_state_fallback(monkeypatch):
    from fastapi import HTTPException

    app = _application()
    scope = {
        "type": "http",
        "method": "POST",
        "path": _ROUTE,
        "app": app,
        "state": {"auth_principal": "Synthetic principal"},
        "headers": [],
    }

    def forbidden(*args, **kwargs):
        raise AssertionError("Missing authentication provenance must precede source input")

    monkeypatch.setattr(scap, "_media", forbidden)
    with pytest.raises(HTTPException) as raised:
        _TEST_LOOP.run_until_complete(scap.collect_scap(Request(scope)))
    assert raised.value.status_code == 403


def test_body_time_request_state_mutation_cannot_change_captured_actor():
    application = _application()
    changes = []

    async def changed_app(scope, receive, send):
        async def changed_receive():
            if not changes:
                scope["state"]["auth_principal"] = "Synthetic changed principal"
                scope["state"]["auth_provider"] = None
                application.state.auth_provider = None
                changes.append(True)
            return await receive()

        return await application(scope, changed_receive, send)

    headers = [(b"authorization", _AUTH), (b"content-type", b"application/xml"), (scap._CLAIM_HEADER, _claim_bytes())]
    result = _run(
        [_OVAL[:50], _OVAL[50:]],
        application=changed_app,
        headers=headers,
        query=_QUERY.replace(b"xccdf-1.2-results", b"oval-5.8-core-results"),
    )
    assert result[0] == 200 and changes == [True]
    assert result[1]["completion"]["assertion"]["actor"] == {
        "basis": "api_authenticated",
        "subject": "Synthetic principal",
        "provider": "synthetic-auth",
    }


def test_api_requires_explicit_write_to_save_and_preserves_duplicate_version(tmp_path, monkeypatch):
    from evidentia_api.routers import evidence
    from evidentia_core import evidence_store
    from evidentia_core.models.evidence import EvidenceArtifact

    directory = tmp_path / "isolated-api-evidence"
    monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(directory))
    monkeypatch.delenv(evidence_store.EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR, raising=False)
    monkeypatch.delenv(evidence_store.EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR, raising=False)
    app = _application()
    app.include_router(evidence.router, prefix="/api")
    first = _run(application=app)
    second = _run(application=app)
    assert first[0] == second[0] == 200
    artifact = first[1]["evidence_artifact"]
    assert artifact == second[1]["evidence_artifact"]
    assert artifact["version"] == 1
    assert artifact["lineage_id"] is None and artifact["predecessor_id"] is None
    assert not directory.exists()
    payload = json.dumps(artifact, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    options = {
        "application": app,
        "route": "/api/evidence",
        "query": b"",
        "headers": [(b"authorization", _AUTH), (b"content-type", b"application/json")],
    }
    refused = _run([payload], **options)
    assert refused[0] == 403
    assert not directory.exists()
    app.state.rbac_policy = RBACPolicy(identities={}, default_role=Role.EDITOR)
    saved = _run([payload], **options)
    assert saved[0] == 201
    assert saved[1] == {
        "artifact_id": artifact["id"],
        "lineage_id": artifact["id"],
        "version": 1,
        "predecessor_id": None,
    }
    target = directory / artifact["id"] / "v1.json"
    before = target.read_bytes()
    assert EvidenceArtifact.model_validate_json(before).model_dump(mode="json") == artifact
    duplicate = _run([payload], **options)
    assert duplicate[0] == 409
    detail = duplicate[1]["detail"]
    assert detail["error"] == "worm_violation"
    assert detail["lineage_id"] == artifact["id"]
    assert detail["attempted_version"] == 1 and detail["next_version"] == 2
    assert target.read_bytes() == before
    assert list(directory.rglob("v*.json")) == [target]


def test_scap_registration_preserves_existing_openapi_names_and_shapes():
    """Registering SCAP preserves existing evidence and incident API contracts."""
    from evidentia_api.routers import evidence, incident_clock

    app = FastAPI()
    app.include_router(evidence.router, prefix="/api")
    app.include_router(incident_clock.router, prefix="/api")
    baseline = app.openapi()
    assert {"EvidenceArtifact", "Diagnostic", "CoverageCount"} <= baseline["components"]["schemas"].keys()

    app.include_router(scap.router, prefix="/api")
    app.openapi_schema = None
    combined = app.openapi()

    assert combined["paths"].keys() == baseline["paths"].keys() | {_ROUTE}
    for path, contract in baseline["paths"].items():
        assert combined["paths"][path] == contract
    for name, schema in baseline["components"]["schemas"].items():
        assert combined["components"]["schemas"][name] == schema
    assert "ScapEvidenceArtifact" in combined["components"]["schemas"]
    assert "ScapDiagnostic" in combined["components"]["schemas"]
