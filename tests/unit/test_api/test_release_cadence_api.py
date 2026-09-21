"""Bounded raw API requests and complete canonical release responses."""

from __future__ import annotations

import json

import pytest
from evidentia_collectors.release_cadence import _traversal
from fastapi.testclient import TestClient

from tests.unit.test_api.test_release_cadence_authority import POLL, SERIES, make_app, request_value
from tests.unit.test_collectors.release_cadence._helpers import pages


@pytest.mark.parametrize("endpoint", [POLL, SERIES])
@pytest.mark.parametrize(
    "media",
    [
        None,
        "text/plain",
        "application/json;charset=latin1",
        "application/json;x=1",
        "application/json;charset=utf-8;charset=utf-8",
    ],
)
def test_media_refusal(monkeypatch, endpoint, media):
    calls = pages(monkeypatch, _traversal, [(b"[]", ())])
    headers = {} if media is None else {"content-type": media}
    result = TestClient(make_app(monkeypatch)).post(endpoint, content=b"{}", headers=headers)
    assert result.status_code == 415 and result.json()["code"] == "unsupported_media"
    assert calls == []


@pytest.mark.parametrize(
    "raw,code,status",
    [
        (b"{" + b" " * 4096, "request_limit_exceeded", 413),
        (b'{"owner":"a","owner":"b"}', "invalid_request", 422),
        (b'{"a":NaN}', "invalid_request", 422),
        (b'"\xff"', "invalid_request", 422),
        (b'"\\ud800"', "invalid_request", 422),
        (b"[" * 9 + b"0" + b"]" * 9, "request_limit_exceeded", 413),
        (b"[" + b"0," * 64 + b"0]", "request_limit_exceeded", 413),
    ],
)
def test_bounded_json_refusal(monkeypatch, raw, code, status):
    calls = pages(monkeypatch, _traversal, [(b"[]", ())])
    result = TestClient(make_app(monkeypatch)).post(POLL, content=raw, headers={"content-type": "application/json"})
    assert result.status_code == status and result.json()["code"] == code
    assert calls == []


@pytest.mark.parametrize("endpoint", [POLL, SERIES])
def test_request_body_is_closed_and_query_is_refused(monkeypatch, endpoint):
    calls = pages(monkeypatch, _traversal, [(b"[]", ())])
    client = TestClient(make_app(monkeypatch))
    value = request_value(series=endpoint == SERIES)
    for invalid in [{**value, "evidence_store": "ignored"}, {**value, "tenant": "other"}, {**value, "clock": 0}]:
        result = client.post(endpoint, json=invalid)
        assert result.status_code == 422 and result.json()["code"] == "invalid_request"
    result = client.post(endpoint + "?tenant=other", json=value)
    assert result.status_code == 422 and calls == []


def test_observation_and_offline_series_publish_exact_compact_bytes(monkeypatch, tmp_path):
    calls = pages(monkeypatch, _traversal, [(b"[]", ())])
    monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(tmp_path))
    client = TestClient(make_app(monkeypatch))
    poll = client.post(POLL, json=request_value())
    assert poll.status_code == 200 and len(calls) == 1
    assert poll.json()["persistence"]["state"] == "not_requested"
    series = client.post(SERIES, json=request_value(series=True))
    assert series.status_code == 200 and len(calls) == 1
    assert series.json()["state"] == "insufficient"
    for result in (poll, series):
        assert (
            result.content
            == json.dumps(result.json(), ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
        )
        assert not result.content.endswith(b"\n")


def test_actual_openapi_keeps_both_closed_request_and_result_models(monkeypatch):
    schema = make_app(monkeypatch).openapi()
    for endpoint in (POLL, SERIES):
        assert endpoint in schema["paths"]
        operation = schema["paths"][endpoint]["post"]
        assert operation["requestBody"]["required"] is True
        assert "application/json" in operation["requestBody"]["content"]
        assert {"200", "401", "403", "413", "415", "422", "500", "503"} <= operation["responses"].keys()


@pytest.mark.parametrize("endpoint", [POLL, SERIES])
def test_one_endpoint_clock_includes_body_and_final_result(monkeypatch, tmp_path, endpoint):
    from evidentia_core.release_cadence import _limits

    original = _limits.start_budget
    captured = []

    def start():
        budget = original()
        captured.append(budget.deadline)
        return budget

    monkeypatch.setattr(_limits, "start_budget", start)
    monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(tmp_path))
    pages(monkeypatch, _traversal, [(b"[]", ())])
    result = TestClient(make_app(monkeypatch)).post(endpoint, json=request_value(series=endpoint == SERIES))
    assert result.status_code == 200 and len(captured) == 1


@pytest.mark.parametrize("endpoint", [POLL, SERIES])
def test_body_work_cannot_restart_expired_budget(monkeypatch, endpoint):
    from evidentia_core.release_cadence import _limits

    original = _limits.time.monotonic
    offset = [0.0]
    monkeypatch.setattr(_limits.time, "monotonic", lambda: original() + offset[0])
    calls = pages(monkeypatch, _traversal, [(b"[]", ())])

    def body():
        offset[0] = 61.0
        yield json.dumps(request_value(series=endpoint == SERIES)).encode()

    result = TestClient(make_app(monkeypatch)).post(
        endpoint, content=body(), headers={"content-type": "application/json"}
    )
    assert result.status_code == 500 and result.json()["code"] == "operation_failed" and calls == []


@pytest.mark.parametrize(
    "headers",
    [
        [("content-type", "application/json"), ("content-type", "application/json")],
        [("content-type", "application/json"), ("content-encoding", "gzip")],
        [("content-type", "application/json"), ("content-encoding", "identity"), ("content-encoding", "identity")],
    ],
)
def test_duplicate_media_and_encoded_body_refuse(monkeypatch, headers):
    calls = pages(monkeypatch, _traversal, [(b"[]", ())])
    result = TestClient(make_app(monkeypatch)).post(POLL, content=b"{}", headers=headers)
    assert result.status_code == 415 and calls == []


@pytest.mark.parametrize("size", [4096, 4097])
def test_exact_request_byte_boundary(monkeypatch, size):
    calls = pages(monkeypatch, _traversal, [(b"[]", ())])
    body = json.dumps(request_value(), separators=(",", ":")).encode()
    body += b" " * (size - len(body))
    result = TestClient(make_app(monkeypatch)).post(POLL, content=body, headers={"content-type": "application/json"})
    assert result.status_code == (200 if size == 4096 else 413)
    assert len(calls) == (1 if size == 4096 else 0)


@pytest.mark.parametrize("save_state", ["created", "collided", "raised"])
def test_admitted_save_expiry_uses_preencoded_uncertainty(monkeypatch, tmp_path, save_state):
    from evidentia_api.routers import release_cadence as route
    from evidentia_collectors.release_cadence import collector
    from evidentia_core import evidence_store
    from evidentia_core.release_cadence import _limits, _store

    from tests.unit.test_collectors.release_cadence._helpers import encoded, row

    clock = _limits.time.monotonic
    offset = [0.0]
    monkeypatch.setattr(_limits.time, "monotonic", lambda: clock() + offset[0])
    monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(tmp_path / "store"))
    monkeypatch.setattr(evidence_store, "_resolve_auto_mirror_backend", lambda: None)
    pages(monkeypatch, _traversal, [(encoded([row(1), row(2)]), ())])
    entered = []
    readbacks = []
    original_save = evidence_store.save_evidence_version_one

    def crossing(artifact, evidence_store_dir):
        entered.append(artifact.id)
        if save_state == "raised":
            offset[0] = 61.0
            raise OSError("Synthetic save failure at the original deadline.")
        returned = original_save(artifact, evidence_store_dir=evidence_store_dir)
        if save_state == "collided":
            returned = original_save(artifact, evidence_store_dir=evidence_store_dir)
        offset[0] = 61.0
        return returned

    def forbidden_readback(*args, **kwargs):
        readbacks.append(True)
        raise AssertionError("Readback started after expiry.")

    monkeypatch.setattr(evidence_store, "save_evidence_version_one", crossing)
    monkeypatch.setattr(_store, "readback", forbidden_readback)
    from evidentia_core.release_cadence import _json
    from evidentia_core.release_cadence._contracts import PollResult, ReleaseError

    for model, method in (
        (ReleaseError, "model_validate"),
        (PollResult, "model_validate"),
        (PollResult, "model_validate_json"),
    ):
        original_validator = getattr(model, method)

        def validator(*args, _original=original_validator, **kwargs):
            assert offset[0] == 0.0, "A result validator started after expiry."
            return _original(*args, **kwargs)

        monkeypatch.setattr(model, method, validator)
    for module in (collector, route, _json):
        original = module.canonical_bytes

        def guarded(*args, _original=original, **kwargs):
            assert offset[0] == 0.0, "Serialization started after expiry."
            return _original(*args, **kwargs)

        monkeypatch.setattr(module, "canonical_bytes", guarded)
    response = TestClient(make_app(monkeypatch)).post(POLL, json=request_value(persist=True))
    expected = (
        b'{"code":"persistence_outcome_unavailable","message":"The release deadline expired '
        b"after a save was attempted. Persistence may have occurred. Inspect local records "
        b'before retrying.","schema_version":"release-error-v1"}'
    )
    assert response.status_code == 500 and response.content == expected
    assert response.headers["content-type"] == "application/json"
    assert response.headers["content-length"] == str(len(expected))
    assert len(expected) < 512 and len(entered) == 1 and readbacks == []


def test_foreign_failure_cannot_claim_persistence(monkeypatch):
    from evidentia_api.routers import release_cadence as route
    from evidentia_core.release_cadence import _limits

    def forged(clock):
        raise _limits.ReleaseFailure("persistence_outcome_unavailable")

    monkeypatch.setattr(route, "_load_poll", lambda: forged)
    client = TestClient(make_app(monkeypatch))
    response = client.post(POLL, json=request_value())
    assert response.status_code == 500 and response.json()["code"] == "operation_failed"
    response = client.post(POLL, json={**request_value(), "code": "persistence_outcome_unavailable"})
    assert response.status_code == 422


def test_expiry_at_actual_api_final_validation_retains_owned_authority(monkeypatch, tmp_path):
    from evidentia_api.routers import release_cadence as route
    from evidentia_core import evidence_store
    from evidentia_core.release_cadence import _limits

    from tests.unit.test_collectors.release_cadence._helpers import encoded, row

    native_clock = _limits.time.monotonic
    offset = [0.0]
    monkeypatch.setattr(_limits.time, "monotonic", lambda: native_clock() + offset[0])
    monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(tmp_path / "store"))
    monkeypatch.setattr(evidence_store, "_resolve_auto_mirror_backend", lambda: None)
    pages(monkeypatch, _traversal, [(encoded([row()]), ())])
    original = route._accepted

    def late(*args, **kwargs):
        offset[0] = 61.0
        return original(*args, **kwargs)

    monkeypatch.setattr(route, "_accepted", late)
    result = TestClient(make_app(monkeypatch)).post(POLL, json=request_value(persist=True))
    assert result.status_code == 500 and result.json()["code"] == "persistence_outcome_unavailable"
    assert len(list((tmp_path / "store").glob("*/v1.json"))) == 1


@pytest.mark.parametrize("endpoint", [POLL, SERIES])
def test_actual_openapi_schema_corresponds_to_complete_model_exports(monkeypatch, endpoint):
    from evidentia_core.release_cadence._contracts import (
        PollRequest,
        PollResult,
        ReleaseError,
        ReleaseSeriesRequest,
        ReleaseSeriesResult,
    )

    def expand(value, definitions):
        if isinstance(value, list):
            return [expand(item, definitions) for item in value]
        if not isinstance(value, dict):
            return value
        if "$ref" in value:
            reference = value["$ref"]
            assert reference.startswith(("#/$defs/", "#/components/schemas/"))
            resolved = dict(definitions[reference.rsplit("/", 1)[-1]])
            resolved.update({key: item for key, item in value.items() if key != "$ref"})
            return expand(resolved, definitions)
        return {key: expand(item, definitions) for key, item in value.items() if key not in {"$defs", "title"}}

    app_schema = make_app(monkeypatch).openapi()
    operation = app_schema["paths"][endpoint]["post"]
    request_type, result_type = (
        (PollRequest, PollResult) if endpoint == POLL else (ReleaseSeriesRequest, ReleaseSeriesResult)
    )
    exported_request = request_type.model_json_schema(mode="validation")
    actual_request = operation["requestBody"]["content"]["application/json"]["schema"]
    assert expand(actual_request, actual_request.get("$defs", {})) == expand(
        exported_request, exported_request.get("$defs", {})
    )
    exported_result = result_type.model_json_schema(mode="serialization")
    actual_result = operation["responses"]["200"]["content"]["application/json"]["schema"]
    assert expand(actual_result, app_schema["components"]["schemas"]) == expand(
        exported_result, exported_result.get("$defs", {})
    )
    exported_error = ReleaseError.model_json_schema(mode="serialization")
    for status in ("413", "415", "422", "500", "503"):
        actual_error = operation["responses"][status]["content"]["application/json"]["schema"]
        assert expand(actual_error, app_schema["components"]["schemas"]) == expand(
            exported_error, exported_error.get("$defs", {})
        )


@pytest.mark.parametrize("series", [False, True])
@pytest.mark.parametrize("kind", ["cancelled", "base_exception"])
def test_request_stream_cancellation_preserves_primary_and_clears_owned_body(series, kind):
    import asyncio

    from evidentia_api.routers import release_cadence as route
    from evidentia_core.release_cadence._limits import _start_invocation
    from starlette.requests import Request

    class SyntheticInterruption(BaseException):
        pass

    primary = (
        asyncio.CancelledError("Synthetic request cancellation")
        if kind == "cancelled"
        else SyntheticInterruption("Synthetic request interruption")
    )
    calls = []

    async def receive():
        calls.append(True)
        if len(calls) == 1:
            return {"type": "http.request", "body": b"{", "more_body": True}
        raise primary

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": SERIES if series else POLL,
            "query_string": b"",
            "headers": [(b"content-type", b"application/json")],
        },
        receive,
    )
    clock = _start_invocation()
    deadline = clock.budget.deadline
    with pytest.raises(type(primary)) as caught:
        asyncio.run(route._read_request(request, clock, series=series))
    assert caught.value is primary and calls == [True, True] and clock.budget.deadline == deadline
    trace, frame = caught.value.__traceback__, None
    while trace is not None:
        if trace.tb_frame.f_code is route._read_request.__code__:
            frame = trace.tb_frame
        trace = trace.tb_next
    assert frame is not None and frame.f_locals["body"] == bytearray()
