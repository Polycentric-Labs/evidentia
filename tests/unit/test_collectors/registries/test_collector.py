"""Check dispatch, detached result identity and collector lifecycle."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from evidentia_collectors.registries._client import RegistryReadSession
from evidentia_collectors.registries._contracts import (
    EndpointTarget,
    RegistryInputError,
    RegistryLookupRequest,
    RegistryLookupResult,
    result_bytes,
)

REQUEST: dict[str, Any] = {
    "registry": "ssl-labs",
    "target": {"hostname": "endpoint.example.org", "endpoint_ip": "93.184.216.34"},
}


def disabled(request: object) -> RegistryLookupResult:
    session = RegistryReadSession(request, _utc=lambda: datetime(2026, 9, 11, tzinfo=UTC))
    target = session.request.root.target
    assert type(target) is EndpointTarget
    return session.read_ssl_labs(target, lambda value: pytest.fail("disabled projector"))


def test_construction_and_lazy_public_export(monkeypatch: pytest.MonkeyPatch) -> None:
    from evidentia_collectors.registries import RegistryCollector

    def factory(selected: RegistryLookupRequest) -> RegistryReadSession:
        pytest.fail("construction created a session")

    collector = RegistryCollector(_session_factory=factory)
    collector.close()
    with pytest.raises(ValueError, match="registry_collection_failed"):
        collector.collect_v2(REQUEST)


def test_full_and_compatibility_results_use_one_session_per_run(monkeypatch: pytest.MonkeyPatch) -> None:
    from evidentia_collectors.registries import collector as module

    calls: list[object] = []

    def reader(session: RegistryReadSession) -> RegistryLookupResult:
        calls.append(session)
        return disabled(session.request)

    monkeypatch.setattr(module, "_read_registry", reader)
    with module.RegistryCollector() as collector:
        result = collector.collect_v2(REQUEST)
        assert result.registry == "ssl-labs" and result.lookup_outcome == "unavailable"
        assert collector.collect(REQUEST) == []
    assert len(calls) == 2 and calls[0] is not calls[1]
    assert json.loads(result_bytes(result))["request"]["target"] == REQUEST["target"]


@pytest.mark.parametrize("value", [{"registry": "unknown"}, {**REQUEST, "credential": "forbidden"}, None, 3])
def test_invalid_request_precedes_session(value: object) -> None:
    from evidentia_collectors.registries import RegistryCollector

    with pytest.raises(RegistryInputError):
        RegistryCollector(_session_factory=lambda selected: pytest.fail("invalid dispatch")).collect_v2(value)


def test_mutating_worker_cannot_rebind_result(monkeypatch: pytest.MonkeyPatch) -> None:
    from evidentia_collectors.registries import collector as module

    original = RegistryLookupRequest.model_validate(REQUEST)

    def mutate(session: RegistryReadSession) -> RegistryLookupResult:
        object.__setattr__(original.root.target, "hostname", "other.example.org")
        changed: dict[str, Any] = {**REQUEST, "target": {**REQUEST["target"], "hostname": "other.example.org"}}
        return disabled(changed)

    monkeypatch.setattr(module, "_read_registry", mutate)
    with pytest.raises(ValueError, match="registry_collection_failed"):
        module.RegistryCollector().collect_v2(original)


def test_internal_failure_is_sanitized_and_cancellation_is_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    from evidentia_collectors.registries import collector as module

    def broken(session: RegistryReadSession) -> RegistryLookupResult:
        raise RuntimeError("internal-only-test-detail")

    monkeypatch.setattr(module, "_read_registry", broken)
    with pytest.raises(ValueError) as error:
        module.RegistryCollector().collect_v2(REQUEST)
    assert str(error.value) == "registry_collection_failed"
    cancellation = KeyboardInterrupt()

    def cancelled(session: RegistryReadSession) -> RegistryLookupResult:
        raise cancellation

    monkeypatch.setattr(module, "_read_registry", cancelled)
    with pytest.raises(KeyboardInterrupt) as interrupted:
        module.RegistryCollector().collect_v2(REQUEST)
    assert interrupted.value is cancellation


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_registry_json_schema_is_recursive_and_closed(mode: Any) -> None:
    schema = RegistryLookupResult.model_json_schema(mode=mode)
    definitions = schema["$defs"]
    names = [name for name in definitions if name.endswith("JsonValue")]
    assert len(names) == 1
    name = names[0]
    assert definitions[name] == {
        "anyOf": [
            {"type": "boolean"},
            {"type": "integer"},
            {"type": "number"},
            {"type": "string"},
            {"type": "array", "items": {"$ref": "#/$defs/" + name}},
            {"type": "object", "additionalProperties": {"$ref": "#/$defs/" + name}},
            {"type": "null"},
        ]
    }
    assert definitions["RegistryObservation"]["properties"]["fields"]["additionalProperties"] == {
        "$ref": "#/$defs/" + name
    }
