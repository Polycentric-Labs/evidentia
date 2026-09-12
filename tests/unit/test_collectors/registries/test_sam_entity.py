"""Keep registered SAM occurrences and their incomplete source scope explicit."""

from __future__ import annotations

import json
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from evidentia_collectors.registries import sam_entity
from evidentia_collectors.registries._client import RegistryReadSession
from evidentia_collectors.registries._contracts import RegistryInputError, result_bytes
from evidentia_collectors.registries._sam_http import SamAttempt

FIXTURES = Path(__file__).parents[3] / "fixtures/registries/sam_entity"
NOW = datetime(2026, 9, 11, 12, tzinfo=UTC)
UEI = "ABCDEFGHIJKL"


@pytest.fixture(autouse=True)
def refuse_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: pytest.fail("unexpected DNS"))


def source(name: str) -> dict[str, Any]:
    value: dict[str, Any] = json.loads((FIXTURES / name).read_bytes())
    return value


def session(body: dict[str, Any]) -> tuple[RegistryReadSession, list[int]]:
    calls: list[int] = []
    content = json.dumps(body).encode()

    class SyntheticSAM(SamAttempt):
        def fetch(self, *args: Any, **kwargs: Any) -> bytes:
            calls.append(kwargs["page"])
            kwargs["consume"](len(content), len(content))
            self.status_code = 200
            return content

    return RegistryReadSession(
        {"registry": "sam-entity", "target": {"uei": UEI}},
        _utc=lambda: NOW,
        _monotonic=lambda: 0.0,
        _sam_factory=SyntheticSAM,
        _sam_resolver=lambda reference: pytest.fail("unexpected credential access"),
    ), calls


def test_registered_fields_are_literal_and_eft_occurrences_remain_distinct() -> None:
    current, calls = session(source("entity-public.json"))
    result = sam_entity.lookup(current)
    assert result.lookup_outcome == "ambiguous" and result.collection_status == "partial"
    assert calls == [0] and len(result.observations) == 2
    expected = {
        "ueiSAM": UEI,
        "samRegistered": "Yes",
        "entityEFTIndicator": "0001",
        "legalBusinessName": "Example Research LLC",
        "registrationStatus": "Active",
        "registrationDate": "2026-08-01",
        "lastUpdateDate": "2026-09-01T00:00:00.123456789Z",
        "registrationExpirationDate": "08/01/2027",
        "activationDate": "2026-08-02",
    }
    assert result.observations[0].fields == expected
    assert result.observations[1].fields == {
        **expected,
        "entityEFTIndicator": "0002",
        "registrationStatus": "SourceFutureStatus",
    }
    assert result.observations[0].observation_id != result.observations[1].observation_id
    assert {item.code for item in result.diagnostics} >= {"source_terminal_unproven", "traversal_incomplete"}
    assert all(item.normalized_utc is None for item in result.observations[0].source_times)
    assert "eligibility" in result.observations[0].interpretation
    assert b"Synthetic excluded contact" not in result_bytes(result)
    assert result.source_reads[0].attempted_pages == result.source_reads[0].accepted_pages == 1
    assert json.loads(result_bytes(result))["findings"][0]["raw_data"]["observation"]["fields"] == expected


def test_single_registered_occurrence_is_found_but_never_complete() -> None:
    body = source("entity-public.json")
    body["entityData"] = body["entityData"][:1]
    current, _ = session(body)
    result = sam_entity.lookup(current)
    assert result.lookup_outcome == "found" and result.collection_status == "partial"


def test_null_empty_unknown_and_omission_are_not_coerced() -> None:
    current, _ = session(source("unknown-null.json"))
    result = sam_entity.lookup(current)
    assert result.lookup_outcome == "found" and result.collection_status == "partial"
    observation = result.observations[0]
    assert observation.fields == {
        "ueiSAM": UEI,
        "samRegistered": "Yes",
        "entityEFTIndicator": None,
        "legalBusinessName": None,
        "registrationStatus": "PublisherFutureStatus",
        "registrationDate": None,
        "lastUpdateDate": "",
        "registrationExpirationDate": "date unknown",
    }
    assert observation.field_coverage["/registrationDate"] == "null"
    assert observation.field_coverage["/lastUpdateDate"] == "present"
    assert observation.field_coverage["/activationDate"] == "absent"


@pytest.mark.parametrize("name", ["identity-mismatch.json", "entity-unregistered.json"])
def test_identity_and_registered_scope_are_checked_before_projection(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sam_entity, "_project", lambda value: pytest.fail("unmatched projection"))
    current, calls = session(source(name))
    result = sam_entity.lookup(current)
    assert not result.observations and result.lookup_outcome == "unavailable"
    assert "identity_mismatch" in {item.code for item in result.diagnostics} and calls == [0]


def test_empty_response_cannot_establish_absence_or_follow_claimed_next() -> None:
    current, calls = session({"entityData": [], "totalRecords": 0, "next": "https://unselected.example.test/next"})
    result = sam_entity.lookup(current)
    assert result.lookup_outcome == "unavailable" and not result.observations and calls == [0]
    assert "source_terminal_unproven" in {item.code for item in result.diagnostics}


@pytest.mark.parametrize("bad", [False, 17, [], {}])
def test_selected_wrong_types_refuse_the_whole_page(bad: object) -> None:
    body = source("entity-public.json")
    body["entityData"][1]["entityRegistration"]["registrationStatus"] = bad
    current, _ = session(body)
    result = sam_entity.lookup(current)
    assert result.lookup_outcome == "unavailable" and not result.observations
    assert "invalid_response" in {item.code for item in result.diagnostics}


def test_later_identity_mismatch_and_oversized_source_page_are_atomic() -> None:
    body = source("entity-public.json")
    body["entityData"][1]["entityRegistration"]["ueiSAM"] = "ZZZZZZZZZZZZ"
    current, _ = session(body)
    assert not sam_entity.lookup(current).observations
    body["entityData"] = [body["entityData"][0]] * 11
    current, _ = session(body)
    result = sam_entity.lookup(current)
    assert not result.observations and "invalid_response" in {item.code for item in result.diagnostics}


def test_projection_does_not_copy_unselected_source_fields() -> None:
    value = {"ueiSAM": UEI, "samRegistered": "Yes", "registrationDate": None, "unselected": {"value": 1}}
    assert sam_entity._project(value) == {"ueiSAM": UEI, "samRegistered": "Yes", "registrationDate": None}
    assert value["unselected"] == {"value": 1}


def test_missing_configuration_uses_the_existing_credential_failure() -> None:
    class MissingCredential(SamAttempt):
        def fetch(self, *args: Any, **kwargs: Any) -> bytes:
            kwargs["credentials"].resolve(lambda: NOW)
            pytest.fail("missing credentials were accepted")

    current = RegistryReadSession(
        {"registry": "sam-entity", "target": {"uei": UEI}},
        _utc=lambda: NOW,
        _monotonic=lambda: 0.0,
        _sam_factory=MissingCredential,
        _sam_resolver=lambda reference: None,
    )
    result = sam_entity.lookup(current)
    assert result.lookup_outcome == "unavailable" and "missing_credential" in {item.code for item in result.diagnostics}


def test_wrong_selector_refuses_dispatch_without_io() -> None:
    current = RegistryReadSession({"registry": "gleif", "target": {"lei": "A" * 20}})
    with pytest.raises(RegistryInputError):
        sam_entity.lookup(current)
