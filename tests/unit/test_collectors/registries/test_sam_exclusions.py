"""Preserve active-firm candidate scope and every selected action occurrence."""

from __future__ import annotations

import copy
import json
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from evidentia_collectors.registries import sam_exclusions
from evidentia_collectors.registries._client import RegistryReadSession
from evidentia_collectors.registries._contracts import RegistryInputError, result_bytes
from evidentia_collectors.registries._sam_http import SamAttempt, SamTransportError

FIXTURES = Path(__file__).parents[3] / "fixtures/registries/sam_exclusions"
NOW = datetime(2026, 9, 11, 12, tzinfo=UTC)
UEI = "ABCDEFGHIJKL"


@pytest.fixture(autouse=True)
def refuse_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: pytest.fail("unexpected DNS"))


def source(name: str) -> dict[str, Any]:
    value: dict[str, Any] = json.loads((FIXTURES / name).read_bytes())
    return value


def session(
    pages: list[dict[str, Any] | SamTransportError], target: dict[str, str] | None = None
) -> tuple[RegistryReadSession, list[int]]:
    calls: list[int] = []

    class SyntheticSAM(SamAttempt):
        def fetch(self, *args: Any, **kwargs: Any) -> bytes:
            page = kwargs["page"]
            calls.append(page)
            reply = pages[page]
            if isinstance(reply, SamTransportError):
                raise reply
            content = json.dumps(reply).encode()
            kwargs["consume"](len(content), len(content))
            self.status_code = 200
            return content

    return RegistryReadSession(
        {"registry": "sam-exclusions", "target": target or {"uei": UEI}},
        _utc=lambda: NOW,
        _monotonic=lambda: 0.0,
        _sam_factory=SyntheticSAM,
        _sam_resolver=lambda reference: pytest.fail("unexpected credential access"),
    ), calls


def expected_first() -> dict[str, Any]:
    return {
        "exclusionDetails": {
            "classificationType": "Firm",
            "exclusionType": "PublisherFutureType",
            "exclusionProgram": "Reciprocal",
            "excludingAgencyCode": "001",
            "excludingAgencyName": "Synthetic Agency 1",
        },
        "exclusionIdentification": {"ueiSAM": UEI, "entityName": "Example Research LLC"},
        "exclusionActions": {
            "listOfActions": [
                {
                    "createDate": "2026-01-01",
                    "updateDate": "2026-02-02T03:04:05.123456789Z",
                    "activateDate": "02/03/2026",
                    "terminationDate": None,
                    "terminationType": "Indefinite",
                    "recordStatus": "Active",
                },
                {"createDate": "2026-01-01", "updateDate": "", "recordStatus": "SourceFutureStatus"},
                None,
            ]
        },
        "exclusionOtherInformation": {"isFASCSAOrder": "N"},
    }


def test_documented_pages_retain_all_agency_and_ordered_action_occurrences() -> None:
    current, calls = session([source("exclusions-first-page.json"), source("exclusions-last-page.json")])
    result = sam_exclusions.lookup(current)
    assert result.lookup_outcome == "ambiguous" and result.collection_status == "complete"
    assert calls == [0, 1] and len(result.observations) == 11
    assert result.observations[0].fields == expected_first()
    assert len({item.observation_id for item in result.observations}) == 11
    assert [read.source_records for read in result.source_reads] == [10, 1]
    assert all(item.normalized_utc is None for item in result.observations[0].source_times)
    assert b"Synthetic omitted" not in result_bytes(result) and b"Synthetic excluded person" not in result_bytes(result)
    assert json.loads(result_bytes(result))["findings"][0]["raw_data"]["observation"]["fields"] == expected_first()


def test_token_candidates_use_exact_local_name_without_merging_different_occurrences() -> None:
    current, _ = session([source("exclusions-name-collision.json")], {"organization_name": "EXAMPLE RESEARCH LLC"})
    result = sam_exclusions.lookup(current)
    assert result.lookup_outcome == "ambiguous" and result.collection_status == "complete"
    assert len(result.observations) == 2 and result.source_reads[0].source_records == 3
    assert all(item.match_basis == "exact_normalized_name" for item in result.observations)
    identifiers: set[str] = set()
    for item in result.observations:
        identification = item.fields["exclusionIdentification"]
        assert isinstance(identification, dict)
        uei = identification["ueiSAM"]
        assert isinstance(uei, str)
        identifiers.add(uei)
    assert identifiers == {UEI, "MNOPQRSTUVWX"}


def test_no_exact_name_is_unavailable_with_match_scope_limit() -> None:
    current, _ = session([source("exclusions-name-collision.json")], {"organization_name": "Different Name"})
    result = sam_exclusions.lookup(current)
    assert not result.observations and result.lookup_outcome == "unavailable"
    assert "source_match_scope_limited" in {item.code for item in result.diagnostics}


def test_named_candidate_can_lack_a_uei_without_inventing_one() -> None:
    current, _ = session([source("exclusions-no-uei.json")], {"organization_name": "Example Research LLC"})
    result = sam_exclusions.lookup(current)
    assert result.lookup_outcome == "found" and result.collection_status == "complete"
    assert result.observations[0].fields["exclusionIdentification"] == {"entityName": "Example Research LLC"}
    assert result.observations[0].field_coverage["/exclusionIdentification/ueiSAM"] == "absent"
    current, _ = session([source("exclusions-no-uei.json")])
    assert sam_exclusions.lookup(current).lookup_outcome == "unavailable"


def test_empty_uei_traversal_is_scoped_not_found_but_empty_name_is_not() -> None:
    body = {"totalRecords": 0, "excludedEntity": []}
    current, calls = session([body])
    result = sam_exclusions.lookup(current)
    assert result.lookup_outcome == "not_found" and result.collection_status == "complete" and calls == [0]
    current, _ = session([body], {"organization_name": "Example Research LLC"})
    assert sam_exclusions.lookup(current).lookup_outcome == "unavailable"


@pytest.mark.parametrize("fault", ["repeated_page", "total_changed", "invalid_response", "connection_failure"])
def test_later_failure_retains_the_first_page_atomically(fault: str) -> None:
    first = source("exclusions-page-loop.json")
    candidate = copy.deepcopy(first)
    if fault == "total_changed":
        candidate["totalRecords"] = 21
    elif fault == "invalid_response":
        candidate["excludedEntity"][0]["exclusionOtherInformation"]["isFASCSAOrder"] = True
    second: dict[str, Any] | SamTransportError = (
        SamTransportError("connection_failure") if fault == "connection_failure" else candidate
    )
    current, calls = session([first, second])
    result = sam_exclusions.lookup(current)
    assert result.collection_status == "partial" and len(result.observations) == 10 and calls == [0, 1]
    assert fault in {item.code for item in result.diagnostics}
    assert result.source_reads[1].admitted_records == 0


@pytest.mark.parametrize("bad", [True, -1, "11"])
def test_total_requires_a_native_nonnegative_integer(bad: object) -> None:
    body = source("exclusions-first-page.json")
    body["totalRecords"] = bad
    current, _ = session([body])
    result = sam_exclusions.lookup(current)
    assert not result.observations and "invalid_response" in {item.code for item in result.diagnostics}


def test_projection_preserves_null_empty_and_detached_nested_values() -> None:
    value: dict[str, Any] = {
        "exclusionActions": {"listOfActions": [None, {}, {"recordStatus": None}]},
        "exclusionDetails": None,
        "exclusionIdentification": {},
        "exclusionOtherInformation": {"isFASCSAOrder": ""},
    }
    projected = sam_exclusions._project(value)
    assert projected == value
    projected["exclusionActions"]["listOfActions"].append({})
    assert len(value["exclusionActions"]["listOfActions"]) == 3


def test_dropped_action_is_refused_by_source_correspondence(monkeypatch: pytest.MonkeyPatch) -> None:
    original = sam_exclusions._project

    def drop(value: dict[str, Any]) -> dict[str, Any]:
        projected = original(value)
        projected["exclusionActions"]["listOfActions"].pop()
        return projected

    monkeypatch.setattr(sam_exclusions, "_project", drop)
    current, _ = session([source("exclusions-no-uei.json")], {"organization_name": "Example Research LLC"})
    result = sam_exclusions.lookup(current)
    assert not result.observations and "projection_mismatch" in {item.code for item in result.diagnostics}


@pytest.mark.parametrize("name", ["Example*", "Example?", "Name:Company", "A/B", "---", " ", "Example\tResearch"])
def test_unsupported_name_is_refused_before_session_or_credentials(name: str) -> None:
    with pytest.raises(ValueError):
        RegistryReadSession(
            {"registry": "sam-exclusions", "target": {"organization_name": name}},
            _sam_resolver=lambda reference: pytest.fail("unexpected credentials"),
        )


def test_non_firm_row_is_not_admitted() -> None:
    body = source("exclusions-no-uei.json")
    body["excludedEntity"][0]["exclusionDetails"]["classificationType"] = "Individual"
    current, _ = session([body], {"organization_name": "Example Research LLC"})
    result = sam_exclusions.lookup(current)
    assert not result.observations and "identity_mismatch" in {item.code for item in result.diagnostics}


def test_wrong_selector_refuses_dispatch() -> None:
    with pytest.raises(RegistryInputError):
        sam_exclusions.lookup(RegistryReadSession({"registry": "sam-entity", "target": {"uei": UEI}}))
