"""Independent outward poll relations derived from literal source examples."""

from __future__ import annotations

import copy
import hashlib
import json
import uuid

import pytest
from evidentia_core.release_cadence._contracts import PollResult
from evidentia_core.release_cadence._limits import ReleaseFailure


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def hand_poll():
    request = {
        "schema_version": "release-poll-request-v1",
        "source_profile": "github-public-releases-2026-03-10",
        "owner": "Example",
        "repository": "Synthetic",
        "channel": "all_published",
        "persist": False,
    }
    selected = {
        "id": 101,
        "node_id": "synthetic-101",
        "url": "inert://source",
        "html_url": "",
        "tag_name": "v1",
        "target_commitish": "main",
        "name": None,
        "draft": False,
        "prerelease": False,
        "created_at": "",
        "published_at": "2000-01-01T00:00:00Z",
    }
    fact_sha = hashlib.sha256(compact(["evidentia.release-selected-facts.v1", selected])).hexdigest()
    event_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            compact(
                [
                    "evidentia.release-publication.v1",
                    "api.github.com",
                    "example",
                    "synthetic",
                    "101",
                ]
            ).decode(),
        )
    )
    body = compact([selected])
    body_sha = hashlib.sha256(body).hexdigest()
    return {
        "schema_version": "release-poll-result-v1",
        "request": request,
        "request_sha256": hashlib.sha256(compact(request)).hexdigest(),
        "scope": {
            "identity_version": "evidentia.release-publication.v1",
            "source_profile": "github-public-releases-2026-03-10",
            "source_host": "api.github.com",
            "canonical_owner": "example",
            "canonical_repository": "synthetic",
            "channel": "all_published",
        },
        "clocks": {
            "poll_id": "00000000-0000-4000-8000-000000000001",
            "started_at": "2001-01-01T00:00:00.000000Z",
            "traversal_completed_at": "2001-01-01T00:00:00.000001Z",
            "completed_at": "2001-01-01T00:00:00.000002Z",
        },
        "collection_state": "complete",
        "terminal_reason": None,
        "reasons": [],
        "counters": {
            "attempts": 1,
            "pages_admitted": 1,
            "rows_admitted": 1,
            "unique_source_events": 1,
            "raw_entity_bytes_observed": len(body),
            "decoded_entity_bytes_observed": len(body),
            "selected_ccompact_bytes_admitted": len(compact(selected)),
            "targeted_record_reads": 0,
            "targeted_raw_bytes_observed": 0,
            "total_store_raw_bytes_observed": 0,
        },
        "discovery": {
            "status": "not_requested",
            "passes": 0,
            "root_entries_observed": 0,
            "child_entries_observed": 0,
            "canonical_files_read": 0,
            "raw_file_bytes_observed": 0,
            "release_record_reads_observed": 0,
            "inventory_sha256": None,
            "selected_scope_records": None,
            "conflicting_events": None,
        },
        "persistence": {
            "requested": False,
            "state": "not_requested",
            "planned_slots": 0,
            "attempted_calls": 0,
            "last_attempted_slot": None,
            "outcome_counts": {
                name: 0
                for name in (
                    "created",
                    "already_saved",
                    "existing_different_facts",
                    "present_after_uncertain_save",
                    "not_applicable",
                    "not_attempted",
                    "failed",
                    "indeterminate",
                    "conflict",
                )
            },
            "stop_reason": None,
            "mirror_outcome": "unobserved",
        },
        "rows": [
            {
                "metadata": {
                    "row_index": 0,
                    "page_index": 0,
                    "record_index": 0,
                    "event_index": 0,
                    "selected_facts_sha256": fact_sha,
                    "source_time": {"classification": "normalized", "normalized_utc": "2000-01-01T00:00:00.000000Z"},
                    "initial_publication_eligible": True,
                    "eligibility_reasons": [],
                },
                "selected": selected,
            }
        ],
        "pages": [
            {
                "page_index": 0,
                "page_ordinal": 1,
                "page_number": 1,
                "http_status": 200,
                "retrieved_at": "2001-01-01T00:00:00.000001Z",
                "raw_bytes_observed": len(body),
                "decoded_bytes_observed": len(body),
                "raw_body_complete": True,
                "decoded_body_complete": True,
                "raw_body_sha256": body_sha,
                "decoded_body_sha256": body_sha,
                "link_state": "absent",
                "link_values_sha256": hashlib.sha256(b"[]").hexdigest(),
                "first_page": None,
                "previous_page": None,
                "next_page": None,
                "last_page": None,
                "json_value_key_occurrences": 24,
                "json_depth_observed": 3,
                "decoded_row_count": 1,
                "admitted": True,
                "row_start": 0,
                "row_count": 1,
                "reason": None,
            }
        ],
        "events": [
            {
                "event_index": 0,
                "event_id": event_id,
                "release_id": 101,
                "representative_row_index": 0,
                "occurrence_count": 1,
                "stored_state": "not_observed",
                "known_observation_count": None,
                "current_vs_parent": None,
                "stored_union_change_codes": [],
                "blocks_full_releases": None,
                "blocks_all_published": None,
                "publication_outcome_index": None,
                "observation_outcome_index": None,
            }
        ],
        "outcomes": [],
        "meaning": "visible_upstream_release_observation",
    }


def test_hand_derived_complete_poll_is_valid():
    assert PollResult.model_validate_json(compact(hand_poll())).collection_state == "complete"


@pytest.mark.parametrize(
    "path,value",
    [
        (("request_sha256",), "0" * 64),
        (("scope", "canonical_owner"), "different"),
        (("scope", "channel"), "full_releases"),
        (("clocks", "completed_at"), "1999-01-01T00:00:00.000000Z"),
        (("clocks", "traversal_completed_at"), None),
        (("collection_state",), "partial"),
        (("terminal_reason",), "timeout"),
        (("counters", "rows_admitted"), 0),
        (("counters", "attempts"), 0),
        (("counters", "selected_ccompact_bytes_admitted"), 0),
        (("counters", "raw_entity_bytes_observed"), 0),
        (("counters", "total_store_raw_bytes_observed"), 1),
        (("rows", 0, "metadata", "event_index"), 1),
        (("rows", 0, "metadata", "row_index"), 1),
        (("rows", 0, "metadata", "selected_facts_sha256"), "0" * 64),
        (("rows", 0, "metadata", "eligibility_reasons"), ["draft"]),
        (("rows", 0, "metadata", "initial_publication_eligible"), False),
        (("rows", 0, "metadata", "source_time", "classification"), "absent"),
        (("pages", 0, "row_start"), None),
        (("pages", 0, "row_count"), 0),
        (("pages", 0, "raw_body_complete"), False),
        (("pages", 0, "link_state"), "unavailable"),
        (("pages", 0, "next_page"), 2),
        (("pages", 0, "page_number"), 2),
        (("events", 0, "event_id"), "00000000-0000-5000-8000-000000000001"),
        (("events", 0, "occurrence_count"), 2),
        (("events", 0, "publication_outcome_index"), 0),
        (("events", 0, "blocks_full_releases"), False),
        (("persistence", "state"), "complete"),
        (("discovery", "passes"), 1),
    ],
)
def test_forged_cross_field_poll_refuses(path, value):
    candidate = hand_poll()
    target = candidate
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    with pytest.raises((ReleaseFailure, ValueError)):
        PollResult.model_validate(candidate)


def test_partial_time_eligibility_is_unestablished():
    candidate = hand_poll()
    candidate["collection_state"] = "partial"
    candidate["terminal_reason"] = "page_limit"
    candidate["reasons"] = ["page_limit"]
    candidate["clocks"]["traversal_completed_at"] = None
    # The page-limit terminal occurs only at the tenth admitted page.
    first = candidate["pages"][0]
    candidate["pages"] = []
    for index in range(10):
        page = copy.deepcopy(first)
        page.update(
            {
                "page_index": index,
                "page_ordinal": index + 1,
                "page_number": index + 1,
                "link_state": "valid",
                "next_page": index + 2,
                "row_start": 0 if index == 0 else 1,
                "row_count": 1 if index == 0 else 0,
                "decoded_row_count": 1 if index == 0 else 0,
                "reason": "page_limit" if index == 9 else None,
            }
        )
        if index:
            page.update(
                {
                    "raw_bytes_observed": 2,
                    "decoded_bytes_observed": 2,
                    "raw_body_sha256": hashlib.sha256(b"[]").hexdigest(),
                    "decoded_body_sha256": hashlib.sha256(b"[]").hexdigest(),
                    "json_value_key_occurrences": 1,
                    "json_depth_observed": 1,
                }
            )
        links = [f"<https://api.github.com/repos/example/synthetic/releases?page={index + 2}&per_page=100>; rel=next"]
        page["link_values_sha256"] = hashlib.sha256(compact(links)).hexdigest()
        candidate["pages"].append(page)
    candidate["counters"].update(
        {
            "attempts": 10,
            "pages_admitted": 10,
            "raw_entity_bytes_observed": first["raw_bytes_observed"] + 18,
            "decoded_entity_bytes_observed": first["decoded_bytes_observed"] + 18,
        }
    )
    candidate["rows"][0]["metadata"]["initial_publication_eligible"] = False
    assert PollResult.model_validate(candidate).rows[0].metadata.eligibility_reasons == []
    candidate["rows"][0]["metadata"]["initial_publication_eligible"] = True
    with pytest.raises((ReleaseFailure, ValueError)):
        PollResult.model_validate(candidate)


@pytest.mark.parametrize("location", ["top_artifacts", "row_artifact", "event_selected"])
def test_inline_artifact_and_extra_selected_copies_refuse(location):
    from ._helpers import artifact

    candidate = hand_poll()
    assert PollResult.model_validate_json(compact(candidate)).collection_state == "complete"
    if location == "top_artifacts":
        candidate["artifacts"] = [artifact()]
    elif location == "row_artifact":
        candidate["rows"][0]["artifact"] = artifact()
    else:
        candidate["events"][0]["selected"] = copy.deepcopy(candidate["rows"][0]["selected"])
    with pytest.raises((ReleaseFailure, ValueError)):
        PollResult.model_validate(candidate)
