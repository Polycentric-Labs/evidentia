"""Offline release families and exact publication-spacing arithmetic."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from typing import cast

from pydantic import ValidationError

from evidentia_core.conmon.calendar import ConmonCadence, interval_days_for
from evidentia_core.conmon.series import allowed_gap_days

from ._contracts import DiscoveryResult, ReleaseSeriesRequest, ReleaseSeriesResult, native_model
from ._identity import _parent_relations, compare_facts, event_identity, event_tuple, validate_artifact
from ._json import _discard, canonical_bytes, load_json
from ._limits import (
    REQUEST_BYTES,
    RESULT_BYTES,
    SOURCE_HOST,
    SOURCE_PROFILE,
    Budget,
    ReleaseFailure,
    _capture_invocation,
    _Invocation,
    start_budget,
)
from ._source import canonical_repository
from ._store import discover, lexical_store_root
from ._time import elapsed_microseconds, parse_window_time, utc_text

_EVENT_REASONS = (
    "node_id_changed",
    "publication_instant_changed",
    "publication_time_unqualified",
    "draft_changed_to_true",
    "prerelease_changed",
)
_UNAVAILABLE = {
    "unavailable": "store_unavailable",
    "changed": "store_changed",
    "limit_exceeded": "store_limit_exceeded",
    "record_invalid": "store_record_invalid",
    "identity_conflict": "store_identity_conflict",
    "deadline_exceeded": "deadline_exceeded",
}
_STATE_REASONS = {
    "continuous": [],
    "gapped": ["gap_exceeds_allowed"],
    "insufficient": ["insufficient_events"],
    "conflict": ["source_conflict"],
}


def _allowed(request: dict[str, object]) -> int:
    cadence = ConmonCadence(
        slug="upstream-release-publication",
        framework="operator-policy",
        activity="upstream-release-publication",
        frequency="custom",
        description="Operator-selected spacing between recorded upstream release publications.",
        citation=None,
        interval_days=cast(int, request["interval_days"]),
    )
    interval = interval_days_for(cadence)
    allowed = allowed_gap_days(
        cadence, parse_window_time(request["window_start"]).date(), cast(int, request["tolerance_days"])
    )
    if type(interval) is not int or interval != request["interval_days"]:
        raise ReleaseFailure()
    if type(allowed) is not int or allowed != interval + cast(int, request["tolerance_days"]):
        raise ReleaseFailure()
    return allowed * 86_400 * 1_000_000


def _family_reasons(parent: dict[str, object], observations: list[dict[str, object]], channel: str) -> list[str]:
    parent_content = cast(dict[str, object], parent["content"])
    original = cast(dict[str, object], parent_content["selected_facts"])
    reasons: set[str] = set()
    for observation in observations:
        content = cast(dict[str, object], observation["content"])
        comparison = compare_facts(original, content["selected_facts"])
        reasons.update(cast(list[str], comparison["change_codes"]))
    return [
        reason
        for reason in _EVENT_REASONS
        if reason in reasons and (reason != "prerelease_changed" or channel == "full_releases")
    ]


def _gap_rows(request: dict[str, object], events: list[dict[str, object]]) -> list[dict[str, object]]:
    selected = [
        (index, event)
        for index, event in enumerate(events)
        if event["eligibility"] == "eligible" and event["in_window"]
    ]
    selected.sort(key=lambda row: (cast(str, row[1]["published_at"]), cast(str, row[1]["event_id"])))
    if len(selected) < 2:
        return []
    allowed = _allowed(request)
    edges: list[tuple[str, str, int | None, int | None, str]] = [
        (
            utc_text(parse_window_time(request["window_start"])),
            cast(str, selected[0][1]["published_at"]),
            None,
            selected[0][0],
            "start",
        ),
    ]
    for (left_index, left), (right_index, right) in pairwise(selected):
        edges.append(
            (cast(str, left["published_at"]), cast(str, right["published_at"]), left_index, right_index, "between")
        )
    edges.append(
        (
            cast(str, selected[-1][1]["published_at"]),
            utc_text(parse_window_time(request["window_end"])),
            selected[-1][0],
            None,
            "end",
        )
    )
    rows: list[dict[str, object]] = []
    for start, end, left_reference, right_reference, boundary in edges:
        elapsed = elapsed_microseconds(
            parse_window_time(start, normalized=True), parse_window_time(end, normalized=True)
        )
        rows.append(
            {
                "start_at": start,
                "end_at": end,
                "left_event_index": left_reference,
                "right_event_index": right_reference,
                "boundary": boundary,
                "elapsed_microseconds": elapsed,
                "allowed_microseconds": allowed,
                "exceeds_allowed": elapsed > allowed,
            }
        )
    return rows


def series_relations(value: dict[str, object]) -> None:
    """Check all relationships that are represented in the closed wire graph."""
    request = cast(dict[str, object], value["request"])
    owner, repository = canonical_repository(request["owner"], request["repository"])
    scope = {
        "source_profile": SOURCE_PROFILE,
        "source_host": SOURCE_HOST,
        "canonical_owner": owner,
        "canonical_repository": repository,
        "channel": request["channel"],
    }
    if (
        value["scope"] != scope
        or value["request_sha256"] != hashlib.sha256(canonical_bytes(request, REQUEST_BYTES)).hexdigest()
    ):
        raise ReleaseFailure()
    evaluation = parse_window_time(value["evaluation_at"], normalized=True)
    completion = parse_window_time(value["completed_at"], normalized=True)
    start = parse_window_time(request["window_start"])
    end = parse_window_time(request["window_end"])
    if end > evaluation or completion < evaluation:
        raise ReleaseFailure("clock_invalid")
    discovery = cast(dict[str, object], value["discovery"])
    records = cast(list[dict[str, object]], value["records"])
    events = cast(list[dict[str, object]], value["events"])
    gaps = cast(list[dict[str, object]], value["gaps"])
    if discovery["status"] != "complete":
        expected_reason = _UNAVAILABLE[cast(str, discovery["status"])]
        if value["state"] != "unavailable" or value["reasons"] != [expected_reason] or records or events or gaps:
            raise ReleaseFailure()
        return
    seen_ids: set[str] = set()
    event_order: list[tuple[str, ...]] = []
    record_order: list[tuple[tuple[str, ...], int, str]] = []
    memberships: dict[int, list[int]] = {index: [] for index in range(len(events))}
    for index, record in enumerate(records):
        artifact_id = cast(str, record["artifact_id"])
        event_index = cast(int, record["event_index"])
        if artifact_id in seen_ids or event_index not in memberships:
            raise ReleaseFailure()
        seen_ids.add(artifact_id)
        memberships[event_index].append(index)
        event = events[event_index]
        key = event_identity(owner, repository, event["release_id"])["event_key"]
        record_order.append(
            (
                tuple(event_tuple(cast(dict[str, object], key))),
                0 if record["record_kind"] == "release_publication" else 1,
                artifact_id,
            )
        )
    if record_order != sorted(record_order):
        raise ReleaseFailure()
    for index, event in enumerate(events):
        identity = event_identity(owner, repository, event["release_id"])
        event_order.append(tuple(event_tuple(cast(dict[str, object], identity["event_key"]))))
        if event["event_id"] != identity["event_id"]:
            raise ReleaseFailure()
        publication_index = cast(int, event["publication_record_index"])
        related = memberships[index]
        publications = [position for position in related if records[position]["record_kind"] == "release_publication"]
        if publications != [publication_index] or records[publication_index]["artifact_id"] != event["event_id"]:
            raise ReleaseFailure()
        if event["observation_count"] != len(related) - 1:
            raise ReleaseFailure()
        instant = parse_window_time(event["published_at"], normalized=True)
        from ._time import classify_publication

        if classify_publication(event["published_at_literal"])["normalized_utc"] != event["published_at"]:
            raise ReleaseFailure()
        if event["in_window"] != (start <= instant <= end):
            raise ReleaseFailure()
        reasons = cast(list[str], event["reasons"])
        eligibility = event["eligibility"]
        if eligibility == "eligible" and reasons:
            raise ReleaseFailure()
        if eligibility == "channel_excluded" and (
            request["channel"] != "full_releases" or reasons != ["prerelease_excluded"]
        ):
            raise ReleaseFailure()
        if eligibility == "conflict" and (
            not reasons
            or reasons != [reason for reason in _EVENT_REASONS if reason in reasons]
            or (request["channel"] == "all_published" and "prerelease_changed" in reasons)
        ):
            raise ReleaseFailure()
    if event_order != sorted(event_order) or len(set(event_order)) != len(event_order):
        raise ReleaseFailure()
    if any(event["eligibility"] == "conflict" for event in events):
        state = "conflict"
        expected_gaps: list[dict[str, object]] = []
    elif sum(event["eligibility"] == "eligible" and bool(event["in_window"]) for event in events) < 2:
        state = "insufficient"
        expected_gaps = []
    else:
        expected_gaps = _gap_rows(request, events)
        state = "gapped" if any(row["exceeds_allowed"] for row in expected_gaps) else "continuous"
    if value["state"] != state or value["reasons"] != _STATE_REASONS[state] or gaps != expected_gaps:
        raise ReleaseFailure()


def _series_value(
    request_bytes: bytes,
    summary_bytes: bytes,
    record_bytes: tuple[tuple[str, bytes], ...],
    evaluation_at: str,
    completed_at: str,
    budget: Budget,
    *,
    artifact_from_source: Callable[[str, bytes], dict[str, object]],
    parent_from_source: Callable[[str, bytes, str, bytes], None],
) -> dict[str, object]:
    request = native_model(ReleaseSeriesRequest.model_validate(load_json(request_bytes, REQUEST_BYTES, budget=budget)))
    summary = native_model(DiscoveryResult.model_validate(load_json(summary_bytes, 4096, budget=budget)))
    owner, repository = canonical_repository(request["owner"], request["repository"])
    value: dict[str, object] = {
        "schema_version": "release-series-result-v1",
        "request": request,
        "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
        "scope": {
            "source_profile": SOURCE_PROFILE,
            "source_host": SOURCE_HOST,
            "canonical_owner": owner,
            "canonical_repository": repository,
            "channel": request["channel"],
        },
        "evaluation_at": evaluation_at,
        "completed_at": completed_at,
        "discovery": summary,
        "state": "unavailable",
        "reasons": [],
        "records": [],
        "events": [],
        "gaps": [],
        "meaning": "recorded_upstream_publication_spacing",
    }
    if summary["status"] != "complete":
        if record_bytes:
            raise ReleaseFailure("store_record_invalid")
        value["reasons"] = [_UNAVAILABLE[cast(str, summary["status"])]]
        return value
    families: dict[tuple[str, ...], list[tuple[dict[str, object], bytes]]] = {}
    identifiers: set[str] = set()
    if len(record_bytes) > 1024:
        raise ReleaseFailure("store_limit_exceeded")
    for relative, raw in record_bytes:
        budget.check()
        artifact = artifact_from_source(relative, raw)
        identifier = cast(str, artifact["id"])
        if relative != identifier + "/v1.json" or identifier in identifiers:
            raise ReleaseFailure("store_identity_conflict")
        identifiers.add(identifier)
        content = cast(dict[str, object], artifact["content"])
        key = cast(dict[str, object], content["event_key"])
        if (key["canonical_owner"], key["canonical_repository"]) != (owner, repository):
            raise ReleaseFailure("store_identity_conflict")
        families.setdefault(tuple(event_tuple(key)), []).append((artifact, raw))
    references: list[dict[str, object]] = []
    events: list[dict[str, object]] = []
    start = parse_window_time(request["window_start"])
    end = parse_window_time(request["window_end"])
    channel = cast(str, request["channel"])
    for event_index, family_key in enumerate(sorted(families)):
        budget.check()
        family = families[family_key]
        publications = [
            row for row in family if cast(dict[str, object], row[0]["content"])["record_kind"] == "release_publication"
        ]
        if len(publications) != 1:
            raise ReleaseFailure("store_parent_missing")
        parent, parent_raw = publications[0]
        observations = sorted(
            [
                row
                for row in family
                if cast(dict[str, object], row[0]["content"])["record_kind"] == "release_source_observation"
            ],
            key=lambda row: cast(str, row[0]["id"]),
        )
        for observation, observation_raw in observations:
            parent_from_source(
                cast(str, observation["id"]) + "/v1.json",
                observation_raw,
                cast(str, parent["id"]) + "/v1.json",
                parent_raw,
            )
        publication_index = len(references)
        for artifact, raw in [publications[0], *observations]:
            content = cast(dict[str, object], artifact["content"])
            first = cast(dict[str, object], content["first_observation"])
            references.append(
                {
                    "artifact_id": artifact["id"],
                    "record_kind": content["record_kind"],
                    "event_index": event_index,
                    "version": 1,
                    "selected_facts_sha256": content["selected_facts_sha256"],
                    "content_sha256": artifact["content_hash"],
                    "stored_file_sha256": hashlib.sha256(raw).hexdigest(),
                    "first_observed_at": first["retrieved_at"],
                }
            )
        parent_content = cast(dict[str, object], parent["content"])
        facts = cast(dict[str, object], parent_content["selected_facts"])
        publication = cast(dict[str, object], parent_content["publication_time"])
        reasons = _family_reasons(parent, [row[0] for row in observations], channel)
        eligibility = (
            "conflict"
            if reasons
            else "channel_excluded"
            if (channel == "full_releases" and facts["prerelease"])
            else "eligible"
        )
        if eligibility == "channel_excluded":
            reasons = ["prerelease_excluded"]
        instant = parse_window_time(publication["normalized_utc"], normalized=True)
        events.append(
            {
                "event_id": parent["id"],
                "release_id": facts["id"],
                "publication_record_index": publication_index,
                "observation_count": len(observations),
                "published_at_literal": facts["published_at"],
                "published_at": publication["normalized_utc"],
                "in_window": start <= instant <= end,
                "eligibility": eligibility,
                "reasons": reasons,
            }
        )
    if any(event["eligibility"] == "conflict" for event in events):
        state = "conflict"
        gaps: list[dict[str, object]] = []
    elif sum(event["eligibility"] == "eligible" and bool(event["in_window"]) for event in events) < 2:
        state = "insufficient"
        gaps = []
    else:
        gaps = _gap_rows(request, events)
        state = "gapped" if any(row["exceeds_allowed"] for row in gaps) else "continuous"
    value.update(
        {"state": state, "reasons": list(_STATE_REASONS[state]), "records": references, "events": events, "gaps": gaps}
    )
    return value


def _evaluate_wire(
    request: object, evidence_store_dir: object, *, _clock: _Invocation | None = None
) -> tuple[bytes, ReleaseSeriesResult]:
    invocation = _capture_invocation(start_budget(), datetime.now(UTC)) if _clock is None else _clock
    if type(invocation) is not _Invocation:
        raise ReleaseFailure("clock_invalid")
    budget, evaluation, clock_check = invocation.take()
    deadline = budget.deadline
    evaluation_at = utc_text(evaluation)

    def guard() -> None:
        clock_check(0)

    try:
        native_request = native_model(ReleaseSeriesRequest.model_validate(request))
    except ValidationError:
        raise ReleaseFailure("invalid_request") from None
    request_bytes = canonical_bytes(native_request, REQUEST_BYTES, budget=budget)
    if parse_window_time(native_request["window_end"]) > evaluation:
        raise ReleaseFailure("invalid_request")
    root = lexical_store_root(evidence_store_dir)
    guard()
    snapshot = discover(root, native_request["owner"], native_request["repository"], budget)
    guard()
    summary_bytes = snapshot.summary_bytes
    record_bytes = tuple((record.relative_path, record.raw) for record in snapshot.records)
    first_reconstruction_complete = False
    retained: dict[str, tuple[bytes, bytes]] = {}

    def artifact_from_source(relative: str, raw: bytes) -> dict[str, object]:
        cached: tuple[bytes, bytes] | None = None
        encoded: bytes | None = None
        artifact: dict[str, object] | None = None
        try:
            guard()
            if type(relative) is not str or type(raw) is not bytes or not 0 < len(raw) <= 131_072:
                raise ReleaseFailure("store_record_invalid")
            cached = retained.get(relative) if first_reconstruction_complete else None
            if cached is not None and raw == cached[0]:
                # These bytes were produced here from a fully validated native artifact.
                artifact = cast(dict[str, object], json.loads(cached[1]))
                if type(artifact) is not dict:
                    raise ReleaseFailure("store_record_invalid")
                guard()
                return artifact
            artifact = validate_artifact(
                load_json(raw, 131_072, budget=Budget(deadline), max_depth=12, max_values=1024),
                budget=Budget(deadline),
            )
            if not first_reconstruction_complete:
                encoded = canonical_bytes(artifact, 65_536, budget=Budget(deadline), max_depth=12, max_values=1024)
                if type(encoded) is not bytes or not 0 < len(encoded) <= 65_536:
                    raise ReleaseFailure("store_record_invalid")
                if relative not in retained and len(retained) >= 1024:
                    raise ReleaseFailure("store_limit_exceeded")
                retained[relative] = (raw, encoded)
            guard()
            return artifact
        except BaseException:
            with suppress(BaseException):
                _discard(artifact)
            raise
        finally:
            raw = b""
            cached = None
            encoded = None
            artifact = None

    def parent_from_source(child_path: str, child_raw: bytes, parent_path: str, parent_raw: bytes) -> None:
        restored: list[dict[str, object]] = []
        native: dict[str, object] | None = None
        cached: tuple[bytes, bytes] | None = None
        relative = ""
        raw = b""
        try:
            for relative, raw in ((child_path, child_raw), (parent_path, parent_raw)):
                guard()
                if type(relative) is not str or type(raw) is not bytes or not 0 < len(raw) <= 131_072:
                    raise ReleaseFailure("store_record_invalid")
                cached = retained.get(relative)
                if cached is None or raw != cached[0]:
                    raise ReleaseFailure("store_changed")
                # Each pair is derived afresh from this invocation's validated immutable bytes.
                native = cast(dict[str, object], json.loads(cached[1]))
                if type(native) is not dict:
                    raise ReleaseFailure("store_record_invalid")
                restored.append(native)
                guard()
            _parent_relations(restored[0], restored[1])
            guard()
        finally:
            with suppress(BaseException):
                _discard(restored)
            with suppress(BaseException):
                _discard(native)
            native = None
            cached = None
            relative = ""
            raw = b""
            child_raw = b""
            parent_raw = b""

    try:
        # Capture once, then verify and return the same immutable wire.
        candidate = _series_value(
            request_bytes,
            summary_bytes,
            record_bytes,
            evaluation_at,
            evaluation_at,
            budget,
            artifact_from_source=artifact_from_source,
            parent_from_source=parent_from_source,
        )
        first_reconstruction_complete = True
        completed_at = utc_text(datetime.now(UTC))
        candidate["completed_at"] = completed_at
        wire = canonical_bytes(candidate, RESULT_BYTES, budget=budget, max_values=RESULT_BYTES)
        guard()
        restored = load_json(wire, RESULT_BYTES, budget=budget, max_values=RESULT_BYTES)
        ReleaseSeriesResult.model_validate(restored)
        expected = _series_value(
            request_bytes,
            summary_bytes,
            record_bytes,
            evaluation_at,
            completed_at,
            Budget(deadline),
            artifact_from_source=artifact_from_source,
            parent_from_source=parent_from_source,
        )
        if canonical_bytes(expected, RESULT_BYTES, budget=Budget(deadline), max_values=RESULT_BYTES) != wire:
            raise ReleaseFailure("operation_failed")
        checked = ReleaseSeriesResult.model_validate_json(wire)
        guard()
        return wire, checked

    finally:
        retained.clear()


def release_series_bytes(request: object, *, evidence_store_dir: str | Path | None = None) -> bytes:
    """Return one fully checked canonical offline result without saving evidence."""
    return _evaluate_wire(request, evidence_store_dir)[0]


def evaluate_release_series(request: object, *, evidence_store_dir: str | Path | None = None) -> ReleaseSeriesResult:
    """Evaluate recorded upstream publication spacing in an explicit local store."""
    return _evaluate_wire(request, evidence_store_dir)[1]
