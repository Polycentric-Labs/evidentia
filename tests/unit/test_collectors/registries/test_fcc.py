"""Exercise FCC selection and session-owned snapshot results."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from evidentia_collectors.registries import fcc
from evidentia_collectors.registries._client import RegistryReadSession
from evidentia_collectors.registries._contracts import RegistryInputError, RegistryLookupResult
from evidentia_collectors.registries._parsing import result_json_bytes
from evidentia_collectors.registries._snapshots import RegistrySnapshot, SnapshotFact, SnapshotFault, load_snapshot

FIXTURES = Path(__file__).parents[3] / "fixtures" / "registries" / "fcc"
NOW = datetime(2026, 9, 11, 12, tzinfo=UTC)


@pytest.fixture(scope="module")
def snapshot() -> RegistrySnapshot:
    return load_snapshot("fcc-covered-list")


def test_real_snapshot_read_uses_owned_offline_session(snapshot: RegistrySnapshot) -> None:
    session = RegistryReadSession(
        {
            "registry": "fcc-covered-list",
            "target": {"organization_name": "Huawei Technologies Company", "query_scope": "named_organization_entries"},
        },
        _snapshot_factory=lambda _: snapshot,
        _utc=lambda: NOW,
        _monotonic=lambda: 0.0,
        _http_factory=lambda: pytest.fail("offline reader attempted HTTP"),
    )
    result = fcc.lookup(session)
    assert result.collection_status == "complete"
    assert result.lookup_outcome == "found"
    assert result.freshness == "dated_snapshot"
    assert len(result.observations) == 1
    assert result.source_reads[0].network_attempts == 0
    assert fcc.lookup(session).model_dump(mode="json") == result.model_dump(mode="json")


def test_wrong_registry_is_rejected_before_reader_use() -> None:
    session = RegistryReadSession({"registry": "fedramp", "target": {"product_id": "F-SYNTHETIC"}})
    with pytest.raises(RegistryInputError):
        fcc.lookup(session)


def test_projection_is_detached_and_excludes_unselected(snapshot: RegistrySnapshot) -> None:
    row = snapshot.family("named_entries")[0]
    source = snapshot.fcc_source(row)
    expected = json.loads(json.dumps(source))
    source["unselected_contact"] = "Synthetic omitted value"
    projected = fcc.project_named_entry(source)
    assert projected == expected
    assert projected is not source
    source.clear()
    assert projected == expected


def test_native_subclass_and_null_are_rejected() -> None:
    class Hostile(dict[str, Any]):
        def items(self) -> Any:
            pytest.fail("subclass callback executed")

    with pytest.raises(ValueError):
        fcc.project_named_entry(Hostile())
    with pytest.raises(ValueError):
        fcc.project_named_entry({"named_entry": None})


def synthetic_snapshot() -> RegistrySnapshot:
    """Construct trusted synthetic facts for tests and the controller demo seam."""
    named = json.loads((FIXTURES / "source-covered-entries.json").read_bytes())["named_entries"]
    footnotes: list[dict[str, Any]] = [
        {
            "appendix": "A",
            "marker_source_literal": marker,
            "text_source_literal": "Synthetic scope note",
            "source_occurrences": [],
        }
        for marker in ("*", "\u00b1")
    ]
    contexts = [
        {
            "kind": "synthetic_context",
            "document": "SYNTHETIC-1",
            "location": "Synthetic context",
            "text_source_literal": "Synthetic scope only",
            "pdf_pages": [1],
        }
        for _ in range(11)
    ]
    for index, kind, document in (
        (3, "named_entity_scope_boundary", "DA 26-786"),
        (4, "named_entity_scope_boundary", "DA 26-870"),
        (8, "affiliate_list_not_comprehensive", "DA 26-957"),
        (9, "affiliate_list_not_comprehensive", "DA 26-870"),
        (10, "affiliate_list_not_comprehensive", "DA 26-786"),
    ):
        contexts[index]["kind"], contexts[index]["document"] = kind, document
    facts = {
        "named_entries": named,
        "category_rows": json.loads((FIXTURES / "source-category-only.json").read_bytes())["category_rows"],
        "footnotes": footnotes,
        "conditional_approvals": json.loads((FIXTURES / "source-conditional-approvals.json").read_bytes())[
            "conditional_approvals"
        ],
        "definition_context": [],
        "source_context": contexts,
    }
    as_of = {
        "basis": "selected_dated_snapshot",
        "date": "2026-09-09",
        "literal": "September 9, 2026",
        "representation": "source_text",
        "source_ids": ["synthetic-fcc"],
    }
    manifest = {"as_of": as_of, "sources": [{"publisher_version": "synthetic-fixture"}]}
    counts = {family: len(items) for family, items in facts.items()}
    raw = result_json_bytes({"manifest": manifest, "facts": facts, "counts": counts})
    return RegistrySnapshot(
        "fcc-covered-list",
        "synthetic/fcc.json",
        hashlib.sha256(raw).hexdigest(),
        len(raw),
        hashlib.sha256(b"synthetic-fcc-tuples").hexdigest(),
        result_json_bytes(manifest),
        result_json_bytes(counts),
        tuple(
            SnapshotFact(family, index, result_json_bytes(item))
            for family, items in facts.items()
            for index, item in enumerate(items)
        ),
    )


def synthetic_result(state: str = "found") -> RegistryLookupResult:
    """Return a real session result; this helper never fabricates an envelope."""
    if state not in {"found", "not_found", "stale", "unavailable"}:
        raise ValueError("unsupported_synthetic_state")
    target: dict[str, Any] = {
        "organization_name": "Synthetic Organization" if state != "not_found" else "Synthetic unmatched organization",
        "query_scope": "named_organization_entries",
    }
    snapshot = synthetic_snapshot()

    def load(_: Any) -> RegistrySnapshot:
        if state == "unavailable":
            raise SnapshotFault("snapshot_missing")
        return snapshot

    session = RegistryReadSession(
        {"registry": "fcc-covered-list", "target": target},
        _snapshot_factory=load,
        _monotonic=lambda: 0.0,
        _utc=lambda: datetime(2026, 9, 20, 12, tzinfo=UTC) if state == "stale" else NOW,
        _http_factory=lambda: pytest.fail("synthetic snapshot attempted HTTP"),
    )
    return fcc.lookup(session)


@pytest.mark.parametrize("state", ["found", "not_found", "stale", "unavailable"])
def test_synthetic_reachable_session_states(state: str) -> None:
    result = synthetic_result(state)
    assert result.collection_status == ("unavailable" if state == "unavailable" else "complete")
    assert result.lookup_outcome == (
        "unavailable" if state == "unavailable" else "not_found" if state == "not_found" else "found"
    )
    if state in {"found", "stale"}:
        assert result.freshness == ("stale" if state == "stale" else "dated_snapshot")
    assert result.source_reads[0].network_attempts == 0


def test_scoped_identity_match_has_no_broadening() -> None:
    snapshot = synthetic_snapshot()
    for target, expected in [
        ({"organization_name": "Synthetic Org", "query_scope": "named_organization_entries"}, "not_found"),
        ({"organization_name": "  SYNTHETIC   alias  ", "query_scope": "named_organization_entries"}, "found"),
    ]:
        session = RegistryReadSession(
            {"registry": "fcc-covered-list", "target": target},
            _snapshot_factory=lambda _: snapshot,
            _utc=lambda: NOW,
            _monotonic=lambda: 0.0,
        )
        assert fcc.lookup(session).lookup_outcome == expected


def test_category_and_conditional_approvals_do_not_enter_named_fields() -> None:
    result = synthetic_result()
    fields = result.observations[0].fields
    assert "conditional_approvals" not in fields and "category_rows" not in fields
    assert fields["scope_limits"] == {
        "category_applicability": "not_assessed",
        "conditional_approval_applicability": "not_assessed",
        "deployment_applicability": "not_assessed",
        "indirect_affiliate_applicability": "not_assessed",
        "later_currency": "not_established",
        "legal_applicability": "not_assessed",
        "query_scope": "named_organization_entries",
    }
