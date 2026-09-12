"""Exercise CMVP selection and session-owned snapshot results."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from evidentia_collectors.registries import cmvp
from evidentia_collectors.registries._client import RegistryReadSession
from evidentia_collectors.registries._contracts import RegistryInputError, RegistryLookupResult
from evidentia_collectors.registries._parsing import result_json_bytes
from evidentia_collectors.registries._snapshots import RegistrySnapshot, SnapshotFact, SnapshotFault, load_snapshot

FIXTURES = Path(__file__).parents[3] / "fixtures" / "registries" / "cmvp"
NOW = datetime(2026, 9, 11, 12, tzinfo=UTC)


@pytest.fixture(scope="module")
def snapshot() -> RegistrySnapshot:
    return load_snapshot("cmvp")


def test_real_snapshot_read_uses_owned_offline_session(snapshot: RegistrySnapshot) -> None:
    session = RegistryReadSession(
        {"registry": "cmvp", "target": {"certificate_number": "5517"}},
        _snapshot_factory=lambda _: snapshot,
        _utc=lambda: NOW,
        _monotonic=lambda: 0.0,
        _http_factory=lambda: pytest.fail("offline reader attempted HTTP"),
    )
    result = cmvp.lookup(session)
    assert result.collection_status == "complete"
    assert result.lookup_outcome == "found"
    assert result.freshness == "unknown"
    assert len(result.observations) == 1
    assert result.source_reads[0].network_attempts == 0
    assert cmvp.lookup(session).model_dump(mode="json") == result.model_dump(mode="json")


def test_wrong_registry_is_rejected_before_reader_use() -> None:
    session = RegistryReadSession({"registry": "fedramp", "target": {"product_id": "F-SYNTHETIC"}})
    with pytest.raises(RegistryInputError):
        cmvp.lookup(session)


def test_projection_is_detached_and_excludes_unselected(snapshot: RegistrySnapshot) -> None:
    row = snapshot.family("certificates")[0]
    source = row.detached()
    expected = json.loads(json.dumps(source))
    source["unselected_contact"] = "Synthetic omitted value"
    projected = cmvp.project_certificate(source)
    assert projected == expected
    assert projected is not source
    source.clear()
    assert projected == expected


def test_native_subclass_and_null_are_rejected() -> None:
    class Hostile(dict[str, Any]):
        def items(self) -> Any:
            pytest.fail("subclass callback executed")

    with pytest.raises(ValueError):
        cmvp.project_certificate(Hostile())
    with pytest.raises(ValueError):
        cmvp.project_certificate({"occurrences": None})


def synthetic_snapshot() -> RegistrySnapshot:
    """Construct trusted synthetic facts for tests and the controller demo seam."""
    facts = {
        "certificates": [
            {
                "certificate_number": "900000001",
                "fields": {
                    "Certificate Number": "900000001",
                    "Vendor Name": "Synthetic vendor",
                    "Module Name": "Synthetic module",
                    "Module Type": "Software",
                    "Validation Date": "01/01/2026\n",
                },
                "status": {"basis": "query_scope", "value": "Active"},
                "occurrences": [
                    {"source_id": "cmvp-active-all", "table_id": "active", "source_index": 0, "query_status": "Active"}
                ],
            }
        ]
    }
    as_of = {
        "basis": "publisher_cutoff_not_selected",
        "date": None,
        "literal": None,
        "representation": "source_text",
        "source_ids": ["synthetic-cmvp"],
    }
    manifest = {"as_of": as_of, "sources": [{"publisher_version": "synthetic-fixture"}]}
    counts = {family: len(items) for family, items in facts.items()}
    raw = result_json_bytes({"manifest": manifest, "facts": facts, "counts": counts})
    return RegistrySnapshot(
        "cmvp",
        "synthetic/cmvp.json",
        hashlib.sha256(raw).hexdigest(),
        len(raw),
        hashlib.sha256(b"synthetic-cmvp-tuples").hexdigest(),
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
    if state not in {"found", "not_found", "unknown", "unavailable"}:
        raise ValueError("unsupported_synthetic_state")
    target: dict[str, Any] = {"certificate_number": "900000001" if state != "not_found" else "900000002"}
    snapshot = synthetic_snapshot()

    def load(_: Any) -> RegistrySnapshot:
        if state == "unavailable":
            raise SnapshotFault("snapshot_missing")
        return snapshot

    session = RegistryReadSession(
        {"registry": "cmvp", "target": target},
        _snapshot_factory=load,
        _monotonic=lambda: 0.0,
        _utc=lambda: datetime(2026, 9, 20, 12, tzinfo=UTC) if state == "unknown" else NOW,
        _http_factory=lambda: pytest.fail("synthetic snapshot attempted HTTP"),
    )
    return cmvp.lookup(session)


@pytest.mark.parametrize("state", ["found", "not_found", "unknown", "unavailable"])
def test_synthetic_reachable_session_states(state: str) -> None:
    result = synthetic_result(state)
    assert result.collection_status == ("unavailable" if state == "unavailable" else "complete")
    assert result.lookup_outcome == (
        "unavailable" if state == "unavailable" else "not_found" if state == "not_found" else "found"
    )
    if state in {"found", "unknown"}:
        assert result.freshness == "unknown"
    assert result.source_reads[0].network_attempts == 0


def test_scoped_identity_match_has_no_broadening() -> None:
    snapshot = synthetic_snapshot()
    for target, expected in [
        ({"certificate_number": "0900000001"}, "not_found"),
        ({"certificate_number": "900000001"}, "found"),
    ]:
        session = RegistryReadSession(
            {"registry": "cmvp", "target": target},
            _snapshot_factory=lambda _: snapshot,
            _utc=lambda: NOW,
            _monotonic=lambda: 0.0,
        )
        assert cmvp.lookup(session).lookup_outcome == expected
