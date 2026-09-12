"""Exercise FEDRAMP selection and session-owned snapshot results."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from evidentia_collectors.registries import fedramp
from evidentia_collectors.registries._client import RegistryReadSession
from evidentia_collectors.registries._contracts import RegistryInputError, RegistryLookupResult
from evidentia_collectors.registries._parsing import result_json_bytes
from evidentia_collectors.registries._snapshots import RegistrySnapshot, SnapshotFact, SnapshotFault, load_snapshot

FIXTURES = Path(__file__).parents[3] / "fixtures" / "registries" / "fedramp"
NOW = datetime(2026, 9, 11, 12, tzinfo=UTC)


@pytest.fixture(scope="module")
def snapshot() -> RegistrySnapshot:
    return load_snapshot("fedramp")


def test_real_snapshot_read_uses_owned_offline_session(snapshot: RegistrySnapshot) -> None:
    session = RegistryReadSession(
        {"registry": "fedramp", "target": {"product_id": "F1607067912"}},
        _snapshot_factory=lambda _: snapshot,
        _utc=lambda: NOW,
        _monotonic=lambda: 0.0,
        _http_factory=lambda: pytest.fail("offline reader attempted HTTP"),
    )
    result = fedramp.lookup(session)
    assert result.collection_status == "complete"
    assert result.lookup_outcome == "found"
    assert result.freshness == "dated_snapshot"
    assert len(result.observations) == 1
    assert result.source_reads[0].network_attempts == 0
    assert fedramp.lookup(session).model_dump(mode="json") == result.model_dump(mode="json")


def test_wrong_registry_is_rejected_before_reader_use() -> None:
    session = RegistryReadSession({"registry": "cmvp", "target": {"certificate_number": "5517"}})
    with pytest.raises(RegistryInputError):
        fedramp.lookup(session)


def test_projection_is_detached_and_excludes_unselected(snapshot: RegistrySnapshot) -> None:
    row = snapshot.family("products")[0]
    source = row.detached()
    expected = json.loads(json.dumps(source))
    source["unselected_contact"] = "Synthetic omitted value"
    projected = fedramp.project_product(source)
    assert projected == expected
    assert projected is not source
    source.clear()
    assert projected == expected


def test_native_subclass_and_null_are_rejected() -> None:
    class Hostile(dict[str, Any]):
        def items(self) -> Any:
            pytest.fail("subclass callback executed")

    with pytest.raises(ValueError):
        fedramp.project_product(Hostile())
    with pytest.raises(ValueError):
        fedramp.project_product({"fields": None})


def synthetic_snapshot() -> RegistrySnapshot:
    """Construct trusted synthetic facts for tests and the controller demo seam."""
    product = json.loads((FIXTURES / "source-products.json").read_bytes())["data"]["Products"][0]
    product.pop("contact")
    histories = json.loads((FIXTURES / "source-status-conflict.json").read_bytes())["data"][
        "certprocessstatuschangelog"
    ]
    facts = {
        "products": [
            {
                "source_index": 0,
                "fields": product,
                "history": [{"source_index": index, "fields": fields} for index, fields in enumerate(histories)],
                "package_rows": [],
            }
        ],
        "unmatched_history": [],
        "unjoined_packages": [],
    }
    as_of = {
        "basis": "oldest_required_publisher_cutoff",
        "date": None,
        "literal": "2026-09-10T00:00:00Z",
        "representation": "rfc3339",
        "source_ids": ["synthetic-fedramp"],
    }
    manifest = {"as_of": as_of, "sources": [{"publisher_version": "synthetic-fixture"}]}
    counts = {family: len(items) for family, items in facts.items()}
    raw = result_json_bytes({"manifest": manifest, "facts": facts, "counts": counts})
    return RegistrySnapshot(
        "fedramp",
        "synthetic/fedramp.json",
        hashlib.sha256(raw).hexdigest(),
        len(raw),
        hashlib.sha256(b"synthetic-fedramp-tuples").hexdigest(),
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
    target: dict[str, Any] = {"product_id": "F-SYNTHETIC" if state != "not_found" else "F-NOT-PRESENT"}
    snapshot = synthetic_snapshot()

    def load(_: Any) -> RegistrySnapshot:
        if state == "unavailable":
            raise SnapshotFault("snapshot_missing")
        return snapshot

    session = RegistryReadSession(
        {"registry": "fedramp", "target": target},
        _snapshot_factory=load,
        _monotonic=lambda: 0.0,
        _utc=lambda: datetime(2026, 9, 20, 12, tzinfo=UTC) if state == "stale" else NOW,
        _http_factory=lambda: pytest.fail("synthetic snapshot attempted HTTP"),
    )
    return fedramp.lookup(session)


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
    for target, expected in [({"product_id": "f-SYNTHETIC"}, "not_found"), ({"product_id": "F-SYNTHETIC"}, "found")]:
        session = RegistryReadSession(
            {"registry": "fedramp", "target": target},
            _snapshot_factory=lambda _: snapshot,
            _utc=lambda: NOW,
            _monotonic=lambda: 0.0,
        )
        assert fedramp.lookup(session).lookup_outcome == expected
