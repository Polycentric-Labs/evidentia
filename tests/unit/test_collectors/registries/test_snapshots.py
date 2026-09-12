"""Verify complete packaged snapshots and scoped lookup before session admission."""

from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from importlib import resources
from typing import Any, cast

import pytest
from evidentia_collectors.registries import _snapshots as snapshots
from evidentia_collectors.registries._contracts import CertificateTarget, FCCOrganizationTarget, ProductTarget
from evidentia_collectors.registries._parsing import parse_result_json, result_json_bytes


@pytest.fixture(scope="module")
def loaded() -> dict[str, snapshots.RegistrySnapshot]:
    return {name: snapshots.load_snapshot(name) for name in ("fedramp", "cmvp", "fcc-covered-list")}


def test_complete_packages_and_selected_occurrence_counts(loaded: dict[str, snapshots.RegistrySnapshot]) -> None:
    assert loaded["fedramp"].counts() == {"products": 666, "unjoined_packages": 62, "unmatched_history": 334}
    assert loaded["cmvp"].counts() == {"certificates": 5510}
    assert sum(loaded["fcc-covered-list"].counts().values()) == 79
    assert sum(len(package.facts) for package in loaded.values()) == 6651
    assert loaded["fedramp"].manifest()["source_occurrence_counts"] == {
        "history": 2120,
        "packages": 69,
        "products": 666,
    }
    assert loaded["cmvp"].manifest()["source_occurrence_counts"] == {
        "active": 1185,
        "historical": 4322,
        "revoked": 25,
        "certificate_5517_detail": 1,
    }


def test_offline_lookup_preserves_literal_identifiers_and_names(loaded: dict[str, snapshots.RegistrySnapshot]) -> None:
    fed = loaded["fedramp"].lookup(ProductTarget(product_id="F1607067912"))
    assert len(fed) == 1 and len(fed[0].detached()["history"]) == 3
    cmvp = loaded["cmvp"].lookup(CertificateTarget(certificate_number="5517"))
    assert len(cmvp) == 1 and cmvp[0].detached()["detail"]["source_id"] == "cmvp-certificate-5517"
    assert not loaded["cmvp"].lookup(CertificateTarget(certificate_number="05517"))
    fcc = loaded["fcc-covered-list"]
    one = fcc.lookup(
        FCCOrganizationTarget(organization_name=" PACIFIC  NETWORKS CORP. ", query_scope="named_organization_entries")
    )
    other = fcc.lookup(
        FCCOrganizationTarget(organization_name="ComNet (USA) LLC", query_scope="named_organization_entries")
    )
    assert one == other and len(one) == 1
    assert not fcc.lookup(
        FCCOrganizationTarget(
            organization_name="Synthetic unmatched organization", query_scope="named_organization_entries"
        )
    )
    with pytest.raises(snapshots.SnapshotFault):
        fcc.lookup(ProductTarget(product_id="Huawei Technologies Company"))


def test_detached_views_and_immutable_facts(loaded: dict[str, snapshots.RegistrySnapshot]) -> None:
    package = loaded["fcc-covered-list"]
    row = package.family("named_entries")[0]
    changed = row.detached()
    changed["names_source_literal"][0] = "Changed"
    assert row.detached()["names_source_literal"] == ["Huawei Technologies Company"]
    manifest = package.manifest()
    manifest["as_of"]["date"] = "2100-01-01"
    assert package.manifest()["as_of"]["date"] == "2026-09-09"
    with pytest.raises(FrozenInstanceError):
        cast(Any, row).selected_bytes = b"{}"
    with pytest.raises(snapshots.SnapshotFault):
        package.family("arbitrary")


def test_fcc_complete_named_scope_without_fabricated_approval_match(
    loaded: dict[str, snapshots.RegistrySnapshot],
) -> None:
    package = loaded["fcc-covered-list"]
    for row in package.family("named_entries"):
        source = package.fcc_source(row)
        assert source["named_entry"] == row.detached()
        assert [(item["appendix"], item["marker_source_literal"]) for item in source["linked_footnotes"]] == [
            ("A", "*"),
            ("A", "\u00b1"),
        ]
        assert len(source["named_scope_context"]) == 5
        assert source["scope_limits"]["conditional_approval_applicability"] == "not_assessed"
        assert "conditional_approvals" not in source
        assert "named_no_match" not in source["scope_limits"]
        assert source["snapshot_context"]["fact_counts"]["conditional_approvals"] == 40
        assert source["snapshot_context"]["snapshot_sha256"] == package.sha256
    assert len(package.family("conditional_approvals")) == 40


def test_age_uses_publisher_cutoff_not_capture_time(loaded: dict[str, snapshots.RegistrySnapshot]) -> None:
    fed = loaded["fedramp"]
    cutoff = datetime(2026, 9, 10, 20, 57, 13, 84000, tzinfo=UTC)
    assert fed.freshness(cutoff + timedelta(days=7)) == "dated_snapshot"
    assert fed.freshness(cutoff + timedelta(days=7, microseconds=1)) == "stale"
    assert fed.freshness(cutoff - timedelta(microseconds=1)) == "unknown"
    fcc = loaded["fcc-covered-list"]
    assert fcc.freshness(datetime(2026, 9, 16, 23, 59, tzinfo=UTC)) == "dated_snapshot"
    assert fcc.freshness(datetime(2026, 9, 17, tzinfo=UTC)) == "stale"
    assert fcc.freshness(datetime(2026, 9, 8, 23, 59, tzinfo=UTC)) == "unknown"
    assert loaded["cmvp"].freshness(datetime(2026, 9, 11, tzinfo=UTC)) == "unknown"


def test_raw_hash_size_gate_precedes_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    entry = snapshots._index_entry("fcc-covered-list")

    def forbidden(_: bytes) -> dict[str, Any]:
        pytest.fail("parser ran before the complete file hash and byte limit were checked")

    monkeypatch.setattr(snapshots, "parse_result_json", forbidden)
    for raw in (b"{}", b"x" * (4_194_304 + 1), b"x" * entry["bytes"]):
        with pytest.raises(snapshots.SnapshotFault):
            snapshots._validate_package("fcc-covered-list", raw, entry)


def test_whole_envelope_and_identity_validation_after_hash_gate() -> None:
    entry = snapshots._index_entry("fcc-covered-list")
    path = resources.files("evidentia_collectors.registries").joinpath(entry["path"])
    original = path.read_bytes()
    for mutation in (
        "unknown_root",
        "unknown_record_field",
        "duplicate_name",
        "bool_ordinal",
        "missing_marker",
        "contradictory_count",
        "missing_fact",
    ):
        package = parse_result_json(original)
        facts = package["facts"]
        assert isinstance(facts, dict)
        named = facts["named_entries"]
        assert isinstance(named, list) and isinstance(named[0], dict) and isinstance(named[1], dict)
        if mutation == "unknown_root":
            package["unexpected"] = True
        elif mutation == "unknown_record_field":
            named[0]["unexpected"] = True
        elif mutation == "duplicate_name":
            named[1]["names_source_literal"] = named[0]["names_source_literal"]
        elif mutation == "bool_ordinal":
            named[0]["derived_appendix_a_row_ordinal"] = True
        elif mutation == "missing_marker":
            named[0]["applicable_appendix_a_footnote_markers"] = ["*"]
        elif mutation == "contradictory_count":
            counts = package["fact_counts"]
            assert isinstance(counts, dict)
            counts["named_entries"] = 11
        else:
            named.pop()
        content = result_json_bytes(package) + b"\n"
        reviewed_entry = {**entry, "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}
        with pytest.raises((snapshots.SnapshotFault, ValueError)):
            snapshots._validate_package("fcc-covered-list", content, reviewed_entry)


def test_fixed_registry_resource_only() -> None:
    for invalid in ("../fcc", "https://example.org/source", "FCC", ""):
        with pytest.raises(snapshots.SnapshotFault):
            snapshots.load_snapshot(cast(snapshots.SnapshotRegistry, invalid))


def test_complete_iana_bootstrap_retains_original_dates_and_cache_metadata() -> None:
    bootstrap = snapshots.load_bootstrap()
    assert len(bootstrap.services) == 590
    assert sum(len(suffixes) for suffixes, _ in bootstrap.services) == 1200
    assert bootstrap.publication == "2026-09-09T23:00:03Z"
    assert bootstrap.sha256 == "203262f750f2db107c74b167382b5bcf30fafb95dabc1ec2f55a4c2b85b53a75"
    selection = bootstrap.select("Example.COM.")
    assert selection.suffix == "com"
    assert selection.service_base == selection.alternatives[0]
    assert selection.service_base.startswith("https://")
    assert b'"cache-control":"max-age=86400"' in selection.source_bytes
    with pytest.raises(snapshots.SnapshotFault):
        bootstrap.select("example.kg")


def test_bootstrap_longest_label_suffix_and_source_order() -> None:
    bootstrap = snapshots.RDAPBootstrap(
        "0" * 64,
        "2026-09-09T23:00:03Z",
        b"{}",
        (
            (("example",), ("https://first.example/rdap/",)),
            (
                ("nested.example",),
                ("http://plain.example/", "https://second.example/service/", "https://third.example/"),
            ),
        ),
    )
    selected = bootstrap.select("host.nested.example")
    assert selected.suffix == "nested.example"
    assert selected.service_base == "https://second.example/service/"
    assert len(selected.alternatives) == 3
    assert bootstrap.select("other.example").service_base == "https://first.example/rdap/"
    with pytest.raises(snapshots.SnapshotFault):
        bootstrap.select("notexample")


@pytest.mark.parametrize(
    "url",
    [
        "http://example.org/",
        "https://example.org/a/../",
        "https://example.org/a/%2e%2e/",
        "https://example.org/a//",
        "https://example.org/a/?query=1",
        "https://example.org/a/?",
        "https://example.org/a/#",
        "https://example.org/a/?#",
        "https://example.org/a/#fragment",
        "https://user@example.org/",
        "https://example.org:444/",
        "https://example.org/no-terminal-slash",
        "https://127.0.0.1/",
        "https://EXAMPLE.org/",
    ],
)
def test_unsafe_or_noncanonical_bootstrap_base_is_not_rewritten(url: str) -> None:
    bootstrap = snapshots.RDAPBootstrap("0" * 64, "2026-09-09T23:00:03Z", b"{}", ((("example",), (url,)),))
    with pytest.raises(snapshots.SnapshotFault):
        bootstrap.select("test.example")


@pytest.mark.parametrize(
    "cutoff",
    [
        None,
        {},
        {"literal": "September 9, 2026"},
        {"date": "2026-09-09"},
        {"literal": "September 9, 2026", "date": "20260909"},
        {"literal": "September 9, 2026", "date": "2026-W37-3"},
        {"literal": None, "date": "2026-09-09"},
        {"literal": True, "date": "2026-09-09"},
    ],
)
def test_noncanonical_or_missing_cutoff_is_unknown(loaded: dict[str, snapshots.RegistrySnapshot], cutoff: Any) -> None:
    original = loaded["fcc-covered-list"]
    manifest = original.manifest()
    if cutoff is None:
        manifest.pop("as_of")
    else:
        manifest["as_of"] = cutoff
    changed = replace(original, manifest_bytes=result_json_bytes(manifest))
    assert changed.freshness(datetime(2026, 9, 11, tzinfo=UTC)) == "unknown"
