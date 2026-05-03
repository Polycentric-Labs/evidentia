"""Unit tests for evidentia_core.vendor_store (v0.7.9 P0.1.2)."""

from __future__ import annotations

from datetime import date, datetime
from pathlib import Path

import pytest
from evidentia_core.models.tprm import (
    CriticalityTier,
    EvidenceRef,
    FourthParty,
    RegulatoryClassification,
    Vendor,
    VendorType,
)
from evidentia_core.vendor_store import (
    InvalidVendorIdError,
    delete_vendor,
    get_vendor_store_dir,
    list_vendors,
    load_vendor_by_id,
    save_vendor,
)


def _make_vendor(
    name: str = "Acme Cloud",
    tier: CriticalityTier = CriticalityTier.CRITICAL,
    type_: VendorType = VendorType.CLOUD_PROVIDER,
) -> Vendor:
    return Vendor(
        name=name,
        type=type_,
        criticality_tier=tier,
        relationship_owner="allen@allenfbyrd.com",
        contract_start_date=date(2025, 1, 1),
    )


# ── store-dir resolution ───────────────────────────────────────────


class TestGetVendorStoreDir:
    def test_explicit_override_wins(self, tmp_path: Path) -> None:
        result = get_vendor_store_dir(tmp_path)
        assert result == tmp_path.expanduser().resolve()

    def test_env_var_used_when_no_override(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("EVIDENTIA_VENDOR_STORE_DIR", str(tmp_path))
        result = get_vendor_store_dir()
        assert result == tmp_path.expanduser().resolve()

    def test_explicit_override_beats_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env_dir = tmp_path / "env"
        override = tmp_path / "override"
        monkeypatch.setenv("EVIDENTIA_VENDOR_STORE_DIR", str(env_dir))
        result = get_vendor_store_dir(override)
        assert result == override.expanduser().resolve()

    def test_default_uses_platformdirs_when_no_env_no_override(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("EVIDENTIA_VENDOR_STORE_DIR", raising=False)
        result = get_vendor_store_dir()
        # Don't pin the absolute path (platform-specific), just shape
        assert result.name == "vendor_store"
        assert "evidentia" in str(result).lower()


# ── save / load roundtrip ──────────────────────────────────────────


class TestSaveAndLoad:
    def test_save_returns_path_and_creates_file(
        self, tmp_path: Path
    ) -> None:
        v = _make_vendor()
        out = save_vendor(v, vendor_store_dir=tmp_path)
        assert out.is_file()
        assert out.parent == tmp_path
        assert out.name == f"{v.id}.json"

    def test_save_creates_store_dir_if_missing(
        self, tmp_path: Path
    ) -> None:
        store = tmp_path / "fresh"
        v = _make_vendor()
        save_vendor(v, vendor_store_dir=store)
        assert store.is_dir()

    def test_save_refreshes_updated_at(self, tmp_path: Path) -> None:
        v = _make_vendor()
        # Force updated_at to the past so we can detect the refresh
        before = datetime.fromtimestamp(0, tz=v.updated_at.tzinfo)
        v.updated_at = before
        save_vendor(v, vendor_store_dir=tmp_path)
        assert v.updated_at > before

    def test_load_by_id_returns_equivalent_record(
        self, tmp_path: Path
    ) -> None:
        original = _make_vendor()
        original.regulatory_classification = [
            RegulatoryClassification.CRITICAL_THIRD_PARTY,
        ]
        original.fourth_parties = [
            FourthParty(
                name="AWS",
                type=VendorType.CLOUD_PROVIDER,
                relationship="underlying IaaS",
            )
        ]
        original.evidence_refs = [
            EvidenceRef(title="SOC 2 Type II", artifact_id="abc-123")
        ]
        save_vendor(original, vendor_store_dir=tmp_path)
        loaded = load_vendor_by_id(original.id, vendor_store_dir=tmp_path)
        assert loaded is not None
        assert loaded.id == original.id
        assert loaded.name == original.name
        assert len(loaded.fourth_parties) == 1
        assert len(loaded.evidence_refs) == 1
        assert (
            RegulatoryClassification.CRITICAL_THIRD_PARTY.value
            in loaded.regulatory_classification
        )

    def test_load_unknown_id_returns_none(self, tmp_path: Path) -> None:
        # Well-formed UUID that doesn't exist on disk
        unknown = "00000000-0000-0000-0000-000000000000"
        loaded = load_vendor_by_id(unknown, vendor_store_dir=tmp_path)
        assert loaded is None

    def test_save_overwrites_existing(self, tmp_path: Path) -> None:
        v = _make_vendor(name="Original Name")
        save_vendor(v, vendor_store_dir=tmp_path)
        v.name = "Updated Name"
        save_vendor(v, vendor_store_dir=tmp_path)
        loaded = load_vendor_by_id(v.id, vendor_store_dir=tmp_path)
        assert loaded is not None
        assert loaded.name == "Updated Name"


# ── ID-shape validation ────────────────────────────────────────────


class TestIdShapeValidation:
    def test_load_rejects_path_traversal_id(self, tmp_path: Path) -> None:
        with pytest.raises(InvalidVendorIdError):
            load_vendor_by_id("../etc/passwd", vendor_store_dir=tmp_path)

    def test_load_rejects_short_id(self, tmp_path: Path) -> None:
        with pytest.raises(InvalidVendorIdError):
            load_vendor_by_id("abc", vendor_store_dir=tmp_path)

    def test_load_rejects_empty_id(self, tmp_path: Path) -> None:
        with pytest.raises(InvalidVendorIdError):
            load_vendor_by_id("", vendor_store_dir=tmp_path)

    def test_load_rejects_non_uuid_chars(self, tmp_path: Path) -> None:
        with pytest.raises(InvalidVendorIdError):
            load_vendor_by_id(
                "ZZZZZZZZ-0000-0000-0000-000000000000",
                vendor_store_dir=tmp_path,
            )

    def test_save_rejects_id_shape_violation(
        self, tmp_path: Path
    ) -> None:
        # Direct construction with a mutated id can't go through
        # the model's default_factory, so simulate by mutating after
        v = _make_vendor()
        v.id = "../bad-id"
        with pytest.raises(InvalidVendorIdError):
            save_vendor(v, vendor_store_dir=tmp_path)


# ── list_vendors ───────────────────────────────────────────────────


class TestListVendors:
    def test_returns_empty_for_missing_store(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist"
        assert list_vendors(vendor_store_dir=missing) == []

    def test_returns_empty_for_empty_store(self, tmp_path: Path) -> None:
        assert list_vendors(vendor_store_dir=tmp_path) == []

    def test_sorted_by_criticality_then_name(self, tmp_path: Path) -> None:
        v_low = _make_vendor(name="ZZZ Low", tier=CriticalityTier.LOW)
        v_high_a = _make_vendor(name="AAA High", tier=CriticalityTier.HIGH)
        v_high_b = _make_vendor(name="BBB High", tier=CriticalityTier.HIGH)
        v_critical = _make_vendor(
            name="MMM Critical", tier=CriticalityTier.CRITICAL
        )
        v_medium = _make_vendor(name="NNN Medium", tier=CriticalityTier.MEDIUM)
        for v in [v_low, v_high_a, v_high_b, v_critical, v_medium]:
            save_vendor(v, vendor_store_dir=tmp_path)
        listed = list_vendors(vendor_store_dir=tmp_path)
        assert [v.name for v in listed] == [
            "MMM Critical",
            "AAA High",
            "BBB High",
            "NNN Medium",
            "ZZZ Low",
        ]

    def test_skips_malformed_files(self, tmp_path: Path) -> None:
        v = _make_vendor()
        save_vendor(v, vendor_store_dir=tmp_path)
        # Drop a malformed file alongside
        (tmp_path / "bogus.json").write_text("not json", encoding="utf-8")
        listed = list_vendors(vendor_store_dir=tmp_path)
        # The well-formed vendor still surfaces; the bogus file is skipped
        assert len(listed) == 1
        assert listed[0].id == v.id


# ── delete_vendor ──────────────────────────────────────────────────


class TestDeleteVendor:
    def test_delete_returns_true_when_record_existed(
        self, tmp_path: Path
    ) -> None:
        v = _make_vendor()
        save_vendor(v, vendor_store_dir=tmp_path)
        assert delete_vendor(v.id, vendor_store_dir=tmp_path) is True
        assert load_vendor_by_id(v.id, vendor_store_dir=tmp_path) is None

    def test_delete_returns_false_when_record_missing(
        self, tmp_path: Path
    ) -> None:
        unknown = "00000000-0000-0000-0000-000000000000"
        assert delete_vendor(unknown, vendor_store_dir=tmp_path) is False

    def test_delete_rejects_id_shape_violation(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(InvalidVendorIdError):
            delete_vendor("../etc/passwd", vendor_store_dir=tmp_path)

    def test_delete_only_removes_matching_record(
        self, tmp_path: Path
    ) -> None:
        v_a = _make_vendor(name="A")
        v_b = _make_vendor(name="B")
        save_vendor(v_a, vendor_store_dir=tmp_path)
        save_vendor(v_b, vendor_store_dir=tmp_path)
        assert delete_vendor(v_a.id, vendor_store_dir=tmp_path) is True
        # v_b still present
        assert load_vendor_by_id(v_b.id, vendor_store_dir=tmp_path) is not None
