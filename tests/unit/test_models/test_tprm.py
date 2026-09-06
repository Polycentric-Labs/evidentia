"""Unit tests for evidentia_core.models.tprm (v0.7.9 P0.1.1).

Covers Vendor / FourthParty / EvidenceRef Pydantic models + the
``compute_next_review_due`` cadence helper. No storage layer in
scope here (P0.1.2 ships the JSON-file vendor_store).
"""

from __future__ import annotations

from datetime import date, datetime

import pytest
from evidentia_core.models.tprm import (
    CriticalityTier,
    EvidenceRef,
    FourthParty,
    RegulatoryClassification,
    Vendor,
    VendorType,
)
from pydantic import ValidationError

# ── Vendor base round-trip ─────────────────────────────────────────


class TestVendor:
    def _make(self, **overrides) -> Vendor:
        defaults = dict(
            name="Acme Cloud",
            type=VendorType.CLOUD_PROVIDER,
            criticality_tier=CriticalityTier.CRITICAL,
            relationship_owner="allen@allenfbyrd.com",
            contract_start_date=date(2025, 1, 1),
        )
        defaults.update(overrides)
        return Vendor(**defaults)

    def test_minimal_construction(self) -> None:
        v = self._make()
        assert v.name == "Acme Cloud"
        assert v.type == VendorType.CLOUD_PROVIDER.value  # use_enum_values=True
        assert v.criticality_tier == CriticalityTier.CRITICAL.value
        assert v.id  # UUID v4 stamped via default_factory
        assert len(v.id) == 36  # UUID4 string length
        assert v.fourth_parties == []
        assert v.evidence_refs == []
        assert v.regulatory_classification == []
        assert v.residual_risk_score == 0  # unscored default

    def test_roundtrip_via_model_dump_validate(self) -> None:
        v = self._make(
            regulatory_classification=[
                RegulatoryClassification.CRITICAL_THIRD_PARTY,
                RegulatoryClassification.DATA_PROCESSOR,
            ],
            residual_risk_score=15,
            notes="Imported from spreadsheet 2026-Q2",
        )
        data = v.model_dump()
        restored = Vendor.model_validate(data)
        assert restored.id == v.id
        assert restored.residual_risk_score == 15
        assert restored.notes == "Imported from spreadsheet 2026-Q2"
        assert RegulatoryClassification.CRITICAL_THIRD_PARTY.value in restored.regulatory_classification

    def test_residual_risk_score_clamps_to_1_25(self) -> None:
        # ge=0, le=25 — 0 is valid (unscored); 26 is not.
        with pytest.raises(ValidationError):
            self._make(residual_risk_score=26)
        with pytest.raises(ValidationError):
            self._make(residual_risk_score=-1)

    def test_extra_fields_forbidden(self) -> None:
        # EvidentiaModel.model_config sets extra="forbid" — typo'd
        # field names must fail validation, not silently drop.
        with pytest.raises(ValidationError):
            Vendor(
                name="X",
                type=VendorType.SAAS,
                criticality_tier=CriticalityTier.LOW,
                relationship_owner="a@b.com",
                contract_start_date=date(2025, 1, 1),
                criticallity_tier="critical",  # typo
            )

    def test_stamping_fields_populate(self) -> None:
        v = self._make()
        assert isinstance(v.created_at, datetime)
        assert isinstance(v.updated_at, datetime)
        assert v.evidentia_version  # captured from current_version()


# ── compute_next_review_due cadence helper ─────────────────────────


class TestComputeNextReviewDue:
    """Per-tier cadence + month-arithmetic edge cases."""

    def _make(self, tier: CriticalityTier, last_review: date | None) -> Vendor:
        return Vendor(
            name="X",
            type=VendorType.SAAS,
            criticality_tier=tier,
            relationship_owner="a@b.com",
            contract_start_date=date(2025, 1, 1),
            last_due_diligence_review=last_review,
        )

    def test_returns_none_when_last_review_unset(self) -> None:
        v = self._make(CriticalityTier.CRITICAL, last_review=None)
        assert v.compute_next_review_due() is None

    def test_critical_tier_is_annual(self) -> None:
        v = self._make(CriticalityTier.CRITICAL, last_review=date(2025, 6, 15))
        assert v.compute_next_review_due() == date(2026, 6, 15)

    def test_high_tier_is_annual(self) -> None:
        v = self._make(CriticalityTier.HIGH, last_review=date(2025, 6, 15))
        assert v.compute_next_review_due() == date(2026, 6, 15)

    def test_medium_tier_is_biennial(self) -> None:
        v = self._make(CriticalityTier.MEDIUM, last_review=date(2025, 6, 15))
        assert v.compute_next_review_due() == date(2027, 6, 15)

    def test_low_tier_is_triennial(self) -> None:
        v = self._make(CriticalityTier.LOW, last_review=date(2025, 6, 15))
        assert v.compute_next_review_due() == date(2028, 6, 15)

    def test_jan_31_anchor_preserves_day_on_annual_roll(self) -> None:
        # The {12, 24, 36}-month cadences always land on the same
        # month-of-year as the anchor, so the day-clamp logic is
        # a defense-in-depth path that only fires if a future
        # cadence becomes non-multiple-of-12. This test pins the
        # invariant: month-31 anchor preserves day-31 on roll.
        v = self._make(CriticalityTier.CRITICAL, last_review=date(2025, 1, 31))
        assert v.compute_next_review_due() == date(2026, 1, 31)

    def test_feb_29_leap_anchor_clamps_to_feb_28_on_non_leap_target(
        self,
    ) -> None:
        # The one cadence-induced clamp scenario: 2024 is a leap year,
        # 2025 is not. Anchor 2024-02-29 + 12 months → target 2025-02-?
        # — Feb 2025 only has 28 days, so the day clamps.
        v = self._make(CriticalityTier.CRITICAL, last_review=date(2024, 2, 29))
        assert v.compute_next_review_due() == date(2025, 2, 28)

    def test_dec_anchor_rolls_year(self) -> None:
        v = self._make(CriticalityTier.CRITICAL, last_review=date(2025, 12, 15))
        assert v.compute_next_review_due() == date(2026, 12, 15)

    def test_pure_function_does_not_mutate_self(self) -> None:
        v = self._make(CriticalityTier.MEDIUM, last_review=date(2025, 6, 15))
        original_next = v.next_review_due
        v.compute_next_review_due()
        # next_review_due field unchanged — caller chooses to assign
        assert v.next_review_due == original_next

    def test_string_form_of_criticality_tier_accepted(self) -> None:
        # Per EvidentiaModel ``use_enum_values=True``, after
        # construction the field stores the str value, not the enum.
        # The helper must work with that representation.
        v = self._make(CriticalityTier.CRITICAL, last_review=date(2025, 6, 15))
        assert isinstance(v.criticality_tier, str)  # str post-validation
        # Doesn't raise:
        assert v.compute_next_review_due() == date(2026, 6, 15)


# ── FourthParty model ──────────────────────────────────────────────


class TestFourthParty:
    def test_basic_construction(self) -> None:
        fp = FourthParty(
            name="Amazon Web Services",
            type=VendorType.CLOUD_PROVIDER,
            relationship="underlying IaaS for vendor SaaS",
            disclosed_at=date(2025, 3, 1),
        )
        assert fp.name == "Amazon Web Services"
        assert fp.type == VendorType.CLOUD_PROVIDER.value

    def test_disclosed_at_optional(self) -> None:
        fp = FourthParty(
            name="Stripe",
            type=VendorType.SAAS,
            relationship="payment processing",
        )
        assert fp.disclosed_at is None

    def test_relationship_max_length(self) -> None:
        # 512-char cap
        with pytest.raises(ValidationError):
            FourthParty(
                name="X",
                type=VendorType.SAAS,
                relationship="a" * 513,
            )


# ── EvidenceRef model ──────────────────────────────────────────────


class TestEvidenceRef:
    def test_internal_artifact_reference(self) -> None:
        ref = EvidenceRef(
            title="SOC 2 Type II — FY2025",
            artifact_id="abc-123",
        )
        assert ref.artifact_id == "abc-123"
        assert ref.file_path is None
        assert ref.collected_at  # default_factory stamped

    def test_external_file_with_sha256(self) -> None:
        ref = EvidenceRef(
            title="ISO 27001 Cert",
            file_path="/var/evidentia/vendor-evidence/acme-iso27001.pdf",
            sha256="a" * 64,
        )
        assert ref.sha256 == "a" * 64

    def test_sha256_pattern_enforces_lowercase_hex_64(self) -> None:
        # Wrong length:
        with pytest.raises(ValidationError):
            EvidenceRef(title="X", file_path="/x", sha256="abc")
        # Uppercase rejected:
        with pytest.raises(ValidationError):
            EvidenceRef(title="X", file_path="/x", sha256="A" * 64)
        # Non-hex char:
        with pytest.raises(ValidationError):
            EvidenceRef(title="X", file_path="/x", sha256="z" * 64)

    def test_notes_max_length(self) -> None:
        # 1024-char cap
        with pytest.raises(ValidationError):
            EvidenceRef(
                title="X",
                artifact_id="x",
                notes="a" * 1025,
            )

    def test_neither_artifact_id_nor_file_path_rejected(self) -> None:
        """H-1 (v0.7.9 P0.1 Continuous review): the docstring claims
        at least one of (artifact_id, file_path) must be set; this test
        pins the model_validator that enforces it."""
        with pytest.raises(ValidationError) as exc_info:
            EvidenceRef(title="Bare title only")
        assert "artifact_id" in str(exc_info.value) or "file_path" in str(exc_info.value)

    def test_file_path_without_sha256_rejected(self) -> None:
        """H-1 follow-up: file_path requires a paired sha256 digest
        for tamper detection per the docstring contract."""
        with pytest.raises(ValidationError) as exc_info:
            EvidenceRef(title="X", file_path="/var/evidentia/x.pdf")
        assert "sha256" in str(exc_info.value)

    def test_file_path_with_sha256_accepted(self) -> None:
        """Sanity: the H-1 validator doesn't break the documented
        external-reference happy path."""
        ref = EvidenceRef(
            title="X",
            file_path="/var/evidentia/x.pdf",
            sha256="a" * 64,
        )
        assert ref.file_path == "/var/evidentia/x.pdf"


class TestEvidenceRefJSONSchema:
    """The published JSON Schema must express the same two-mode
    contract ``_enforce_reference_invariants`` enforces at construction
    time. Otherwise schema-driven consumers (GUI type generation,
    schemathesis/DAST data generation) produce schema-valid bodies the
    API then rejects with 422 — flagged as RejectedPositiveData in the
    2026-07-06 schemathesis scoping run against POST
    /api/model-risk/models.

    Each branch requires the field to be present AND a string (not
    null), matching the validator's ``is None`` checks — a bare
    ``required`` would wrongly accept ``{"artifact_id": null}``.
    """

    def test_schema_requires_at_least_one_reference_mode(self) -> None:
        schema = EvidenceRef.model_json_schema()
        assert schema["anyOf"] == [
            {
                "required": ["artifact_id"],
                "properties": {"artifact_id": {"type": "string"}},
            },
            {
                "required": ["file_path"],
                "properties": {"file_path": {"type": "string"}},
            },
        ]

    def test_schema_pairs_file_path_with_sha256(self) -> None:
        schema = EvidenceRef.model_json_schema()
        assert schema["if"] == {
            "required": ["file_path"],
            "properties": {"file_path": {"type": "string"}},
        }
        assert schema["then"] == {
            "required": ["sha256"],
            "properties": {"sha256": {"type": "string"}},
        }


# ── Integration: Vendor with embedded sub-models ───────────────────


def test_vendor_with_fourth_parties_and_evidence_refs() -> None:
    v = Vendor(
        name="Acme Compliance Inc.",
        type=VendorType.SAAS,
        criticality_tier=CriticalityTier.HIGH,
        relationship_owner="allen@allenfbyrd.com",
        contract_start_date=date(2025, 1, 1),
        last_due_diligence_review=date(2025, 6, 15),
        regulatory_classification=[
            RegulatoryClassification.MODEL,
        ],
        fourth_parties=[
            FourthParty(
                name="Amazon Web Services",
                type=VendorType.CLOUD_PROVIDER,
                relationship="underlying IaaS",
            ),
        ],
        evidence_refs=[
            EvidenceRef(
                title="SOC 2 Type II — FY2025",
                artifact_id="evidence-abc-123",
            ),
        ],
        residual_risk_score=8,
    )
    # Round-trip
    data = v.model_dump()
    restored = Vendor.model_validate(data)
    assert len(restored.fourth_parties) == 1
    assert len(restored.evidence_refs) == 1
    assert restored.fourth_parties[0].name == "Amazon Web Services"
    assert restored.evidence_refs[0].title == "SOC 2 Type II — FY2025"
    assert restored.compute_next_review_due() == date(2026, 6, 15)
