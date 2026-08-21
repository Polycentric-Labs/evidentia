"""Unit tests for the SDR ``fedRampRequirements`` block (v0.12).

``SDR-CSO-FRR`` is a MUST in the FedRAMP Consolidated Rules: a Security
Decision Record "MUST include at least" an explanation, verification,
validation, and related statements *for each applicable FedRAMP rule*.
Through v0.11.x the emitter shipped ``fedRampRequirements: []`` — which
satisfies the *schema* (the array is required, its contents are not)
but not the *rule*. An emitted SDR was schema-valid and rule-incomplete.

v0.12 closes that structurally, mirroring the KSI block: the operator's
status file gains a ``requirements`` map keyed by FRR ID, IDs are checked
against a new ``fedramp-frr-2026`` catalog generated from the same pinned
rules blob, and the block is emitted with coverage reported. The
statements stay operator-authored governance prose, exactly as KSI
statements are — nothing is invented.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from evidentia_core.fedramp import (
    FRR_CATALOG_ID,
    build_sdr_document,
    frr_coverage,
    load_frr_catalog,
    validate_sdr_document,
)
from evidentia_core.models.fedramp_ksi import KsiStatusDocument
from pydantic import ValidationError

LAST_UPDATED = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)

#: A provider-facing rule present in every CR26 revision.
A_REAL_FRR_ID = "SDR-CSO-FRR"


def _status(
    *,
    indicators: dict[str, Any] | None = None,
    requirements: dict[str, Any] | None = None,
) -> KsiStatusDocument:
    body: dict[str, Any] = {
        "certification_package_overview_uri": (
            "https://provider.example/fedramp/cpo.json"
        ),
        "document_version": "1.0.0",
        "source": "unit tests",
        "indicators": indicators or {"KSI-CED-RAT": {"implementation": ["m."]}},
    }
    if requirements is not None:
        body["requirements"] = requirements
    return KsiStatusDocument.model_validate(body)


# ── the catalog ────────────────────────────────────────────────────


class TestFrrCatalog:
    def test_catalog_id_matches_the_ksi_naming_convention(self) -> None:
        assert FRR_CATALOG_ID == "fedramp-frr-2026"

    def test_catalog_loads_and_is_provider_scoped(self) -> None:
        """Only rules whose upstream ``affects`` names Providers belong.

        An SDR is the provider's record; rules addressed to FedRAMP
        itself, assessors, or agencies are not things a provider can
        implement, so they would be noise in a coverage report.
        """
        catalog = load_frr_catalog()
        ids = {c.id for c in catalog.controls}
        assert A_REAL_FRR_ID in ids
        # FedRAMP-addressed rules (``affects: [FedRAMP]``) must be absent.
        assert "AFC-FRP-VRE" not in ids

    def test_catalog_carries_the_rule_force_in_guidance(self) -> None:
        """MUST vs SHOULD is the operator's prioritisation signal."""
        catalog = load_frr_catalog()
        rule = next(c for c in catalog.controls if c.id == A_REAL_FRR_ID)
        assert "MUST" in (rule.guidance or "")

    def test_catalog_is_substantially_larger_than_ksi(self) -> None:
        """Sanity floor: upstream names Providers in well over 100 rules."""
        assert len(load_frr_catalog().controls) > 100


# ── the status-file model ──────────────────────────────────────────


class TestRequirementsModel:
    def test_requirements_default_to_empty_for_back_compat(self) -> None:
        """Existing v0.11 status files (no ``requirements`` key) still load."""
        status = _status()
        assert status.requirements == {}

    def test_requirement_entry_needs_at_least_one_implementation(self) -> None:
        """An entry with no implementation statement says nothing."""
        with pytest.raises(ValidationError):
            _status(requirements={A_REAL_FRR_ID: {"implementation": []}})

    def test_requirement_status_vocabulary_is_the_schema_enum(self) -> None:
        with pytest.raises(ValidationError):
            _status(
                requirements={
                    A_REAL_FRR_ID: {
                        "implementation": ["x"],
                        "status": "Mostly Done",
                    }
                }
            )


# ── emission ───────────────────────────────────────────────────────


class TestEmitFrrBlock:
    def test_requirements_emit_into_fedramp_requirements(self) -> None:
        doc = build_sdr_document(
            _status(
                requirements={
                    A_REAL_FRR_ID: {
                        "status": "Implemented",
                        "implementation": ["We emit the SDR via conmon ksi."],
                        "validation": ["Validated by schema round-trip."],
                        "assessment": ["3PAO reviewed 2026-08."],
                    }
                }
            ),
            last_updated=LAST_UPDATED,
        )
        assert validate_sdr_document(doc) == []
        [item] = doc["fedRampRequirements"]
        assert item["frrID"] == A_REAL_FRR_ID
        assert item["frrImplementationStatus"] == "Implemented"
        assert item["frrImplementation"] == ["We emit the SDR via conmon ksi."]
        assert item["frrValidation"] == ["Validated by schema round-trip."]
        assert item["frrAssessment"] == ["3PAO reviewed 2026-08."]

    def test_optional_status_is_omitted_when_unset(self) -> None:
        doc = build_sdr_document(
            _status(requirements={A_REAL_FRR_ID: {"implementation": ["x"]}}),
            last_updated=LAST_UPDATED,
        )
        [item] = doc["fedRampRequirements"]
        assert "frrImplementationStatus" not in item
        assert validate_sdr_document(doc) == []

    def test_requirements_are_emitted_in_sorted_id_order(self) -> None:
        """Deterministic output: the same file always renders the same SDR."""
        catalog_ids = sorted(c.id for c in load_frr_catalog().controls)
        first, second = catalog_ids[0], catalog_ids[-1]
        doc = build_sdr_document(
            _status(
                requirements={
                    second: {"implementation": ["b"]},
                    first: {"implementation": ["a"]},
                }
            ),
            last_updated=LAST_UPDATED,
        )
        assert [i["frrID"] for i in doc["fedRampRequirements"]] == [first, second]

    def test_unknown_frr_id_is_an_operator_error(self) -> None:
        with pytest.raises(ValueError, match="unknown FRR"):
            build_sdr_document(
                _status(requirements={"ZZZ-CSO-NOPE": {"implementation": ["x"]}}),
                last_updated=LAST_UPDATED,
            )

    def test_no_requirements_still_emits_an_empty_array(self) -> None:
        """The schema requires the key; v0.11 files keep validating."""
        doc = build_sdr_document(_status(), last_updated=LAST_UPDATED)
        assert doc["fedRampRequirements"] == []
        assert validate_sdr_document(doc) == []


# ── coverage ───────────────────────────────────────────────────────


class TestFrrCoverage:
    def test_coverage_counts_against_the_provider_scoped_catalog(self) -> None:
        cov = frr_coverage(
            _status(requirements={A_REAL_FRR_ID: {"implementation": ["x"]}})
        )
        assert cov.total == len(load_frr_catalog().controls)
        assert cov.addressed == 1
        assert A_REAL_FRR_ID not in cov.missing
        assert not cov.complete

    def test_empty_requirements_report_zero_addressed(self) -> None:
        cov = frr_coverage(_status())
        assert cov.addressed == 0
        assert len(cov.missing) == cov.total
