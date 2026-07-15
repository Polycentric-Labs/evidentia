"""Unit tests for the FedRAMP CR26 SDR KSI emitter (v0.11 Wave 2).

Round-trips emitted documents through the vendored
``fedramp-security-decision-record-schema-2026-06-24.json`` (Draft
2020-12) with the offline ``$id`` registry — including a negative case
proving the validator actually resolves the cross-document ``$ref``
that upstream published malformed (FedRAMP/schemas#3; our vendored copy
carries the documented fragment fix).
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

import pytest
from evidentia_core.fedramp import (
    build_sdr_document,
    ksi_coverage,
    load_ksi_catalog,
    validate_sdr_document,
)
from evidentia_core.models.fedramp_ksi import KsiStatusDocument
from pydantic import ValidationError

LAST_UPDATED = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)


def _status(indicators: dict[str, Any]) -> KsiStatusDocument:
    return KsiStatusDocument.model_validate(
        {
            "certification_package_overview_uri": (
                "https://provider.example/fedramp/cpo.json"
            ),
            "document_version": "1.0.0",
            "source": "unit tests",
            "indicators": indicators,
        }
    )


def _minimal_entry() -> dict[str, Any]:
    return {"implementation": ["Measure statement."]}


class TestBuildSdrDocument:
    def test_minimal_document_is_schema_valid(self) -> None:
        doc = build_sdr_document(
            _status({"KSI-CED-RAT": _minimal_entry()}),
            last_updated=LAST_UPDATED,
        )
        assert validate_sdr_document(doc) == []
        assert doc["fedRampRequirements"] == []
        assert doc["keySecurityIndicators"][0]["ksiId"] == "KSI-CED-RAT"

    def test_metadata_block_is_rule_required_and_schema_permitted(self) -> None:
        """SDR-CSO-MTD metadata rides as an additional property.

        The published schema models no metadata field but does not set
        ``additionalProperties: false`` — if upstream ever locks that
        down, this round-trip breaks and the emitter must move the
        block. This test pins the assumption.
        """
        doc = build_sdr_document(
            _status({"KSI-CED-RAT": _minimal_entry()}),
            last_updated=LAST_UPDATED,
        )
        assert doc["metadata"] == {
            "version": "1.0.0",
            "lastUpdated": "2026-07-14T12:00:00+00:00",
            "source": "unit tests",
        }
        assert validate_sdr_document(doc) == []

    def test_indicators_sorted_by_id_for_determinism(self) -> None:
        doc = build_sdr_document(
            _status(
                {
                    "KSI-SVC-VCM": _minimal_entry(),
                    "KSI-CED-RAT": _minimal_entry(),
                    "KSI-IAM-JIT": _minimal_entry(),
                }
            ),
            last_updated=LAST_UPDATED,
        )
        ids = [k["ksiId"] for k in doc["keySecurityIndicators"]]
        assert ids == sorted(ids)

    def test_status_omitted_when_not_supplied(self) -> None:
        doc = build_sdr_document(
            _status({"KSI-CED-RAT": _minimal_entry()}),
            last_updated=LAST_UPDATED,
        )
        assert "ksiImplementationStatus" not in doc["keySecurityIndicators"][0]

    def test_evidence_maps_to_sdr_shape(self) -> None:
        entry = {
            "implementation": ["Measure."],
            "evidence": [
                {
                    "evidence_type": "Audit Record",
                    "description": "WORM audit chain excerpt",
                    "location": "https://provider.example/evidence/audit.json",
                    "text": "…",
                    "last_updated": "2026-07-01",
                }
            ],
        }
        doc = build_sdr_document(
            _status({"KSI-MLA-ALA": entry}), last_updated=LAST_UPDATED
        )
        ev = doc["keySecurityIndicators"][0]["ksiEvidence"][0]
        assert ev == {
            "evidenceType": "Audit Record",
            "evidenceDescription": "WORM audit chain excerpt",
            "evidenceLocation": "https://provider.example/evidence/audit.json",
            "evidenceText": "…",
            "lastUpdated": "2026-07-01",
        }
        assert validate_sdr_document(doc) == []

    def test_unknown_ksi_id_is_a_hard_error(self) -> None:
        with pytest.raises(ValueError, match="unknown KSI indicator ID"):
            build_sdr_document(
                _status({"KSI-FAKE-XXX": _minimal_entry()}),
                last_updated=LAST_UPDATED,
            )


class TestPersistenceCycles:
    def test_cycle_statement_with_state_anchor(self) -> None:
        entry = {
            "implementation": ["Measure."],
            "persistence_cycles": [{"cadence_slug": "nist-800-53-rev5-ca7"}],
        }
        doc = build_sdr_document(
            _status({"KSI-CED-RAT": entry}),
            last_updated=LAST_UPDATED,
            last_completed={"nist-800-53-rev5-ca7": date(2026, 7, 1)},
        )
        statements = doc["keySecurityIndicators"][0]["ksiImplementation"]
        assert statements[0] == "Measure."
        assert "nist-800-53-rev5-ca7" in statements[1]
        assert "last completed 2026-07-01" in statements[1]
        assert "next due 2026-08-01" in statements[1]

    def test_cycle_statement_without_state_anchor(self) -> None:
        entry = {
            "implementation": ["Measure."],
            "persistence_cycles": [
                {"cadence_slug": "nist-800-53-rev5-ca7", "note": "Owner: SecOps."}
            ],
        }
        doc = build_sdr_document(
            _status({"KSI-CED-RAT": entry}), last_updated=LAST_UPDATED
        )
        statement = doc["keySecurityIndicators"][0]["ksiImplementation"][1]
        assert "last completed" not in statement
        assert statement.endswith("Owner: SecOps.")

    def test_unknown_cadence_slug_is_a_hard_error(self) -> None:
        entry = {
            "implementation": ["Measure."],
            "persistence_cycles": [{"cadence_slug": "totally-not-real"}],
        }
        with pytest.raises(ValueError, match="unknown CONMON cadence slug"):
            build_sdr_document(
                _status({"KSI-CED-RAT": entry}), last_updated=LAST_UPDATED
            )


class TestValidateSdrDocument:
    def test_validator_bites_on_missing_required_field(self) -> None:
        doc = build_sdr_document(
            _status({"KSI-CED-RAT": _minimal_entry()}),
            last_updated=LAST_UPDATED,
        )
        del doc["fedRampRequirements"]
        errors = validate_sdr_document(doc)
        assert any("fedRampRequirements" in e for e in errors)

    def test_validator_resolves_cross_document_ref(self) -> None:
        """The one cross-document $ref must resolve through the local
        registry AND enforce the referenced type (string URI)."""
        doc = build_sdr_document(
            _status({"KSI-CED-RAT": _minimal_entry()}),
            last_updated=LAST_UPDATED,
        )
        doc["certificationPackageOverviewUri"] = 12345
        errors = validate_sdr_document(doc)
        assert any("certificationPackageOverviewUri" in e for e in errors)


class TestModels:
    def test_empty_implementation_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _status({"KSI-CED-RAT": {"implementation": []}})

    def test_invalid_evidence_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _status(
                {
                    "KSI-CED-RAT": {
                        "implementation": ["Measure."],
                        "evidence": [
                            {"evidence_type": "Vibes", "description": "no"}
                        ],
                    }
                }
            )

    def test_invalid_status_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _status(
                {
                    "KSI-CED-RAT": {
                        "implementation": ["Measure."],
                        "status": "Mostly Done",
                    }
                }
            )


class TestCoverage:
    def test_coverage_math(self) -> None:
        status = _status(
            {
                "KSI-CED-RAT": _minimal_entry(),
                "KSI-SCR-MON": _minimal_entry(),
            }
        )
        coverage = ksi_coverage(status)
        assert coverage.total == 46
        assert coverage.addressed == 2
        assert len(coverage.missing) == 44
        assert not coverage.complete

    def test_full_coverage_is_complete(self) -> None:
        catalog = load_ksi_catalog()
        status = _status(
            {control.id: _minimal_entry() for control in catalog.controls}
        )
        coverage = ksi_coverage(status)
        assert coverage.complete
        assert coverage.addressed == coverage.total == 46
        doc = build_sdr_document(status, last_updated=LAST_UPDATED)
        assert validate_sdr_document(doc) == []
        assert len(doc["keySecurityIndicators"]) == 46
