"""Schema + provenance validation tests for OSPS crosswalks.

v0.10.6 Phase C5 — extends ``CrosswalkDefinition`` with 3 optional
provenance fields (``provenance``, ``verification``,
``verification_note``) and lands 5 OSPS-Baseline crosswalks alongside
the 8 pre-existing in-tree crosswalks.

These tests verify:
  1. The extended schema accepts the new optional fields.
  2. Existing pre-v0.10.6 crosswalks still load (backward-compat).
  3. ``verification`` rejects values outside the allowed ``Literal``.
  4. Each of the 5 OSPS crosswalk files loads + carries the expected
     upstream-attested provenance posture.

See ``docs/api-stability.md`` revision-history row for v0.10.6 +
``docs/v0.10.6-plan.md`` §Phase 5 for the upstream-attested rationale.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evidentia_core.models.catalog import CrosswalkDefinition

# Path-arithmetic: this file lives at
#   tests/unit/test_catalogs/test_crosswalks.py
# so ``parent`` is ``test_catalogs``, ``parent.parent`` is ``unit``,
# ``parent.parent.parent`` is ``tests``, and ``parent.parent.parent.parent``
# is the repo root. Verified empirically before committing.
MAPPINGS_DIR = (
    Path(__file__).parent.parent.parent.parent
    / "packages"
    / "evidentia-core"
    / "src"
    / "evidentia_core"
    / "catalogs"
    / "data"
    / "mappings"
)


def test_crosswalkdefinition_accepts_optional_provenance_fields() -> None:
    """Extended schema accepts provenance/verification/verification_note as optional."""
    obj = CrosswalkDefinition(
        source_framework="osps-baseline-2026.02.19",
        target_framework="nist-ssdf-800-218",
        version="OSPS Baseline / NIST SSDF",
        generated_at="2026-05-26",
        source="Auto-extracted upstream OSPS guidelines[]",
        provenance="upstream-osps-guidelines",
        verification="self-attested-via-upstream",
        verification_note="Mappings auto-extracted; not independently verified.",
        mappings=[],
    )
    assert obj.provenance == "upstream-osps-guidelines"
    assert obj.verification == "self-attested-via-upstream"
    assert obj.verification_note is not None
    assert obj.verification_note.startswith("Mappings")


def test_crosswalkdefinition_backward_compat_without_provenance_fields() -> None:
    """Existing crosswalks without new fields still load (fields default to None)."""
    obj = CrosswalkDefinition(
        source_framework="fedramp-rev5-moderate",
        target_framework="cmmc-2-l2",
        version="...",
        generated_at="2026-04-16",
        source="Evidentia-authored",
        mappings=[],
    )
    assert obj.provenance is None
    assert obj.verification is None
    assert obj.verification_note is None


def test_crosswalkdefinition_rejects_invalid_verification_literal() -> None:
    """verification must be one of the allowed literals."""
    with pytest.raises(ValueError):
        CrosswalkDefinition(
            source_framework="x",
            target_framework="y",
            version="...",
            generated_at="...",
            source="...",
            verification="bogus-value",  # type: ignore[arg-type]
            mappings=[],
        )


@pytest.mark.parametrize(
    "filename",
    [
        "osps-baseline_to_nist-ssdf-800-218.json",
        "osps-baseline_to_nist-csf-2.0.json",
        "osps-baseline_to_eu-cra.json",
        "osps-baseline_to_pci-dss-4.0.json",
        "osps-baseline_to_nist-800-161.json",
    ],
)
def test_osps_crosswalks_load_and_self_attest(filename: str) -> None:
    """Each OSPS crosswalk loads + declares upstream-osps provenance."""
    path = MAPPINGS_DIR / filename
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    obj = CrosswalkDefinition.model_validate(data)
    assert obj.source_framework.startswith("osps-baseline")
    assert obj.provenance == "upstream-osps-guidelines"
    assert obj.verification == "self-attested-via-upstream"
    assert len(obj.mappings) > 0
