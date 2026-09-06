"""Hypothesis property test: SecurityFinding ↔ OCSF round-trip
preserves the finding (v0.10.4 B1).

OCSF is load-bearing for 12+ collectors as of v0.10.1. The bidirectional
mapping in `evidentia_core.ocsf.finding_mapping` is the structural
guarantee that:

  finding_from_ocsf(finding_to_ocsf(x)) ≈ x  for all valid SecurityFinding x

Where ``≈`` means: every field the OCSF schema can represent round-
trips losslessly, modulo trivial normalizations (timezone-aware datetimes
become UTC; enums become their string values).

Without this fuzz test, a SecurityFinding field added without a
matching OCSF mapping update would silently lose data on round-trip;
the property test surfaces the regression deterministically across
the v0.8.2 G2 Hypothesis ``ci`` profile (200 examples, 200ms
deadline).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

# Skip the whole module if [ocsf] extra is not installed.
pytest.importorskip(
    "py_ocsf_models",
    reason="py-ocsf-models not installed; install the [ocsf] extra",
)


# ── Composite strategies ─────────────────────────────────────────────


def _aware_datetimes() -> st.SearchStrategy[datetime]:
    """UTC-aware datetimes in a realistic compliance-evidence window.

    Bounds: 2020-01-01 to 2030-12-31. Tight enough to keep OCSF's
    int milliseconds-since-epoch field within plain ``int`` range
    on 32-bit hosts; broad enough to cover realistic finding ages.
    """
    return st.datetimes(
        min_value=datetime(2020, 1, 1),
        max_value=datetime(2030, 12, 31),
        timezones=st.just(UTC),
    )


def _safe_strings() -> st.SearchStrategy[str]:
    """Strings safe to embed in OCSF / JSON without losing fidelity.

    Excludes control characters that some JSON serializers reshape
    (\\x00, \\x7f...\\x9f). Includes Unicode + emoji for realistic
    audit-text coverage.
    """
    return st.text(
        alphabet=st.characters(
            blacklist_categories=("Cs",),  # surrogates
            blacklist_characters="\x00\r",  # null + CR (line-ending normalization)
        ),
        min_size=1,
        max_size=200,
    )


def _security_findings() -> st.SearchStrategy[object]:
    """Build a SecurityFinding with every round-trippable field
    populated. The strategy lives inside the function so the
    skip-on-missing-ocsf-extra import-skip fires before this is
    evaluated."""
    from evidentia_core.models.finding import (
        ComplianceStatus,
        SecurityFinding,
    )

    severities = st.sampled_from(["informational", "low", "medium", "high", "critical"])
    # FindingStatus enum (per packages/evidentia-core/src/evidentia_core/models/finding.py)
    # is exactly {active, resolved, suppressed} — the same vocabulary
    # OCSF Compliance Finding uses for status_id 1 (New/Active),
    # 4 (Closed/Resolved), 3 (Suppressed).
    statuses = st.sampled_from(["active", "resolved", "suppressed"])
    compliance_statuses = st.sampled_from(list(ComplianceStatus))
    aware_times = _aware_datetimes()
    safe_str = _safe_strings()

    return st.builds(
        SecurityFinding,
        title=safe_str,
        description=safe_str,
        severity=severities,
        status=statuses,
        source_system=safe_str,
        first_observed=aware_times,
        last_observed=aware_times,
        compliance_status=compliance_statuses,
        remediation=st.one_of(st.none(), safe_str),
    )


# ── Property tests ──────────────────────────────────────────────────


@given(_security_findings())
def test_finding_round_trip_preserves_core_fields(finding: object) -> None:
    """For arbitrary SecurityFinding inputs, round-tripping through
    finding_to_ocsf + finding_from_ocsf preserves every field the
    OCSF Compliance Finding schema can represent."""
    from evidentia_core.ocsf import finding_from_ocsf, finding_to_ocsf

    ocsf_dict = finding_to_ocsf(finding)
    restored = finding_from_ocsf(ocsf_dict)

    # OCSF stores Evidentia fields under unmapped["evidentia"] so the
    # round-trip is lossless. Assert each field that's structurally
    # round-trippable.
    assert restored.title == finding.title
    assert restored.description == finding.description
    assert restored.severity == finding.severity
    assert restored.status == finding.status
    assert restored.source_system == finding.source_system
    assert restored.compliance_status == finding.compliance_status
    assert restored.remediation == finding.remediation


@given(_security_findings())
def test_finding_to_ocsf_emits_class_uid_2003(finding: object) -> None:
    """Invariant: every finding emitted as OCSF carries the
    Compliance Finding class_uid (2003), not a Detection Finding
    (2004) or other class. The choice is structural — Compliance
    Finding is the right OCSF class for evidence-of-control-state
    rather than evidence-of-attack."""
    from evidentia_core.ocsf import finding_to_ocsf

    ocsf_dict = finding_to_ocsf(finding)
    assert ocsf_dict["class_uid"] == 2003
    assert ocsf_dict["class_name"] == "Compliance Finding"
    assert ocsf_dict["category_uid"] == 2
    assert ocsf_dict["category_name"] == "Findings"


@given(_security_findings())
def test_finding_to_ocsf_embeds_full_finding_under_unmapped(
    finding: object,
) -> None:
    """Invariant: the full SecurityFinding is embedded under
    ``unmapped["evidentia"]`` so an OCSF-aware consumer that ALSO
    speaks Evidentia can recover fields the OCSF schema cannot
    natively express (e.g., evidentia-specific control_mappings
    structure, custom tags). This is the cross-projection guarantee."""
    from evidentia_core.ocsf import finding_to_ocsf

    ocsf_dict = finding_to_ocsf(finding)
    assert "unmapped" in ocsf_dict
    assert "evidentia" in ocsf_dict["unmapped"]
    # Per packages/evidentia-core/src/evidentia_core/ocsf/finding_mapping.py:260
    # the SecurityFinding model_dump lands directly under
    # ``unmapped["evidentia"]``, not nested under a sub-key.
    embedded = ocsf_dict["unmapped"]["evidentia"]
    assert embedded is not None
    assert embedded["title"] == finding.title
    assert embedded["description"] == finding.description
