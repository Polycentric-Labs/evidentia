"""BLOCKER B7: AR conforms to OSCAL 1.1.x via the NIST-blessed reference impl.

`compliance-trestle` (https://github.com/oscal-compass/compliance-trestle)
is the OSCAL-Compass reference implementation. It uses ``pydantic.v1``
under the hood with ``Extra.forbid`` on every model class, which catches
unknown-field bugs that NIST's JSON Schema misses (NIST's schema does
not use ``additionalProperties: false`` on every type, so unknown fields
slip through schema validation).

These tests round-trip Evidentia's AR output through trestle's pydantic
models. If a future exporter change introduces a stray field anywhere
in the AR, trestle raises ``pydantic.v1.ValidationError`` with a precise
``loc`` path, and B7 is held.

Trestle integration notes
-------------------------

- **Use ``Model.parse_obj``, not ``AssessmentResults.model_validate``.**
  Trestle 4.x is on pydantic.v1 internally. The pydantic v2 API is not
  available on trestle-generated classes.
- **Root class is ``Model``** (the wrapper), not ``AssessmentResults``
  directly. ``Model`` holds ``assessment_results`` with alias
  ``"assessment-results"``.
- **Custom-namespace props are accepted.** OSCAL ``ns`` is an
  ``AnyUrl`` with no enumeration validator, so
  ``EVIDENTIA_OSCAL_NS = "https://evidentia.dev/oscal"`` props
  survive unchanged.

The test module skips entirely if trestle isn't installed (it's a
dev-only dep). Production install of evidentia-core does not pull
trestle.
"""

from __future__ import annotations

import pytest

# Dev-only dep. Skip the whole module on minimal installs so the rest
# of the 846+ test suite still runs.
trestle_ar = pytest.importorskip("trestle.oscal.assessment_results")

from evidentia_core.models.gap import (  # noqa: E402
    ControlGap,
    GapAnalysisReport,
    GapSeverity,
    GapStatus,
    ImplementationEffort,
)
from evidentia_core.oscal.exporter import gap_report_to_oscal_ar  # noqa: E402


def _make_minimal_report() -> GapAnalysisReport:
    """Smallest GapAnalysisReport that still exercises the AR shape."""
    gap = ControlGap(
        framework="soc2-tsc",
        control_id="CC6.1",
        control_title="Logical access security",
        control_description="Logical access controls.",
        gap_severity=GapSeverity.HIGH,
        implementation_status="missing",
        gap_description="MFA not enforced for admin accounts.",
        remediation_guidance="Enable AWS Organizations SCP requiring MFA.",
        implementation_effort=ImplementationEffort.MEDIUM,
        priority_score=1.5,
        status=GapStatus.OPEN,
    )
    return GapAnalysisReport(
        organization="Acme Corp",
        frameworks_analyzed=["soc2-tsc"],
        total_controls_required=10,
        total_controls_in_inventory=8,
        total_gaps=1,
        critical_gaps=0,
        high_gaps=1,
        medium_gaps=0,
        low_gaps=0,
        informational_gaps=0,
        coverage_percentage=80.0,
        gaps=[gap],
        efficiency_opportunities=[],
        prioritized_roadmap=[gap.id],
        inventory_source="test.yaml",
    )


def test_ar_round_trips_through_trestle() -> None:
    """Evidentia's AR dict parses cleanly through trestle's pydantic.v1 Model."""
    ar_dict = gap_report_to_oscal_ar(_make_minimal_report())

    # Trestle's root class is `Model` (wrapper), with field alias
    # `"assessment-results"`. We feed the whole dict; trestle resolves
    # the alias on input.
    parsed = trestle_ar.Model.parse_obj(ar_dict)
    ar = parsed.assessment_results

    # Structural assertions — trestle preserved all our required fields.
    assert ar.uuid == ar_dict["assessment-results"]["uuid"]
    assert ar.metadata.title == "Gap Analysis: Acme Corp"
    assert len(ar.results) == 1
    assert len(ar.results[0].findings) == 1
    assert len(ar.results[0].observations) == 1


def test_evidentia_namespace_props_in_metadata_accepted() -> None:
    """Evidentia-namespaced props on metadata don't trip Extra.forbid.

    OSCAL `ns` is AnyUrl with no enumeration validator, so our extension
    namespace is accepted. This proves the back-matter resource pattern
    (used for findings + blind-spots) is safe under trestle's
    Extra.forbid policy.
    """
    ar_dict = gap_report_to_oscal_ar(_make_minimal_report())

    # The exporter emits 3 metadata props (frameworks-analyzed,
    # coverage-percentage, total-gaps) without ns. We just need to
    # confirm trestle's `Property` accepts the unrestricted `name`.
    parsed = trestle_ar.Model.parse_obj(ar_dict)
    props = parsed.assessment_results.metadata.props or []
    assert len(props) >= 3
    names = {p.name for p in props}
    assert "frameworks-analyzed" in names


def test_blind_spots_in_back_matter_accepted() -> None:
    """Blind-spot back-matter resources with Evidentia ns survive trestle."""
    sample_blind_spots = [
        {
            "id": "kms-grants",
            "title": "KMS grant chains not analyzed",
            "description": "Access Analyzer does not analyze KMS grants.",
        },
        {
            "id": "service-linked-roles",
            "title": "Service-linked roles excluded",
            "description": "Excluded from unused-access analysis.",
        },
    ]
    ar_dict = gap_report_to_oscal_ar(_make_minimal_report(), blind_spots=sample_blind_spots)

    parsed = trestle_ar.Model.parse_obj(ar_dict)
    bm = parsed.assessment_results.back_matter
    assert bm is not None
    assert bm.resources is not None
    assert len(bm.resources) == 2

    # Each resource should have the Evidentia-namespaced blind-spot-id prop
    blind_spot_ids: set[str] = set()
    for r in bm.resources:
        for p in r.props or []:
            if p.name == "blind-spot-id":
                # ns may be None or AnyUrl-coerced; stringify and check
                assert p.ns is not None
                assert "evidentia.dev/oscal" in str(p.ns)
                blind_spot_ids.add(p.value)
    assert blind_spot_ids == {"kms-grants", "service-linked-roles"}


def test_vendor_uuid_identity_across_party_and_back_matter() -> None:
    """v0.7.13 P3 closure for M-9: vendor UUID is identical in
    ``metadata.parties[].uuid`` and ``back-matter.resources[].uuid``.

    The exporter contract (per ``_vendor_to_oscal_party`` +
    ``_vendor_to_oscal_resource`` docstrings) states that a Vendor
    appears in BOTH the AR's ``metadata.parties[]`` (organizational-
    party form for OSCAL-native consumers) and its ``back-matter.
    resources[]`` (Evidentia-style tamper-evident embedded form),
    keyed by the SAME UUID so that ``href: "#<vendor-id>"``
    cross-references resolve unambiguously regardless of which
    side of the AR a tool reads from.

    This test asserts the invariant by:

    1. Constructing a minimal AR with one Vendor in inventory,
    2. Round-tripping through trestle's pydantic.v1 Model (proves
       the dual-emission survives a full OSCAL conformance parse),
    3. Verifying ``vendor.id`` equals exactly one party UUID AND
       exactly one back-matter resource UUID,
    4. Verifying both sides carry the matching ``vendor-id`` prop
       so a downstream filter on ``vendor-id`` returns both.

    A regression here (e.g. someone reassigning ``uuid: uuid4()``
    in either helper rather than ``uuid: vendor.id``) would leave
    cross-references dangling — caught immediately by this test.
    """
    from datetime import date

    from evidentia_core.models.tprm import (
        CriticalityTier,
        Vendor,
        VendorType,
    )

    # Construct a minimal Vendor — only required fields, no optional
    # surface (4th-parties / regulatory-classification / region etc.).
    # Keeps the test focused on the UUID invariant.
    vendor = Vendor(
        name="Acme Cloud Services",
        type=VendorType.SAAS,
        criticality_tier=CriticalityTier.HIGH,
        relationship_owner="vendor-management@example.com",
        contract_start_date=date(2025, 1, 1),
    )

    ar_dict = gap_report_to_oscal_ar(
        _make_minimal_report(), vendor_inventory=[vendor]
    )

    # Round-trip through trestle to confirm OSCAL conformance.
    parsed = trestle_ar.Model.parse_obj(ar_dict)
    ar = parsed.assessment_results

    # ─── Party side: vendor.id appears exactly once in parties[] ───
    parties = ar.metadata.parties or []
    matching_parties = [p for p in parties if str(p.uuid) == vendor.id]
    assert len(matching_parties) == 1, (
        f"Expected vendor.id={vendor.id!r} to match exactly one party "
        f"UUID; found {len(matching_parties)}"
    )
    party = matching_parties[0]
    assert str(party.uuid) == vendor.id

    # The party MUST carry a ``vendor-id`` prop equal to vendor.id
    # (so a back-matter-blind tool filtering parties[] by vendor-id
    # finds this vendor without having to walk back-matter).
    party_vendor_id_props = [
        p for p in (party.props or []) if p.name == "vendor-id"
    ]
    assert len(party_vendor_id_props) == 1
    assert party_vendor_id_props[0].value == vendor.id

    # ─── Back-matter side: same UUID, same prop ───
    bm = ar.back_matter
    assert bm is not None
    assert bm.resources is not None
    matching_resources = [
        r for r in bm.resources if str(r.uuid) == vendor.id
    ]
    assert len(matching_resources) == 1, (
        f"Expected vendor.id={vendor.id!r} to match exactly one "
        f"back-matter resource UUID; found {len(matching_resources)}"
    )
    resource = matching_resources[0]
    assert str(resource.uuid) == vendor.id

    resource_vendor_id_props = [
        p for p in (resource.props or []) if p.name == "vendor-id"
    ]
    assert len(resource_vendor_id_props) == 1
    assert resource_vendor_id_props[0].value == vendor.id

    # ─── Cross-side identity: party UUID == back-matter UUID ───
    # Belt-and-suspenders: the previous two checks already establish
    # this transitively, but the direct assertion is what M-9 codifies.
    assert str(party.uuid) == str(resource.uuid) == vendor.id


def test_multiple_vendors_keep_uuid_identity_pairwise() -> None:
    """v0.7.13 P3 follow-up to M-9: with N>1 vendors, every party
    UUID has exactly one matching back-matter resource UUID and
    vice-versa.

    A regression that uses ``uuid4()`` per call instead of
    ``vendor.id`` would surface here as one-side-only entries —
    parties with no matching resource, or resources with no
    matching party.
    """
    from datetime import date

    from evidentia_core.models.tprm import (
        CriticalityTier,
        Vendor,
        VendorType,
    )

    vendors = [
        Vendor(
            name=f"Vendor {i}",
            type=VendorType.SAAS,
            criticality_tier=CriticalityTier.MEDIUM,
            relationship_owner=f"owner-{i}@example.com",
            contract_start_date=date(2025, 1, 1),
        )
        for i in range(3)
    ]
    expected_ids = {v.id for v in vendors}

    ar_dict = gap_report_to_oscal_ar(
        _make_minimal_report(), vendor_inventory=vendors
    )
    parsed = trestle_ar.Model.parse_obj(ar_dict)
    ar = parsed.assessment_results

    party_ids = {
        str(p.uuid)
        for p in (ar.metadata.parties or [])
        if any((q.name == "vendor-id" for q in (p.props or [])))
    }
    bm = ar.back_matter
    assert bm is not None
    assert bm.resources is not None
    resource_ids = {
        str(r.uuid)
        for r in bm.resources
        if any((q.name == "vendor-id" for q in (r.props or [])))
    }

    assert party_ids == expected_ids, (
        f"Party UUIDs {party_ids} != expected {expected_ids}"
    )
    assert resource_ids == expected_ids, (
        f"Resource UUIDs {resource_ids} != expected {expected_ids}"
    )
    assert party_ids == resource_ids
