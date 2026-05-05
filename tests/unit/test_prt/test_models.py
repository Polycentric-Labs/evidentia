"""Unit + integration tests for v0.8.0 P0.2 Policy Reasoning Traces.

Three test classes covering:

1. :class:`TestReasoningTraceModel` — Pydantic field validation
   + JSON round-trip + backward compatibility (pre-v0.8.0
   RiskStatement deserialization with no reasoning_trace key).
2. :class:`TestOSCALEmit` — :func:`gap_report_to_oscal_ar` with
   ``risk_statements_with_traces`` kwarg surfaces traces as
   back-matter resources; statements without a trace are
   skipped; canonical JSON hash is reproducible.
3. :class:`TestTrestleRoundTrip` — emit an AR with reasoning
   traces, parse it via the trestle pydantic.v1 root model
   (when available), confirm the trace data survives the
   round-trip. Skipped when trestle isn't installed.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest
from evidentia_core.models.gap import GapAnalysisReport
from evidentia_core.models.risk import (
    ImpactRating,
    LikelihoodRating,
    ReasoningTrace,
    RiskLevel,
    RiskStatement,
    TraceClaim,
)
from evidentia_core.oscal.exporter import gap_report_to_oscal_ar

# ── Test fixtures ──────────────────────────────────────────────────


def _make_trace() -> ReasoningTrace:
    return ReasoningTrace(
        claims=[
            TraceClaim(
                claim=(
                    "Account management controls are insufficient "
                    "given the scale of the user base."
                ),
                clause_citations=[
                    "nist-800-53-rev5-moderate:AC-2",
                    "nist-800-53-rev5-moderate:AC-2(1)",
                ],
                confidence=0.85,
            ),
            TraceClaim(
                claim=(
                    "The vulnerability is exploitable by external "
                    "attackers with valid credentials."
                ),
                clause_citations=[
                    "nist-800-53-rev5-moderate:AC-3",
                ],
                confidence=0.70,
            ),
        ],
        methodology=(
            "Per-claim atomic decomposition; "
            "geometric-mean confidence aggregation."
        ),
        overall_confidence=0.77,
    )


def _make_risk_statement_with_trace(
    *, with_trace: bool = True
) -> RiskStatement:
    # Use a real UUID for stmt.id — the OSCAL emitter pipes
    # this through to back-matter resource.uuid, and trestle
    # validates the UUID-format.
    return RiskStatement(
        id="99796ea1-5ade-4ac9-bd62-2d993648a2a2",
        asset="user-database",
        threat_source="external-attacker",
        threat_event="unauthorized-access",
        vulnerability="weak-account-management",
        likelihood=LikelihoodRating.MODERATE,
        likelihood_rationale="Limited monitoring of account lifecycle.",
        impact=ImpactRating.HIGH,
        impact_rationale="Database holds PII for ~10K users.",
        risk_level=RiskLevel.HIGH,
        risk_description=(
            "Insufficient account management controls expose the "
            "user database to unauthorized-access by external "
            "attackers with valid credentials."
        ),
        recommended_controls=["AC-2", "AC-3"],
        remediation_priority=2,
        source_gap_id="gap-test-001",
        reasoning_trace=_make_trace() if with_trace else None,
    )


def _make_minimal_gap_report() -> GapAnalysisReport:
    return GapAnalysisReport(
        organization="Test Org",
        frameworks_analyzed=["nist-800-53-rev5-moderate"],
        analyzed_at=datetime(2026, 5, 5, tzinfo=UTC),
        total_controls_required=100,
        total_controls_in_inventory=50,
        total_gaps=50,
        critical_gaps=0,
        high_gaps=10,
        medium_gaps=20,
        low_gaps=20,
        informational_gaps=0,
        coverage_percentage=50.0,
        gaps=[],
        efficiency_opportunities=[],
        prioritized_roadmap=[],
        evidentia_version="0.7.16",
    )


# ── 1. ReasoningTrace model ───────────────────────────────────────


class TestReasoningTraceModel:
    def test_construct_minimal_trace(self) -> None:
        trace = ReasoningTrace(
            claims=[
                TraceClaim(
                    claim="Some claim.",
                    clause_citations=["nist-800-53-rev5:AC-1"],
                    confidence=0.5,
                )
            ],
        )
        assert len(trace.claims) == 1
        assert trace.methodology == ""
        assert trace.overall_confidence == 0.0

    def test_confidence_bounded(self) -> None:
        with pytest.raises(ValueError):
            TraceClaim(
                claim="x",
                clause_citations=[],
                confidence=1.1,
            )
        with pytest.raises(ValueError):
            TraceClaim(
                claim="x",
                clause_citations=[],
                confidence=-0.1,
            )

    def test_clause_citations_can_be_empty(self) -> None:
        # Foundational claims (e.g., facts about the system
        # context) need not cite an external clause.
        c = TraceClaim(claim="x", clause_citations=[], confidence=0.5)
        assert c.clause_citations == []

    def test_pydantic_round_trip(self) -> None:
        trace = _make_trace()
        dumped = trace.model_dump_json()
        round_tripped = ReasoningTrace.model_validate_json(dumped)
        assert round_tripped == trace

    def test_risk_statement_without_trace_round_trip(self) -> None:
        stmt = _make_risk_statement_with_trace(with_trace=False)
        dumped = stmt.model_dump_json()
        round_tripped = RiskStatement.model_validate_json(dumped)
        assert round_tripped.reasoning_trace is None

    def test_risk_statement_with_trace_round_trip(self) -> None:
        stmt = _make_risk_statement_with_trace(with_trace=True)
        dumped = stmt.model_dump_json()
        round_tripped = RiskStatement.model_validate_json(dumped)
        assert round_tripped.reasoning_trace is not None
        assert (
            len(round_tripped.reasoning_trace.claims)
            == len(stmt.reasoning_trace.claims)  # type: ignore[union-attr]
        )

    def test_pre_v0_8_0_payload_deserializes(self) -> None:
        """A risk statement from before v0.8.0 has no reasoning_trace key.

        This MUST still parse cleanly so existing audit artifacts
        on disk don't break post-upgrade.
        """
        legacy_payload = {
            "id": "legacy-stmt",
            "asset": "x",
            "threat_source": "y",
            "threat_event": "z",
            "vulnerability": "w",
            "likelihood": "moderate",
            "likelihood_rationale": "rationale",
            "impact": "high",
            "impact_rationale": "rationale",
            "risk_level": "high",
            "risk_description": "desc",
            "recommended_controls": ["AC-1"],
            "remediation_priority": 3,
        }
        stmt = RiskStatement.model_validate(legacy_payload)
        assert stmt.reasoning_trace is None


# ── 2. OSCAL emit ─────────────────────────────────────────────────


class TestOSCALEmit:
    def test_emit_without_traces_unchanged(self) -> None:
        report = _make_minimal_gap_report()
        ar = gap_report_to_oscal_ar(report)
        # OSCAL exporter only emits back-matter when there are
        # resources to attach (per the v0.7.0 design — empty
        # arrays are valid but noisy in diffs). With no findings,
        # blind-spots, vendors, or traces, back-matter is absent.
        assert "back-matter" not in ar["assessment-results"]

    def test_emit_with_trace_creates_back_matter_resource(
        self,
    ) -> None:
        report = _make_minimal_gap_report()
        stmt = _make_risk_statement_with_trace(with_trace=True)
        ar = gap_report_to_oscal_ar(
            report, risk_statements_with_traces=[stmt]
        )
        resources = ar["assessment-results"]["back-matter"]["resources"]
        assert len(resources) == 1
        resource = resources[0]
        assert resource["uuid"] == stmt.id
        assert "Policy Reasoning Trace" in resource["description"]
        assert "base64" in resource
        assert "rlinks" in resource

    def test_statements_without_traces_skipped(self) -> None:
        report = _make_minimal_gap_report()
        with_trace = _make_risk_statement_with_trace(with_trace=True)
        without_trace = _make_risk_statement_with_trace(with_trace=False)
        ar = gap_report_to_oscal_ar(
            report,
            risk_statements_with_traces=[with_trace, without_trace],
        )
        resources = ar["assessment-results"]["back-matter"]["resources"]
        # Only the with_trace statement contributes.
        assert len(resources) == 1
        assert resources[0]["uuid"] == with_trace.id

    def test_back_matter_props_carry_evidentia_namespace(
        self,
    ) -> None:
        report = _make_minimal_gap_report()
        stmt = _make_risk_statement_with_trace(with_trace=True)
        ar = gap_report_to_oscal_ar(
            report, risk_statements_with_traces=[stmt]
        )
        resource = ar["assessment-results"]["back-matter"]["resources"][0]
        ns_props = [
            p
            for p in resource["props"]
            if p.get("ns") == "https://evidentia.dev/oscal"
        ]
        assert len(ns_props) >= 4
        names = {p["name"] for p in ns_props}
        assert "reasoning-trace-claim-count" in names
        assert "reasoning-trace-overall-confidence" in names
        assert "evidence-digest" in names

    def test_canonical_json_round_trips_via_base64(
        self,
    ) -> None:
        """The base64-embedded payload is the canonical trace JSON."""
        report = _make_minimal_gap_report()
        stmt = _make_risk_statement_with_trace(with_trace=True)
        ar = gap_report_to_oscal_ar(
            report, risk_statements_with_traces=[stmt]
        )
        resource = ar["assessment-results"]["back-matter"]["resources"][0]
        encoded = resource["base64"]["value"]
        decoded = base64.b64decode(encoded.encode("ascii"))
        round_tripped = ReasoningTrace.model_validate_json(decoded)
        # The trace embedded in the back-matter is byte-identical to
        # the original.
        assert round_tripped == stmt.reasoning_trace

    def test_evidence_digest_matches_canonical(self) -> None:
        """The evidence-digest prop matches SHA-256 of base64 payload."""
        import hashlib

        report = _make_minimal_gap_report()
        stmt = _make_risk_statement_with_trace(with_trace=True)
        ar = gap_report_to_oscal_ar(
            report, risk_statements_with_traces=[stmt]
        )
        resource = ar["assessment-results"]["back-matter"]["resources"][0]
        encoded = resource["base64"]["value"]
        decoded = base64.b64decode(encoded.encode("ascii"))
        recomputed_hex = hashlib.sha256(decoded).hexdigest()
        digest_props = [
            p
            for p in resource["props"]
            if p["name"] == "evidence-digest"
        ]
        assert digest_props[0]["value"] == f"sha256:{recomputed_hex}"


# ── 3. Trestle round-trip ─────────────────────────────────────────


class TestTrestleRoundTrip:
    """Verify the AR with reasoning traces survives a trestle parse.

    Trestle is a NIST-OSCAL reference implementation built on
    Pydantic v1 with strict ``Extra.forbid`` semantics. If our
    AR schema has any unknown fields trestle doesn't recognise,
    parsing fails. The Evidentia-namespaced props are accepted
    via OSCAL's standard extension mechanism (``ns`` field on
    props).
    """

    def test_ar_with_traces_parses_via_trestle(self) -> None:
        trestle_ar = pytest.importorskip(
            "trestle.oscal.assessment_results"
        )
        report = _make_minimal_gap_report()
        stmt = _make_risk_statement_with_trace(with_trace=True)
        ar = gap_report_to_oscal_ar(
            report, risk_statements_with_traces=[stmt]
        )
        # Trestle's root class is ``Model`` (the wrapper); use
        # parse_obj on the whole dict per the existing
        # tests/unit/test_oscal/test_trestle_conformance.py
        # convention.
        parsed = trestle_ar.Model.parse_obj(ar)
        # Trestle keeps back-matter under
        # parsed.assessment_results.back_matter.resources
        assert parsed.assessment_results.back_matter is not None
        assert (
            len(parsed.assessment_results.back_matter.resources)
            >= 1
        )
        # Trace resource carries the integrity prop.
        for resource in parsed.assessment_results.back_matter.resources:
            if "Policy Reasoning Trace" in (
                resource.description or ""
            ):
                # Confirmed the trace resource survives parsing.
                assert resource.props is not None
                names = {p.name for p in resource.props}
                assert "evidence-digest" in names
                break
        else:
            pytest.fail("No Policy Reasoning Trace resource found")
