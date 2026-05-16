"""Tests for :mod:`evidentia_collectors.github.dependabot` (v0.7.0)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from evidentia_collectors.github.dependabot import (
    COLLECTOR_ID,
    DEFAULT_DISMISSAL_POLICY,
    DependabotCollector,
    DependabotCollectorError,
    DismissalVerdict,
)
from evidentia_core.models.common import OLIRRelationship
from evidentia_core.models.finding import FindingStatus


def _make_alert(**overrides: Any) -> dict[str, Any]:
    """Build a Dependabot alert dict matching the GitHub REST API shape."""
    defaults: dict[str, Any] = {
        "number": 42,
        "state": "open",
        "dependency": {
            "package": {"ecosystem": "pip", "name": "requests"},
            "manifest_path": "requirements.txt",
            "scope": "runtime",
            "relationship": "direct",
        },
        "security_advisory": {
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "cve_id": "CVE-2025-12345",
            "summary": "Test vulnerability summary",
            "description": "Long form description",
            "severity": "high",
            "cvss_severities": {
                "cvss_v3": {"vector_string": "CVSS:3.1/AV:N", "score": 8.5},
                "cvss_v4": None,
            },
            "published_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-02T00:00:00Z",
            "withdrawn_at": None,
        },
        "security_vulnerability": {
            "package": {"ecosystem": "pip", "name": "requests"},
            "severity": "high",
            "vulnerable_version_range": "< 2.31.0",
            "first_patched_version": {"identifier": "2.31.0"},
        },
        "created_at": "2025-04-01T00:00:00Z",
        "updated_at": "2025-04-02T00:00:00Z",
        "dismissed_at": None,
        "dismissed_by": None,
        "dismissed_reason": None,
        "dismissed_comment": None,
        "fixed_at": None,
        "auto_dismissed_at": None,
        "url": "https://api.github.com/repos/polycentric-labs/evidentia/dependabot/alerts/42",
        "html_url": "https://github.com/polycentric-labs/evidentia/security/dependabot/42",
    }
    for key, value in overrides.items():
        defaults[key] = value
    return defaults


def _make_collector(
    *, alerts: list[dict[str, Any]] | None = None,
    fail_with: Exception | None = None,
    dismissal_policy: dict[str, DismissalVerdict] | None = None,
) -> DependabotCollector:
    """Build a collector with a mocked GitHub client."""
    client = MagicMock()
    if fail_with is not None:
        client.request.side_effect = fail_with
    else:
        # Simulate single page (less than per_page=100, so pagination stops).
        client.request.return_value = alerts or []

    return DependabotCollector(
        owner="polycentric-labs",
        repo="evidentia",
        client=client,
        dismissal_policy=dismissal_policy,
    )


# ── constructor ──────────────────────────────────────────────────────────


def test_constructor_rejects_empty_owner_or_repo() -> None:
    with pytest.raises(DependabotCollectorError, match="owner \\+ repo"):
        DependabotCollector(owner="", repo="evidentia", client=MagicMock())
    with pytest.raises(DependabotCollectorError, match="owner \\+ repo"):
        DependabotCollector(
            owner="polycentric-labs", repo="", client=MagicMock()
        )


def test_constructor_uses_default_dismissal_policy() -> None:
    collector = _make_collector()
    # Default: no_bandwidth and tolerable_risk treat_as_open; others resolved.
    assert (
        collector.dismissal_policy["no_bandwidth"]
        == DismissalVerdict.TREAT_AS_OPEN
    )
    assert (
        collector.dismissal_policy["tolerable_risk"]
        == DismissalVerdict.TREAT_AS_OPEN
    )
    assert (
        collector.dismissal_policy["fix_started"]
        == DismissalVerdict.TREAT_AS_RESOLVED
    )
    assert (
        collector.dismissal_policy["not_used"]
        == DismissalVerdict.TREAT_AS_RESOLVED
    )
    assert (
        collector.dismissal_policy["inaccurate"]
        == DismissalVerdict.TREAT_AS_RESOLVED
    )


def test_constructor_merges_policy_override_with_defaults() -> None:
    collector = _make_collector(
        dismissal_policy={
            "tolerable_risk": DismissalVerdict.TREAT_AS_RESOLVED,
        }
    )
    # Override applied.
    assert (
        collector.dismissal_policy["tolerable_risk"]
        == DismissalVerdict.TREAT_AS_RESOLVED
    )
    # Other defaults preserved.
    assert (
        collector.dismissal_policy["no_bandwidth"]
        == DismissalVerdict.TREAT_AS_OPEN
    )


# ── state → status mapping ───────────────────────────────────────────────


def test_open_alert_maps_to_active() -> None:
    collector = _make_collector(alerts=[_make_alert(state="open")])
    findings = collector.collect()
    assert findings[0].status == FindingStatus.ACTIVE


def test_fixed_alert_maps_to_resolved() -> None:
    collector = _make_collector(alerts=[_make_alert(state="fixed")])
    findings = collector.collect()
    assert findings[0].status == FindingStatus.RESOLVED


def test_auto_dismissed_alert_maps_to_resolved() -> None:
    """auto_dismissed means GitHub auto-closed (package removed / repo
    archived) — functionally resolved."""
    collector = _make_collector(
        alerts=[_make_alert(state="auto_dismissed")]
    )
    findings = collector.collect()
    assert findings[0].status == FindingStatus.RESOLVED


# ── dismissal policy (Tier 3) ────────────────────────────────────────────


@pytest.mark.parametrize(
    "reason, expected_status",
    [
        ("fix_started", FindingStatus.RESOLVED),
        ("inaccurate", FindingStatus.RESOLVED),
        ("no_bandwidth", FindingStatus.ACTIVE),   # auditor-default
        ("not_used", FindingStatus.RESOLVED),
        ("tolerable_risk", FindingStatus.ACTIVE),  # auditor-default
    ],
)
def test_default_dismissal_policy_classification(
    reason: str, expected_status: FindingStatus
) -> None:
    """Default policy matches the research-backed auditor interpretation:
    ``no_bandwidth`` and ``tolerable_risk`` surface to auditors as ACTIVE
    (POA&M-tracked gaps), others are RESOLVED."""
    collector = _make_collector(
        alerts=[_make_alert(state="dismissed", dismissed_reason=reason)]
    )
    findings = collector.collect()
    assert findings[0].status == expected_status


def test_policy_override_changes_dismissal_classification() -> None:
    """Operator can reclassify any dismissed_reason."""
    collector = _make_collector(
        alerts=[
            _make_alert(
                state="dismissed", dismissed_reason="tolerable_risk"
            ),
        ],
        dismissal_policy={
            "tolerable_risk": DismissalVerdict.TREAT_AS_RESOLVED,
        },
    )
    findings = collector.collect()
    # Override: tolerable_risk now treated as resolved.
    assert findings[0].status == FindingStatus.RESOLVED


def test_unknown_dismissed_reason_defaults_to_active() -> None:
    """Unknown dismissal_reason (future GitHub addition) defaults to
    ACTIVE — safer for audit visibility."""
    collector = _make_collector(
        alerts=[
            _make_alert(
                state="dismissed",
                dismissed_reason="future_reason_github_adds",
            ),
        ]
    )
    findings = collector.collect()
    assert findings[0].status == FindingStatus.ACTIVE


# ── control mappings ─────────────────────────────────────────────────────


def test_every_alert_carries_core_nist_and_ssdf_mappings() -> None:
    collector = _make_collector(alerts=[_make_alert()])
    finding = collector.collect()[0]
    control_ids = {m.control_id for m in finding.control_mappings}
    # NIST SP 800-53 Rev 5
    assert {"SI-2", "SI-5", "RA-5", "SR-3", "SR-11"}.issubset(control_ids)
    # NIST SP 800-218 SSDF
    assert {"PO.3", "PW.4", "RV.2"}.issubset(control_ids)


def test_si2_mapping_is_subset_of_with_ssdf_citation() -> None:
    collector = _make_collector(alerts=[_make_alert()])
    finding = collector.collect()[0]
    si2 = next(m for m in finding.control_mappings if m.control_id == "SI-2")
    assert si2.relationship == OLIRRelationship.SUBSET_OF
    # Authoritative justification cites GitHub SSDF guide.
    assert "SSDF" in si2.justification or "RV.2" in si2.justification


def test_ssdf_mappings_use_ssdf_framework_identifier() -> None:
    collector = _make_collector(alerts=[_make_alert()])
    finding = collector.collect()[0]
    ssdf_mappings = [
        m for m in finding.control_mappings
        if m.framework == "nist-sp-800-218-ssdf"
    ]
    assert len(ssdf_mappings) == 3  # PO.3, PW.4, RV.2
    assert {m.control_id for m in ssdf_mappings} == {"PO.3", "PW.4", "RV.2"}


def test_every_mapping_has_nonempty_justification() -> None:
    collector = _make_collector(alerts=[_make_alert()])
    finding = collector.collect()[0]
    for m in finding.control_mappings:
        assert m.justification, (
            f"Empty justification on Dependabot mapping to "
            f"{m.framework}:{m.control_id}"
        )


# ── severity mapping ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "advisory_severity, expected",
    [
        ("critical", "critical"),
        ("high", "high"),
        ("medium", "medium"),
        ("moderate", "medium"),  # legacy GitHub label
        ("low", "low"),
    ],
)
def test_severity_from_advisory(
    advisory_severity: str, expected: str
) -> None:
    alert = _make_alert()
    alert["security_advisory"]["severity"] = advisory_severity
    alert["security_vulnerability"]["severity"] = advisory_severity
    collector = _make_collector(alerts=[alert])
    assert collector.collect()[0].severity == expected


# ── filtering ────────────────────────────────────────────────────────────


def test_include_dismissed_false_skips_dismissed_alerts() -> None:
    alerts = [
        _make_alert(number=1, state="open"),
        _make_alert(
            number=2, state="dismissed", dismissed_reason="inaccurate"
        ),
    ]
    collector = _make_collector(alerts=alerts)
    findings = collector.collect(include_dismissed=False)
    assert len(findings) == 1
    assert findings[0].source_finding_id == "1"


def test_include_auto_dismissed_false_skips_auto_dismissed() -> None:
    alerts = [
        _make_alert(number=1, state="open"),
        _make_alert(number=2, state="auto_dismissed"),
    ]
    collector = _make_collector(alerts=alerts)
    findings = collector.collect(include_auto_dismissed=False)
    assert len(findings) == 1
    assert findings[0].source_finding_id == "1"


# ── manifest + provenance ────────────────────────────────────────────────


def test_collect_v2_returns_findings_and_manifest() -> None:
    collector = _make_collector(alerts=[_make_alert()])
    findings, manifest = collector.collect_v2()
    assert len(findings) == 1
    assert manifest.run_id
    assert manifest.collector_id == COLLECTOR_ID
    assert manifest.is_complete


def test_manifest_counts_by_state_coverage() -> None:
    alerts = [
        _make_alert(number=1, state="open"),
        _make_alert(number=2, state="open"),
        _make_alert(number=3, state="fixed"),
    ]
    collector = _make_collector(alerts=alerts)
    _, manifest = collector.collect_v2()
    # Coverage counts include per-state breakdown.
    resource_types = {c.resource_type for c in manifest.coverage_counts}
    assert "github-dependabot-alert-open" in resource_types
    assert "github-dependabot-alert-fixed" in resource_types


def test_manifest_empty_set_attestation_when_no_alerts() -> None:
    collector = _make_collector(alerts=[])
    _, manifest = collector.collect_v2()
    assert "github-dependabot-alerts" in manifest.empty_categories


def test_collection_context_populated_on_findings() -> None:
    collector = _make_collector(alerts=[_make_alert()])
    findings, manifest = collector.collect_v2()
    ctx = findings[0].collection_context
    assert ctx.collector_id == COLLECTOR_ID
    assert ctx.run_id == manifest.run_id
    assert "polycentric-labs/evidentia" in ctx.source_system_id
    # Dismissal policy captured in filter_applied for audit traceability.
    assert "dismissal_policy" in ctx.filter_applied


# ── error handling ───────────────────────────────────────────────────────


def test_collect_v2_captures_exception_in_manifest() -> None:
    collector = _make_collector(fail_with=RuntimeError("API down"))
    findings, manifest = collector.collect_v2()
    assert findings == []
    assert not manifest.is_complete
    assert "API down" in (manifest.incomplete_reason or "")


# ── finding fields ───────────────────────────────────────────────────────


def test_finding_title_includes_ghsa_and_package_name() -> None:
    alert = _make_alert()
    alert["security_advisory"]["ghsa_id"] = "GHSA-abc1-def2-ghi3"
    alert["dependency"]["package"]["name"] = "requests"
    collector = _make_collector(alerts=[alert])
    finding = collector.collect()[0]
    assert "GHSA-abc1-def2-ghi3" in finding.title


def test_finding_description_includes_cvss_score() -> None:
    alert = _make_alert()
    alert["security_advisory"]["cvss_severities"]["cvss_v3"]["score"] = 9.8
    collector = _make_collector(alerts=[alert])
    finding = collector.collect()[0]
    assert "9.8" in finding.description


def test_finding_description_includes_dismissal_reason_when_dismissed() -> None:
    alert = _make_alert(
        state="dismissed", dismissed_reason="tolerable_risk"
    )
    collector = _make_collector(alerts=[alert])
    finding = collector.collect()[0]
    assert "tolerable_risk" in finding.description


def test_dry_run_returns_empty_without_api_calls() -> None:
    client = MagicMock()
    collector = DependabotCollector(
        owner="polycentric-labs", repo="evidentia", client=client,
    )
    findings = collector.collect(dry_run=True)
    assert findings == []
    client.request.assert_not_called()


# ── default policy sanity check ──────────────────────────────────────────


def test_default_dismissal_policy_keys_match_github_spec() -> None:
    """GitHub's dismissed_reason enum (per 2025 API docs) must be
    fully represented in our default policy."""
    github_reasons = {
        "fix_started",
        "inaccurate",
        "no_bandwidth",
        "not_used",
        "tolerable_risk",
    }
    assert set(DEFAULT_DISMISSAL_POLICY.keys()) == github_reasons
