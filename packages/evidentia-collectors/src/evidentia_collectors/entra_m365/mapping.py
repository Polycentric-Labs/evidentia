"""Authored observation mappings with no runtime catalog lookup."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from evidentia_core.models.common import ControlMapping, OLIRRelationship

FindingRule = Literal[
    "conditional-access-policy",
    "authentication-registration-summary",
    "sign-in-observation",
    "directory-role-inventory",
    "managed-device-state",
    "retention-label-configuration",
    "dlp-policy-configuration",
    "dlp-unresolved-rule",
    "defender-alert-observation",
    "defender-incident-observation",
]

FRAMEWORK = "nist-800-53-rev5"


@dataclass(frozen=True, slots=True)
class RuleSpec:
    """Immutable authored rule metadata for the shared finding factory."""

    rule: FindingRule
    capability: str
    source_suffix: str
    resource_type: str
    title: str
    description: str
    control_ids: tuple[str, ...]
    relationship: OLIRRelationship
    justification: str


_RULES: tuple[RuleSpec, ...] = (
    RuleSpec(
        rule="conditional-access-policy",
        capability="conditional-access",
        source_suffix="conditional-access:{source_id}",
        resource_type="MicrosoftEntra::ConditionalAccessPolicy",
        title="Conditional Access policy configuration",
        description=(
            "Observed access-policy configuration. Effective identity and application coverage is not established."
        ),
        control_ids=("AC-3", "IA-2"),
        relationship=OLIRRelationship.INTERSECTS_WITH,
        justification=(
            "observed access-policy configuration does not establish effective identity/application coverage."
        ),
    ),
    RuleSpec(
        rule="authentication-registration-summary",
        capability="authentication-registration",
        source_suffix="authentication-registration:summary",
        resource_type="MicrosoftEntra::AuthenticationRegistrationSummary",
        title="Authentication registration and capability summary",
        description=(
            "Observed registration and capability flags for the returned report population. "
            "Disabled accounts are excluded; registration does not establish enforcement."
        ),
        control_ids=("IA-2", "IA-5"),
        relationship=OLIRRelationship.INTERSECTS_WITH,
        justification=(
            "observed registration/capability flags cover part of authentication evidence "
            "and exclude disabled accounts."
        ),
    ),
    RuleSpec(
        rule="sign-in-observation",
        capability="sign-ins",
        source_suffix="sign-ins:{source_id}",
        resource_type="MicrosoftEntra::SignIn",
        title="Sign-in event observation",
        description="Observed sign-in event in the requested window. Review and complete history are not established.",
        control_ids=("AU-6", "SI-4"),
        relationship=OLIRRelationship.INTERSECTS_WITH,
        justification="the event is monitoring input, not proof of review or complete history.",
    ),
    RuleSpec(
        rule="directory-role-inventory",
        capability="directory-roles",
        source_suffix="directory-roles:{source_id}",
        resource_type="MicrosoftEntra::DirectoryRole",
        title="Activated directory role inventory",
        description="Observed activated directory role. Assignments, membership and eligibility are not enumerated.",
        control_ids=("AC-2", "AC-6"),
        relationship=OLIRRelationship.INTERSECTS_WITH,
        justification="role inventory does not enumerate assignments or eligibility.",
    ),
    RuleSpec(
        rule="managed-device-state",
        capability="managed-devices",
        source_suffix="managed-devices:{source_id}",
        resource_type="MicrosoftIntune::ManagedDevice",
        title="Managed device state observation",
        description="Observed Intune device-management state with source scope limits.",
        control_ids=("CM-8", "CA-7"),
        relationship=OLIRRelationship.INTERSECTS_WITH,
        justification="Intune state is observed device-management evidence with source scope limits.",
    ),
    RuleSpec(
        rule="retention-label-configuration",
        capability="retention-labels",
        source_suffix="retention-labels:{source_id}",
        resource_type="MicrosoftPurview::RetentionLabel",
        title="Retention label configuration",
        description=(
            "Observed retention label configuration. Record-set completeness and item application are not established."
        ),
        control_ids=("SI-12",),
        relationship=OLIRRelationship.INTERSECTS_WITH,
        justification="label configuration does not establish record-set completeness or item application.",
    ),
    RuleSpec(
        rule="dlp-policy-configuration",
        capability="dlp-export",
        source_suffix="dlp-export:policy:{source_id}",
        resource_type="MicrosoftPurview::DlpPolicy",
        title="DLP policy configuration",
        description=(
            "Observed policy configuration and selected linked rule states. "
            "Effective content enforcement is not established."
        ),
        control_ids=("AC-4", "SI-4"),
        relationship=OLIRRelationship.INTERSECTS_WITH,
        justification="configuration state does not establish effective content enforcement.",
    ),
    RuleSpec(
        rule="dlp-unresolved-rule",
        capability="dlp-export",
        source_suffix="dlp-export:unresolved-rule:{source_id}",
        resource_type="MicrosoftPurview::DlpRule",
        title="DLP rule with unresolved parent policy",
        description="Observed DLP rule with an orphaned or conflicting parent. Its policy scope remains unresolved.",
        control_ids=("AC-4",),
        relationship=OLIRRelationship.RELATED_TO,
        justification="an unresolved parent prevents interpreting the rule's policy scope.",
    ),
    RuleSpec(
        rule="defender-alert-observation",
        capability="defender-alerts",
        source_suffix="defender-alerts:{source_id}",
        resource_type="MicrosoftDefender::Alert",
        title="Defender alert observation",
        description=(
            "Observed alert metadata. Endpoint-protection deployment and response completion are not established."
        ),
        control_ids=("SI-4", "IR-5"),
        relationship=OLIRRelationship.INTERSECTS_WITH,
        justification=(
            "observed alert metadata does not establish endpoint-protection deployment or response completion."
        ),
    ),
    RuleSpec(
        rule="defender-incident-observation",
        capability="defender-incidents",
        source_suffix="defender-incidents:{source_id}",
        resource_type="MicrosoftDefender::Incident",
        title="Defender incident observation",
        description="Source-reported incident state. A validated human determination is not established.",
        control_ids=("IR-4", "IR-5"),
        relationship=OLIRRelationship.INTERSECTS_WITH,
        justification="incident state is source-reported operational evidence, not a validated human determination.",
    ),
)


def rule_specs() -> tuple[RuleSpec, ...]:
    """Return the immutable rule inventory in approved order."""
    return _RULES


def get_rule(rule: FindingRule) -> RuleSpec:
    """Look up one exact rule without interpreting arbitrary source strings."""
    for spec in _RULES:
        if spec.rule == rule:
            return spec
    raise ValueError("Unknown finding rule")


def control_mappings(rule: FindingRule) -> list[ControlMapping]:
    """Construct fresh core mappings so caller mutations cannot persist."""
    spec = get_rule(rule)
    return [
        ControlMapping(
            framework=FRAMEWORK,
            control_id=control,
            relationship=spec.relationship,
            justification=spec.justification,
        )
        for control in spec.control_ids
    ]
