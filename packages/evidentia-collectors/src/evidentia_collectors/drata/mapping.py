"""NIST 800-53 + OCC 2013-29 + FFIEC mappings for the Drata collector.

Each mapping list represents the controls a particular Drata-derived
finding satisfies. Mirrors the per-evidence-source mapping pattern
from `evidentia_collectors.{vanta,okta,databricks,snowflake}`.

The OCC Bulletin 2013-29 + FRB SR 13-19 references attach to
vendor-inventory and ongoing-monitoring evidence specifically — the
banking-supervisor framing for third-party-risk programs.
"""

from __future__ import annotations

from evidentia_core.models.common import ControlMapping, OLIRRelationship

# Drata vendor-inventory finding — captures that a vendor record
# exists in the operator's Drata workspace; Evidentia surfaces it
# in the cross-framework evidence chain.
VENDOR_INVENTORY_MAPPINGS: list[ControlMapping] = [
    ControlMapping(
        framework="nist-800-53-rev5",
        control_id="SR-2",
        control_title="Supply Chain Risk Management Plan",
        relationship=OLIRRelationship.SUBSET_OF,
        justification=(
            "An itemized inventory of third-party vendors with risk "
            "attributes is one of the SR-2 plan artifacts."
        ),
    ),
    ControlMapping(
        framework="nist-800-53-rev5",
        control_id="SR-3",
        control_title="Supply Chain Controls and Processes",
        relationship=OLIRRelationship.SUBSET_OF,
        justification=(
            "Per-vendor metadata + relationship-owner attribution "
            "evidences the SR-3 process for controlling third-party "
            "supply-chain relationships."
        ),
    ),
    ControlMapping(
        framework="nist-800-53-rev5",
        control_id="SR-6",
        control_title="Supplier Assessments and Reviews",
        relationship=OLIRRelationship.RELATED_TO,
        justification=(
            "Drata's vendor records typically carry the latest "
            "assessment date + ongoing-monitoring posture; that "
            "evidence supports SR-6 review-cadence claims."
        ),
    ),
    ControlMapping(
        framework="occ-2013-29",
        control_id="III.A",
        control_title=(
            "Risk Management — Planning, Due Diligence, "
            "Contract Negotiation, Ongoing Monitoring, Termination"
        ),
        relationship=OLIRRelationship.SUBSET_OF,
        justification=(
            "OCC Bulletin 2013-29 expects banks to maintain a "
            "comprehensive third-party inventory with risk "
            "categorization. The Drata vendor inventory directly "
            "addresses this expectation."
        ),
    ),
    ControlMapping(
        framework="frb-sr-13-19",
        control_id="II",
        control_title="Vendor Risk Management Program Elements",
        relationship=OLIRRelationship.SUBSET_OF,
        justification=(
            "FRB SR 13-19 §II expects a risk-tiered vendor inventory "
            "as a core program element. Drata-disclosed vendors "
            "feed the inventory."
        ),
    ),
    ControlMapping(
        framework="ffiec-it-handbook-outsourcing",
        control_id="OUT.II",
        control_title="Risk Management Process",
        relationship=OLIRRelationship.RELATED_TO,
        justification=(
            "FFIEC IT Examination Handbook Outsourcing booklet §II "
            "covers the structured risk management process for "
            "third-party relationships; vendor inventory is the "
            "starting input."
        ),
    ),
]


# Vendor with at-rest risk-attribute data marked HIGH-or-CRITICAL by
# Drata — operator should review the underlying control gaps.
VENDOR_HIGH_RISK_MAPPINGS: list[ControlMapping] = [
    ControlMapping(
        framework="nist-800-53-rev5",
        control_id="RA-3",
        control_title="Risk Assessment",
        relationship=OLIRRelationship.SUBSET_OF,
        justification=(
            "A high-risk vendor flag in Drata represents a "
            "completed risk assessment whose outcome warrants "
            "operator review."
        ),
    ),
    ControlMapping(
        framework="occ-2013-29",
        control_id="III.A.4",
        control_title="Ongoing Monitoring",
        relationship=OLIRRelationship.SUBSET_OF,
        justification=(
            "OCC 2013-29 §III.A.4 expects ongoing monitoring of "
            "third-party risk; high-risk-flagged vendors are the "
            "monitoring priority list."
        ),
    ),
    ControlMapping(
        framework="frb-sr-13-19",
        control_id="II.D",
        control_title="Ongoing Monitoring",
        relationship=OLIRRelationship.SUBSET_OF,
        justification=(
            "Same ongoing-monitoring expectation as OCC 2013-29 "
            "§III.A.4 from the FRB framing."
        ),
    ),
]
