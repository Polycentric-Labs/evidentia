"""NIST 800-53 + OCC 2013-29 + FFIEC mappings for the BitSight collector.

BitSight's portfolio inventory + per-company rating maps to the same
core SR-2 / SR-3 / SR-6 + OCC §III.A + FRB SR 13-19 + FFIEC IT
Examination Handbook Outsourcing booklet stack as the Vanta + Drata
collectors. The low-rating finding adds an RA-3 + OCC §III.A.4
ongoing-monitoring overlay specific to security-ratings providers.
"""

from __future__ import annotations

from evidentia_core.models.common import ControlMapping, OLIRRelationship

# BitSight portfolio company finding — captures that a vendor
# company is being externally rated by BitSight on the operator's
# behalf.
PORTFOLIO_INVENTORY_MAPPINGS: list[ControlMapping] = [
    ControlMapping(
        framework="nist-800-53-rev5",
        control_id="SR-2",
        control_title="Supply Chain Risk Management Plan",
        relationship=OLIRRelationship.SUBSET_OF,
        justification=(
            "An itemized portfolio of BitSight-rated third-party "
            "companies with risk attributes is one of the SR-2 "
            "plan artifacts."
        ),
    ),
    ControlMapping(
        framework="nist-800-53-rev5",
        control_id="SR-3",
        control_title="Supply Chain Controls and Processes",
        relationship=OLIRRelationship.SUBSET_OF,
        justification=(
            "Portfolio metadata + per-company rating attribution "
            "evidences the SR-3 process for monitoring third-party "
            "supply-chain relationships."
        ),
    ),
    ControlMapping(
        framework="nist-800-53-rev5",
        control_id="SR-6",
        control_title="Supplier Assessments and Reviews",
        relationship=OLIRRelationship.RELATED_TO,
        justification=(
            "BitSight portfolio entries carry continuously-refreshed "
            "external-attack-surface ratings; that evidence supports "
            "SR-6 review-cadence claims."
        ),
    ),
    ControlMapping(
        framework="occ-2013-29",
        control_id="III.A",
        control_title=(
            "Risk Management — Planning, Due Diligence, Contract Negotiation, Ongoing Monitoring, Termination"
        ),
        relationship=OLIRRelationship.SUBSET_OF,
        justification=(
            "OCC Bulletin 2013-29 expects banks to maintain a "
            "comprehensive third-party risk view. BitSight's "
            "portfolio rating directly addresses ongoing-monitoring "
            "expectations."
        ),
    ),
    ControlMapping(
        framework="frb-sr-13-19",
        control_id="II",
        control_title="Vendor Risk Management Program Elements",
        relationship=OLIRRelationship.SUBSET_OF,
        justification=(
            "FRB SR 13-19 §II expects a risk-tiered vendor inventory; "
            "BitSight's continuous-rating portfolio is one of the "
            "industry-standard inputs."
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
            "third-party relationships; BitSight rating data is the "
            "canonical industry security-posture input."
        ),
    ),
]


# Vendor company with a BitSight rating BELOW the operator-
# configured threshold — operator should review the underlying
# attack-surface findings.
LOW_RATING_MAPPINGS: list[ControlMapping] = [
    ControlMapping(
        framework="nist-800-53-rev5",
        control_id="RA-3",
        control_title="Risk Assessment",
        relationship=OLIRRelationship.SUBSET_OF,
        justification=(
            "A BitSight rating below the operator-configured "
            "threshold represents an external-evidence risk "
            "assessment whose outcome warrants operator review."
        ),
    ),
    ControlMapping(
        framework="nist-800-53-rev5",
        control_id="CA-7",
        control_title="Continuous Monitoring",
        relationship=OLIRRelationship.SUBSET_OF,
        justification=(
            "BitSight's continuous-rating model satisfies CA-7's "
            "continuous-monitoring expectation for third-party "
            "risk. A low-rating signal triggers the CA-7 review "
            "cycle."
        ),
    ),
    ControlMapping(
        framework="occ-2013-29",
        control_id="III.A.4",
        control_title="Ongoing Monitoring",
        relationship=OLIRRelationship.SUBSET_OF,
        justification=(
            "OCC 2013-29 §III.A.4 expects ongoing monitoring of "
            "third-party risk; BitSight low-rating-flagged "
            "companies are the monitoring priority list."
        ),
    ),
    ControlMapping(
        framework="frb-sr-13-19",
        control_id="II.D",
        control_title="Ongoing Monitoring",
        relationship=OLIRRelationship.SUBSET_OF,
        justification=("Same ongoing-monitoring expectation as OCC 2013-29 §III.A.4 from the FRB framing."),
    ),
]
