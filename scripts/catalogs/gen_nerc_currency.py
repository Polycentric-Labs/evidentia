"""Generate a dated US NERC CIP heading catalog and separate publication notices.

The NERC index supplies designators, headings and standard applicability dates.
FERC's published orders supply approval, publication and order-effective dates.
Requirement text and glossary definitions are excluded pending permission.
"""

from pathlib import Path

from _generators import emit_control_catalog

INDEX = "https://www.nerc.com/standards/reliability-standards/cip"
TERMS = "https://www.nerc.com/legal-privacy-policy"
ORDER_919 = "https://www.govinfo.gov/content/pkg/FR-2026-03-24/pdf/2026-05716.pdf"
ORDER_918 = "https://www.govinfo.gov/content/pkg/FR-2026-03-24/pdf/2026-05711.pdf"
ORDER_907 = "https://www.govinfo.gov/content/pkg/FR-2025-07-02/pdf/2025-12309.pdf"
ORDER_002_8 = "https://www.govinfo.gov/content/pkg/FR-2026-03-24/pdf/2026-05715.pdf"

CURRENT = [
    ("CIP-002-5.1a", "Cyber Security - BES Cyber System Categorization", "Categorization", "2016-12-27"),
    ("CIP-003-9", "Cyber Security - Security Management Controls", "Governance", "2026-04-01"),
    ("CIP-004-7", "Cyber Security - Personnel & Training", "Personnel", "2024-01-01"),
    ("CIP-005-7", "Cyber Security - Electronic Security Perimeter(s)", "Access Controls", "2022-10-01"),
    ("CIP-006-6", "Cyber Security - Physical Security of BES Cyber Systems", "Physical Security", "2016-07-01"),
    ("CIP-007-6", "Cyber Security - System Security Management", "System Security", "2016-07-01"),
    ("CIP-008-6", "Cyber Security - Incident Reporting and Response Planning", "Incident Response", "2021-01-01"),
    ("CIP-009-6", "Cyber Security - Recovery Plans for BES Cyber Systems", "Recovery", "2016-07-01"),
    (
        "CIP-010-4",
        "Cyber Security - Configuration Change Management and Vulnerability Assessments",
        "Configuration",
        "2022-10-01",
    ),
    ("CIP-011-3", "Cyber Security - Information Protection", "Information Protection", "2024-01-01"),
    ("CIP-012-2", "Cyber Security - Communications between Control Centers", "Communications", "2026-07-01"),
    ("CIP-013-2", "Cyber Security - Supply Chain Risk Management", "Supply Chain", "2022-10-01"),
    ("CIP-014-3", "Physical Security", "Physical Security", "2022-06-16"),
]


def publication_notices() -> list[dict]:
    """Return facts about announced revisions without making them controls."""
    titles = {row[0][:7]: row[1] for row in CURRENT}
    notices = []
    for designator in (
        "CIP-002-7",
        "CIP-003-10",
        "CIP-004-8",
        "CIP-005-8",
        "CIP-006-7.1",
        "CIP-007-7.1",
        "CIP-008-7.1",
        "CIP-009-7.1",
        "CIP-010-5",
        "CIP-011-4.1",
        "CIP-013-3",
    ):
        notices.append(
            {
                "id": designator,
                "title": titles[designator[:7]],
                "status": "approved-future",
                "source_url": ORDER_919,
                "approved_on": "2026-03-19",
                "published_on": "2026-03-24",
                "order_effective_on": "2026-05-26",
                "effective_on": "2028-07-01",
                "notes": (
                    "US applicability from the NERC CIP index, verified 2026-09-09. Order 919 permits "
                    "notified early adoption; this catalog does not select it."
                ),
            }
        )
    notices[0].update(
        {
            "status": "approved-superseded",
            "superseded_by": "CIP-002-8",
            "notes": (
                "Approval history only: CIP-002-8 supersedes this revision. NERC's CIP-002-7 page "
                "gives an inconsistent order-effective date; the Federal Register supplies 2026-05-26."
            ),
        }
    )
    notices[1].update({"inactive_on": "2029-06-30", "superseded_by": "CIP-003-11"})
    notices.extend(
        [
            {
                "id": "CIP-002-8",
                "title": titles["CIP-002"],
                "status": "approved-future",
                "source_url": ORDER_002_8,
                "approved_on": "2026-03-19",
                "published_on": "2026-03-24",
                "order_effective_on": "2026-05-26",
                "effective_on": "2028-07-01",
                "notes": "Separate RD25-8-000 approval; supersedes CIP-002-7. US date from the NERC CIP index.",
            },
            {
                "id": "CIP-003-11",
                "title": titles["CIP-003"],
                "status": "approved-future",
                "source_url": ORDER_918,
                "approved_on": "2026-03-19",
                "published_on": "2026-03-24",
                "order_effective_on": "2026-05-26",
                "effective_on": "2029-07-01",
                "notes": "Approved by Order 918, separately from Order 919. Supersedes CIP-003-10 at implementation.",
            },
            {
                "id": "CIP-015-1",
                "title": "Cyber Security - Internal Network Security Monitoring",
                "status": "approved-future",
                "source_url": ORDER_907,
                "approved_on": "2025-06-26",
                "published_on": "2025-07-02",
                "order_effective_on": "2025-09-02",
                "effective_on": "2028-10-01",
                "inactive_on": "2029-09-30",
                "superseded_by": "CIP-015-2",
                "notes": "US dates from the NERC CIP-015-1 page. The successor preserves earlier duties.",
            },
            {
                "id": "CIP-015-2",
                "title": "Cyber Security - Internal Network Security Monitoring",
                "status": "approved-future",
                "source_url": INDEX + "/cip-015-2",
                "approved_on": "2026-08-10",
                "order_effective_on": "2026-08-10",
                "effective_on": "2029-10-01",
                "notes": (
                    "FERC RD26-6-000 approval, accession 20260810-3047. No separate Federal Register "
                    "publication date verified. Additional scope phases apply on 2030-10-01 and "
                    "2031-10-01; consult the implementation plan for affected systems."
                ),
            },
            {
                "id": "CIP-014-4",
                "title": "Physical Security",
                "status": "pending",
                "source_url": INDEX + "/cip-014-4",
                "notes": "Filed 2026-07-16 in RD26-9-000; NERC still lists pending regulatory approval on 2026-09-09.",
            },
        ]
    )
    return notices


def main() -> Path:
    """Write only the NERC catalog, retaining its established file and framework handle."""
    return emit_control_catalog(
        framework_id="nerc-cip-v7",
        framework_name="NERC CIP - US enforced standards (heading catalog)",
        version="US enforcement snapshot 2026-09-09",
        source=INDEX,
        families=list(dict.fromkeys(row[2] for row in CURRENT)),
        controls=[
            {
                "id": designator,
                "title": title,
                "description": "",
                "family": family,
                "tier": "C",
                "placeholder": True,
                "license_required": True,
                "license_url": TERMS,
                "properties": {
                    "jurisdiction": "US",
                    "effective_on": effective,
                    "source_url": INDEX + "/" + designator.lower(),
                },
            }
            for designator, title, family, effective in CURRENT
        ],
        tier="C",
        subdir="us-federal",
        placeholder=True,
        license_required=True,
        license_terms=(
            "NERC copyrighted material. IDs, short headings and factual dates only; authoritative "
            "requirements require separate permission."
        ),
        license_url=TERMS,
        status="current",
        verified_on="2026-09-09",
        notes=(
            "13 standards currently subject to US enforcement as verified on 2026-09-09. The "
            "legacy framework handle does not name a uniform v7 suite. Requirement text and "
            "glossary definitions are excluded pending permission. Approved future revisions are "
            "separate notices and do not enter assessment totals. Canadian jurisdictions and "
            "requirement-specific phase-ins need separate scoping; nothing activates automatically"
            " as dates pass."
        ),
        publication_notices=publication_notices(),
    )


if __name__ == "__main__":
    print(main())
