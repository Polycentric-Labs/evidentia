"""Generate NYDFS Part 500 headings with scoped amendment transition metadata."""

from pathlib import Path

from _generators import emit_control_catalog

SOURCE = "https://www.dfs.ny.gov/cybersecurity/23-NYCRR-Part-500"

ROWS = [
    ("500.2", "Cybersecurity program", "Program Requirements"),
    ("500.3", "Cybersecurity policy", "Program Requirements"),
    ("500.4(a)", "Chief Information Security Officer (CISO)", "Governance"),
    ("500.4(b)", "CISO report to the senior governing body", "Governance"),
    ("500.4(c)", "CISO reporting of material cybersecurity issues", "Governance"),
    ("500.4(d)", "Senior governing body oversight", "Governance"),
    ("500.5", "Vulnerability management", "Program Requirements"),
    ("500.6", "Audit trail", "Program Requirements"),
    ("500.7", "Access privileges and management", "Access Controls"),
    ("500.8", "Application security", "Program Requirements"),
    ("500.9", "Risk assessment", "Program Requirements"),
    ("500.10", "Cybersecurity personnel and intelligence", "Governance"),
    ("500.11", "Third-party service provider security policy", "Third-Party"),
    ("500.12", "Multi-factor authentication", "Access Controls"),
    ("500.13", "Asset management and data retention requirements", "Program Requirements"),
    ("500.14(a)", "Monitoring, malicious-code protection and cybersecurity awareness training", "Program Requirements"),
    ("500.14(b)", "Class A endpoint detection and response and centralized logging", "Program Requirements"),
    ("500.15", "Encryption of nonpublic information", "Data Protection"),
    ("500.16", "Incident response and business continuity management", "Incident Response"),
    ("500.17(a)", "Notice of cybersecurity incident", "Incident Response"),
    ("500.17(b)", "Notice of compliance", "Governance"),
    ("500.17(c)", "Notice and explanation of extortion payment", "Incident Response"),
    ("500.18", "Confidentiality", "Program Requirements"),
    ("500.19", "Exemptions", "General"),
    ("500.20", "Enforcement", "General"),
    ("500.21", "Effective date", "General"),
    ("500.22", "Transitional periods", "General"),
    ("500.23", "Severability", "General"),
    ("500.24", "Exemptions from electronic filing and submission requirements", "General"),
]


def main() -> Path:
    """Keep the heading scope while distinguishing transition and ongoing deadlines."""
    controls = [{"id": key, "title": title, "description": title, "family": family} for key, title, family in ROWS]
    by_id = {c["id"]: c for c in controls}
    by_id["500.21"]["properties"] = {"amendment_effective_on": "2023-11-01"}
    by_id["500.22"]["properties"] = {"last_amendment_transition_on": "2025-11-01"}
    return emit_control_catalog(
        framework_id="ny-dfs-500",
        framework_name="NY DFS 23 NYCRR Part 500 - Cybersecurity Requirements",
        version="Second Amendment (2023-11-01); transitions completed 2025-11-01",
        source=SOURCE,
        families=list(dict.fromkeys(row[2] for row in ROWS)),
        controls=controls,
        tier="D",
        subdir="us-federal",
        status="current",
        verified_on="2026-09-09",
        license_terms="New York regulation; heading-only catalog with links to the issuing authority.",
        notes=(
            "Section headings and selected subsection summaries, not full regulatory text or every "
            "clause. The 2023 Second Amendment became effective on 2023-11-01. Its final scheduled "
            "transition periods ended 2025-11-01. This does not end ongoing entity-specific "
            "periods: section 500.19(h), for example, allows 180 days after loss of an exemption. "
            "Applicability depends on covered-entity status and exemptions. This heading catalog "
            "does not assess those conditions. DFS labels its linked formatted text as a "
            "convenience copy rather than the official version. Recheck prior evidence attached to "
            "500.4(c)/(d), 500.14(b), 500.16 and 500.17(a)/(b)/(c): earlier bundled headings "
            "misidentified their subjects. Section 500.24 is now included. No automatic "
            "evidence migration or applicability determination is performed."
        ),
    )


if __name__ == "__main__":
    print(main())
