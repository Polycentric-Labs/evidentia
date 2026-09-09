"""Generate US regulatory and related catalog references.

Federal agency works, New York regulation and NERC material have different
redistribution terms. Each emitted catalog declares its own tier and scope.
NERC includes headings and factual publication notices only, pending text permission.
"""

from __future__ import annotations

from _generators import emit_control_catalog  # type: ignore[import-not-found]


# ---------------------------------------------------------------------------
# HIPAA Security Rule (45 CFR 164 Subpart C)
# ---------------------------------------------------------------------------

HIPAA_SECURITY = [
    ("164.308(a)(1)(i)", "Security Management Process — Standard", "Administrative Safeguards"),
    ("164.308(a)(1)(ii)(A)", "Risk Analysis", "Administrative Safeguards"),
    ("164.308(a)(1)(ii)(B)", "Risk Management", "Administrative Safeguards"),
    ("164.308(a)(1)(ii)(C)", "Sanction Policy", "Administrative Safeguards"),
    ("164.308(a)(1)(ii)(D)", "Information System Activity Review", "Administrative Safeguards"),
    ("164.308(a)(2)", "Assigned Security Responsibility", "Administrative Safeguards"),
    ("164.308(a)(3)(i)", "Workforce Security — Standard", "Administrative Safeguards"),
    ("164.308(a)(3)(ii)(A)", "Authorization and/or Supervision", "Administrative Safeguards"),
    ("164.308(a)(3)(ii)(B)", "Workforce Clearance Procedure", "Administrative Safeguards"),
    ("164.308(a)(3)(ii)(C)", "Termination Procedures", "Administrative Safeguards"),
    ("164.308(a)(4)(i)", "Information Access Management — Standard", "Administrative Safeguards"),
    ("164.308(a)(4)(ii)(A)", "Isolating Health Care Clearinghouse Function", "Administrative Safeguards"),
    ("164.308(a)(4)(ii)(B)", "Access Authorization", "Administrative Safeguards"),
    ("164.308(a)(4)(ii)(C)", "Access Establishment and Modification", "Administrative Safeguards"),
    ("164.308(a)(5)(i)", "Security Awareness and Training — Standard", "Administrative Safeguards"),
    ("164.308(a)(5)(ii)(A)", "Security Reminders", "Administrative Safeguards"),
    ("164.308(a)(5)(ii)(B)", "Protection from Malicious Software", "Administrative Safeguards"),
    ("164.308(a)(5)(ii)(C)", "Log-in Monitoring", "Administrative Safeguards"),
    ("164.308(a)(5)(ii)(D)", "Password Management", "Administrative Safeguards"),
    ("164.308(a)(6)(i)", "Security Incident Procedures — Standard", "Administrative Safeguards"),
    ("164.308(a)(6)(ii)", "Response and Reporting", "Administrative Safeguards"),
    ("164.308(a)(7)(i)", "Contingency Plan — Standard", "Administrative Safeguards"),
    ("164.308(a)(7)(ii)(A)", "Data Backup Plan", "Administrative Safeguards"),
    ("164.308(a)(7)(ii)(B)", "Disaster Recovery Plan", "Administrative Safeguards"),
    ("164.308(a)(7)(ii)(C)", "Emergency Mode Operation Plan", "Administrative Safeguards"),
    ("164.308(a)(7)(ii)(D)", "Testing and Revision Procedures", "Administrative Safeguards"),
    ("164.308(a)(7)(ii)(E)", "Applications and Data Criticality Analysis", "Administrative Safeguards"),
    ("164.308(a)(8)", "Evaluation", "Administrative Safeguards"),
    ("164.308(b)(1)", "Business Associate Contracts and Other Arrangements", "Administrative Safeguards"),
    ("164.310(a)(1)", "Facility Access Controls — Standard", "Physical Safeguards"),
    ("164.310(a)(2)(i)", "Contingency Operations", "Physical Safeguards"),
    ("164.310(a)(2)(ii)", "Facility Security Plan", "Physical Safeguards"),
    ("164.310(a)(2)(iii)", "Access Control and Validation Procedures", "Physical Safeguards"),
    ("164.310(a)(2)(iv)", "Maintenance Records", "Physical Safeguards"),
    ("164.310(b)", "Workstation Use", "Physical Safeguards"),
    ("164.310(c)", "Workstation Security", "Physical Safeguards"),
    ("164.310(d)(1)", "Device and Media Controls — Standard", "Physical Safeguards"),
    ("164.310(d)(2)(i)", "Disposal", "Physical Safeguards"),
    ("164.310(d)(2)(ii)", "Media Re-use", "Physical Safeguards"),
    ("164.310(d)(2)(iii)", "Accountability", "Physical Safeguards"),
    ("164.310(d)(2)(iv)", "Data Backup and Storage", "Physical Safeguards"),
    ("164.312(a)(1)", "Access Control — Standard", "Technical Safeguards"),
    ("164.312(a)(2)(i)", "Unique User Identification", "Technical Safeguards"),
    ("164.312(a)(2)(ii)", "Emergency Access Procedure", "Technical Safeguards"),
    ("164.312(a)(2)(iii)", "Automatic Logoff", "Technical Safeguards"),
    ("164.312(a)(2)(iv)", "Encryption and Decryption", "Technical Safeguards"),
    ("164.312(b)", "Audit Controls", "Technical Safeguards"),
    ("164.312(c)(1)", "Integrity — Standard", "Technical Safeguards"),
    ("164.312(c)(2)", "Mechanism to Authenticate Electronic Protected Health Information", "Technical Safeguards"),
    ("164.312(d)", "Person or Entity Authentication", "Technical Safeguards"),
    ("164.312(e)(1)", "Transmission Security — Standard", "Technical Safeguards"),
    ("164.312(e)(2)(i)", "Integrity Controls", "Technical Safeguards"),
    ("164.312(e)(2)(ii)", "Encryption", "Technical Safeguards"),
    ("164.314(a)(1)", "Business Associate Contracts — Standard", "Organizational Requirements"),
    ("164.314(a)(2)(i)", "Business Associate Contracts", "Organizational Requirements"),
    ("164.314(a)(2)(ii)", "Other Arrangements", "Organizational Requirements"),
    ("164.314(b)(1)", "Requirements for Group Health Plans — Standard", "Organizational Requirements"),
    ("164.314(b)(2)(i)", "Amend Plan Documents", "Organizational Requirements"),
    ("164.316(a)", "Policies and Procedures", "Policies and Procedures"),
    ("164.316(b)(1)", "Documentation — Standard", "Policies and Procedures"),
    ("164.316(b)(2)(i)", "Time Limit", "Policies and Procedures"),
    ("164.316(b)(2)(ii)", "Availability", "Policies and Procedures"),
    ("164.316(b)(2)(iii)", "Updates", "Policies and Procedures"),
]

emit_control_catalog(
    framework_id="hipaa-security",
    framework_name="HIPAA Security Rule (45 CFR § 164 Subpart C)",
    version="2013 (Omnibus Rule)",
    source="HHS OCR — 45 CFR 164 (U.S. federal regulation, not copyrightable)",
    families=["Administrative Safeguards", "Physical Safeguards", "Technical Safeguards", "Organizational Requirements", "Policies and Procedures"],
    controls=[{"id": c, "title": t, "description": t, "family": f} for c, t, f in HIPAA_SECURITY],
    tier="A",
)


# ---------------------------------------------------------------------------
# HIPAA Privacy Rule (45 CFR 164 Subpart E) — core provisions
# ---------------------------------------------------------------------------

HIPAA_PRIVACY = [
    ("164.500", "Applicability", "General Provisions"),
    ("164.502", "Uses and disclosures of PHI — general rules", "General Provisions"),
    ("164.504", "Uses and disclosures — organizational requirements", "General Provisions"),
    ("164.506", "Uses and disclosures to carry out treatment, payment, or health care operations", "General Provisions"),
    ("164.508", "Uses and disclosures requiring an authorization", "General Provisions"),
    ("164.510", "Uses and disclosures requiring an opportunity to agree or object", "General Provisions"),
    ("164.512", "Uses and disclosures for which authorization or opportunity to agree is not required", "General Provisions"),
    ("164.514", "Other requirements relating to uses and disclosures of PHI", "General Provisions"),
    ("164.520", "Notice of privacy practices for PHI", "Individual Rights"),
    ("164.522", "Rights to request privacy protection for PHI", "Individual Rights"),
    ("164.524", "Access of individuals to PHI", "Individual Rights"),
    ("164.526", "Amendment of PHI", "Individual Rights"),
    ("164.528", "Accounting of disclosures of PHI", "Individual Rights"),
    ("164.530", "Administrative requirements", "Administrative Requirements"),
    ("164.532", "Transition provisions", "Administrative Requirements"),
    ("164.534", "Compliance dates for initial implementation", "Administrative Requirements"),
]

emit_control_catalog(
    framework_id="hipaa-privacy",
    framework_name="HIPAA Privacy Rule (45 CFR § 164 Subpart E)",
    version="2013 (Omnibus Rule)",
    source="HHS OCR — 45 CFR 164 Subpart E (U.S. federal regulation)",
    families=["General Provisions", "Individual Rights", "Administrative Requirements"],
    controls=[{"id": c, "title": t, "description": t, "family": f} for c, t, f in HIPAA_PRIVACY],
    tier="A",
)


# ---------------------------------------------------------------------------
# HIPAA Breach Notification Rule (45 CFR 164 Subpart D)
# ---------------------------------------------------------------------------

HIPAA_BREACH = [
    ("164.400", "Applicability", "General"),
    ("164.402", "Definitions — breach, unsecured PHI", "General"),
    ("164.404", "Notification to individuals", "Notifications"),
    ("164.406", "Notification to the media (500+ affected)", "Notifications"),
    ("164.408", "Notification to the Secretary", "Notifications"),
    ("164.410", "Notification by a business associate", "Notifications"),
    ("164.412", "Law enforcement delay", "Administrative"),
    ("164.414", "Administrative requirements and burden of proof", "Administrative"),
]

emit_control_catalog(
    framework_id="hipaa-breach",
    framework_name="HIPAA Breach Notification Rule (45 CFR § 164 Subpart D)",
    version="2013",
    source="HHS OCR — 45 CFR 164 Subpart D (U.S. federal regulation)",
    families=["General", "Notifications", "Administrative"],
    controls=[{"id": c, "title": t, "description": t, "family": f} for c, t, f in HIPAA_BREACH],
    tier="A",
)


# ---------------------------------------------------------------------------
# GLBA Safeguards Rule (16 CFR Part 314) — FTC revised 2021/2023
# ---------------------------------------------------------------------------

GLBA = [
    ("314.3", "Standards for safeguarding customer information", "Standards"),
    ("314.4(a)", "Designate a qualified individual responsible for the information security program", "Elements"),
    ("314.4(b)(1)", "Identify reasonably foreseeable internal and external risks", "Elements"),
    ("314.4(b)(2)", "Assess likelihood and potential damage of risks", "Elements"),
    ("314.4(b)(3)", "Assess sufficiency of safeguards in place", "Elements"),
    ("314.4(c)(1)", "Implement access controls", "Elements"),
    ("314.4(c)(2)", "Identify and manage data, personnel, devices, systems, and facilities", "Elements"),
    ("314.4(c)(3)", "Encrypt all customer information at rest and in transit", "Elements"),
    ("314.4(c)(4)", "Adopt secure development practices", "Elements"),
    ("314.4(c)(5)", "Implement MFA for anyone accessing customer information", "Elements"),
    ("314.4(c)(6)", "Securely dispose of customer information", "Elements"),
    ("314.4(c)(7)", "Adopt procedures for change management", "Elements"),
    ("314.4(c)(8)", "Monitor and log authorized user activity", "Elements"),
    ("314.4(d)(1)", "Continuous monitoring or annual penetration testing + biannual vulnerability assessment", "Elements"),
    ("314.4(e)", "Implement policies and procedures for secure disposal", "Elements"),
    ("314.4(f)", "Monitor, evaluate, and adjust the information security program", "Elements"),
    ("314.4(g)", "Establish an incident response plan", "Elements"),
    ("314.4(h)", "Report to the board of directors annually", "Elements"),
    ("314.4(i)", "Notify FTC of security events affecting 500+ consumers within 30 days", "Elements"),
]

emit_control_catalog(
    framework_id="glba-safeguards",
    framework_name="GLBA Safeguards Rule (16 CFR § 314)",
    version="2023 (Notification Amendment)",
    source="FTC — 16 CFR 314 (U.S. federal regulation)",
    families=["Standards", "Elements"],
    controls=[{"id": c, "title": t, "description": t, "family": f} for c, t, f in GLBA],
    tier="A",
)


# ---------------------------------------------------------------------------
# NY DFS Part 500 — Cybersecurity Requirements for Financial Services Companies
# ---------------------------------------------------------------------------

from gen_nydfs_currency import main as generate_nydfs_currency

generate_nydfs_currency()

# ---------------------------------------------------------------------------
# CISA Cross-Sector Cybersecurity Performance Goals, version 2.0
# ---------------------------------------------------------------------------

from gen_currency_headings import generate_cisa_catalog

generate_cisa_catalog()


# ---------------------------------------------------------------------------
# NERC CIP: current US designators and separate publication notices
# ---------------------------------------------------------------------------

from gen_nerc_currency import main as generate_nerc_currency

generate_nerc_currency()

# ---------------------------------------------------------------------------
# FDA 21 CFR Part 11 — Electronic Records; Electronic Signatures
# ---------------------------------------------------------------------------

FDA_21_CFR_11 = [
    ("11.10(a)", "Validation of systems to ensure accuracy, reliability, consistent intended performance, and the ability to discern invalid or altered records", "Controls for Closed Systems"),
    ("11.10(b)", "Ability to generate accurate and complete copies of records", "Controls for Closed Systems"),
    ("11.10(c)", "Protection of records to enable accurate and ready retrieval throughout the retention period", "Controls for Closed Systems"),
    ("11.10(d)", "Limiting system access to authorized individuals", "Controls for Closed Systems"),
    ("11.10(e)", "Use of secure, computer-generated, time-stamped audit trails", "Controls for Closed Systems"),
    ("11.10(f)", "Use of operational system checks to enforce permitted sequencing of steps and events", "Controls for Closed Systems"),
    ("11.10(g)", "Use of authority checks to ensure that only authorized individuals can use the system, electronically sign a record, or perform operations", "Controls for Closed Systems"),
    ("11.10(h)", "Use of device checks to determine validity of source of data input or operational instruction", "Controls for Closed Systems"),
    ("11.10(i)", "Determination that persons who develop, maintain, or use electronic records/signature systems have the appropriate education, training, and experience", "Controls for Closed Systems"),
    ("11.10(j)", "Establishment of, and adherence to, written policies that hold individuals accountable and responsible for actions initiated under their electronic signatures", "Controls for Closed Systems"),
    ("11.10(k)", "Use of appropriate controls over systems documentation", "Controls for Closed Systems"),
    ("11.30", "Controls for Open Systems", "Controls for Open Systems"),
    ("11.50", "Signature Manifestations", "Electronic Signatures"),
    ("11.70", "Signature/Record Linking", "Electronic Signatures"),
    ("11.100(a)", "Each electronic signature shall be unique to one individual", "Electronic Signature General Requirements"),
    ("11.100(b)", "Verify identity before establishing, assigning, certifying, or sanctioning electronic signatures", "Electronic Signature General Requirements"),
    ("11.100(c)", "Certify to FDA that electronic signatures are intended to be the legally binding equivalent of traditional handwritten signatures", "Electronic Signature General Requirements"),
    ("11.200(a)", "Electronic signatures not based upon biometrics shall employ at least two distinct identification components (ID + password) and fall under administrative controls", "Electronic Signature Components and Controls"),
    ("11.200(b)", "Electronic signatures based upon biometrics shall be designed to ensure that they cannot be used by anyone other than their genuine owners", "Electronic Signature Components and Controls"),
    ("11.300", "Controls for Identification Codes/Passwords", "Controls for ID Codes/Passwords"),
]

emit_control_catalog(
    framework_id="fda-21-cfr-pt11",
    framework_name="FDA 21 CFR Part 11 — Electronic Records; Electronic Signatures",
    version="1997 (with guidance updates)",
    source="FDA — 21 CFR Part 11 (U.S. federal regulation)",
    families=["Controls for Closed Systems", "Controls for Open Systems", "Electronic Signatures", "Electronic Signature General Requirements", "Electronic Signature Components and Controls", "Controls for ID Codes/Passwords"],
    controls=[{"id": c, "title": t, "description": t, "family": f} for c, t, f in FDA_21_CFR_11],
    tier="A",
)


# ---------------------------------------------------------------------------
# IRS Publication 1075 — Tax Information Security Guidelines
# ---------------------------------------------------------------------------

IRS_1075 = [
    ("9.3.1", "Access Control Policy and Procedures", "Management"),
    ("9.3.2", "Awareness and Training Policy and Procedures", "Management"),
    ("9.3.3", "Audit and Accountability Policy and Procedures", "Management"),
    ("9.3.4", "Security Assessment and Authorization", "Management"),
    ("9.3.5", "Configuration Management", "Management"),
    ("9.3.6", "Contingency Planning", "Operational"),
    ("9.3.7", "Identification and Authentication", "Technical"),
    ("9.3.8", "Incident Response", "Operational"),
    ("9.3.9", "Maintenance", "Operational"),
    ("9.3.10", "Media Protection", "Operational"),
    ("9.3.11", "Physical and Environmental Protection", "Operational"),
    ("9.3.12", "Planning", "Management"),
    ("9.3.13", "Personnel Security", "Operational"),
    ("9.3.14", "Risk Assessment", "Management"),
    ("9.3.15", "System and Services Acquisition", "Management"),
    ("9.3.16", "System and Communications Protection", "Technical"),
    ("9.3.17", "System and Information Integrity", "Operational"),
    ("9.3.18", "Program Management", "Management"),
    ("9.4", "Disclosure to Contractors", "Disclosure"),
    ("9.5", "Protection of FTI in Transit", "Protection"),
    ("9.6", "Secure Storage of FTI", "Protection"),
    ("9.7", "Secure Disposal of FTI", "Protection"),
]

emit_control_catalog(
    framework_id="irs-1075",
    framework_name="IRS Publication 1075 — Tax Information Security Guidelines",
    version="November 2021",
    source="IRS Publication 1075 (U.S. federal agency document)",
    families=["Management", "Operational", "Technical", "Disclosure", "Protection"],
    controls=[{"id": c, "title": t, "description": t, "family": f} for c, t, f in IRS_1075],
    tier="A",
)


# ---------------------------------------------------------------------------
# CMS ARS 5.1 historical family summaries
# ---------------------------------------------------------------------------

CMS_ARS = [
    # Preserve legacy headings without asserting baseline or control equivalence.
    ("CMS-AC", "Access Control — CMS-tailored 800-53 Rev 5", "Access Control"),
    ("CMS-AT", "Awareness and Training — CMS-tailored 800-53 Rev 5", "Awareness and Training"),
    ("CMS-AU", "Audit and Accountability — CMS-tailored 800-53 Rev 5", "Audit and Accountability"),
    ("CMS-CA", "Security Assessment, Authorization, and Monitoring — CMS-tailored", "Security Assessment"),
    ("CMS-CM", "Configuration Management — CMS-tailored 800-53 Rev 5", "Configuration Management"),
    ("CMS-CP", "Contingency Planning — CMS-tailored 800-53 Rev 5", "Contingency Planning"),
    ("CMS-IA", "Identification and Authentication — CMS-tailored 800-53 Rev 5", "Identification and Authentication"),
    ("CMS-IR", "Incident Response — CMS-tailored 800-53 Rev 5", "Incident Response"),
    ("CMS-MA", "Maintenance — CMS-tailored 800-53 Rev 5", "Maintenance"),
    ("CMS-MP", "Media Protection — CMS-tailored 800-53 Rev 5", "Media Protection"),
    ("CMS-PE", "Physical and Environmental Protection — CMS-tailored", "Physical and Environmental"),
    ("CMS-PL", "Planning — CMS-tailored 800-53 Rev 5", "Planning"),
    ("CMS-PM", "Program Management — CMS-tailored 800-53 Rev 5", "Program Management"),
    ("CMS-PS", "Personnel Security — CMS-tailored 800-53 Rev 5", "Personnel Security"),
    ("CMS-RA", "Risk Assessment — CMS-tailored 800-53 Rev 5", "Risk Assessment"),
    ("CMS-SA", "System and Services Acquisition — CMS-tailored", "System and Services Acquisition"),
    ("CMS-SC", "System and Communications Protection — CMS-tailored", "System and Communications Protection"),
    ("CMS-SI", "System and Information Integrity — CMS-tailored", "System and Information Integrity"),
    ("CMS-SR", "Supply Chain Risk Management — CMS-tailored", "Supply Chain"),
]

emit_control_catalog(
    framework_id="cms-ars-5.1",
    framework_name="CMS ARS 5.1 (historical family summaries)",
    version="5.1 (2023-07-26)",
    source="https://security.cms.gov/policy-guidance/cms-acceptable-risk-safeguards-ars",
    families=["Access Control", "Awareness and Training", "Audit and Accountability", "Security Assessment", "Configuration Management", "Contingency Planning", "Identification and Authentication", "Incident Response", "Maintenance", "Media Protection", "Physical and Environmental", "Planning", "Program Management", "Personnel Security", "Risk Assessment", "System and Services Acquisition", "System and Communications Protection", "System and Information Integrity", "Supply Chain"],
    controls=[{"id": c, "title": t, "description": t, "family": f} for c, t, f in CMS_ARS],
    status="historical",
    verified_on="2026-09-09",
    superseded_by="cms-ars-5.2",
    notes="Preserves 19 legacy CMS-* family summaries for existing assessment references. These are selected headings, not an archived full ARS 5.1 catalog. The edition date is corrected from 2022 to 2023-07-26. Review CMS ARS 5.2 for current source content; old family IDs do not map automatically to the new control and enhancement IDs.",
    tier="A",
)


# ---------------------------------------------------------------------------
# CJIS v6.0 historical selected headings
# ---------------------------------------------------------------------------

CJIS = [
    ("5.1", "Information Exchange Agreements", "Information Exchange"),
    ("5.2", "Security Awareness Training", "Security Awareness Training"),
    ("5.3", "Incident Response", "Incident Response"),
    ("5.4", "Auditing and Accountability", "Auditing"),
    ("5.5", "Access Control", "Access Control"),
    ("5.5.1", "Account Management", "Access Control"),
    ("5.5.2", "Access Enforcement", "Access Control"),
    ("5.5.3", "Unsuccessful Login Attempts", "Access Control"),
    ("5.5.4", "System Use Notification", "Access Control"),
    ("5.5.5", "Session Lock", "Access Control"),
    ("5.5.6", "Remote Access", "Access Control"),
    ("5.6", "Identification and Authentication", "Identification and Authentication"),
    ("5.6.1", "Identification Policy and Procedures", "Identification and Authentication"),
    ("5.6.2", "Authentication Policy and Procedures", "Identification and Authentication"),
    ("5.6.2.2", "Advanced Authentication (multi-factor)", "Identification and Authentication"),
    ("5.7", "Configuration Management", "Configuration Management"),
    ("5.8", "Media Protection", "Media Protection"),
    ("5.9", "Physical Protection", "Physical Protection"),
    ("5.10", "System and Communications Protection", "System and Communications Protection"),
    ("5.10.1.1", "Encryption for CJI in transit", "System and Communications Protection"),
    ("5.10.1.2", "Encryption for CJI at rest", "System and Communications Protection"),
    ("5.11", "Formal Audits", "Auditing"),
    ("5.12", "Personnel Security", "Personnel Security"),
    ("5.13", "Mobile Devices", "Mobile Devices"),
]

emit_control_catalog(
    framework_id="cjis-v6",
    framework_name="FBI CJIS v6.0 (historical selected headings)",
    version="6.0 (2024-12-27)",
    source="https://le.fbi.gov/cjis-division/cjis-security-policy-resource-center",
    families=["Information Exchange", "Security Awareness Training", "Incident Response", "Auditing", "Access Control", "Identification and Authentication", "Configuration Management", "Media Protection", "Physical Protection", "System and Communications Protection", "Personnel Security", "Mobile Devices"],
    controls=[{"id": c, "title": t, "description": t, "family": f} for c, t, f in CJIS],
    status="historical",
    verified_on="2026-09-09",
    superseded_by="cjis-v6.1",
    notes="Preserves 24 legacy selected headings for existing assessment references. Original source coverage has not been verified against the full version 6.0 policy. The successor is a version 6.1 companion reference catalog with different addresses and coverage; assessment evidence is not migrated automatically. Publication version does not determine a state authority's audit version.",
    tier="A",
)


if __name__ == "__main__":
    import _generators as catalog_helpers
    from gen_cjis_companion import main as generate_cjis_companion
    from gen_cms_ars import main as generate_cms_ars

    for generate, filename in (
        (generate_cms_ars, "cms-ars-5.2.json"),
        (generate_cjis_companion, "cjis-v6.1.json"),
    ):
        output = catalog_helpers.DATA_ROOT / "us-federal" / filename
        if generate(["--output", str(output)]) != 0:
            raise SystemExit(1)
    print("Generated US regulatory catalogs.")
