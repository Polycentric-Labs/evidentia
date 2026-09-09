"""Generate international catalogs — Tier A/D.

- EU: GDPR (obligation), EU AI Act, NIS2, DORA
- UK: NCSC CAF, Cyber Essentials, DPA 2018
- Australia: Essential 8, ISM
- Canada: ITSG-33, PIPEDA (obligation)
- NZ: NZISM

Tier D = government regulations, not copyrightable (EU/UK/AU/CA/NZ law).
Tier A = government-published frameworks with attribution terms.
"""

from __future__ import annotations

from _generators import (  # type: ignore[import-not-found]
    emit_control_catalog,
    emit_obligation_catalog,
)


# ---------------------------------------------------------------------------
# EU GDPR — General Data Protection Regulation (Regulation 2016/679)
# ---------------------------------------------------------------------------

GDPR_REGIME = {
    "jurisdiction": "EU",
    "effective_date": "2018-05-25",
    "subject_rights": ["access", "delete", "correct", "portability", "restrict-processing", "object"],
    "data_minimization_required": True,
    "dpia_required": True,
    "breach_notification_threshold_days": 3,  # 72 hours to supervisory authority
    "breach_notification_to_subjects": True,
    "private_right_of_action": True,
    "cure_period_days": None,
    "regulator": "Member State Data Protection Authorities (coordinated by European Data Protection Board)",
    "notes": "Fines up to €20M or 4% of global annual turnover, whichever is higher.",
}

GDPR_OBLIGATIONS = [
    ("GDPR.Art.5", "Principles relating to processing of personal data", "Cross-cutting", "Lawfulness, fairness, transparency; purpose limitation; data minimisation; accuracy; storage limitation; integrity and confidentiality; accountability", "Article 5"),
    ("GDPR.Art.6", "Lawfulness of processing", "Lawful Basis", "Processing is lawful only if one of six bases applies: consent, contract, legal obligation, vital interests, public task, or legitimate interests.", "Article 6"),
    ("GDPR.Art.7", "Conditions for consent", "Lawful Basis", "Consent must be freely given, specific, informed, unambiguous, demonstrable, and as easy to withdraw as to give.", "Article 7"),
    ("GDPR.Art.9", "Processing of special categories of personal data", "Lawful Basis", "Processing sensitive data is prohibited except under specific conditions (explicit consent, employment law, vital interests, etc.).", "Article 9"),
    ("GDPR.Art.12", "Transparent information and communication", "Transparency", "Provide transparent, concise, and accessible information about processing.", "Article 12"),
    ("GDPR.Art.13", "Information to be provided when data is collected from the data subject", "Transparency", "Specific information elements at the time of collection.", "Article 13"),
    ("GDPR.Art.14", "Information to be provided when data is not collected from the data subject", "Transparency", "Specific information elements when collecting from third parties.", "Article 14"),
    ("GDPR.Art.15", "Right of access by the data subject", "Subject Rights", "Right to confirmation, access to data, and information about processing.", "Article 15"),
    ("GDPR.Art.16", "Right to rectification", "Subject Rights", "Right to have inaccurate data corrected.", "Article 16"),
    ("GDPR.Art.17", "Right to erasure ('right to be forgotten')", "Subject Rights", "Right to have data deleted under specific circumstances.", "Article 17"),
    ("GDPR.Art.18", "Right to restriction of processing", "Subject Rights", "Right to have processing limited in specific cases.", "Article 18"),
    ("GDPR.Art.19", "Notification obligation regarding rectification or erasure of personal data or restriction of processing", "Subject Rights", "Communicate rectifications/erasures to third parties.", "Article 19"),
    ("GDPR.Art.20", "Right to data portability", "Subject Rights", "Right to receive data in a structured, commonly used, machine-readable format and transmit it to another controller.", "Article 20"),
    ("GDPR.Art.21", "Right to object", "Subject Rights", "Right to object to processing based on legitimate interests or direct marketing.", "Article 21"),
    ("GDPR.Art.22", "Automated individual decision-making, including profiling", "Subject Rights", "Right not to be subject to decisions based solely on automated processing with legal or similarly significant effects.", "Article 22"),
    ("GDPR.Art.24", "Responsibility of the controller", "Accountability", "Implement technical and organisational measures to ensure and demonstrate compliance.", "Article 24"),
    ("GDPR.Art.25", "Data protection by design and by default", "Accountability", "Implement privacy by design and by default.", "Article 25"),
    ("GDPR.Art.26", "Joint controllers", "Accountability", "Arrangements between joint controllers.", "Article 26"),
    ("GDPR.Art.28", "Processor", "Vendor Management", "Processor requirements, including written contract with specific terms.", "Article 28"),
    ("GDPR.Art.30", "Records of processing activities", "Accountability", "Maintain records of processing (with SME exemptions).", "Article 30"),
    ("GDPR.Art.32", "Security of processing", "Security", "Implement appropriate technical and organisational measures to ensure security appropriate to the risk.", "Article 32"),
    ("GDPR.Art.33", "Notification of a personal data breach to the supervisory authority", "Breach Notification", "Notify the supervisory authority of breaches within 72 hours where feasible.", "Article 33"),
    ("GDPR.Art.34", "Communication of a personal data breach to the data subject", "Breach Notification", "Notify affected individuals of high-risk breaches without undue delay.", "Article 34"),
    ("GDPR.Art.35", "Data protection impact assessment (DPIA)", "Accountability", "Carry out DPIAs for high-risk processing.", "Article 35"),
    ("GDPR.Art.36", "Prior consultation", "Accountability", "Consult supervisory authority when DPIA indicates high residual risk.", "Article 36"),
    ("GDPR.Art.37", "Designation of the data protection officer", "Accountability", "Designate a DPO in specified cases.", "Article 37"),
    ("GDPR.Art.44", "General principle for transfers", "International Transfers", "Transfers only under GDPR adequacy or appropriate safeguards.", "Article 44"),
    ("GDPR.Art.45", "Transfers on the basis of an adequacy decision", "International Transfers", "Transfers to adequate countries.", "Article 45"),
    ("GDPR.Art.46", "Transfers subject to appropriate safeguards", "International Transfers", "SCCs, BCRs, approved codes of conduct/certifications.", "Article 46"),
    ("GDPR.Art.49", "Derogations for specific situations", "International Transfers", "Limited exceptions for specific transfers.", "Article 49"),
]

emit_obligation_catalog(
    framework_id="eu-gdpr",
    framework_name="EU General Data Protection Regulation (GDPR)",
    version="Regulation (EU) 2016/679",
    source="Official Journal of the European Union L 119, 4 May 2016",
    regime=GDPR_REGIME,
    obligations=[
        {
            "id": oid,
            "title": title,
            "description": desc,
            "category": cat,
            "citation": cite,
        }
        for oid, title, cat, desc, cite in GDPR_OBLIGATIONS
    ],
    tier="D",
)


# ---------------------------------------------------------------------------
# EU AI Act (Regulation 2024/1689)
# ---------------------------------------------------------------------------

from gen_eu_ai_act import main as generate_eu_ai_act

generate_eu_ai_act()

# ---------------------------------------------------------------------------
# EU NIS2 Directive (Directive (EU) 2022/2555)
# ---------------------------------------------------------------------------

EU_NIS2 = [
    ("NIS2.Art.20", "Governance — management body approval and oversight", "Governance"),
    ("NIS2.Art.21(2)(a)", "Policies on risk analysis and information system security", "Risk Management"),
    ("NIS2.Art.21(2)(b)", "Incident handling", "Incident Response"),
    ("NIS2.Art.21(2)(c)", "Business continuity (backup, disaster recovery, crisis management)", "Business Continuity"),
    ("NIS2.Art.21(2)(d)", "Supply chain security", "Supply Chain"),
    ("NIS2.Art.21(2)(e)", "Security in network and information systems acquisition, development, and maintenance, including vulnerability handling and disclosure", "SDLC"),
    ("NIS2.Art.21(2)(f)", "Policies and procedures to assess effectiveness of cybersecurity risk-management measures", "Assurance"),
    ("NIS2.Art.21(2)(g)", "Basic cyber hygiene practices and training", "Training"),
    ("NIS2.Art.21(2)(h)", "Policies and procedures regarding the use of cryptography and encryption", "Cryptography"),
    ("NIS2.Art.21(2)(i)", "Human resources security, access control policies and asset management", "HR Security"),
    ("NIS2.Art.21(2)(j)", "Use of multi-factor authentication, secured communications, and emergency comms", "Authentication"),
    ("NIS2.Art.23", "Reporting obligations — 24h early warning, 72h incident notification, 1-month final report", "Incident Reporting"),
    ("NIS2.Art.24", "Use of certified ICT products, services, and processes", "Certification"),
]

emit_control_catalog(
    framework_id="eu-nis2",
    framework_name="EU NIS2 Directive",
    version="Directive (EU) 2022/2555",
    source="Official Journal of the European Union — NIS2 Directive (regulation text)",
    families=["Governance", "Risk Management", "Incident Response", "Business Continuity", "Supply Chain", "SDLC", "Assurance", "Training", "Cryptography", "HR Security", "Authentication", "Incident Reporting", "Certification"],
    controls=[{"id": c, "title": t, "description": t, "family": f} for c, t, f in EU_NIS2],
    tier="D",
)


# ---------------------------------------------------------------------------
# EU DORA — Digital Operational Resilience Act (Regulation 2022/2554)
# ---------------------------------------------------------------------------

EU_DORA = [
    ("DORA.Art.5", "ICT governance and control framework", "Governance"),
    ("DORA.Art.6", "ICT risk management framework", "Risk Management"),
    ("DORA.Art.8", "Identification of functions, processes and assets", "Risk Management"),
    ("DORA.Art.9", "Protection and prevention", "Protection"),
    ("DORA.Art.10", "Detection", "Detection"),
    ("DORA.Art.11", "Response and recovery", "Response"),
    ("DORA.Art.12", "Backup policies, restoration and recovery procedures", "Backup"),
    ("DORA.Art.13", "Learning and evolving", "Continuous Improvement"),
    ("DORA.Art.14", "Communication", "Communication"),
    ("DORA.Art.17", "ICT-related incident management process", "Incident Management"),
    ("DORA.Art.19", "Reporting of major ICT-related incidents and voluntary reporting of significant cyber threats", "Incident Reporting"),
    ("DORA.Art.24", "Advanced testing of ICT tools, systems and processes based on threat-led penetration testing (TLPT)", "Testing"),
    ("DORA.Art.28", "General principles on ICT third-party risk", "Third-Party Risk"),
    ("DORA.Art.30", "Key contractual provisions with ICT third-party service providers", "Third-Party Risk"),
    ("DORA.Art.40", "Cyber threat information and intelligence sharing arrangements", "Information Sharing"),
]

emit_control_catalog(
    framework_id="eu-dora",
    framework_name="EU Digital Operational Resilience Act (DORA)",
    version="Regulation (EU) 2022/2554",
    source="Official Journal of the European Union — DORA (regulation text)",
    families=["Governance", "Risk Management", "Protection", "Detection", "Response", "Backup", "Continuous Improvement", "Communication", "Incident Management", "Incident Reporting", "Testing", "Third-Party Risk", "Information Sharing"],
    controls=[{"id": c, "title": t, "description": t, "family": f} for c, t, f in EU_DORA],
    tier="D",
)


# ---------------------------------------------------------------------------
# UK NCSC Cyber Assessment Framework (CAF) v3.2
# ---------------------------------------------------------------------------

UK_NCSC_CAF = [
    ("A1", "Governance", "A — Managing Security Risk"),
    ("A2", "Risk Management", "A — Managing Security Risk"),
    ("A3", "Asset Management", "A — Managing Security Risk"),
    ("A4", "Supply Chain", "A — Managing Security Risk"),
    ("B1", "Service Protection Policies, Processes and Procedures", "B — Protecting Against Cyber Attack"),
    ("B2", "Identity and Access Control", "B — Protecting Against Cyber Attack"),
    ("B3", "Data Security", "B — Protecting Against Cyber Attack"),
    ("B4", "System Security", "B — Protecting Against Cyber Attack"),
    ("B5", "Resilient Networks and Systems", "B — Protecting Against Cyber Attack"),
    ("B6", "Staff Awareness and Training", "B — Protecting Against Cyber Attack"),
    ("C1", "Security Monitoring", "C — Detecting Cyber Security Events"),
    ("C2", "Proactive Security Event Discovery", "C — Detecting Cyber Security Events"),
    ("D1", "Response and Recovery Planning", "D — Minimising the Impact of Cyber Security Incidents"),
    ("D2", "Lessons Learned", "D — Minimising the Impact of Cyber Security Incidents"),
]

emit_control_catalog(
    framework_id="uk-ncsc-caf-3.2",
    framework_name="UK NCSC Cyber Assessment Framework (CAF) v3.2",
    version="3.2 (2024)",
    source="UK National Cyber Security Centre — https://www.ncsc.gov.uk/collection/cyber-assessment-framework (Open Government Licence v3.0)",
    families=["A — Managing Security Risk", "B — Protecting Against Cyber Attack", "C — Detecting Cyber Security Events", "D — Minimising the Impact of Cyber Security Incidents"],
    controls=[{"id": c, "title": t, "description": t, "family": f} for c, t, f in UK_NCSC_CAF],
    tier="A",
    subdir="international",
)


# ---------------------------------------------------------------------------
# UK Cyber Essentials
# ---------------------------------------------------------------------------

UK_CYBER_ESSENTIALS = [
    ("CE.1", "Firewalls", "Technical Controls"),
    ("CE.2", "Secure Configuration", "Technical Controls"),
    ("CE.3", "User Access Control", "Technical Controls"),
    ("CE.4", "Malware Protection", "Technical Controls"),
    ("CE.5", "Security Update Management", "Technical Controls"),
]

emit_control_catalog(
    framework_id="uk-cyber-essentials",
    framework_name="UK Cyber Essentials",
    version="Montpellier (Apr 2025)",
    source="IASME / UK NCSC — Cyber Essentials scheme (Open Government Licence v3.0)",
    families=["Technical Controls"],
    controls=[{"id": c, "title": t, "description": t, "family": f} for c, t, f in UK_CYBER_ESSENTIALS],
    tier="A",
    subdir="international",
)


# ---------------------------------------------------------------------------
# Australian Essential Eight (ACSC)
# ---------------------------------------------------------------------------

AU_ESSENTIAL_8 = [
    ("E8.1", "Application Control", "Essential Eight Strategies"),
    ("E8.2", "Patch Applications", "Essential Eight Strategies"),
    ("E8.3", "Configure Microsoft Office Macro Settings", "Essential Eight Strategies"),
    ("E8.4", "User Application Hardening", "Essential Eight Strategies"),
    ("E8.5", "Restrict Administrative Privileges", "Essential Eight Strategies"),
    ("E8.6", "Patch Operating Systems", "Essential Eight Strategies"),
    ("E8.7", "Multi-Factor Authentication", "Essential Eight Strategies"),
    ("E8.8", "Regular Backups", "Essential Eight Strategies"),
]

emit_control_catalog(
    framework_id="au-essential-8",
    framework_name="Australian Essential Eight",
    version="Nov 2023",
    source="Australian Cyber Security Centre (ACSC) — https://cyber.gov.au/essential-eight (Creative Commons BY 4.0)",
    families=["Essential Eight Strategies"],
    controls=[{"id": c, "title": t, "description": t, "family": f} for c, t, f in AU_ESSENTIAL_8],
    tier="A",
    subdir="international",
)


# ---------------------------------------------------------------------------
# Australian ISM (Information Security Manual) — top-level chapters
# ---------------------------------------------------------------------------

AU_ISM = [
    ("ISM.Gov", "Cyber security principles — Govern", "Principles"),
    ("ISM.Protect", "Cyber security principles — Protect", "Principles"),
    ("ISM.Detect", "Cyber security principles — Detect", "Principles"),
    ("ISM.Respond", "Cyber security principles — Respond", "Principles"),
    ("ISM.Strategy", "Guidelines for cyber security roles and governance", "Governance"),
    ("ISM.PhysicalSec", "Guidelines for physical security", "Physical Security"),
    ("ISM.Personnel", "Guidelines for personnel security", "Personnel Security"),
    ("ISM.CommInfra", "Guidelines for communications infrastructure", "Communications"),
    ("ISM.CommSys", "Guidelines for communications systems", "Communications"),
    ("ISM.ICTEqpt", "Guidelines for ICT equipment", "ICT Equipment"),
    ("ISM.Media", "Guidelines for media", "Media"),
    ("ISM.SysHardening", "Guidelines for system hardening", "System Hardening"),
    ("ISM.SysMgmt", "Guidelines for system management", "System Management"),
    ("ISM.SysMon", "Guidelines for system monitoring", "System Monitoring"),
    ("ISM.Software", "Guidelines for software development", "Software Development"),
    ("ISM.DbSys", "Guidelines for database systems", "Database Systems"),
    ("ISM.Email", "Guidelines for email", "Email"),
    ("ISM.Networks", "Guidelines for networking", "Networking"),
    ("ISM.Crypto", "Guidelines for cryptography", "Cryptography"),
    ("ISM.Gateways", "Guidelines for gateways", "Gateways"),
    ("ISM.DataTrans", "Guidelines for data transfers", "Data Transfers"),
    ("ISM.CyberIncident", "Guidelines for cyber security incidents", "Incident Response"),
    ("ISM.OutSysMgmt", "Guidelines for outsourcing", "Third-Party"),
    ("ISM.Procure", "Guidelines for procurement and outsourcing", "Third-Party"),
]

emit_control_catalog(
    framework_id="au-ism",
    framework_name="Australian Information Security Manual",
    version="September 2024",
    source="Australian Signals Directorate (ACSC) — https://cyber.gov.au/ism (Creative Commons BY 4.0)",
    families=sorted({f for _, _, f in AU_ISM}),
    controls=[{"id": c, "title": t, "description": t, "family": f} for c, t, f in AU_ISM],
    tier="A",
    subdir="international",
)


# ---------------------------------------------------------------------------
# Canada ITSG-33 (IT Security Risk Management: A Lifecycle Approach)
# ---------------------------------------------------------------------------

CANADA_ITSG_33 = [
    ("AC", "Access Control", "Technical"),
    ("AT", "Awareness and Training", "Operational"),
    ("AU", "Audit and Accountability", "Technical"),
    ("CA", "Security Assessment and Authorization", "Management"),
    ("CM", "Configuration Management", "Operational"),
    ("CP", "Contingency Planning", "Operational"),
    ("IA", "Identification and Authentication", "Technical"),
    ("IR", "Incident Response", "Operational"),
    ("MA", "Maintenance", "Operational"),
    ("MP", "Media Protection", "Operational"),
    ("PE", "Physical and Environmental Protection", "Operational"),
    ("PL", "Planning", "Management"),
    ("PS", "Personnel Security", "Operational"),
    ("RA", "Risk Assessment", "Management"),
    ("SA", "System and Services Acquisition", "Management"),
    ("SC", "System and Communications Protection", "Technical"),
    ("SI", "System and Information Integrity", "Operational"),
]

emit_control_catalog(
    framework_id="canada-itsg-33",
    framework_name="Canada ITSG-33 — IT Security Risk Management: A Lifecycle Approach",
    version="December 2014 (current)",
    source="Canadian Centre for Cyber Security (CCCS) — ITSG-33 Annex 3A (public document)",
    families=["Management", "Operational", "Technical"],
    controls=[{"id": c, "title": t, "description": t, "family": f} for c, t, f in CANADA_ITSG_33],
    tier="A",
    subdir="international",
)


# ---------------------------------------------------------------------------
# Canada PIPEDA (Personal Information Protection and Electronic Documents Act)
# ---------------------------------------------------------------------------

PIPEDA_REGIME = {
    "jurisdiction": "CA",
    "effective_date": "2001-01-01",
    "amendments": ["Digital Privacy Act 2015 (PIPEDA breach notification)"],
    "subject_rights": ["access", "correct"],
    "data_minimization_required": True,
    "breach_notification_threshold_days": None,  # "as soon as feasible"
    "breach_notification_to_subjects": True,
    "private_right_of_action": False,
    "regulator": "Office of the Privacy Commissioner of Canada (OPC)",
    "notes": "Based on 10 fair information principles derived from the CSA Privacy Code.",
}

PIPEDA_OBLIGATIONS = [
    ("PIPEDA.P1", "Accountability", "Principles", "Organization is responsible for personal information under its control; designate a privacy officer.", "Schedule 1, 4.1"),
    ("PIPEDA.P2", "Identifying Purposes", "Principles", "Identify purposes for collecting personal information at or before collection.", "Schedule 1, 4.2"),
    ("PIPEDA.P3", "Consent", "Principles", "Knowledge and consent required, subject to limited exceptions.", "Schedule 1, 4.3"),
    ("PIPEDA.P4", "Limiting Collection", "Principles", "Collection limited to what is necessary for identified purposes.", "Schedule 1, 4.4"),
    ("PIPEDA.P5", "Limiting Use, Disclosure, and Retention", "Principles", "Use and disclose only for identified purposes; retain only as long as necessary.", "Schedule 1, 4.5"),
    ("PIPEDA.P6", "Accuracy", "Principles", "Keep information as accurate, complete, and up-to-date as necessary.", "Schedule 1, 4.6"),
    ("PIPEDA.P7", "Safeguards", "Principles", "Safeguards appropriate to the sensitivity of the information.", "Schedule 1, 4.7"),
    ("PIPEDA.P8", "Openness", "Principles", "Make policies and practices readily available.", "Schedule 1, 4.8"),
    ("PIPEDA.P9", "Individual Access", "Principles", "Right of access to one's own information, subject to exceptions.", "Schedule 1, 4.9"),
    ("PIPEDA.P10", "Challenging Compliance", "Principles", "Provide a mechanism to challenge compliance.", "Schedule 1, 4.10"),
    ("PIPEDA.10.1", "Breach reporting and record-keeping", "Breach Notification", "Report breaches of security safeguards to Privacy Commissioner and affected individuals when there is real risk of significant harm.", "Section 10.1"),
]

emit_obligation_catalog(
    framework_id="canada-pipeda",
    framework_name="Canada PIPEDA — Personal Information Protection and Electronic Documents Act",
    version="S.C. 2000, c. 5 (current)",
    source="Government of Canada — https://laws-lois.justice.gc.ca/eng/acts/P-8.6/ (federal statute)",
    regime=PIPEDA_REGIME,
    obligations=[
        {"id": oid, "title": title, "description": desc, "category": cat, "citation": cite}
        for oid, title, cat, desc, cite in PIPEDA_OBLIGATIONS
    ],
    tier="D",
)


# ---------------------------------------------------------------------------
# New Zealand Information Security Manual (NZISM)
# ---------------------------------------------------------------------------

NZ_NZISM = [
    ("NZISM.Part1", "Introduction to this Manual", "Part 1"),
    ("NZISM.Part2", "Information Security Governance", "Part 2 — Information Security Governance"),
    ("NZISM.Part3", "Information Security Policy", "Part 2 — Information Security Governance"),
    ("NZISM.Part4", "Information Security Documentation", "Part 2 — Information Security Governance"),
    ("NZISM.Part5", "Information Technology Security", "Part 3 — Information Technology Security"),
    ("NZISM.Part6", "Physical Security", "Part 4 — Physical Security"),
    ("NZISM.Part7", "Personnel Security", "Part 5 — Personnel Security"),
    ("NZISM.Part8", "Communications Security", "Part 6 — Communications Security"),
    ("NZISM.Part9", "Information Technology Operational Security", "Part 7 — Information Technology Operational Security"),
    ("NZISM.Part10", "Access Control and Passwords", "Part 8 — Access Control and Passwords"),
    ("NZISM.Part11", "Cryptography", "Part 9 — Cryptography"),
    ("NZISM.Part12", "Network Security", "Part 10 — Network Security"),
    ("NZISM.Part13", "Data Transfer and Content Filtering", "Part 11 — Data Transfers"),
    ("NZISM.Part14", "Working Off-site", "Part 12 — Working Off-site"),
    ("NZISM.Part15", "Product Security", "Part 13 — Product Security"),
    ("NZISM.Part16", "Software Security", "Part 14 — Software Security"),
    ("NZISM.Part17", "Email and Web Security", "Part 15 — Email and Web Security"),
    ("NZISM.Part18", "Authentication and Identity", "Part 16 — Authentication and Identity"),
    ("NZISM.Part19", "Gateway Security", "Part 17 — Gateway Security"),
    ("NZISM.Part20", "Virtualisation", "Part 18 — Virtualisation"),
    ("NZISM.Part21", "Emerging Technologies", "Part 19 — Emerging Technologies"),
    ("NZISM.Part22", "Incident Response", "Part 20 — Incident Response"),
    ("NZISM.Part23", "Business Continuity and Disaster Recovery", "Part 21 — Business Continuity and DR"),
]

emit_control_catalog(
    framework_id="nz-nzism",
    framework_name="New Zealand Information Security Manual (NZISM)",
    version="Version 3.7 (Dec 2024)",
    source="Government Communications Security Bureau (GCSB) — https://nzism.gcsb.govt.nz (Creative Commons BY 4.0)",
    families=sorted({f for _, _, f in NZ_NZISM}),
    controls=[{"id": c, "title": t, "description": t, "family": f} for c, t, f in NZ_NZISM],
    tier="A",
    subdir="international",
)


# ---------------------------------------------------------------------------
# UK DPA 2018 (Data Protection Act) — implements GDPR in UK law post-Brexit
# ---------------------------------------------------------------------------

DPA_2018_REGIME = {
    "jurisdiction": "UK",
    "effective_date": "2018-05-25",
    "subject_rights": ["access", "delete", "correct", "portability", "restrict-processing", "object"],
    "data_minimization_required": True,
    "dpia_required": True,
    "breach_notification_threshold_days": 3,
    "breach_notification_to_subjects": True,
    "private_right_of_action": True,
    "regulator": "Information Commissioner's Office (ICO)",
    "notes": "Post-Brexit UK equivalent to GDPR; also covers law enforcement processing (Part 3) and intelligence services (Part 4).",
}

DPA_2018_OBLIGATIONS = [
    ("UK-DPA.Pt1", "Preliminary — scope and definitions", "General", "Scope, definitions, and interpretation.", "Part 1"),
    ("UK-DPA.Pt2", "General processing (UK GDPR)", "UK GDPR", "Applies UK GDPR rules to general processing.", "Part 2"),
    ("UK-DPA.Pt3", "Law enforcement processing", "Law Enforcement", "Processing for law enforcement purposes under the LED.", "Part 3"),
    ("UK-DPA.Pt4", "Intelligence services processing", "Intelligence", "Processing by the intelligence services.", "Part 4"),
    ("UK-DPA.Pt5", "The Information Commissioner", "Regulator", "ICO powers and duties.", "Part 5"),
    ("UK-DPA.Pt6", "Enforcement", "Enforcement", "Enforcement notices, penalties, and offences.", "Part 6"),
    ("UK-DPA.Pt7", "Supplementary and final provisions", "Misc", "Miscellaneous provisions.", "Part 7"),
]

emit_obligation_catalog(
    framework_id="uk-dpa-2018",
    framework_name="UK Data Protection Act 2018",
    version="c. 12 (2018) as amended",
    source="UK Parliament — https://www.legislation.gov.uk/ukpga/2018/12 (Open Government Licence v3.0)",
    regime=DPA_2018_REGIME,
    obligations=[
        {"id": oid, "title": title, "description": desc, "category": cat, "citation": cite}
        for oid, title, cat, desc, cite in DPA_2018_OBLIGATIONS
    ],
    tier="D",
)


if __name__ == "__main__":
    print("Generated international catalogs.")
