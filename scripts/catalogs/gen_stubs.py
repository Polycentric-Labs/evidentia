"""Generate Tier C stubs — copyrighted control text, public numbering only.

These frameworks have copyrighted authoritative text that cannot be
bundled (AICPA, ISO/IEC, PCI SSC, HITRUST, ISACA, SWIFT, CIS). We ship:
- Public clause/control numbering
- Neutral descriptive titles where defensibly uncopyrightable
- placeholder=true descriptions pointing users at the license URL
- Full license_terms + license_url for user import

Users can import their licensed copies via:
    evidentia catalog import ./my-iso27001.json --force
"""

from __future__ import annotations

from _generators import emit_control_catalog, make_stub_control  # type: ignore[import-not-found]

# ---------------------------------------------------------------------------
# ISO/IEC 27001:2022 Annex A — 93 controls across 4 themes
# ---------------------------------------------------------------------------

ISO_27001_URL = "https://www.iso.org/standard/27001"

ISO_27001_ANNEX_A = [
    # 5 — Organizational controls (37)
    ("A.5.1", "Policies for information security", "5. Organizational controls"),
    ("A.5.2", "Information security roles and responsibilities", "5. Organizational controls"),
    ("A.5.3", "Segregation of duties", "5. Organizational controls"),
    ("A.5.4", "Management responsibilities", "5. Organizational controls"),
    ("A.5.5", "Contact with authorities", "5. Organizational controls"),
    ("A.5.6", "Contact with special interest groups", "5. Organizational controls"),
    ("A.5.7", "Threat intelligence", "5. Organizational controls"),
    ("A.5.8", "Information security in project management", "5. Organizational controls"),
    ("A.5.9", "Inventory of information and other associated assets", "5. Organizational controls"),
    ("A.5.10", "Acceptable use of information and other associated assets", "5. Organizational controls"),
    ("A.5.11", "Return of assets", "5. Organizational controls"),
    ("A.5.12", "Classification of information", "5. Organizational controls"),
    ("A.5.13", "Labelling of information", "5. Organizational controls"),
    ("A.5.14", "Information transfer", "5. Organizational controls"),
    ("A.5.15", "Access control", "5. Organizational controls"),
    ("A.5.16", "Identity management", "5. Organizational controls"),
    ("A.5.17", "Authentication information", "5. Organizational controls"),
    ("A.5.18", "Access rights", "5. Organizational controls"),
    ("A.5.19", "Information security in supplier relationships", "5. Organizational controls"),
    ("A.5.20", "Addressing information security within supplier agreements", "5. Organizational controls"),
    ("A.5.21", "Managing information security in the ICT supply chain", "5. Organizational controls"),
    ("A.5.22", "Monitoring, review and change management of supplier services", "5. Organizational controls"),
    ("A.5.23", "Information security for use of cloud services", "5. Organizational controls"),
    ("A.5.24", "Information security incident management planning and preparation", "5. Organizational controls"),
    ("A.5.25", "Assessment and decision on information security events", "5. Organizational controls"),
    ("A.5.26", "Response to information security incidents", "5. Organizational controls"),
    ("A.5.27", "Learning from information security incidents", "5. Organizational controls"),
    ("A.5.28", "Collection of evidence", "5. Organizational controls"),
    ("A.5.29", "Information security during disruption", "5. Organizational controls"),
    ("A.5.30", "ICT readiness for business continuity", "5. Organizational controls"),
    ("A.5.31", "Legal, statutory, regulatory and contractual requirements", "5. Organizational controls"),
    ("A.5.32", "Intellectual property rights", "5. Organizational controls"),
    ("A.5.33", "Protection of records", "5. Organizational controls"),
    ("A.5.34", "Privacy and protection of PII", "5. Organizational controls"),
    ("A.5.35", "Independent review of information security", "5. Organizational controls"),
    ("A.5.36", "Compliance with policies, rules and standards for information security", "5. Organizational controls"),
    ("A.5.37", "Documented operating procedures", "5. Organizational controls"),
    # 6 — People controls (8)
    ("A.6.1", "Screening", "6. People controls"),
    ("A.6.2", "Terms and conditions of employment", "6. People controls"),
    ("A.6.3", "Information security awareness, education and training", "6. People controls"),
    ("A.6.4", "Disciplinary process", "6. People controls"),
    ("A.6.5", "Responsibilities after termination or change of employment", "6. People controls"),
    ("A.6.6", "Confidentiality or non-disclosure agreements", "6. People controls"),
    ("A.6.7", "Remote working", "6. People controls"),
    ("A.6.8", "Information security event reporting", "6. People controls"),
    # 7 — Physical controls (14)
    ("A.7.1", "Physical security perimeters", "7. Physical controls"),
    ("A.7.2", "Physical entry", "7. Physical controls"),
    ("A.7.3", "Securing offices, rooms and facilities", "7. Physical controls"),
    ("A.7.4", "Physical security monitoring", "7. Physical controls"),
    ("A.7.5", "Protecting against physical and environmental threats", "7. Physical controls"),
    ("A.7.6", "Working in secure areas", "7. Physical controls"),
    ("A.7.7", "Clear desk and clear screen", "7. Physical controls"),
    ("A.7.8", "Equipment siting and protection", "7. Physical controls"),
    ("A.7.9", "Security of assets off-premises", "7. Physical controls"),
    ("A.7.10", "Storage media", "7. Physical controls"),
    ("A.7.11", "Supporting utilities", "7. Physical controls"),
    ("A.7.12", "Cabling security", "7. Physical controls"),
    ("A.7.13", "Equipment maintenance", "7. Physical controls"),
    ("A.7.14", "Secure disposal or re-use of equipment", "7. Physical controls"),
    # 8 — Technological controls (34)
    ("A.8.1", "User endpoint devices", "8. Technological controls"),
    ("A.8.2", "Privileged access rights", "8. Technological controls"),
    ("A.8.3", "Information access restriction", "8. Technological controls"),
    ("A.8.4", "Access to source code", "8. Technological controls"),
    ("A.8.5", "Secure authentication", "8. Technological controls"),
    ("A.8.6", "Capacity management", "8. Technological controls"),
    ("A.8.7", "Protection against malware", "8. Technological controls"),
    ("A.8.8", "Management of technical vulnerabilities", "8. Technological controls"),
    ("A.8.9", "Configuration management", "8. Technological controls"),
    ("A.8.10", "Information deletion", "8. Technological controls"),
    ("A.8.11", "Data masking", "8. Technological controls"),
    ("A.8.12", "Data leakage prevention", "8. Technological controls"),
    ("A.8.13", "Information backup", "8. Technological controls"),
    ("A.8.14", "Redundancy of information processing facilities", "8. Technological controls"),
    ("A.8.15", "Logging", "8. Technological controls"),
    ("A.8.16", "Monitoring activities", "8. Technological controls"),
    ("A.8.17", "Clock synchronization", "8. Technological controls"),
    ("A.8.18", "Use of privileged utility programs", "8. Technological controls"),
    ("A.8.19", "Installation of software on operational systems", "8. Technological controls"),
    ("A.8.20", "Networks security", "8. Technological controls"),
    ("A.8.21", "Security of network services", "8. Technological controls"),
    ("A.8.22", "Segregation of networks", "8. Technological controls"),
    ("A.8.23", "Web filtering", "8. Technological controls"),
    ("A.8.24", "Use of cryptography", "8. Technological controls"),
    ("A.8.25", "Secure development life cycle", "8. Technological controls"),
    ("A.8.26", "Application security requirements", "8. Technological controls"),
    ("A.8.27", "Secure system architecture and engineering principles", "8. Technological controls"),
    ("A.8.28", "Secure coding", "8. Technological controls"),
    ("A.8.29", "Security testing in development and acceptance", "8. Technological controls"),
    ("A.8.30", "Outsourced development", "8. Technological controls"),
    ("A.8.31", "Separation of development, test and production environments", "8. Technological controls"),
    ("A.8.32", "Change management", "8. Technological controls"),
    ("A.8.33", "Test information", "8. Technological controls"),
    ("A.8.34", "Protection of information systems during audit testing", "8. Technological controls"),
]

emit_control_catalog(
    framework_id="iso-27001-2022",
    framework_name="ISO/IEC 27001:2022 (Annex A controls)",
    version="2022",
    source="ISO/IEC — ISO/IEC 27001:2022",
    families=["5. Organizational controls", "6. People controls", "7. Physical controls", "8. Technological controls"],
    controls=[make_stub_control(c, t, f, ISO_27001_URL) for c, t, f in ISO_27001_ANNEX_A],
    tier="C",
    placeholder=True,
    license_required=True,
    license_terms=(
        "© ISO/IEC. Control text is copyrighted. Ships as a stub with public Annex A numbering and neutral "
        "control titles. Purchase the standard from ISO and import your licensed copy via `evidentia catalog import`."
    ),
    license_url=ISO_27001_URL,
)


# ---------------------------------------------------------------------------
# ISO/IEC 27002:2022 — same 93 controls as 27001 Annex A with guidance
# ---------------------------------------------------------------------------

emit_control_catalog(
    framework_id="iso-27002-2022",
    framework_name="ISO/IEC 27002:2022 — Code of Practice for Information Security Controls",
    version="2022",
    source="ISO/IEC — ISO/IEC 27002:2022",
    families=["5. Organizational controls", "6. People controls", "7. Physical controls", "8. Technological controls"],
    controls=[make_stub_control(c, t, f, "https://www.iso.org/standard/27002") for c, t, f in ISO_27001_ANNEX_A],
    tier="C",
    placeholder=True,
    license_required=True,
    license_terms=(
        "© ISO/IEC. Control text and implementation guidance are copyrighted. Same 93 controls as "
        "ISO 27001:2022 Annex A, but with detailed implementation guidance (ships as stub \u2014 purchase from ISO)."
    ),
    license_url="https://www.iso.org/standard/27002",
)


# ---------------------------------------------------------------------------
# ISO/IEC 27017:2015 is maintained in stubs/iso-27017-2015.yaml.
# Do not generate a competing JSON catalog for the same framework id.


# ---------------------------------------------------------------------------
# ISO/IEC 27018:2019 — PII in public cloud
# ---------------------------------------------------------------------------

emit_control_catalog(
    framework_id="iso-27018-2019",
    framework_name="ISO/IEC 27018:2019 — Protection of PII in Public Clouds",
    version="2019",
    source="ISO/IEC — ISO/IEC 27018:2019",
    families=["PII-specific extensions"],
    controls=[
        make_stub_control(
            f"A.{i + 1}",
            f"ISO 27018 control A.{i + 1}",
            "PII-specific extensions",
            "https://www.iso.org/standard/76559",
        )
        for i in range(25)
    ],
    tier="C",
    placeholder=True,
    license_required=True,
    license_terms="© ISO/IEC.",
    license_url="https://www.iso.org/standard/76559",
)


# ---------------------------------------------------------------------------
# ISO/IEC 27701:2019 — Privacy Information Management System (PIMS)
# ---------------------------------------------------------------------------

emit_control_catalog(
    framework_id="iso-27701-2019",
    framework_name="ISO/IEC 27701:2019 — Privacy Information Management",
    version="2019",
    source="ISO/IEC — ISO/IEC 27701:2019",
    families=["Annex A — PII Controllers", "Annex B — PII Processors"],
    controls=[
        make_stub_control(
            f"A.7.{i + 1}",
            f"PII controller control A.7.{i + 1}",
            "Annex A \u2014 PII Controllers",
            "https://www.iso.org/standard/71670",
        )
        for i in range(31)
    ]
    + [
        make_stub_control(
            f"B.8.{i + 1}",
            f"PII processor control B.8.{i + 1}",
            "Annex B \u2014 PII Processors",
            "https://www.iso.org/standard/71670",
        )
        for i in range(18)
    ],
    tier="C",
    placeholder=True,
    license_required=True,
    license_terms="© ISO/IEC.",
    license_url="https://www.iso.org/standard/71670",
)


# ---------------------------------------------------------------------------
# ISO/IEC 42001:2023 — AI Management System
# ---------------------------------------------------------------------------

# Annex A of ISO/IEC 42001:2023 has 38 controls under nine objectives, A.2
# through A.10 (the first entry under each objective is the objective
# statement itself, so control numbering within each objective starts at
# .2). These are the published Annex A control identifiers and neutral
# titles, not sequential placeholders: verified against two independent
# public summaries on 2026-09-07.
ISO_42001_URL = "https://www.iso.org/standard/81230"

ISO_42001_ANNEX_A = [
    ("A.2.2", "AI policy", "A.2 Policies related to AI"),
    ("A.2.3", "Alignment with other organizational policies", "A.2 Policies related to AI"),
    ("A.2.4", "Review of the AI policy", "A.2 Policies related to AI"),
    ("A.3.2", "AI roles and responsibilities", "A.3 Internal organization"),
    ("A.3.3", "Reporting of concerns", "A.3 Internal organization"),
    ("A.4.2", "Resource documentation", "A.4 Resources for AI systems"),
    ("A.4.3", "Data resources", "A.4 Resources for AI systems"),
    ("A.4.4", "Tooling resources", "A.4 Resources for AI systems"),
    ("A.4.5", "System and computing resources", "A.4 Resources for AI systems"),
    ("A.4.6", "Human resources", "A.4 Resources for AI systems"),
    ("A.5.2", "AI system impact assessment process", "A.5 Assessing impacts of AI systems"),
    ("A.5.3", "Documentation of AI system impact assessments", "A.5 Assessing impacts of AI systems"),
    ("A.5.4", "Assessing AI system impact on individuals or groups", "A.5 Assessing impacts of AI systems"),
    ("A.5.5", "Assessing societal impacts of AI systems", "A.5 Assessing impacts of AI systems"),
    ("A.6.1.2", "Objectives for responsible development of AI systems", "A.6 AI system life cycle"),
    ("A.6.1.3", "Processes for responsible design and development of AI systems", "A.6 AI system life cycle"),
    ("A.6.2.2", "AI system requirements and specification", "A.6 AI system life cycle"),
    ("A.6.2.3", "Documentation of AI system design and development", "A.6 AI system life cycle"),
    ("A.6.2.4", "AI system verification and validation", "A.6 AI system life cycle"),
    ("A.6.2.5", "AI system deployment", "A.6 AI system life cycle"),
    ("A.6.2.6", "AI system operation and monitoring", "A.6 AI system life cycle"),
    ("A.6.2.7", "AI system technical documentation", "A.6 AI system life cycle"),
    ("A.6.2.8", "AI system recording of event logs", "A.6 AI system life cycle"),
    ("A.7.2", "Data for development and enhancement of AI systems", "A.7 Data for AI systems"),
    ("A.7.3", "Acquisition of data", "A.7 Data for AI systems"),
    ("A.7.4", "Quality of data for AI systems", "A.7 Data for AI systems"),
    ("A.7.5", "Data provenance", "A.7 Data for AI systems"),
    ("A.7.6", "Data preparation", "A.7 Data for AI systems"),
    ("A.8.2", "System documentation and information for users", "A.8 Information for interested parties of AI systems"),
    ("A.8.3", "External reporting", "A.8 Information for interested parties of AI systems"),
    ("A.8.4", "Communication of incidents", "A.8 Information for interested parties of AI systems"),
    ("A.8.5", "Information for interested parties", "A.8 Information for interested parties of AI systems"),
    ("A.9.2", "Processes for responsible use of AI systems", "A.9 Use of AI systems"),
    ("A.9.3", "Objectives for responsible use of AI systems", "A.9 Use of AI systems"),
    ("A.9.4", "Intended use of the AI system", "A.9 Use of AI systems"),
    ("A.10.2", "Allocating responsibilities", "A.10 Third-party and customer relationships"),
    ("A.10.3", "Suppliers", "A.10 Third-party and customer relationships"),
    ("A.10.4", "Customers", "A.10 Third-party and customer relationships"),
]

emit_control_catalog(
    framework_id="iso-42001-2023",
    framework_name="ISO/IEC 42001:2023 — AI Management System",
    version="2023",
    source="ISO/IEC — ISO/IEC 42001:2023",
    families=[
        "A.2 Policies related to AI",
        "A.3 Internal organization",
        "A.4 Resources for AI systems",
        "A.5 Assessing impacts of AI systems",
        "A.6 AI system life cycle",
        "A.7 Data for AI systems",
        "A.8 Information for interested parties of AI systems",
        "A.9 Use of AI systems",
        "A.10 Third-party and customer relationships",
    ],
    controls=[make_stub_control(c, t, f, ISO_42001_URL) for c, t, f in ISO_42001_ANNEX_A],
    tier="C",
    placeholder=True,
    license_required=True,
    license_terms=(
        "© ISO/IEC. Control text is copyrighted. Ships as a stub with public Annex A numbering and "
        "neutral control titles. Purchase the standard from ISO and import your licensed copy via "
        "`evidentia catalog import`."
    ),
    license_url="https://www.iso.org/standard/81230",
)


# ---------------------------------------------------------------------------
# ISO 22301:2019 — Business Continuity
# ---------------------------------------------------------------------------

emit_control_catalog(
    framework_id="iso-22301-2019",
    framework_name="ISO 22301:2019 — Business Continuity Management System",
    version="2019",
    source="ISO — ISO 22301:2019",
    families=["Clause 4-10 BCMS requirements"],
    controls=[
        make_stub_control(
            f"Clause.{i + 4}",
            f"BCMS clause {i + 4}",
            "Clause 4-10 BCMS requirements",
            "https://www.iso.org/standard/75106",
        )
        for i in range(7)
    ],
    tier="C",
    placeholder=True,
    license_required=True,
    license_terms="© ISO.",
    license_url="https://www.iso.org/standard/75106",
)


# ---------------------------------------------------------------------------
# PCI DSS v4.0.1
# ---------------------------------------------------------------------------

PCI_URL = "https://www.pcisecuritystandards.org/document_library/"

PCI_DSS_4 = [
    ("1", "Install and Maintain Network Security Controls", "Build and Maintain a Secure Network"),
    ("2", "Apply Secure Configurations to All System Components", "Build and Maintain a Secure Network"),
    ("3", "Protect Stored Account Data", "Protect Account Data"),
    (
        "4",
        "Protect Cardholder Data with Strong Cryptography During Transmission Over Open, Public Networks",
        "Protect Account Data",
    ),
    ("5", "Protect All Systems and Networks from Malicious Software", "Maintain a Vulnerability Management Program"),
    ("6", "Develop and Maintain Secure Systems and Software", "Maintain a Vulnerability Management Program"),
    (
        "7",
        "Restrict Access to System Components and Cardholder Data by Business Need to Know",
        "Implement Strong Access Control Measures",
    ),
    ("8", "Identify Users and Authenticate Access to System Components", "Implement Strong Access Control Measures"),
    ("9", "Restrict Physical Access to Cardholder Data", "Implement Strong Access Control Measures"),
    (
        "10",
        "Log and Monitor All Access to System Components and Cardholder Data",
        "Regularly Monitor and Test Networks",
    ),
    ("11", "Test Security of Systems and Networks Regularly", "Regularly Monitor and Test Networks"),
    (
        "12",
        "Support Information Security with Organizational Policies and Programs",
        "Maintain an Information Security Policy",
    ),
]

emit_control_catalog(
    framework_id="pci-dss-4.0.1",
    framework_name="PCI DSS v4.0.1",
    version="4.0.1 (June 2024)",
    source="PCI Security Standards Council",
    families=[
        "Build and Maintain a Secure Network",
        "Protect Account Data",
        "Maintain a Vulnerability Management Program",
        "Implement Strong Access Control Measures",
        "Regularly Monitor and Test Networks",
        "Maintain an Information Security Policy",
    ],
    controls=[make_stub_control(c, t, f, PCI_URL) for c, t, f in PCI_DSS_4],
    tier="C",
    placeholder=True,
    license_required=True,
    license_terms=(
        "© PCI Security Standards Council. PCI DSS text is copyrighted. Download the standard "
        "(free registration required) from PCI SSC and import your licensed copy."
    ),
    license_url=PCI_URL,
)


# ---------------------------------------------------------------------------
# HITRUST CSF v11
# ---------------------------------------------------------------------------

HITRUST_DOMAINS = [
    ("01", "Information Protection Program"),
    ("02", "Endpoint Protection"),
    ("03", "Portable Media Security"),
    ("04", "Mobile Device Security"),
    ("05", "Wireless Security"),
    ("06", "Configuration Management"),
    ("07", "Vulnerability Management"),
    ("08", "Network Protection"),
    ("09", "Transmission Protection"),
    ("10", "Password Management"),
    ("11", "Access Control"),
    ("12", "Audit Logging & Monitoring"),
    ("13", "Education, Training and Awareness"),
    ("14", "Third Party Assurance"),
    ("15", "Incident Management"),
    ("16", "Business Continuity & Disaster Recovery"),
    ("17", "Risk Management"),
    ("18", "Physical & Environmental Security"),
    ("19", "Data Protection & Privacy"),
]

emit_control_catalog(
    framework_id="hitrust-csf-v11",
    framework_name="HITRUST CSF v11",
    version="v11",
    source="HITRUST Alliance",
    families=[f"{n}. {d}" for n, d in HITRUST_DOMAINS],
    controls=[
        make_stub_control(
            f"{num}.{chr(ord('a') + i)}",
            f"HITRUST CSF objective {num}.{chr(ord('a') + i)}",
            f"{num}. {domain}",
            "https://hitrustalliance.net/csf",
        )
        for num, domain in HITRUST_DOMAINS
        for i in range(5)  # sample 5 objectives per domain
    ],
    tier="C",
    placeholder=True,
    license_required=True,
    license_terms="© HITRUST Alliance. The HITRUST Common Security Framework is subscription-licensed.",
    license_url="https://hitrustalliance.net/csf",
)


# ---------------------------------------------------------------------------
# COBIT 2019
# ---------------------------------------------------------------------------

COBIT_DOMAINS = [
    ("EDM", "Evaluate, Direct and Monitor"),
    ("APO", "Align, Plan and Organise"),
    ("BAI", "Build, Acquire and Implement"),
    ("DSS", "Deliver, Service and Support"),
    ("MEA", "Monitor, Evaluate and Assess"),
]

COBIT_OBJECTIVES = [
    ("EDM01", "Ensured Governance Framework Setting and Maintenance", "EDM"),
    ("EDM02", "Ensured Benefits Delivery", "EDM"),
    ("EDM03", "Ensured Risk Optimisation", "EDM"),
    ("EDM04", "Ensured Resource Optimisation", "EDM"),
    ("EDM05", "Ensured Stakeholder Engagement", "EDM"),
    ("APO01", "Managed I&T Management Framework", "APO"),
    ("APO02", "Managed Strategy", "APO"),
    ("APO03", "Managed Enterprise Architecture", "APO"),
    ("APO04", "Managed Innovation", "APO"),
    ("APO05", "Managed Portfolio", "APO"),
    ("APO06", "Managed Budget and Costs", "APO"),
    ("APO07", "Managed Human Resources", "APO"),
    ("APO08", "Managed Relationships", "APO"),
    ("APO09", "Managed Service Agreements", "APO"),
    ("APO10", "Managed Vendors", "APO"),
    ("APO11", "Managed Quality", "APO"),
    ("APO12", "Managed Risk", "APO"),
    ("APO13", "Managed Security", "APO"),
    ("APO14", "Managed Data", "APO"),
    ("BAI01", "Managed Programs", "BAI"),
    ("BAI02", "Managed Requirements Definition", "BAI"),
    ("BAI03", "Managed Solutions Identification and Build", "BAI"),
    ("BAI04", "Managed Availability and Capacity", "BAI"),
    ("BAI05", "Managed Organisational Change", "BAI"),
    ("BAI06", "Managed IT Changes", "BAI"),
    ("BAI07", "Managed IT Change Acceptance and Transitioning", "BAI"),
    ("BAI08", "Managed Knowledge", "BAI"),
    ("BAI09", "Managed Assets", "BAI"),
    ("BAI10", "Managed Configuration", "BAI"),
    ("BAI11", "Managed Projects", "BAI"),
    ("DSS01", "Managed Operations", "DSS"),
    ("DSS02", "Managed Service Requests and Incidents", "DSS"),
    ("DSS03", "Managed Problems", "DSS"),
    ("DSS04", "Managed Continuity", "DSS"),
    ("DSS05", "Managed Security Services", "DSS"),
    ("DSS06", "Managed Business Process Controls", "DSS"),
    ("MEA01", "Managed Performance and Conformance Monitoring", "MEA"),
    ("MEA02", "Managed System of Internal Control", "MEA"),
    ("MEA03", "Managed Compliance With External Requirements", "MEA"),
    ("MEA04", "Managed Assurance", "MEA"),
]

emit_control_catalog(
    framework_id="cobit-2019",
    framework_name="COBIT 2019",
    version="2019 (with 2022 focus area guides)",
    source="ISACA",
    families=[f"{code}: {name}" for code, name in COBIT_DOMAINS],
    controls=[
        make_stub_control(
            cid,
            title,
            next(f for code, name in COBIT_DOMAINS if code == fam_code for f in [f"{code}: {name}"]),
            "https://www.isaca.org/resources/cobit",
        )
        for cid, title, fam_code in COBIT_OBJECTIVES
    ],
    tier="C",
    placeholder=True,
    license_required=True,
    license_terms="© ISACA. COBIT framework content is license-protected.",
    license_url="https://www.isaca.org/resources/cobit",
)


# ---------------------------------------------------------------------------
# SWIFT CSCF v2024 — SWIFT Customer Security Controls Framework
# ---------------------------------------------------------------------------

SWIFT_CSCF = [
    ("1.1", "SWIFT Environment Protection", "1. Restrict Internet Access and Protect Critical Systems"),
    ("1.2", "Operating System Privileged Account Control", "1. Restrict Internet Access and Protect Critical Systems"),
    ("1.3", "Virtualisation or Cloud Platform Protection", "1. Restrict Internet Access and Protect Critical Systems"),
    ("1.4", "Restriction of Internet Access", "1. Restrict Internet Access and Protect Critical Systems"),
    (
        "1.5",
        "Customer Environment Protection (A4 architecture)",
        "1. Restrict Internet Access and Protect Critical Systems",
    ),
    ("2.1", "Internal Data Flow Security", "2. Reduce Attack Surface and Vulnerabilities"),
    ("2.2", "Security Updates", "2. Reduce Attack Surface and Vulnerabilities"),
    ("2.3", "System Hardening", "2. Reduce Attack Surface and Vulnerabilities"),
    ("2.4A", "Back Office Data Flow Security", "2. Reduce Attack Surface and Vulnerabilities"),
    ("2.5A", "External Transmission Data Protection", "2. Reduce Attack Surface and Vulnerabilities"),
    ("2.6", "Operator Session Confidentiality and Integrity", "2. Reduce Attack Surface and Vulnerabilities"),
    ("2.7", "Vulnerability Scanning", "2. Reduce Attack Surface and Vulnerabilities"),
    ("2.8A", "Critical Activity Outsourcing", "2. Reduce Attack Surface and Vulnerabilities"),
    ("2.9", "Transaction Business Controls", "2. Reduce Attack Surface and Vulnerabilities"),
    ("2.10", "Application Hardening", "2. Reduce Attack Surface and Vulnerabilities"),
    ("2.11A", "RMA Business Controls", "2. Reduce Attack Surface and Vulnerabilities"),
    ("3.1", "Physical Security", "3. Physically Secure the Environment"),
    ("4.1", "Password Policy", "4. Prevent Compromise of Credentials"),
    ("4.2", "Multi-factor Authentication", "4. Prevent Compromise of Credentials"),
    ("5.1", "Logical Access Control", "5. Manage Identities and Segregate Privileges"),
    ("5.2", "Token Management", "5. Manage Identities and Segregate Privileges"),
    ("5.3A", "Personnel Vetting Process", "5. Manage Identities and Segregate Privileges"),
    ("5.4", "Physical and Logical Password Storage", "5. Manage Identities and Segregate Privileges"),
    ("6.1", "Malware Protection", "6. Detect Anomalous Activity to Systems or Transaction Records"),
    ("6.2", "Software Integrity", "6. Detect Anomalous Activity to Systems or Transaction Records"),
    ("6.3", "Database Integrity", "6. Detect Anomalous Activity to Systems or Transaction Records"),
    ("6.4", "Logging and Monitoring", "6. Detect Anomalous Activity to Systems or Transaction Records"),
    ("6.5A", "Intrusion Detection", "6. Detect Anomalous Activity to Systems or Transaction Records"),
    ("7.1", "Cyber Incident Response Planning", "7. Plan for Incident Response and Information Sharing"),
    ("7.2", "Security Training and Awareness", "7. Plan for Incident Response and Information Sharing"),
    ("7.3A", "Penetration Testing", "7. Plan for Incident Response and Information Sharing"),
    ("7.4A", "Scenario Risk Assessment", "7. Plan for Incident Response and Information Sharing"),
    ("7.5", "Incident Response Collaboration", "7. Plan for Incident Response and Information Sharing"),
]

emit_control_catalog(
    framework_id="swift-cscf-2024",
    framework_name="SWIFT Customer Security Controls Framework (CSCF) v2024",
    version="v2024",
    source="SWIFT",
    families=sorted({f for _, _, f in SWIFT_CSCF}),
    controls=[
        make_stub_control(c, t, f, "https://www.swift.com/myswift/customer-security-programme-csp")
        for c, t, f in SWIFT_CSCF
    ],
    tier="C",
    placeholder=True,
    license_required=True,
    license_terms="© SWIFT. CSCF is available to SWIFT customers via MySWIFT.",
    license_url="https://www.swift.com/myswift/customer-security-programme-csp",
)


# ---------------------------------------------------------------------------
# CIS Controls v8.1 is maintained in stubs/cis-controls-v8.1.yaml.
# Do not generate a competing JSON catalog for the same framework id.


# ---------------------------------------------------------------------------
# CIS Benchmark samples (AWS, Azure, GCP, Kubernetes, RHEL 9)
# ---------------------------------------------------------------------------

for bench_id, bench_name in [
    ("cis-benchmark-aws", "CIS Amazon Web Services Foundations Benchmark"),
    ("cis-benchmark-azure", "CIS Microsoft Azure Foundations Benchmark"),
    ("cis-benchmark-gcp", "CIS Google Cloud Platform Foundations Benchmark"),
    ("cis-benchmark-kubernetes", "CIS Kubernetes Benchmark"),
    ("cis-benchmark-rhel9", "CIS Red Hat Enterprise Linux 9 Benchmark"),
]:
    emit_control_catalog(
        framework_id=bench_id,
        framework_name=bench_name,
        version="Current",
        source="Center for Internet Security (CIS)",
        families=["Sections 1-5+ (see benchmark)"],
        controls=[
            make_stub_control(
                f"{bench_id}.1.{i + 1}",
                f"Benchmark control 1.{i + 1}",
                "Sections 1-5+ (see benchmark)",
                f"https://www.cisecurity.org/benchmark/{bench_id.replace('cis-benchmark-', '')}",
            )
            for i in range(20)
        ],
        tier="C",
        placeholder=True,
        license_required=True,
        license_terms=(
            "© Center for Internet Security. CIS Benchmarks are freely downloadable; redistribution "
            "in catalog form requires CIS licensing."
        ),
        license_url="https://www.cisecurity.org/cis-benchmarks",
    )


# ---------------------------------------------------------------------------
# Secure Controls Framework (SCF) 2024 — sample
# ---------------------------------------------------------------------------

SCF_DOMAINS = [
    "Governance, Risk, and Compliance (GRC)",
    "Asset Management (AST)",
    "Business Continuity (BCD)",
    "Capacity & Performance Planning (CAP)",
    "Change Management (CHG)",
    "Cloud Security (CLD)",
    "Compliance (CPL)",
    "Configuration Management (CFG)",
    "Continuous Monitoring (MON)",
    "Cryptographic Protections (CRY)",
    "Data Classification & Handling (DCH)",
    "Endpoint Security (END)",
    "Human Resources Security (HRS)",
    "Identification & Authentication (IAC)",
    "Incident Response (IRO)",
    "Information Assurance (IAO)",
    "Maintenance (MNT)",
    "Mobile Device Management (MDM)",
    "Network Security (NET)",
    "Physical & Environmental Security (PES)",
    "Privacy (PRI)",
    "Project Management (PRM)",
    "Risk Management (RSK)",
    "Security Operations (OPS)",
    "Security Awareness and Training (SAT)",
    "Secure Engineering & Architecture (SEA)",
    "Technology Development & Acquisition (TDA)",
    "Third-Party Management (TPM)",
    "Threat Management (THR)",
    "Vulnerability & Patch Management (VPM)",
    "Web Security (WEB)",
]

emit_control_catalog(
    framework_id="scf-2024",
    framework_name="Secure Controls Framework (SCF) 2024",
    version="2024",
    source="Secure Controls Framework Council",
    families=SCF_DOMAINS,
    controls=[
        make_stub_control(
            f"{domain.split('(')[1].rstrip(')')}-{i + 1:02d}",
            f"SCF control {domain.split('(')[1].rstrip(')')}-{i + 1:02d}",
            domain,
            "https://securecontrolsframework.com",
        )
        for domain in SCF_DOMAINS
        for i in range(3)
    ],
    tier="C",
    placeholder=True,
    license_required=True,
    license_terms=(
        "© Secure Controls Framework. SCF is licensed CC BY-ND \u2014 no derivatives. Download the current SCF "
        "spreadsheet from securecontrolsframework.com and import your copy."
    ),
    license_url="https://securecontrolsframework.com",
)


# ---------------------------------------------------------------------------
# IEC 62443 — Industrial Communication Networks — IT Security (ICS/OT)
# ---------------------------------------------------------------------------

IEC_62443 = [
    ("1.1", "IEC 62443-1-1: Terminology, concepts and models", "Part 1 — General"),
    ("2.1", "IEC 62443-2-1: Establishing an IACS security program", "Part 2 — Policies and Procedures"),
    ("2.3", "IEC 62443-2-3: Patch management in the IACS environment", "Part 2 — Policies and Procedures"),
    (
        "2.4",
        "IEC 62443-2-4: Security program requirements for IACS service providers",
        "Part 2 \u2014 Policies and Procedures",
    ),
    ("3.2", "IEC 62443-3-2: Security risk assessment for system design", "Part 3 — System"),
    ("3.3", "IEC 62443-3-3: System security requirements and security levels", "Part 3 — System"),
    ("4.1", "IEC 62443-4-1: Secure product development lifecycle requirements", "Part 4 — Component"),
    ("4.2", "IEC 62443-4-2: Technical security requirements for IACS components", "Part 4 — Component"),
]

emit_control_catalog(
    framework_id="iec-62443",
    framework_name="IEC 62443 — Industrial Automation and Control Systems Security",
    version="Multiple parts (2018-2023)",
    source="IEC/ISA",
    families=["Part 1 — General", "Part 2 — Policies and Procedures", "Part 3 — System", "Part 4 — Component"],
    controls=[
        make_stub_control(
            c, t, f, "https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards"
        )
        for c, t, f in IEC_62443
    ],
    tier="C",
    placeholder=True,
    license_required=True,
    license_terms="© IEC/ISA. Purchase individual parts from ISA or IEC.",
    license_url="https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards",
)


if __name__ == "__main__":
    print("Generated Tier C stubs.")
