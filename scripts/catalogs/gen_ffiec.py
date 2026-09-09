"""Generate retained FFIEC catalogs and current handbook heading catalogs.

Historical control tables retain their IDs and descriptions for existing
assessments. Operations and CAT carry dated lifecycle notices. The current
booklet generator adds six catalogs from reviewed public HTML body headings.
These sources and scopes are recorded in each catalog's metadata.
"""

from __future__ import annotations

from _generators import emit_control_catalog  # type: ignore[import-not-found]
from gen_ffiec_current import main as generate_current_booklets


# ---------------------------------------------------------------------------
# FFIEC IT Examination Handbook — Outsourcing Technology Services booklet
# ---------------------------------------------------------------------------
#
# Structure: 7 examination categories (Roles + Responsibilities, Risk
# Management, Outsourcing Decision, Vendor Selection, Contract Issues,
# Ongoing Monitoring, Related Topics) × ~5 sub-elements each = ~30
# control items.
#
# Each control's ``id`` is structured as ``<chapter>.<section>``
# matching the booklet's numbered subsections so operators can
# trace from the bundled catalog back to the source PDF.
FFIEC_OUTSOURCING_URL = (
    "https://ithandbook.ffiec.gov/it-booklets/"
    "outsourcing-technology-services.aspx"
)


def _ctl(
    id_: str,
    title: str,
    description: str,
    family: str,
) -> dict[str, str]:
    return {
        "id": id_,
        "title": title,
        "description": description,
        "family": family,
    }


# Control catalog. Per the FFIEC public-domain stance, full
# authoritative paraphrases are bundled. Operators consuming this
# catalog should refer to the source URL for the full booklet
# narrative; the bundled descriptions are scoped to the
# control-objective level.
FFIEC_OUTSOURCING_CONTROLS: list[dict[str, str]] = [
    # --- 1. Roles + Responsibilities ---
    _ctl(
        "1.1",
        "Board and Senior Management Responsibility",
        "The board of directors and senior management are "
        "responsible for understanding the risks associated with "
        "outsourcing arrangements and ensuring effective risk "
        "management throughout the relationship lifecycle.",
        "1. Roles + Responsibilities",
    ),
    _ctl(
        "1.2",
        "Outsourcing Risk Management Function",
        "The institution establishes a clearly-defined outsourcing "
        "risk management function with documented authority + "
        "reporting lines to the board.",
        "1. Roles + Responsibilities",
    ),
    _ctl(
        "1.3",
        "Information Security Officer Involvement",
        "The Information Security Officer is involved in vendor "
        "selection + ongoing-monitoring decisions for arrangements "
        "involving sensitive customer data or operational impact.",
        "1. Roles + Responsibilities",
    ),
    # --- 2. Risk Management ---
    _ctl(
        "2.1",
        "Risk Assessment Methodology",
        "Outsourcing risk assessments cover: strategic / reputational "
        "/ operational / transaction / credit / compliance / country "
        "risks, prioritized by criticality of the outsourced "
        "function.",
        "2. Risk Management",
    ),
    _ctl(
        "2.2",
        "Critical Function Identification",
        "The institution identifies its critical business functions "
        "and applies enhanced due diligence + monitoring to vendors "
        "supporting them.",
        "2. Risk Management",
    ),
    _ctl(
        "2.3",
        "Concentration Risk Analysis",
        "The institution assesses concentration risk arising from "
        "reliance on a small number of vendors, geographic "
        "concentrations, or shared-service-provider relationships.",
        "2. Risk Management",
    ),
    _ctl(
        "2.4",
        "Subcontractor (4th Party) Risk",
        "The institution maintains visibility into critical "
        "subcontractor relationships used by primary vendors and "
        "extends ongoing-monitoring expectations to those parties.",
        "2. Risk Management",
    ),
    # --- 3. Outsourcing Decision ---
    _ctl(
        "3.1",
        "Strategic Alignment Review",
        "The decision to outsource is documented and reviewed for "
        "alignment with the institution's strategic objectives, "
        "regulatory obligations, and risk appetite.",
        "3. Outsourcing Decision",
    ),
    _ctl(
        "3.2",
        "Cost-Benefit + Risk-Adjusted Analysis",
        "The outsourcing business case includes risk-adjusted "
        "analysis of in-house vs vendor cost, capability, and "
        "quality dimensions.",
        "3. Outsourcing Decision",
    ),
    _ctl(
        "3.3",
        "Regulatory Notification (where required)",
        "The institution notifies the appropriate federal regulator "
        "of material outsourcing arrangements per 12 USC §1867 "
        "(BSCA) when applicable.",
        "3. Outsourcing Decision",
    ),
    # --- 4. Vendor Selection ---
    _ctl(
        "4.1",
        "Due Diligence Scope",
        "Vendor due diligence covers: financial condition, "
        "experience + reputation, business continuity capability, "
        "information security posture, regulatory compliance "
        "history, insurance coverage, and reference checks.",
        "4. Vendor Selection",
    ),
    _ctl(
        "4.2",
        "Information Security Posture Review",
        "Vendor security posture review covers: encryption + key "
        "management, access controls, audit logging, incident "
        "response, vulnerability + patch management, third-party "
        "audit reports (SOC 2, ISO 27001).",
        "4. Vendor Selection",
    ),
    _ctl(
        "4.3",
        "Business Continuity + Disaster Recovery Capability",
        "Vendor BC/DR capability is evaluated, including documented "
        "RTO + RPO targets, tested recovery procedures, and "
        "geographic resilience.",
        "4. Vendor Selection",
    ),
    _ctl(
        "4.4",
        "Pre-Contract Site Visit + Audit",
        "For critical relationships, the institution performs an "
        "on-site or virtual review of vendor facilities + controls "
        "before contract execution.",
        "4. Vendor Selection",
    ),
    # --- 5. Contract Issues ---
    _ctl(
        "5.1",
        "Contract Scope and Performance Standards",
        "The contract clearly defines the services in scope, "
        "performance standards (SLAs), and remedies for "
        "non-performance.",
        "5. Contract Issues",
    ),
    _ctl(
        "5.2",
        "Right-to-Audit Clause",
        "The contract grants the institution + its regulators the "
        "right to audit vendor controls + access vendor records "
        "relating to services provided.",
        "5. Contract Issues",
    ),
    _ctl(
        "5.3",
        "Confidentiality + Data Protection",
        "The contract addresses customer-data protection, "
        "confidentiality, breach notification timelines, and data "
        "return / destruction at contract end.",
        "5. Contract Issues",
    ),
    _ctl(
        "5.4",
        "Subcontracting Restrictions",
        "The contract restricts vendor subcontracting (assignment) "
        "to require prior institution approval for material "
        "transfers; flow-down clauses bind subcontractors to the "
        "same protections.",
        "5. Contract Issues",
    ),
    _ctl(
        "5.5",
        "Termination + Exit Provisions",
        "The contract includes clear termination triggers, notice "
        "periods, transition assistance obligations, and data "
        "return / portability requirements.",
        "5. Contract Issues",
    ),
    _ctl(
        "5.6",
        "Foreign-Based Vendor Considerations",
        "Contracts with foreign-based vendors address governing "
        "law, jurisdiction, regulatory access, and country-risk "
        "factors per FFIEC offshore-outsourcing guidance.",
        "5. Contract Issues",
    ),
    # --- 6. Ongoing Monitoring ---
    _ctl(
        "6.1",
        "Performance Monitoring",
        "Ongoing monitoring covers: SLA performance, financial "
        "condition, control effectiveness (via SOC 2 / ISO 27001 / "
        "right-to-audit), security incidents, regulatory matters.",
        "6. Ongoing Monitoring",
    ),
    _ctl(
        "6.2",
        "Periodic Risk Reassessment",
        "Vendor risk assessments are refreshed on a documented "
        "cadence (typically annual for critical vendors; biennial "
        "for moderate; triennial for low-impact).",
        "6. Ongoing Monitoring",
    ),
    _ctl(
        "6.3",
        "Incident + Issue Tracking",
        "Vendor-side security incidents, control deficiencies, and "
        "SLA misses are tracked + remediated via documented "
        "issue-management processes.",
        "6. Ongoing Monitoring",
    ),
    _ctl(
        "6.4",
        "Change Notification",
        "Vendors are required to notify the institution of material "
        "changes: ownership, key personnel, subcontracting, "
        "service-delivery model, or geographic location.",
        "6. Ongoing Monitoring",
    ),
    _ctl(
        "6.5",
        "Annual Senior-Management + Board Review",
        "Senior management + the board receive at-least-annual "
        "reports on the outsourcing portfolio: vendor list, risk "
        "ratings, performance, incidents, concentration analysis.",
        "6. Ongoing Monitoring",
    ),
    # --- 7. Related Topics ---
    _ctl(
        "7.1",
        "Cloud Computing Considerations",
        "Cloud arrangements receive enhanced scrutiny for shared-"
        "responsibility model clarity, multi-tenancy controls, "
        "data residency, and cross-border data flows.",
        "7. Related Topics",
    ),
    _ctl(
        "7.2",
        "Software-as-a-Service (SaaS) Arrangements",
        "SaaS arrangements are evaluated for vendor lock-in risk, "
        "data portability provisions, and service-availability "
        "track records.",
        "7. Related Topics",
    ),
    _ctl(
        "7.3",
        "Resilience + Concentration Across Critical Functions",
        "The institution's overall outsourcing posture is reviewed "
        "for resilience: avoiding single-point-of-failure vendor "
        "dependencies for critical operations.",
        "7. Related Topics",
    ),
    _ctl(
        "7.4",
        "Affiliate + Group-Level Outsourcing",
        "Intra-group outsourcing is documented + governed under the "
        "same standards as third-party outsourcing, including "
        "affiliate transactions per Regulation W.",
        "7. Related Topics",
    ),
    _ctl(
        "7.5",
        "Records Retention + Examination Access",
        "Vendor-held records are retained per the institution's "
        "retention policy + applicable regulatory requirements; "
        "regulators have access via the right-to-audit clause.",
        "7. Related Topics",
    ),
]


# ---------------------------------------------------------------------------
# FFIEC IT Examination Handbook — Audit booklet
# ---------------------------------------------------------------------------
FFIEC_AUDIT_URL = "https://ithandbook.ffiec.gov/it-booklets/audit.aspx"

FFIEC_AUDIT_CONTROLS: list[dict[str, str]] = [
    # --- 1. Audit Function and Independence ---
    _ctl("1.1", "Audit Charter and Independence",
         "The internal audit function operates under a board-approved "
         "charter establishing organizational independence + reporting "
         "to the board / audit committee.",
         "1. Audit Function and Independence"),
    _ctl("1.2", "Audit Committee Oversight",
         "The audit committee (or equivalent) approves the audit plan, "
         "reviews findings, and oversees remediation of identified issues.",
         "1. Audit Function and Independence"),
    _ctl("1.3", "Auditor Qualifications + Continuing Education",
         "Audit staff possess appropriate IT + financial-services "
         "qualifications + complete annual continuing education to "
         "maintain competency.",
         "1. Audit Function and Independence"),
    _ctl("1.4", "External Audit Coordination",
         "Internal audit coordinates with external auditors + regulatory "
         "examiners to avoid duplication + maximize coverage efficiency.",
         "1. Audit Function and Independence"),
    # --- 2. IT Audit Planning ---
    _ctl("2.1", "Risk-Based Audit Planning",
         "The audit plan is built on a risk assessment covering all "
         "significant IT processes + systems, prioritized by business "
         "criticality + risk magnitude.",
         "2. IT Audit Planning"),
    _ctl("2.2", "Annual Audit Plan Coverage",
         "The annual audit plan covers IT governance, infrastructure, "
         "applications, information security, business continuity, "
         "third-party relationships, + IT operations on a documented cadence.",
         "2. IT Audit Planning"),
    _ctl("2.3", "Audit Universe Maintenance",
         "The audit universe (the population of auditable units) is "
         "documented + refreshed at least annually to reflect new "
         "systems, processes, + third-party relationships.",
         "2. IT Audit Planning"),
    _ctl("2.4", "Resource Allocation + Budget",
         "Audit resources (headcount, budget, tooling) are sized to "
         "deliver the approved audit plan within the planned cycle.",
         "2. IT Audit Planning"),
    _ctl("2.5", "Multi-Year Coverage Strategy",
         "High-risk areas receive at-least-annual coverage; medium-risk "
         "every 2-3 years; low-risk on a longer cycle. Coverage gaps "
         "are documented with rationale.",
         "2. IT Audit Planning"),
    # --- 3. Audit Execution ---
    _ctl("3.1", "Audit Programs + Procedures",
         "Engagement-specific audit programs document scope, objectives, "
         "test procedures, + sample-selection methodology.",
         "3. Audit Execution"),
    _ctl("3.2", "Workpaper Documentation",
         "Audit workpapers document the procedures performed, evidence "
         "obtained, + conclusions reached, with sufficient detail for an "
         "independent reviewer to replicate the work.",
         "3. Audit Execution"),
    _ctl("3.3", "Use of CAATs (Computer-Assisted Audit Techniques)",
         "Auditors use data-analytic + sampling tooling to test "
         "transaction-level controls + identify anomalies at scale.",
         "3. Audit Execution"),
    _ctl("3.4", "Quality-Assurance + Peer Review",
         "Audit work undergoes documented supervisory + peer review "
         "before issuance of the final report.",
         "3. Audit Execution"),
    _ctl("3.5", "Audit Sampling Methodology",
         "Statistical or judgmental sampling methods are documented + "
         "applied consistently; sample sizes are justified relative to "
         "control population + assurance objective.",
         "3. Audit Execution"),
    # --- 4. Audit Reporting ---
    _ctl("4.1", "Findings Classification + Severity",
         "Audit findings are classified by severity (high / moderate / "
         "low) using documented criteria + reported to appropriate "
         "management levels.",
         "4. Audit Reporting"),
    _ctl("4.2", "Management Response + Remediation Commitments",
         "Each finding receives a documented management response with "
         "remediation owner, target date, + commitment to closure.",
         "4. Audit Reporting"),
    _ctl("4.3", "Audit Report Distribution",
         "Audit reports are distributed to appropriate levels: high-"
         "severity findings to the audit committee + senior management; "
         "lower findings to relevant operating management.",
         "4. Audit Reporting"),
    _ctl("4.4", "Trend Analysis + Periodic Reporting",
         "Aggregate audit results + trends are reported to the audit "
         "committee on at least an annual basis.",
         "4. Audit Reporting"),
    # --- 5. Issue Tracking + Follow-Up ---
    _ctl("5.1", "Issue Management System",
         "All audit findings are tracked in a documented system showing "
         "status, target date, owner, + evidence of closure.",
         "5. Issue Tracking + Follow-Up"),
    _ctl("5.2", "Validation of Remediation",
         "Audit independently validates that management's remediation "
         "actions effectively address the underlying control gap before "
         "closing the finding.",
         "5. Issue Tracking + Follow-Up"),
    _ctl("5.3", "Aging + Escalation",
         "Past-due findings escalate through documented thresholds; "
         "findings that age substantially past target receive board / "
         "audit committee attention.",
         "5. Issue Tracking + Follow-Up"),
    _ctl("5.4", "Repeat Findings Analysis",
         "Repeat findings (same control gap re-emerging) are tracked + "
         "analyzed for systemic root cause; chronic repeats trigger "
         "management-level remediation.",
         "5. Issue Tracking + Follow-Up"),
    # --- 6. Specialized Audit Topics ---
    _ctl("6.1", "Information Security Audit",
         "IS audits cover access control, encryption, vulnerability + "
         "patch management, incident response, + security monitoring "
         "controls.",
         "6. Specialized Audit Topics"),
    _ctl("6.2", "Business Continuity + DR Audit",
         "BC/DR audits cover plan documentation, BIA accuracy, "
         "recovery testing, + alignment with the institution's RTO + "
         "RPO commitments.",
         "6. Specialized Audit Topics"),
    _ctl("6.3", "Third-Party / Vendor Audit",
         "Critical vendors receive periodic audit coverage via on-site "
         "visits, SOC report review, or right-to-audit exercises.",
         "6. Specialized Audit Topics"),
    _ctl("6.4", "IT Project Audit",
         "Material IT projects (e.g., core-banking conversions, M&A "
         "system integrations) receive audit coverage at key project "
         "milestones.",
         "6. Specialized Audit Topics"),
    _ctl("6.5", "Cloud + SaaS Audit",
         "Cloud + SaaS arrangements are audited for shared-responsibility "
         "model clarity, vendor SOC report sufficiency, + data-residency "
         "compliance.",
         "6. Specialized Audit Topics"),
    _ctl("6.6", "Application + Change Management Audit",
         "Application development + change management processes are "
         "audited for SDLC adherence, segregation-of-duties, + "
         "production-change controls.",
         "6. Specialized Audit Topics"),
    _ctl("6.7", "Data Governance + Privacy Audit",
         "Data governance (classification, retention, access) + privacy "
         "(GLBA, state laws) processes receive audit coverage on a "
         "documented cadence.",
         "6. Specialized Audit Topics"),
    # --- 7. Audit Function Maturity ---
    _ctl("7.1", "Use of Continuous Auditing Techniques",
         "Where appropriate, the audit function deploys continuous-"
         "auditing tooling to detect control failures in near-real-time "
         "rather than periodic-only review.",
         "7. Audit Function Maturity"),
    _ctl("7.2", "Audit Skill + Tooling Investment",
         "The audit function invests in skills (cloud / cyber / data "
         "analytics) + tooling (CAATs, GRC platforms) to keep pace with "
         "the institution's technology + risk profile.",
         "7. Audit Function Maturity"),
    _ctl("7.3", "External Quality Assessment",
         "The audit function obtains an external quality assessment "
         "(typically every 5 years per IIA standards) confirming "
         "conformance with applicable professional standards.",
         "7. Audit Function Maturity"),
]


# ---------------------------------------------------------------------------
# FFIEC IT Examination Handbook — Management booklet
# ---------------------------------------------------------------------------
FFIEC_MANAGEMENT_URL = "https://ithandbook.ffiec.gov/it-booklets/management.aspx"

FFIEC_MANAGEMENT_CONTROLS: list[dict[str, str]] = [
    # --- 1. IT Governance ---
    _ctl("1.1", "Board Oversight of IT",
         "The board (or designated committee) understands the institution's "
         "IT environment + provides documented oversight of IT strategy, "
         "risk, + investment decisions.",
         "1. IT Governance"),
    _ctl("1.2", "IT Strategic Plan",
         "An IT strategic plan aligned with the institution's business "
         "strategy is documented, board-approved, + refreshed at least "
         "every 3 years.",
         "1. IT Governance"),
    _ctl("1.3", "IT Steering / Governance Committee",
         "An IT steering committee (or equivalent) provides ongoing "
         "tactical governance: project prioritization, resource "
         "allocation, + risk-acceptance decisions.",
         "1. IT Governance"),
    _ctl("1.4", "IT Policies + Standards Framework",
         "Documented IT policies + standards cover information security, "
         "change management, BC/DR, vendor management, + acceptable use, "
         "with annual or change-driven review.",
         "1. IT Governance"),
    # --- 2. Strategic Planning ---
    _ctl("2.1", "IT Investment Prioritization",
         "IT investments are prioritized via a documented process "
         "considering: business value, regulatory requirement, risk "
         "reduction, + technical-debt burden.",
         "2. Strategic Planning"),
    _ctl("2.2", "Technology Roadmap",
         "A documented technology roadmap shows in-flight + planned "
         "initiatives across a 1-3 year horizon, refreshed at least annually.",
         "2. Strategic Planning"),
    _ctl("2.3", "Innovation + Emerging-Tech Posture",
         "The institution maintains a documented posture on emerging "
         "technologies (AI / ML / cloud / blockchain) including evaluation "
         "criteria + risk-tolerance thresholds.",
         "2. Strategic Planning"),
    # --- 3. Organization + Staffing ---
    _ctl("3.1", "IT Organizational Structure",
         "IT roles + reporting relationships are documented with clear "
         "segregation of duties between development, operations, + "
         "security functions.",
         "3. Organization + Staffing"),
    _ctl("3.2", "Information Security Officer Independence",
         "The CISO / Information Security Officer reports independently "
         "of IT operations management to ensure objective security "
         "posture decisions.",
         "3. Organization + Staffing"),
    _ctl("3.3", "Staffing Levels + Skill Coverage",
         "IT staffing levels are sized to support the institution's "
         "operations + risk profile; key-person dependencies are "
         "documented + mitigated.",
         "3. Organization + Staffing"),
    _ctl("3.4", "Background Screening for IT Personnel",
         "IT personnel + privileged-access role holders undergo "
         "documented pre-employment background screening + periodic "
         "re-screening for sensitive roles.",
         "3. Organization + Staffing"),
    _ctl("3.5", "Training + Awareness Program",
         "All staff receive at-least-annual security awareness training; "
         "IT + IS staff receive role-appropriate technical training.",
         "3. Organization + Staffing"),
    # --- 4. Project + Change Management ---
    _ctl("4.1", "Project Management Methodology",
         "Material IT projects follow a documented project-management "
         "methodology with defined gates: initiation, design, build, "
         "test, deploy, post-implementation review.",
         "4. Project + Change Management"),
    _ctl("4.2", "Project Risk Assessment",
         "Each material project receives a documented risk assessment "
         "covering business, operational, + security dimensions.",
         "4. Project + Change Management"),
    _ctl("4.3", "Change Management Process",
         "Production changes follow a documented change-management "
         "process: request, risk-assessed approval, scheduled deployment, "
         "post-implementation review.",
         "4. Project + Change Management"),
    _ctl("4.4", "Emergency Change Procedures",
         "Emergency change procedures (out-of-band production changes) "
         "are documented with retrospective approval + post-implementation "
         "review requirements.",
         "4. Project + Change Management"),
    _ctl("4.5", "Configuration Management",
         "Production system configurations are documented + maintained "
         "in a configuration management database (CMDB) or equivalent.",
         "4. Project + Change Management"),
    # --- 5. Risk Management Integration ---
    _ctl("5.1", "Enterprise Risk Management Integration",
         "IT risk management integrates with enterprise risk management "
         "framework: shared taxonomy, escalation thresholds, reporting cadence.",
         "5. Risk Management Integration"),
    _ctl("5.2", "Risk Appetite + Tolerance Statements",
         "Documented risk appetite + tolerance statements cover IT risk "
         "categories: cybersecurity, operational, third-party, model.",
         "5. Risk Management Integration"),
    _ctl("5.3", "Risk Acceptance + Exception Process",
         "Risk acceptance decisions follow a documented process with "
         "appropriate approval levels + periodic re-evaluation requirements.",
         "5. Risk Management Integration"),
    # --- 6. Performance + Capacity Management ---
    _ctl("6.1", "Service-Level Management",
         "IT services have documented service-level objectives + "
         "agreements with internal customers + are monitored against them.",
         "6. Performance + Capacity Management"),
    _ctl("6.2", "Capacity + Performance Planning",
         "Documented capacity-planning processes monitor system "
         "utilization + forecast capacity needs to avoid degradation.",
         "6. Performance + Capacity Management"),
    _ctl("6.3", "Performance Reporting to Management",
         "IT performance metrics (uptime, MTTR, project delivery, "
         "incidents) are reported to management on a documented cadence.",
         "6. Performance + Capacity Management"),
    # --- 7. Audit + Independent Review ---
    _ctl("7.1", "Coordination with Internal Audit",
         "IT management coordinates with internal audit to support "
         "audit coverage + ensure timely remediation of findings.",
         "7. Audit + Independent Review"),
    _ctl("7.2", "Self-Assessment + Continuous-Improvement",
         "IT functions perform documented self-assessments to identify "
         "control gaps + opportunities for process improvement.",
         "7. Audit + Independent Review"),
    _ctl("7.3", "Regulatory Examination Readiness",
         "IT management maintains documentation, control evidence, + "
         "personnel availability for regulatory examination on demand.",
         "7. Audit + Independent Review"),
]


# ---------------------------------------------------------------------------
# FFIEC IT Examination Handbook — Operations booklet
# ---------------------------------------------------------------------------
FFIEC_OPERATIONS_URL = "https://www.ffiec.gov/news/press-releases/2021/pr-06-30"

FFIEC_OPERATIONS_CONTROLS: list[dict[str, str]] = [
    # --- 1. Operations Governance ---
    _ctl("1.1", "Operations Function Documentation",
         "The IT operations function operates under documented procedures "
         "covering daily processing, monitoring, + escalation responsibilities.",
         "1. Operations Governance"),
    _ctl("1.2", "Operations Run Books",
         "Critical-system run books document startup, shutdown, recovery, "
         "+ routine-maintenance procedures with sufficient detail for "
         "operations staff to follow without designer involvement.",
         "1. Operations Governance"),
    _ctl("1.3", "Shift Handoff + Communication",
         "Shift transitions follow documented handoff procedures "
         "ensuring continuity of issue tracking + situational awareness.",
         "1. Operations Governance"),
    # --- 2. Production Processing ---
    _ctl("2.1", "Job Scheduling + Monitoring",
         "Production batch jobs are scheduled, monitored, + alerted "
         "through documented automation; job failures trigger documented "
         "escalation paths.",
         "2. Production Processing"),
    _ctl("2.2", "Real-Time Transaction Monitoring",
         "Real-time payment + transaction processing systems have "
         "documented monitoring + alerting on volume, latency, + error rates.",
         "2. Production Processing"),
    _ctl("2.3", "Batch Cycle Management",
         "Daily / monthly / quarterly batch cycles have documented "
         "schedules + completion criteria; cycle failures escalate "
         "to management on documented timelines.",
         "2. Production Processing"),
    # --- 3. Infrastructure Management ---
    _ctl("3.1", "Server + Storage Provisioning",
         "Server + storage capacity is provisioned through a documented "
         "process aligned with capacity-planning forecasts.",
         "3. Infrastructure Management"),
    _ctl("3.2", "Network Operations + Monitoring",
         "Network infrastructure is monitored 24x7 with documented "
         "performance + availability thresholds + alerting.",
         "3. Infrastructure Management"),
    _ctl("3.3", "Data Center Physical Operations",
         "Data centers (owned or co-located) operate under documented "
         "environmental controls (power, cooling, fire, physical access).",
         "3. Infrastructure Management"),
    _ctl("3.4", "Cloud Infrastructure Operations",
         "Cloud-hosted infrastructure operates under shared-responsibility "
         "documentation with provider; operations team maintains visibility "
         "into provider service-level + incident posture.",
         "3. Infrastructure Management"),
    # --- 4. Backup + Recovery ---
    _ctl("4.1", "Backup Schedule + Retention",
         "Backup schedules + retention periods are documented + aligned "
         "with the institution's RPO commitments + retention requirements.",
         "4. Backup + Recovery"),
    _ctl("4.2", "Backup Restoration Testing",
         "Backup restoration is tested on a documented cadence (typically "
         "at least annually for critical systems) to confirm restorability.",
         "4. Backup + Recovery"),
    _ctl("4.3", "Off-Site Backup Storage",
         "Backup media (or replication targets) are stored off-site at "
         "sufficient geographic distance to survive regional disasters.",
         "4. Backup + Recovery"),
    _ctl("4.4", "Backup Encryption + Integrity",
         "Backups are encrypted at rest + during transmission; "
         "integrity-verification (hash check) confirms backup validity "
         "before relying on it for recovery.",
         "4. Backup + Recovery"),
    # --- 5. Incident + Problem Management ---
    _ctl("5.1", "Incident Management Process",
         "IT incidents are logged, classified, + tracked through a "
         "documented incident-management process with defined SLAs by "
         "severity.",
         "5. Incident + Problem Management"),
    _ctl("5.2", "Major Incident Communication",
         "Major incidents trigger documented stakeholder communication "
         "(business management, customer service, regulators where "
         "applicable) on documented timelines.",
         "5. Incident + Problem Management"),
    _ctl("5.3", "Problem Management + Root-Cause Analysis",
         "Recurring incidents trigger problem-management investigations "
         "with documented root-cause analysis + permanent-fix tracking.",
         "5. Incident + Problem Management"),
    _ctl("5.4", "Post-Incident Review",
         "Major incidents undergo documented post-incident review "
         "covering: timeline, root cause, response effectiveness, + "
         "improvement actions.",
         "5. Incident + Problem Management"),
    # --- 6. Capacity + Performance Management ---
    _ctl("6.1", "Capacity Monitoring",
         "Production system capacity (CPU, memory, storage, network, "
         "I/O) is monitored against documented thresholds with alerting "
         "on saturation risk.",
         "6. Capacity + Performance Management"),
    _ctl("6.2", "Performance Tuning + Optimization",
         "Performance issues identified through monitoring trigger "
         "documented tuning + optimization activities; persistent issues "
         "escalate to capacity-planning review.",
         "6. Capacity + Performance Management"),
    _ctl("6.3", "Capacity Forecasting",
         "Capacity forecasting uses historical-trend analysis + planned-"
         "growth assumptions to project capacity needs over a documented "
         "horizon (typically 12-24 months).",
         "6. Capacity + Performance Management"),
    # --- 7. Service Continuity ---
    _ctl("7.1", "BC/DR Plan Maintenance",
         "Business continuity + disaster recovery plans are documented + "
         "refreshed on a documented cadence (typically annually) + after "
         "material changes.",
         "7. Service Continuity"),
    _ctl("7.2", "BC/DR Testing",
         "BC/DR plans are tested on a documented cadence; test scope + "
         "results are documented with identified gaps + remediation tracking.",
         "7. Service Continuity"),
    _ctl("7.3", "Recovery Time + Point Objectives",
         "Documented RTO + RPO commitments per critical system are "
         "consistent with backup schedules + recovery infrastructure "
         "capability.",
         "7. Service Continuity"),
    _ctl("7.4", "Pandemic + Workforce Continuity",
         "Pandemic / workforce-continuity scenarios (mass remote work, "
         "key-person illness) are addressed in BC plans with "
         "documented mitigations.",
         "7. Service Continuity"),
    # --- 8. Operations Reporting ---
    _ctl("8.1", "Operations Performance Dashboards",
         "Operational performance is reported via dashboards covering "
         "uptime, incidents, change success rate, capacity utilization.",
         "8. Operations Reporting"),
    _ctl("8.2", "Periodic Operations Review with Management",
         "Operations leadership reviews performance + risk indicators "
         "with senior management on a documented cadence.",
         "8. Operations Reporting"),
]


# ---------------------------------------------------------------------------
# FFIEC IT Examination Handbook — Information Security booklet
# ---------------------------------------------------------------------------
FFIEC_INFOSEC_URL = (
    "https://ithandbook.ffiec.gov/it-booklets/information-security.aspx"
)

# This is the largest FFIEC IT Handbook booklet — ~80 controls. We
# capture the major control areas (governance, risk assessment,
# access, encryption, monitoring, incident response, BC, third-party,
# cloud) at the control-objective level. Operators can extend via
# `evidentia catalog import` for more granular institution-specific
# overlays.
FFIEC_INFOSEC_CONTROLS: list[dict[str, str]] = [
    # --- 1. Information Security Program Governance ---
    _ctl("1.1", "Board-Approved Information Security Program",
         "A documented, board-approved information security program "
         "covers the institution's IT risk profile + customer-information "
         "protection obligations under GLBA + state privacy laws.",
         "1. IS Program Governance"),
    _ctl("1.2", "CISO / ISO Designation + Authority",
         "A designated Chief Information Security Officer (or "
         "equivalent) has documented authority + reporting line "
         "appropriate for the institution's complexity.",
         "1. IS Program Governance"),
    _ctl("1.3", "Annual Board Reporting",
         "The board (or designated committee) receives at-least-annual "
         "information-security program status reports covering risk, "
         "incidents, + program effectiveness.",
         "1. IS Program Governance"),
    _ctl("1.4", "Information Security Policies + Standards",
         "Documented IS policies + supporting technical standards cover "
         "the institution's IS control environment + are reviewed at "
         "least annually.",
         "1. IS Program Governance"),
    # --- 2. Risk Assessment ---
    _ctl("2.1", "Information Asset Inventory",
         "An information asset inventory documents systems + data stores, "
         "with classification by sensitivity + criticality.",
         "2. Risk Assessment"),
    _ctl("2.2", "Threat + Vulnerability Identification",
         "Documented processes identify threats (insider, external, "
         "environmental) + vulnerabilities (technical + procedural) "
         "applicable to the institution's environment.",
         "2. Risk Assessment"),
    _ctl("2.3", "Risk Assessment Methodology",
         "A documented risk-assessment methodology produces "
         "qualitative or quantitative risk ratings used to prioritize "
         "control investments.",
         "2. Risk Assessment"),
    _ctl("2.4", "Periodic Risk Reassessment",
         "Risk assessments are refreshed on a documented cadence "
         "(typically annual) + after material environment changes.",
         "2. Risk Assessment"),
    # --- 3. Access Control ---
    _ctl("3.1", "Access Provisioning + Deprovisioning",
         "User access is provisioned via documented approval workflow + "
         "deprovisioned promptly upon role change or termination.",
         "3. Access Control"),
    _ctl("3.2", "Least-Privilege + Need-to-Know",
         "Access rights follow least-privilege + need-to-know principles; "
         "deviations are exception-tracked.",
         "3. Access Control"),
    _ctl("3.3", "Privileged Access Management",
         "Privileged accounts are inventoried, time-limited where "
         "feasible, monitored, + subject to enhanced authentication "
         "requirements.",
         "3. Access Control"),
    _ctl("3.4", "Multi-Factor Authentication",
         "Multi-factor authentication is required for: customer-facing "
         "remote access, internal privileged access, + administrative "
         "access to sensitive systems.",
         "3. Access Control"),
    _ctl("3.5", "Periodic Access Recertification",
         "User + privileged access is recertified on a documented "
         "cadence (typically annual for general; more frequent for "
         "privileged) by appropriate management.",
         "3. Access Control"),
    _ctl("3.6", "Segregation of Duties",
         "Critical processes (payment authorization, change deployment, "
         "log review) are split across roles to prevent single-actor "
         "compromise.",
         "3. Access Control"),
    # --- 4. Data Protection ---
    _ctl("4.1", "Data Classification",
         "Data is classified by sensitivity using a documented schema; "
         "classification drives handling + retention requirements.",
         "4. Data Protection"),
    _ctl("4.2", "Encryption at Rest",
         "Sensitive data is encrypted at rest using documented + "
         "industry-accepted algorithms + key-management practices.",
         "4. Data Protection"),
    _ctl("4.3", "Encryption in Transit",
         "Sensitive data is encrypted in transit; deprecated protocols "
         "(SSLv2/v3, TLS 1.0/1.1) are documented as deprecated + phased out.",
         "4. Data Protection"),
    _ctl("4.4", "Cryptographic Key Management",
         "Cryptographic keys are managed under a documented key-"
         "management lifecycle (generation, distribution, storage, "
         "rotation, retirement).",
         "4. Data Protection"),
    _ctl("4.5", "Data Loss Prevention",
         "Documented DLP controls (technical + procedural) prevent + "
         "detect unauthorized exfiltration of sensitive data.",
         "4. Data Protection"),
    _ctl("4.6", "Secure Disposal",
         "Documented secure-disposal procedures cover end-of-life IT "
         "assets + storage media to prevent residual-data exposure.",
         "4. Data Protection"),
    # --- 5. Network Security ---
    _ctl("5.1", "Network Segmentation",
         "Network is segmented by trust zone (public, DMZ, internal, "
         "PCI, OT) with documented inter-zone traffic-control rules.",
         "5. Network Security"),
    _ctl("5.2", "Firewall + Boundary Protection",
         "Firewalls + network access controls enforce the documented "
         "segmentation model with periodic rule-base reviews.",
         "5. Network Security"),
    _ctl("5.3", "Intrusion Detection + Prevention",
         "Network IDS / IPS + endpoint detection are deployed on "
         "appropriate boundaries + monitored + tuned on a documented cadence.",
         "5. Network Security"),
    _ctl("5.4", "Wireless Network Security",
         "Wireless networks use strong authentication + encryption; "
         "guest networks are segregated from production environments.",
         "5. Network Security"),
    _ctl("5.5", "Remote Access Security",
         "Remote access uses MFA + encrypted tunnels; remote-access "
         "session recording / monitoring is in place for privileged use.",
         "5. Network Security"),
    # --- 6. Vulnerability + Patch Management ---
    _ctl("6.1", "Vulnerability Scanning",
         "Production environments receive periodic vulnerability scans "
         "(typically monthly internal + quarterly external) with "
         "documented remediation SLAs.",
         "6. Vulnerability + Patch Management"),
    _ctl("6.2", "Patch Management Process",
         "Documented patch management process covers identification, "
         "risk-assessed prioritization, testing, + deployment with "
         "severity-driven SLAs.",
         "6. Vulnerability + Patch Management"),
    _ctl("6.3", "Penetration Testing",
         "Independent penetration testing is performed periodically "
         "(typically annual) covering external + internal attack surfaces; "
         "findings are remediated.",
         "6. Vulnerability + Patch Management"),
    # --- 7. Logging + Monitoring ---
    _ctl("7.1", "Centralized Logging",
         "Security-relevant events from network, system, + application "
         "layers are aggregated to a central logging platform.",
         "7. Logging + Monitoring"),
    _ctl("7.2", "Log Retention",
         "Logs are retained per documented schedule meeting regulatory "
         "+ investigative requirements (typically 1 year online; longer "
         "for regulated data).",
         "7. Logging + Monitoring"),
    _ctl("7.3", "SIEM + Correlation",
         "Security events are correlated via SIEM (or equivalent) + "
         "monitored 24x7 in-house or via MSSP, with documented escalation.",
         "7. Logging + Monitoring"),
    _ctl("7.4", "Privileged Activity Monitoring",
         "Privileged-user actions are logged in tamper-resistant form + "
         "reviewed on a documented cadence by independent reviewers.",
         "7. Logging + Monitoring"),
    # --- 8. Incident Response ---
    _ctl("8.1", "Incident Response Plan",
         "A documented incident response plan covers detection, "
         "containment, eradication, recovery, + post-incident review.",
         "8. Incident Response"),
    _ctl("8.2", "Incident Response Team + Authority",
         "An incident response team has documented authority, "
         "escalation paths, + cross-functional representation (IT, IS, "
         "legal, compliance, communications).",
         "8. Incident Response"),
    _ctl("8.3", "Incident Response Testing",
         "Incident response capabilities are exercised through periodic "
         "tabletop or live-fire scenarios with documented improvement "
         "actions.",
         "8. Incident Response"),
    _ctl("8.4", "Customer-Notification Procedures",
         "Documented procedures cover customer notification under "
         "applicable laws (state breach laws, GLBA Interagency "
         "Guidance) including content + timing requirements.",
         "8. Incident Response"),
    _ctl("8.5", "Regulatory Notification",
         "Documented procedures cover regulatory incident notification "
         "per primary regulator's requirements (e.g., 36-hour rule "
         "under FFIEC Interagency Computer-Security Incident Notification).",
         "8. Incident Response"),
    # --- 9. Third-Party + Cloud Security ---
    _ctl("9.1", "Vendor Information-Security Due Diligence",
         "Third-party security posture is evaluated via documented "
         "due-diligence process before contract + on ongoing basis.",
         "9. Third-Party + Cloud Security"),
    _ctl("9.2", "Cloud Service Provider Security",
         "Cloud provider security posture is evaluated via SOC reports, "
         "industry attestations, + provider-specific configuration reviews.",
         "9. Third-Party + Cloud Security"),
    _ctl("9.3", "Vendor + Cloud Concentration Risk",
         "Concentration of critical functions with single vendors / "
         "providers is assessed + mitigated where appropriate.",
         "9. Third-Party + Cloud Security"),
    # --- 10. Workforce Security ---
    _ctl("10.1", "Security Awareness Training",
         "All workforce members receive at-least-annual security "
         "awareness training covering current threat landscape.",
         "10. Workforce Security"),
    _ctl("10.2", "Phishing Resistance Program",
         "Documented phishing simulation + training program; click-rate "
         "trends are tracked + addressed via targeted training.",
         "10. Workforce Security"),
    _ctl("10.3", "Insider-Threat Program",
         "Documented insider-threat program addresses unusual privileged-"
         "user activity, departing-employee risk, + role-based monitoring.",
         "10. Workforce Security"),
]


# ---------------------------------------------------------------------------
# FFIEC Cybersecurity Assessment Tool (CAT)
# ---------------------------------------------------------------------------
#
# This historical representative subset contains 33 controls. CAT retired
# on 2025-08-31; preserve the existing IDs for prior assessment references.
FFIEC_CAT_URL = (
    "https://www.ffiec.gov/sites/default/files/media/press-releases/2024/"
    "cat-sunset-statement-ffiec-letterhead.pdf"
)

FFIEC_CAT_CONTROLS: list[dict[str, str]] = [
    # --- 1. Cyber Risk Management + Oversight ---
    _ctl("CRMO.1.1", "Governance — Board-Approved Cyber Risk Strategy",
         "Board-approved cyber-risk strategy aligned with institution's "
         "risk appetite (FFIEC CAT Domain 1, Baseline).",
         "1. Cyber Risk Management + Oversight"),
    _ctl("CRMO.1.2", "Risk Management — Documented Cyber Risk Assessment",
         "Documented enterprise-wide cyber risk assessment, refreshed "
         "annually (FFIEC CAT Domain 1, Baseline).",
         "1. Cyber Risk Management + Oversight"),
    _ctl("CRMO.1.3", "Resources — Adequate Cyber Resourcing",
         "Cybersecurity function staffed + budgeted to support the "
         "institution's risk profile (FFIEC CAT Domain 1, Baseline).",
         "1. Cyber Risk Management + Oversight"),
    _ctl("CRMO.1.4", "Training + Culture — Annual Awareness Training",
         "All personnel receive annual cybersecurity awareness training "
         "(FFIEC CAT Domain 1, Baseline).",
         "1. Cyber Risk Management + Oversight"),
    _ctl("CRMO.2.1", "Governance — Cyber Risk Reporting Framework",
         "Cyber risk reporting cadence + content defined for "
         "board / committee + senior management (FFIEC CAT Domain 1, Evolving).",
         "1. Cyber Risk Management + Oversight"),
    _ctl("CRMO.2.2", "Risk Management — Quantitative Risk Modeling",
         "Cyber risk quantification using FAIR or similar framework "
         "(FFIEC CAT Domain 1, Advanced).",
         "1. Cyber Risk Management + Oversight"),
    # --- 2. Threat Intelligence + Collaboration ---
    _ctl("TIC.1.1", "Threat Intelligence — FS-ISAC Membership",
         "Membership in FS-ISAC (or equivalent sector ISAC) for threat-"
         "intelligence sharing (FFIEC CAT Domain 2, Baseline).",
         "2. Threat Intelligence + Collaboration"),
    _ctl("TIC.1.2", "Threat Intelligence — Threat-Source Diversification",
         "Threat-intelligence sources include: government (CISA), "
         "commercial vendors, sector ISACs, peer institutions "
         "(FFIEC CAT Domain 2, Baseline).",
         "2. Threat Intelligence + Collaboration"),
    _ctl("TIC.1.3", "Information Sharing — Bilateral Peer Sharing",
         "Bilateral information-sharing relationships with peer "
         "institutions (FFIEC CAT Domain 2, Evolving).",
         "2. Threat Intelligence + Collaboration"),
    _ctl("TIC.2.1", "Threat Intelligence — Threat Modeling Integration",
         "Threat intelligence drives threat modeling for new + existing "
         "systems (FFIEC CAT Domain 2, Intermediate).",
         "2. Threat Intelligence + Collaboration"),
    # --- 3. Cybersecurity Controls ---
    _ctl("CC.1.1", "Preventative — Patch Management",
         "Documented patch management process with severity-driven SLAs "
         "(FFIEC CAT Domain 3, Baseline).",
         "3. Cybersecurity Controls"),
    _ctl("CC.1.2", "Preventative — Anti-Malware Coverage",
         "Anti-malware deployed on all endpoints + servers + email "
         "gateways (FFIEC CAT Domain 3, Baseline).",
         "3. Cybersecurity Controls"),
    _ctl("CC.1.3", "Preventative — MFA on Privileged + Remote Access",
         "MFA on all privileged accounts + remote access "
         "(FFIEC CAT Domain 3, Baseline).",
         "3. Cybersecurity Controls"),
    _ctl("CC.1.4", "Preventative — Network Segmentation",
         "Network segmented into trust zones with controlled inter-zone "
         "traffic (FFIEC CAT Domain 3, Baseline).",
         "3. Cybersecurity Controls"),
    _ctl("CC.1.5", "Preventative — Encryption at Rest + in Transit",
         "Sensitive data encrypted at rest + in transit using "
         "industry-accepted algorithms (FFIEC CAT Domain 3, Baseline).",
         "3. Cybersecurity Controls"),
    _ctl("CC.2.1", "Detective — 24x7 Monitoring",
         "Security event monitoring is 24x7 (in-house or MSSP) "
         "(FFIEC CAT Domain 3, Baseline).",
         "3. Cybersecurity Controls"),
    _ctl("CC.2.2", "Detective — SIEM Deployment",
         "Centralized SIEM aggregates logs from network, system, + "
         "application layers (FFIEC CAT Domain 3, Evolving).",
         "3. Cybersecurity Controls"),
    _ctl("CC.2.3", "Detective — Behavioral Analytics",
         "User + entity behavior analytics (UEBA) deployed for "
         "anomaly detection (FFIEC CAT Domain 3, Advanced).",
         "3. Cybersecurity Controls"),
    _ctl("CC.3.1", "Corrective — Incident Containment Capability",
         "Documented containment playbooks + automated containment "
         "tooling (FFIEC CAT Domain 3, Evolving).",
         "3. Cybersecurity Controls"),
    _ctl("CC.3.2", "Corrective — Backup + Recovery Capability",
         "Backup + recovery infrastructure tested + aligned with "
         "institution's RTO + RPO (FFIEC CAT Domain 3, Baseline).",
         "3. Cybersecurity Controls"),
    # --- 4. External Dependency Management ---
    _ctl("EDM.1.1", "Vendor Inventory + Risk Tiering",
         "Documented vendor inventory with risk-tier classification "
         "(FFIEC CAT Domain 4, Baseline).",
         "4. External Dependency Management"),
    _ctl("EDM.1.2", "Vendor Cyber Due Diligence",
         "Documented vendor cybersecurity due diligence covering: SOC "
         "reports, security questionnaires, on-site review for critical "
         "vendors (FFIEC CAT Domain 4, Baseline).",
         "4. External Dependency Management"),
    _ctl("EDM.1.3", "Vendor Contract Cybersecurity Provisions",
         "Vendor contracts include: right-to-audit, breach notification, "
         "data protection, subcontracting controls (FFIEC CAT Domain 4, "
         "Baseline).",
         "4. External Dependency Management"),
    _ctl("EDM.1.4", "Ongoing Vendor Monitoring",
         "Documented ongoing monitoring covering: SOC report refreshes, "
         "vendor incidents, regulatory matters (FFIEC CAT Domain 4, Baseline).",
         "4. External Dependency Management"),
    _ctl("EDM.2.1", "Concentration Risk Analysis",
         "Vendor concentration risk assessed across providers, "
         "geographies, + service categories (FFIEC CAT Domain 4, Evolving).",
         "4. External Dependency Management"),
    _ctl("EDM.2.2", "4th-Party / Subcontractor Visibility",
         "Visibility into critical-vendor 4th-party relationships "
         "(FFIEC CAT Domain 4, Evolving).",
         "4. External Dependency Management"),
    # --- 5. Cyber Incident Management + Resilience ---
    _ctl("CIMR.1.1", "Incident Response Plan",
         "Documented incident response plan covering detection through "
         "post-incident review (FFIEC CAT Domain 5, Baseline).",
         "5. Cyber Incident Management + Resilience"),
    _ctl("CIMR.1.2", "Incident Response Testing",
         "Annual incident response testing via tabletop exercises "
         "(FFIEC CAT Domain 5, Baseline).",
         "5. Cyber Incident Management + Resilience"),
    _ctl("CIMR.1.3", "Customer + Regulatory Notification Procedures",
         "Documented procedures for customer + regulatory incident "
         "notification per applicable laws + 36-hour FFIEC rule "
         "(FFIEC CAT Domain 5, Baseline).",
         "5. Cyber Incident Management + Resilience"),
    _ctl("CIMR.1.4", "Resilience — BC/DR Capability",
         "Tested BC/DR capability supporting documented RTO + RPO "
         "(FFIEC CAT Domain 5, Baseline).",
         "5. Cyber Incident Management + Resilience"),
    _ctl("CIMR.2.1", "Forensic Capability",
         "In-house or contracted forensic capability for material "
         "incident investigation (FFIEC CAT Domain 5, Evolving).",
         "5. Cyber Incident Management + Resilience"),
    _ctl("CIMR.2.2", "Cyber Insurance Coverage",
         "Cyber insurance coverage assessed against the institution's "
         "risk profile + reviewed annually (FFIEC CAT Domain 5, Evolving).",
         "5. Cyber Incident Management + Resilience"),
    _ctl("CIMR.2.3", "Live-Fire Resilience Testing",
         "Live-fire (red-team / threat-led) resilience testing performed "
         "periodically (FFIEC CAT Domain 5, Advanced).",
         "5. Cyber Incident Management + Resilience"),
]


def main() -> None:
    """Emit all FFIEC IT Handbook + FFIEC CAT bundled catalogs."""
    emit_control_catalog(
        framework_id="ffiec-outsourcing",
        framework_name=(
            "FFIEC IT Examination Handbook — Outsourcing "
            "Technology Services booklet"
        ),
        version="June 2004 + 2008/2010 supplements",
        source=FFIEC_OUTSOURCING_URL,
        families=[
            "1. Roles + Responsibilities",
            "2. Risk Management",
            "3. Outsourcing Decision",
            "4. Vendor Selection",
            "5. Contract Issues",
            "6. Ongoing Monitoring",
            "7. Related Topics",
        ],
        controls=FFIEC_OUTSOURCING_CONTROLS,
        tier="A",
    )

    emit_control_catalog(
        framework_id="ffiec-audit",
        framework_name="FFIEC IT Examination Handbook — Audit booklet",
        version="April 2012",
        source=FFIEC_AUDIT_URL,
        families=[
            "1. Audit Function and Independence",
            "2. IT Audit Planning",
            "3. Audit Execution",
            "4. Audit Reporting",
            "5. Issue Tracking + Follow-Up",
            "6. Specialized Audit Topics",
            "7. Audit Function Maturity",
        ],
        controls=FFIEC_AUDIT_CONTROLS,
        tier="A",
    )

    emit_control_catalog(
        framework_id="ffiec-management",
        framework_name="FFIEC IT Examination Handbook — Management booklet",
        version="November 2015",
        source=FFIEC_MANAGEMENT_URL,
        families=[
            "1. IT Governance",
            "2. Strategic Planning",
            "3. Organization + Staffing",
            "4. Project + Change Management",
            "5. Risk Management Integration",
            "6. Performance + Capacity Management",
            "7. Audit + Independent Review",
        ],
        controls=FFIEC_MANAGEMENT_CONTROLS,
        tier="A",
    )

    emit_control_catalog(
        framework_id="ffiec-operations",
        framework_name="FFIEC IT Examination Handbook — Operations booklet",
        version="July 2004",
        source=FFIEC_OPERATIONS_URL,
        families=[
            "1. Operations Governance",
            "2. Production Processing",
            "3. Infrastructure Management",
            "4. Backup + Recovery",
            "5. Incident + Problem Management",
            "6. Capacity + Performance Management",
            "7. Service Continuity",
            "8. Operations Reporting",
        ],
        controls=FFIEC_OPERATIONS_CONTROLS,
        tier="A",
        status="superseded",
        verified_on="2026-09-09",
        superseded_by="ffiec-aio",
        notes=(
            "Superseded on 2021-06-30 by Architecture, Infrastructure, and Operations (ffiec-aio). "
            "The July 2004 edition and all 27 historical control records are retained for existing references. "
            "No equivalence mapping to the successor's section locators is implied."
        ),
    )

    emit_control_catalog(
        framework_id="ffiec-information-security",
        framework_name=(
            "FFIEC IT Examination Handbook — Information Security booklet"
        ),
        version="September 2016",
        source=FFIEC_INFOSEC_URL,
        families=[
            "1. IS Program Governance",
            "2. Risk Assessment",
            "3. Access Control",
            "4. Data Protection",
            "5. Network Security",
            "6. Vulnerability + Patch Management",
            "7. Logging + Monitoring",
            "8. Incident Response",
            "9. Third-Party + Cloud Security",
            "10. Workforce Security",
        ],
        controls=FFIEC_INFOSEC_CONTROLS,
        tier="A",
    )

    emit_control_catalog(
        framework_id="ffiec-cat",
        framework_name="FFIEC Cybersecurity Assessment Tool",
        version="2017 (representative subset)",
        source=FFIEC_CAT_URL,
        families=[
            "1. Cyber Risk Management + Oversight",
            "2. Threat Intelligence + Collaboration",
            "3. Cybersecurity Controls",
            "4. External Dependency Management",
            "5. Cyber Incident Management + Resilience",
        ],
        controls=FFIEC_CAT_CONTROLS,
        tier="A",
        status="retired",
        verified_on="2026-09-09",
        notes=(
            "Retired by FFIEC on 2025-08-31. All 33 controls in this historical representative subset are retained. "
            "The source statement points to NIST CSF 2.0, CISA Cybersecurity Performance Goals, "
            "CRI's Cyber Profile, and CIS Critical Security Controls as alternatives. "
            "No one-to-one equivalence or single successor is asserted."
        ),
    )
    generate_current_booklets()


if __name__ == "__main__":
    main()
