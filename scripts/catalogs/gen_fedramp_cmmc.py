"""Generate FedRAMP baselines + CMMC 2.0 levels, Tier A (US Government work).

FedRAMP baselines are tailored subsets of NIST 800-53 Rev 5. We ship pointer
catalogs that reference the NIST control IDs; `rewrite_fedramp_pointers.py`
then fills in the real control text from the bundled NIST catalog.

Baseline MEMBERSHIP is NOT authored here. It is read from the vendored
provenance file `upstream/fedramp-rev5-baselines.json`, extracted from the
FedRAMP PMO's own OSCAL profiles. Do not hand-edit the membership lists.

History, so the mistake is not repeated: through v0.11.2 the Low and LI-SaaS
lists were derived as `[c for c in FEDRAMP_MODERATE if "(" not in c][:125]`
and `[:150]`. Because the source list is family-ordered, that truncation
silently dropped every family from PS onward, so the shipped Low baseline was
missing PS, RA, SA, SC, SI and SR in their entirety (57 controls, including
RA-5, SC-7 and SI-2; 69 controls are restored in total, the rest from families
the truncation cut through mid-way) while carrying 33 PM-family controls that SP 800-53B does
not allocate to any baseline. The control TEXT was correct, which made the
membership error invisible on inspection. `_assert_baseline_invariants()`
below now makes that class of error a build failure.

CMMC levels are the DoD's tailored CUI-protection baselines derived from
NIST 800-171 + 800-172. Published by DoD, public domain.
"""

from __future__ import annotations

import json
import pathlib

from _generators import emit_control_catalog  # type: ignore[import-not-found]

FEDRAMP_URL = "https://www.fedramp.gov"
CMMC_URL = "https://dodcio.defense.gov/CMMC/"


# Control families in NIST 800-53 Rev 5 (common across all baselines)
NIST_800_53_FAMILIES = [
    "AC — Access Control",
    "AT — Awareness and Training",
    "AU — Audit and Accountability",
    "CA — Assessment, Authorization, and Monitoring",
    "CM — Configuration Management",
    "CP — Contingency Planning",
    "IA — Identification and Authentication",
    "IR — Incident Response",
    "MA — Maintenance",
    "MP — Media Protection",
    "PE — Physical and Environmental Protection",
    "PL — Planning",
    "PM — Program Management",
    "PS — Personnel Security",
    "PT — PII Processing and Transparency",
    "RA — Risk Assessment",
    "SA — System and Services Acquisition",
    "SC — System and Communications Protection",
    "SI — System and Information Integrity",
    "SR — Supply Chain Risk Management",
]

# ---------------------------------------------------------------------------
# Baseline membership: vendored from the FedRAMP PMO OSCAL profiles.
# ---------------------------------------------------------------------------
_UPSTREAM_PATH = pathlib.Path(__file__).resolve().parent / "upstream" / "fedramp-rev5-baselines.json"
_UPSTREAM = json.loads(_UPSTREAM_PATH.read_text(encoding="utf-8"))

FEDRAMP_LOW: list[str] = _UPSTREAM["baselines"]["low"]
FEDRAMP_MODERATE: list[str] = _UPSTREAM["baselines"]["moderate"]
FEDRAMP_HIGH: list[str] = _UPSTREAM["baselines"]["high"]
FEDRAMP_LI_SAAS: list[str] = _UPSTREAM["baselines"]["li-saas"]

# NIST SP 800-53 Rev 5 withdrawn controls. None may appear in a baseline: they
# do not exist as active controls and cannot resolve against the Rev 5 catalog.
_WITHDRAWN = {"CM-8(5)", "CP-2(4)", "SA-12", "SC-13(1)"}


def _assert_baseline_invariants() -> None:
    """Fail the build if the vendored membership violates a known-true property.

    Every assertion here corresponds to a defect actually shipped through
    v0.11.2, so each one is a regression test rather than a theoretical check.
    Sources: the FedRAMP PMO OSCAL profiles for the counts and the nesting, and
    NIST SP 800-53B Table 3-13 (PM) and Table 3-15 (PT) for the exclusions.
    """
    low, mod = set(FEDRAMP_LOW), set(FEDRAMP_MODERATE)
    high, li = set(FEDRAMP_HIGH), set(FEDRAMP_LI_SAAS)
    every = low | mod | high | li

    expected = {"low": 156, "moderate": 323, "high": 410, "li-saas": 156}
    actual = {
        "low": len(FEDRAMP_LOW), "moderate": len(FEDRAMP_MODERATE),
        "high": len(FEDRAMP_HIGH), "li-saas": len(FEDRAMP_LI_SAAS),
    }
    assert actual == expected, f"baseline counts changed: {actual} != {expected}"

    for name, ids in (
        ("low", FEDRAMP_LOW), ("moderate", FEDRAMP_MODERATE),
        ("high", FEDRAMP_HIGH), ("li-saas", FEDRAMP_LI_SAAS),
    ):
        assert len(ids) == len(set(ids)), f"{name} contains duplicate control ids"

    # LI-SaaS selects the SAME ids as Low. The FedRAMP Tailored distinction is
    # carried by a per-control `method` property, not by a smaller control set.
    assert low == li, "LI-SaaS membership must equal Low"
    assert low < mod, "Low must be a strict subset of Moderate"
    assert mod < high, "Moderate must be a strict subset of High"
    assert every == high, "the union of all baselines must equal High"

    pm = sorted(i for i in every if i.startswith("PM-"))
    pt = sorted(i for i in every if i.startswith("PT-"))
    assert not pm, f"PM controls are not allocated to security baselines (SP 800-53B Table 3-13): {pm}"
    assert not pt, f"PT controls are not allocated to security baselines (SP 800-53B Table 3-15): {pt}"

    withdrawn = sorted(every & _WITHDRAWN)
    assert not withdrawn, f"withdrawn Rev 5 controls cannot appear in a baseline: {withdrawn}"


_assert_baseline_invariants()


def _families_present_in(controls: list[str]) -> list[str]:
    """The subset of ``NIST_800_53_FAMILIES`` this baseline actually populates.

    ``ControlCatalog.families`` is documented as "control families in this
    catalog", and for OSCAL-sourced catalogs the loader DERIVES it from the
    groups that really exist. A pointer catalog that hardcodes all 20 NIST
    families breaks that contract the moment a baseline excludes one.

    It does, now. Removing the 33 PM and 9 PT controls that SP 800-53B
    Tables 3-13 and 3-15 allocate to no baseline leaves PM and PT declared
    with zero members, so the GUI renders "323 top-level controls
    (20 families)" for a catalog covering 18, telling an operator FedRAMP
    Moderate covers Program Management and PII Processing when it does not.
    Deriving the list keeps the count true for whatever the profiles say.

    Order follows ``NIST_800_53_FAMILIES`` so output stays deterministic.
    """
    present = {cid.split("-", 1)[0] for cid in controls}
    return [fam for fam in NIST_800_53_FAMILIES if fam.split(maxsplit=1)[0] in present]


def _baseline_source(baseline_name: str) -> str:
    """Provenance string for a baseline catalog, including the LI-SaaS caveat."""
    prov = _UPSTREAM["provenance"]
    base = (
        f"FedRAMP PMO, {FEDRAMP_URL} (U.S. Government work, public domain). "
        f"Baseline is a tailored subset of NIST SP 800-53 Rev 5. Control membership "
        f"extracted from the FedRAMP PMO OSCAL profiles published {prov['published'][:10]}, "
        f"retrieved {prov['retrieved']} from {prov['republisher'].split(' (')[0]}."
    )
    if baseline_name == "li-saas":
        base += (
            " NOTE: LI-SaaS selects the same control set as Low. The FedRAMP Tailored "
            "distinction is carried by a per-control method property (ATTEST, ASSESS, "
            "CONDITIONAL, NSO, FED) which this pointer catalog does not yet represent."
        )
    return base


def _make_pointer_control(cid: str) -> dict:
    """Create a pointer entry referencing the NIST 800-53 Rev 5 master catalog."""
    # Extract family prefix (e.g. "AC-2(1)" -> "AC")
    family_code = cid.split("-")[0]
    family_map = {f.split(" — ")[0]: f for f in NIST_800_53_FAMILIES}
    family_full = family_map.get(family_code, family_code)
    return {
        "id": cid,
        "title": f"NIST 800-53 Rev 5 control {cid}",
        "description": f"See nist-800-53-rev5 catalog for full control text (baseline references). Control {cid} in family {family_full}.",
        "family": family_full,
    }


for baseline_name, baseline_controls in [
    ("low", FEDRAMP_LOW),
    ("moderate", FEDRAMP_MODERATE),
    ("high", FEDRAMP_HIGH),
    ("li-saas", FEDRAMP_LI_SAAS),
]:
    emit_control_catalog(
        framework_id=f"fedramp-rev5-{baseline_name}",
        framework_name=f"FedRAMP Rev 5 {baseline_name.upper() if baseline_name=='li-saas' else baseline_name.capitalize()} Baseline",
        version="Rev 5 (profiles published 2024-09-24)",
        source=_baseline_source(baseline_name),
        families=_families_present_in(baseline_controls),
        controls=[_make_pointer_control(c) for c in baseline_controls],
        tier="A",
    )


# ---------------------------------------------------------------------------
# CMMC 2.0 Level 1, Level 2, Level 3
# ---------------------------------------------------------------------------

CMMC_L1 = [
    ("AC.L1-3.1.1", "Authorized Access Control", "Access Control"),
    ("AC.L1-3.1.2", "Transaction & Function Control", "Access Control"),
    ("AC.L1-3.1.20", "External Connections", "Access Control"),
    ("AC.L1-3.1.22", "Control Public Information", "Access Control"),
    ("IA.L1-3.5.1", "Identification", "Identification and Authentication"),
    ("IA.L1-3.5.2", "Authentication", "Identification and Authentication"),
    ("MP.L1-3.8.3", "Media Disposal", "Media Protection"),
    ("PE.L1-3.10.1", "Limit Physical Access", "Physical Protection"),
    ("PE.L1-3.10.3", "Escort Visitors", "Physical Protection"),
    ("PE.L1-3.10.4", "Physical Access Logs", "Physical Protection"),
    ("PE.L1-3.10.5", "Manage Physical Access", "Physical Protection"),
    ("SC.L1-3.13.1", "Boundary Protection", "System and Communications Protection"),
    ("SC.L1-3.13.5", "Public-Access System Separation", "System and Communications Protection"),
    ("SI.L1-3.14.1", "Flaw Remediation", "System and Information Integrity"),
    ("SI.L1-3.14.2", "Malicious Code Protection", "System and Information Integrity"),
    ("SI.L1-3.14.4", "Update Malicious Code Protection", "System and Information Integrity"),
    ("SI.L1-3.14.5", "System & File Scanning", "System and Information Integrity"),
]

emit_control_catalog(
    framework_id="cmmc-2-l1",
    framework_name="CMMC 2.0 Level 1 (Foundational)",
    version="2.0 (2024 Final Rule)",
    source=f"DoD CIO — {CMMC_URL} (U.S. Government work). Based on the 17 FAR 52.204-21 basic safeguarding practices.",
    families=["Access Control", "Identification and Authentication", "Media Protection", "Physical Protection", "System and Communications Protection", "System and Information Integrity"],
    controls=[{"id": c, "title": t, "description": t, "family": f} for c, t, f in CMMC_L1],
    tier="A",
)


# CMMC Level 2 = all 110 NIST 800-171 Rev 2 requirements (DoD has pinned to Rev 2
# for the 2024 Final Rule; Rev 3 transition is TBD).
CMMC_L2 = [
    (f"CMMC.L2-{cid.replace('3.', '3.')}", title, family)
    for cid, title, family in [
        # Mirror NIST 800-171 Rev 2 (110 controls) — full list pulled from gen_nist_family
        ("3.1.1", "Limit system access to authorized users", "Access Control"),
        ("3.1.2", "Limit system access to the types of transactions and functions that authorized users are permitted to execute", "Access Control"),
        ("3.1.3", "Control the flow of CUI in accordance with approved authorizations", "Access Control"),
        ("3.1.4", "Separate the duties of individuals to reduce the risk of malevolent activity without collusion", "Access Control"),
        ("3.1.5", "Employ the principle of least privilege", "Access Control"),
        ("3.1.6", "Use non-privileged accounts or roles when accessing nonsecurity functions", "Access Control"),
        ("3.1.7", "Prevent non-privileged users from executing privileged functions", "Access Control"),
        ("3.1.8", "Limit unsuccessful logon attempts", "Access Control"),
        ("3.1.9", "Provide privacy and security notices consistent with applicable CUI rules", "Access Control"),
        ("3.1.10", "Use session lock with pattern-hiding displays", "Access Control"),
        ("3.1.11", "Terminate user sessions after a defined condition", "Access Control"),
        ("3.1.12", "Monitor and control remote access sessions", "Access Control"),
        ("3.1.13", "Employ cryptographic mechanisms to protect remote access sessions", "Access Control"),
        ("3.1.14", "Route remote access via managed access control points", "Access Control"),
        ("3.1.15", "Authorize remote execution of privileged commands", "Access Control"),
        ("3.1.16", "Authorize wireless access prior to allowing connections", "Access Control"),
        ("3.1.17", "Protect wireless access using authentication and encryption", "Access Control"),
        ("3.1.18", "Control connection of mobile devices", "Access Control"),
        ("3.1.19", "Encrypt CUI on mobile devices and mobile computing platforms", "Access Control"),
        ("3.1.20", "Verify and control/limit connections to external systems", "Access Control"),
        ("3.1.21", "Limit use of organizational portable storage devices on external systems", "Access Control"),
        ("3.1.22", "Control CUI posted or processed on publicly accessible systems", "Access Control"),
        ("3.2.1", "Ensure personnel are aware of security risks", "Awareness and Training"),
        ("3.2.2", "Ensure personnel are trained for their security-related duties", "Awareness and Training"),
        ("3.2.3", "Provide insider threat awareness training", "Awareness and Training"),
        ("3.3.1", "Create and retain system audit logs", "Audit and Accountability"),
        ("3.3.2", "Ensure actions of individual users can be uniquely traced", "Audit and Accountability"),
        ("3.3.3", "Review and update logged events", "Audit and Accountability"),
        ("3.3.4", "Alert in the event of an audit logging process failure", "Audit and Accountability"),
        ("3.3.5", "Correlate audit record review, analysis, and reporting", "Audit and Accountability"),
        ("3.3.6", "Provide audit record reduction and report generation", "Audit and Accountability"),
        ("3.3.7", "Synchronize internal system clocks", "Audit and Accountability"),
        ("3.3.8", "Protect audit information and audit logging tools", "Audit and Accountability"),
        ("3.3.9", "Limit management of audit logging functionality to privileged users", "Audit and Accountability"),
        ("3.4.1", "Establish and maintain baseline configurations and inventories", "Configuration Management"),
        ("3.4.2", "Establish and enforce security configuration settings", "Configuration Management"),
        ("3.4.3", "Track, review, approve, and log changes to systems", "Configuration Management"),
        ("3.4.4", "Analyze the security impact of changes prior to implementation", "Configuration Management"),
        ("3.4.5", "Define, document, approve, and enforce access restrictions for changes", "Configuration Management"),
        ("3.4.6", "Employ the principle of least functionality", "Configuration Management"),
        ("3.4.7", "Restrict use of nonessential programs, functions, ports, protocols, and services", "Configuration Management"),
        ("3.4.8", "Apply deny-by-exception or permit-by-exception software policy", "Configuration Management"),
        ("3.4.9", "Control and monitor user-installed software", "Configuration Management"),
        ("3.5.1", "Identify system users, processes, and devices", "Identification and Authentication"),
        ("3.5.2", "Authenticate identities of users, processes, or devices", "Identification and Authentication"),
        ("3.5.3", "Use multifactor authentication for privileged and network access", "Identification and Authentication"),
        ("3.5.4", "Employ replay-resistant authentication", "Identification and Authentication"),
        ("3.5.5", "Prevent reuse of identifiers for a defined period", "Identification and Authentication"),
        ("3.5.6", "Disable identifiers after a defined period of inactivity", "Identification and Authentication"),
        ("3.5.7", "Enforce minimum password complexity and change of characters", "Identification and Authentication"),
        ("3.5.8", "Prohibit password reuse for a specified number of generations", "Identification and Authentication"),
        ("3.5.9", "Allow temporary passwords with immediate change", "Identification and Authentication"),
        ("3.5.10", "Store and transmit only cryptographically-protected passwords", "Identification and Authentication"),
        ("3.5.11", "Obscure feedback of authentication information", "Identification and Authentication"),
        ("3.6.1", "Establish an operational incident-handling capability", "Incident Response"),
        ("3.6.2", "Track, document, and report incidents", "Incident Response"),
        ("3.6.3", "Test the organizational incident response capability", "Incident Response"),
        ("3.7.1", "Perform maintenance on organizational systems", "Maintenance"),
        ("3.7.2", "Provide controls on tools, techniques, and personnel used for maintenance", "Maintenance"),
        ("3.7.3", "Ensure equipment removed for off-site maintenance is sanitized", "Maintenance"),
        ("3.7.4", "Check media containing diagnostic programs for malicious code", "Maintenance"),
        ("3.7.5", "Require MFA for nonlocal maintenance sessions", "Maintenance"),
        ("3.7.6", "Supervise maintenance activities without access authorization", "Maintenance"),
        ("3.8.1", "Protect system media containing CUI", "Media Protection"),
        ("3.8.2", "Limit access to CUI on system media to authorized users", "Media Protection"),
        ("3.8.3", "Sanitize or destroy system media containing CUI before disposal", "Media Protection"),
        ("3.8.4", "Mark media with necessary CUI markings", "Media Protection"),
        ("3.8.5", "Control access to media containing CUI during transport", "Media Protection"),
        ("3.8.6", "Implement cryptographic mechanisms to protect CUI on digital media", "Media Protection"),
        ("3.8.7", "Control the use of removable media on system components", "Media Protection"),
        ("3.8.8", "Prohibit use of portable storage devices without identifiable owners", "Media Protection"),
        ("3.8.9", "Protect the confidentiality of backup CUI at storage locations", "Media Protection"),
        ("3.9.1", "Screen individuals prior to authorizing access to CUI", "Personnel Security"),
        ("3.9.2", "Ensure systems are protected during and after personnel actions", "Personnel Security"),
        ("3.10.1", "Limit physical access to organizational systems", "Physical Protection"),
        ("3.10.2", "Protect and monitor physical facility and support infrastructure", "Physical Protection"),
        ("3.10.3", "Escort visitors and monitor visitor activity", "Physical Protection"),
        ("3.10.4", "Maintain audit logs of physical access", "Physical Protection"),
        ("3.10.5", "Control and manage physical access devices", "Physical Protection"),
        ("3.10.6", "Enforce safeguarding measures at alternate work sites", "Physical Protection"),
        ("3.11.1", "Periodically assess risk to organizational operations", "Risk Assessment"),
        ("3.11.2", "Scan for vulnerabilities periodically and when new vulns identified", "Risk Assessment"),
        ("3.11.3", "Remediate vulnerabilities in accordance with risk assessments", "Risk Assessment"),
        ("3.12.1", "Periodically assess security controls for effectiveness", "Security Assessment"),
        ("3.12.2", "Develop and implement plans of action to correct deficiencies", "Security Assessment"),
        ("3.12.3", "Monitor security controls on an ongoing basis", "Security Assessment"),
        ("3.12.4", "Develop and periodically update system security plans", "Security Assessment"),
        ("3.13.1", "Monitor, control, and protect communications at external/internal boundaries", "System and Communications Protection"),
        ("3.13.2", "Employ secure architectural designs and development techniques", "System and Communications Protection"),
        ("3.13.3", "Separate user functionality from system management functionality", "System and Communications Protection"),
        ("3.13.4", "Prevent unauthorized information transfer via shared resources", "System and Communications Protection"),
        ("3.13.5", "Implement subnetworks for publicly accessible components", "System and Communications Protection"),
        ("3.13.6", "Deny network traffic by default, allow by exception", "System and Communications Protection"),
        ("3.13.7", "Prevent split tunneling", "System and Communications Protection"),
        ("3.13.8", "Implement cryptographic mechanisms to prevent unauthorized disclosure", "System and Communications Protection"),
        ("3.13.9", "Terminate network connections at end of session or inactivity", "System and Communications Protection"),
        ("3.13.10", "Establish and manage cryptographic keys", "System and Communications Protection"),
        ("3.13.11", "Employ FIPS-validated cryptography for CUI", "System and Communications Protection"),
        ("3.13.12", "Prohibit remote activation of collaborative computing devices", "System and Communications Protection"),
        ("3.13.13", "Control and monitor use of mobile code", "System and Communications Protection"),
        ("3.13.14", "Control and monitor use of VoIP technologies", "System and Communications Protection"),
        ("3.13.15", "Protect authenticity of communications sessions", "System and Communications Protection"),
        ("3.13.16", "Protect confidentiality of CUI at rest", "System and Communications Protection"),
        ("3.14.1", "Identify, report, and correct system flaws in a timely manner", "System and Information Integrity"),
        ("3.14.2", "Provide protection from malicious code", "System and Information Integrity"),
        ("3.14.3", "Monitor system security alerts and advisories", "System and Information Integrity"),
        ("3.14.4", "Update malicious code protection mechanisms", "System and Information Integrity"),
        ("3.14.5", "Perform periodic and real-time scans", "System and Information Integrity"),
        ("3.14.6", "Monitor systems for attacks and indicators of potential attacks", "System and Information Integrity"),
        ("3.14.7", "Identify unauthorized use of organizational systems", "System and Information Integrity"),
    ]
]

emit_control_catalog(
    framework_id="cmmc-2-l2",
    framework_name="CMMC 2.0 Level 2 (Advanced)",
    version="2.0 (2024 Final Rule)",
    source=f"DoD CIO — {CMMC_URL}. Level 2 = all 110 NIST SP 800-171 Rev 2 requirements.",
    families=sorted({f for _, _, f in CMMC_L2}),
    controls=[{"id": c, "title": t, "description": t, "family": f} for c, t, f in CMMC_L2],
    tier="A",
)


# CMMC Level 3 adds a subset of NIST 800-172 requirements on top of L2
CMMC_L3_ADDS = [
    ("AC.L3-3.1.2e", "Restrict access to systems and components", "Access Control"),
    ("AC.L3-3.1.3e", "Employ secure information transfer solutions", "Access Control"),
    ("AT.L3-3.2.1e", "Advanced threat awareness training", "Awareness and Training"),
    ("AT.L3-3.2.2e", "Practical exercises in awareness training", "Awareness and Training"),
    ("CM.L3-3.4.1e", "Authoritative source and repository for approved components", "Configuration Management"),
    ("CM.L3-3.4.2e", "Automated detection of misconfigured/unauthorized components", "Configuration Management"),
    ("CM.L3-3.4.3e", "Automated inventory discovery and management", "Configuration Management"),
    ("IA.L3-3.5.1e", "Bidirectional authentication for components", "Identification and Authentication"),
    ("IA.L3-3.5.3e", "Block unknown or unconfigured components from connecting", "Identification and Authentication"),
    ("IR.L3-3.6.1e", "24/7 security operations center capability", "Incident Response"),
    ("IR.L3-3.6.2e", "Cyber incident response team deployable within 24 hours", "Incident Response"),
    ("RA.L3-3.11.1e", "Employ threat intelligence to inform risk assessments", "Risk Assessment"),
    ("RA.L3-3.11.2e", "Conduct cyber threat hunting activities", "Risk Assessment"),
    ("RA.L3-3.11.6e", "Assess and monitor supply chain risks", "Risk Assessment"),
    ("RA.L3-3.11.7e", "Develop a supply chain risk management plan", "Risk Assessment"),
    ("CA.L3-3.12.1e", "Conduct penetration testing at least annually", "Security Assessment"),
    ("SC.L3-3.13.4e", "Employ technical means to mislead adversaries", "System and Communications Protection"),
    ("SI.L3-3.14.1e", "Verify integrity of security-critical software", "System and Information Integrity"),
    ("SI.L3-3.14.3e", "Real-time event and alert analysis", "System and Information Integrity"),
    ("SI.L3-3.14.6e", "Use threat indicator information for intrusion detection", "System and Information Integrity"),
]

emit_control_catalog(
    framework_id="cmmc-2-l3",
    framework_name="CMMC 2.0 Level 3 (Expert)",
    version="2.0 (2024 Final Rule)",
    source=f"DoD CIO — {CMMC_URL}. Level 3 = Level 2 + subset of NIST SP 800-172 enhanced requirements.",
    families=sorted({f for _, _, f in (CMMC_L2 + CMMC_L3_ADDS)}),
    controls=[
        {"id": c, "title": t, "description": t, "family": f}
        for c, t, f in (CMMC_L2 + CMMC_L3_ADDS)
    ],
    tier="A",
)


if __name__ == "__main__":
    print("Generated FedRAMP + CMMC catalogs.")
