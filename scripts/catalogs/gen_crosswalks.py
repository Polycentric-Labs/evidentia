"""Generate the six hand-authored bundled crosswalks: cross-framework control mappings.

Ships informational crosswalks for commonly referenced framework pairs.

v0.13 re-keyed four of the six crosswalks so a framework id that used to point at the
retired 16-control ``nist-800-53-mod`` sample now points at the full
``nist-800-53-rev5`` catalog: the CSF and ISO 27001 tables target it, and the HIPAA
and SOC 2 tables source from it. Because ``nist-800-53-rev5-moderate``, the other
Rev 5 baselines, and ``nist-800-53-mod`` itself all belong to the
``nist-800-53-rev5`` crosswalk family (see ``scripts/catalogs/regenerate_manifest.py``),
the crosswalk engine now resolves these four crosswalks for every one of those
baselines, not only the single id each names.

This module used to write its six JSON files as import-time side effects. It is now
pure data, one :class:`CrosswalkSpec` per output file, plus a small CLI with two run
modes:

``gen_crosswalks.py``
    Regenerate all six JSONs in place under the bundled mappings directory.
``gen_crosswalks.py --check``
    Exit 0 if the regenerated output matches the committed JSONs (exit 1 and print a
    per-file first-divergence summary otherwise). The comparison normalizes checkout
    CRLF bytes to LF, while preserving lone CR bytes as content drift.
``gen_crosswalks.py --output-dir DIR``
    Write into ``DIR`` instead of the in-tree mappings directory. ``--check`` also
    compares against this directory, so pointing it elsewhere checks a copy rather
    than the committed files.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MAPPINGS_DIR = REPO_ROOT / "packages" / "evidentia-core" / "src" / "evidentia_core" / "catalogs" / "data" / "mappings"

# The mapping content was authored on this date. The v0.13 re-key changed
# framework identifiers in four files; their mapping rows stayed the same.
# That change is recorded in the CHANGELOG.
GENERATED_AT = "2026-04-16"


# ---------------------------------------------------------------------------
# Pure data: one spec per output file.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CrosswalkSpec:
    """Everything needed to build and name one crosswalk JSON."""

    source_framework: str
    target_framework: str
    version: str
    source: str
    mappings: list[dict[str, str]]
    # Five of the six committed files have no trailing newline; only
    # nist-800-53-rev5_to_soc2-tsc.json does. This is a fact about how the
    # files were originally hand-authored and committed, not an
    # inconsistency to fix in this batch: the flag exists so `serialize`
    # reproduces each file's actual bytes.
    trailing_newline: bool

    @property
    def filename(self) -> str:
        return f"{self.source_framework}_to_{self.target_framework}.json"


def _bare_rows(rows: list[tuple[str, str, str, str]]) -> list[dict[str, str]]:
    """Build mapping rows with empty source and target control titles.

    ``rows`` is ``(source_control_id, target_control_id, relationship, notes)``.
    """
    return [
        {
            "source_control_id": src,
            "source_control_title": "",
            "target_control_id": tgt,
            "target_control_title": "",
            "relationship": rel,
            "notes": notes,
        }
        for src, tgt, rel, notes in rows
    ]


def _titled_rows(rows: list[tuple[str, str, str, str, str, str]]) -> list[dict[str, str]]:
    """Build mapping rows that carry explicit source and target control titles.

    ``rows`` is ``(source_control_id, source_control_title, target_control_id,
    target_control_title, relationship, notes)``.
    """
    return [
        {
            "source_control_id": src_id,
            "source_control_title": src_title,
            "target_control_id": tgt_id,
            "target_control_title": tgt_title,
            "relationship": rel,
            "notes": notes,
        }
        for src_id, src_title, tgt_id, tgt_title, rel, notes in rows
    ]


# ---------------------------------------------------------------------------
# NIST CSF 2.0 -> NIST 800-53 Rev 5 (informative references from NIST OLIR)
# ---------------------------------------------------------------------------

CSF_TO_800_53 = [
    ("GV.OC-01", "AC-1", "related", "Policy linking mission to security"),
    ("GV.OC-03", "PL-2", "related", "System security plans document legal/regulatory requirements"),
    ("GV.RM-01", "PM-1", "equivalent", "Program management policy establishes risk objectives"),
    ("GV.RM-02", "PM-9", "equivalent", "Risk management strategy with appetite and tolerance"),
    ("GV.RR-02", "PS-7", "related", "Roles and responsibilities for security"),
    ("GV.SC-01", "SR-1", "equivalent", "Supply chain risk management policy"),
    ("GV.SC-05", "SR-3", "equivalent", "Supply chain controls and processes"),
    ("ID.AM-01", "CM-8", "equivalent", "Hardware inventory"),
    ("ID.AM-02", "CM-8", "equivalent", "Software inventory"),
    ("ID.AM-03", "AC-4", "related", "Network data flow mapping"),
    ("ID.RA-01", "RA-5", "equivalent", "Vulnerability identification"),
    ("ID.RA-05", "RA-3", "equivalent", "Risk determination"),
    ("PR.AA-01", "IA-2", "related", "Identity and credential management"),
    ("PR.AA-03", "IA-2", "equivalent", "User/device authentication"),
    ("PR.AA-05", "AC-3", "equivalent", "Access enforcement"),
    ("PR.AA-06", "PE-2", "related", "Physical access authorization"),
    ("PR.AT-01", "AT-2", "equivalent", "General security awareness training"),
    ("PR.AT-02", "AT-3", "equivalent", "Role-based training"),
    ("PR.DS-01", "SC-28", "equivalent", "Data-at-rest protection"),
    ("PR.DS-02", "SC-8", "equivalent", "Data-in-transit protection"),
    ("PR.DS-11", "CP-9", "equivalent", "Backup protection and testing"),
    ("PR.PS-01", "CM-2", "equivalent", "Baseline configuration management"),
    ("PR.PS-04", "AU-2", "equivalent", "Log record generation"),
    ("PR.PS-05", "CM-7", "related", "Prevent unauthorized software"),
    ("PR.IR-01", "AC-3", "related", "Network access control"),
    ("DE.CM-01", "SI-4", "equivalent", "Network monitoring"),
    ("DE.CM-03", "AU-12", "related", "Personnel activity logging"),
    ("DE.AE-02", "IR-4", "related", "Event analysis"),
    ("DE.AE-08", "IR-8", "related", "Incident declaration criteria"),
    ("RS.MA-01", "IR-4", "equivalent", "Incident response execution"),
    ("RS.MA-03", "IR-4", "equivalent", "Incident categorization and prioritization"),
    ("RS.CO-02", "IR-6", "equivalent", "Incident notification to stakeholders"),
    ("RS.MI-01", "IR-4", "equivalent", "Incident containment"),
    ("RS.MI-02", "IR-4", "equivalent", "Incident eradication"),
    ("RC.RP-01", "CP-10", "equivalent", "System recovery and reconstitution"),
    ("RC.RP-03", "CP-9", "equivalent", "Verify backup integrity before restore"),
]


# ---------------------------------------------------------------------------
# FedRAMP Moderate -> CMMC Level 2 (both derive from NIST 800-53 / 800-171)
# ---------------------------------------------------------------------------

FEDRAMP_MOD_TO_CMMC_L2 = [
    ("AC-2", "CMMC.L2-3.1.1", "related", "Authorized user access"),
    ("AC-3", "CMMC.L2-3.1.2", "equivalent", "Transaction/function control"),
    ("AC-6", "CMMC.L2-3.1.5", "equivalent", "Least privilege"),
    ("AC-7", "CMMC.L2-3.1.8", "equivalent", "Unsuccessful logon attempts"),
    ("AC-11", "CMMC.L2-3.1.10", "equivalent", "Session lock"),
    ("AC-17", "CMMC.L2-3.1.12", "equivalent", "Remote access control"),
    ("AT-2", "CMMC.L2-3.2.1", "equivalent", "Security awareness"),
    ("AT-3", "CMMC.L2-3.2.2", "equivalent", "Role-based training"),
    ("AU-2", "CMMC.L2-3.3.1", "equivalent", "Event logging"),
    ("AU-3", "CMMC.L2-3.3.1", "related", "Audit record content"),
    ("AU-6", "CMMC.L2-3.3.5", "equivalent", "Audit record review"),
    ("AU-8", "CMMC.L2-3.3.7", "equivalent", "Time stamps"),
    ("CM-2", "CMMC.L2-3.4.1", "equivalent", "Baseline configuration"),
    ("CM-6", "CMMC.L2-3.4.2", "equivalent", "Configuration settings"),
    ("CM-7", "CMMC.L2-3.4.7", "equivalent", "Least functionality"),
    ("CM-8", "CMMC.L2-3.4.1", "related", "System component inventory"),
    ("IA-2", "CMMC.L2-3.5.3", "equivalent", "Multi-factor authentication"),
    ("IA-5", "CMMC.L2-3.5.7", "equivalent", "Authenticator management"),
    ("IR-4", "CMMC.L2-3.6.1", "equivalent", "Incident handling"),
    ("IR-6", "CMMC.L2-3.6.2", "equivalent", "Incident reporting"),
    ("MP-6", "CMMC.L2-3.8.3", "equivalent", "Media sanitization"),
    ("PE-2", "CMMC.L2-3.10.1", "equivalent", "Physical access authorization"),
    ("PE-3", "CMMC.L2-3.10.1", "related", "Physical access control"),
    ("RA-3", "CMMC.L2-3.11.1", "equivalent", "Risk assessment"),
    ("RA-5", "CMMC.L2-3.11.2", "equivalent", "Vulnerability scanning"),
    ("SC-7", "CMMC.L2-3.13.1", "equivalent", "Boundary protection"),
    ("SC-8", "CMMC.L2-3.13.8", "equivalent", "Transmission confidentiality"),
    ("SC-13", "CMMC.L2-3.13.11", "equivalent", "Cryptographic protection (FIPS)"),
    ("SC-28", "CMMC.L2-3.13.16", "equivalent", "Data at rest protection"),
    ("SI-2", "CMMC.L2-3.14.1", "equivalent", "Flaw remediation"),
    ("SI-3", "CMMC.L2-3.14.2", "equivalent", "Malicious code protection"),
    ("SI-4", "CMMC.L2-3.14.6", "equivalent", "System monitoring"),
]


# ---------------------------------------------------------------------------
# NIST 800-53 Rev 5 -> HIPAA Security Rule
# ---------------------------------------------------------------------------

NIST_TO_HIPAA = [
    ("AC-2", "164.308(a)(4)(ii)(B)", "equivalent", "Access authorization"),
    ("AC-2", "164.308(a)(4)(ii)(C)", "related", "Access establishment and modification"),
    ("AC-3", "164.312(a)(1)", "equivalent", "Access control"),
    ("AU-2", "164.312(b)", "equivalent", "Audit controls"),
    ("CP-2", "164.308(a)(7)(i)", "equivalent", "Contingency plan"),
    ("CP-9", "164.308(a)(7)(ii)(A)", "equivalent", "Data backup plan"),
    ("CP-10", "164.308(a)(7)(ii)(B)", "equivalent", "Disaster recovery plan"),
    ("IA-2", "164.312(d)", "equivalent", "Person or entity authentication"),
    ("IA-5", "164.308(a)(5)(ii)(D)", "related", "Password management"),
    ("IR-4", "164.308(a)(6)(ii)", "equivalent", "Response and reporting"),
    ("MP-6", "164.310(d)(2)(i)", "equivalent", "Disposal"),
    ("PE-3", "164.310(a)(1)", "equivalent", "Facility access controls"),
    ("PS-3", "164.308(a)(3)(ii)(B)", "equivalent", "Workforce clearance"),
    ("PS-4", "164.308(a)(3)(ii)(C)", "equivalent", "Termination procedures"),
    ("RA-3", "164.308(a)(1)(ii)(A)", "equivalent", "Risk analysis"),
    ("SC-8", "164.312(e)(1)", "equivalent", "Transmission security"),
    ("SC-13", "164.312(e)(2)(ii)", "equivalent", "Encryption"),
    ("SC-28", "164.312(a)(2)(iv)", "equivalent", "Encryption at rest"),
    ("SI-2", "164.308(a)(5)(ii)(B)", "related", "Protection from malicious software"),
    ("AT-2", "164.308(a)(5)(i)", "equivalent", "Security awareness training"),
]


# ---------------------------------------------------------------------------
# State privacy laws (VCDPA) -> CCPA/CPRA canonical
# ---------------------------------------------------------------------------

VCDPA_TO_CCPA = [
    ("VCDPA.ACCESS", "CCPA.ACCESS", "equivalent", "Right to access"),
    ("VCDPA.DELETE", "CCPA.DELETE", "equivalent", "Right to delete"),
    ("VCDPA.CORRECT", "CCPA.CORRECT", "equivalent", "Right to correct"),
    ("VCDPA.PORTABILITY", "CCPA.PORTABILITY", "equivalent", "Right to portability"),
    ("VCDPA.OPT-OUT-SALE", "CCPA.OPT-OUT-SALE", "equivalent", "Opt out of sale"),
    ("VCDPA.OPT-OUT-PROFILING", "CCPA.OPT-OUT-PROFILING", "equivalent", "Opt out of profiling"),
    ("VCDPA.NOTICE", "CCPA.NOTICE", "equivalent", "Privacy notice"),
    (
        "VCDPA.CONSENT-SENSITIVE",
        "CCPA.CONSENT-SENSITIVE",
        "related",
        "Sensitive data \u2014 CCPA uses 'limit' rather than consent",
    ),
    ("VCDPA.MINIMIZATION", "CCPA.MINIMIZATION", "equivalent", "Data minimization"),
    ("VCDPA.SECURITY", "CCPA.SECURITY", "equivalent", "Reasonable security"),
    ("VCDPA.DPA-CONTRACT", "CCPA.DPA-CONTRACT", "equivalent", "Processor contracts"),
    ("VCDPA.DPA-ASSESSMENT", "CCPA.DPA-ASSESSMENT", "equivalent", "DPIA / risk assessment"),
    ("VCDPA.NON-DISCRIMINATION", "CCPA.NON-DISCRIMINATION", "equivalent", "Non-discrimination"),
]


# ---------------------------------------------------------------------------
# ISO 27001 (stub) -> NIST 800-53 Rev 5 (conceptual parity mapping)
# ---------------------------------------------------------------------------

ISO_TO_NIST = [
    ("A.5.1", "PM-1", "equivalent", "Information security policy"),
    ("A.5.2", "PS-7", "related", "Roles and responsibilities"),
    ("A.5.3", "AC-5", "equivalent", "Separation of duties"),
    ("A.5.15", "AC-3", "equivalent", "Access control"),
    ("A.5.16", "IA-2", "equivalent", "Identity management"),
    ("A.5.19", "SR-3", "equivalent", "Supplier relationships (supply chain)"),
    ("A.5.24", "IR-8", "equivalent", "Incident management planning"),
    ("A.5.29", "CP-2", "equivalent", "Business continuity"),
    ("A.6.3", "AT-2", "equivalent", "Awareness training"),
    ("A.7.2", "PE-3", "equivalent", "Physical entry"),
    ("A.7.14", "MP-6", "equivalent", "Secure disposal"),
    ("A.8.2", "AC-6", "equivalent", "Privileged access"),
    ("A.8.3", "AC-3", "related", "Information access restriction"),
    ("A.8.5", "IA-2", "equivalent", "Secure authentication"),
    ("A.8.7", "SI-3", "equivalent", "Malware protection"),
    ("A.8.8", "RA-5", "equivalent", "Vulnerability management"),
    ("A.8.9", "CM-2", "equivalent", "Configuration management"),
    ("A.8.13", "CP-9", "equivalent", "Information backup"),
    ("A.8.15", "AU-2", "equivalent", "Logging"),
    ("A.8.16", "SI-4", "equivalent", "Monitoring"),
    ("A.8.24", "SC-13", "equivalent", "Cryptography"),
    ("A.8.28", "SA-11", "equivalent", "Secure coding"),
    ("A.8.32", "CM-3", "equivalent", "Change management"),
]


# ---------------------------------------------------------------------------
# NIST 800-53 Rev 5 -> SOC 2 Trust Services Criteria
#
# Not previously produced by this script: the committed file was
# hand-authored directly as JSON. Added here so the generator's --check
# covers all six shipped crosswalks instead of five.
# ---------------------------------------------------------------------------

NIST_TO_SOC2 = [
    (
        "AC-2",
        "Account Management",
        "CC6.1",
        "Common Criteria 6.1",
        "related",
        "Account lifecycle management in AC-2 maps to the logical-access criterion in CC6.1.",
    ),
    (
        "AC-2",
        "Account Management",
        "CC6.2",
        "Common Criteria 6.2",
        "related",
        "User provisioning and deprovisioning in AC-2 supports the registration/authorization criterion in CC6.2.",
    ),
    (
        "AC-3",
        "Access Enforcement",
        "CC6.3",
        "Common Criteria 6.3",
        "related",
        "AC-3 enforces authorizations at runtime; CC6.3 governs role/least-privilege assignment.",
    ),
    (
        "AC-6",
        "Least Privilege",
        "CC6.3",
        "Common Criteria 6.3",
        "equivalent",
        "Both controls require least-privilege enforcement.",
    ),
    (
        "AU-2",
        "Event Logging",
        "CC7.2",
        "Common Criteria 7.2",
        "related",
        "Event logging in AU-2 produces the data consumed by the monitoring criterion in CC7.2.",
    ),
    (
        "AU-6",
        "Audit Record Review, Analysis, and Reporting",
        "CC7.2",
        "Common Criteria 7.2",
        "related",
        "Audit review and analysis in AU-6 is the analytical step behind CC7.2 monitoring.",
    ),
    (
        "CM-2",
        "Baseline Configuration",
        "CC8.1",
        "Common Criteria 8.1",
        "related",
        "Baseline configurations in CM-2 are the starting point for the change-management criterion in CC8.1.",
    ),
    (
        "CM-6",
        "Configuration Settings",
        "CC7.1",
        "Common Criteria 7.1",
        "related",
        "Configuration-setting drift detection in CM-6 feeds the detection criterion in CC7.1.",
    ),
    (
        "IA-2",
        "Identification and Authentication (Organizational Users)",
        "CC6.2",
        "Common Criteria 6.2",
        "equivalent",
        "Both controls require uniquely identifying and authenticating users.",
    ),
    (
        "IA-5",
        "Authenticator Management",
        "CC6.1",
        "Common Criteria 6.1",
        "partial",
        "Authenticator content protections in IA-5 support the logical-access criterion in CC6.1.",
    ),
    (
        "IR-4",
        "Incident Handling",
        "CC7.3",
        "Common Criteria 7.3",
        "equivalent",
        "Incident handling in IR-4 and the incident-evaluation criterion in CC7.3 cover the same lifecycle.",
    ),
    (
        "RA-5",
        "Vulnerability Monitoring and Scanning",
        "CC7.1",
        "Common Criteria 7.1",
        "equivalent",
        "Both controls require ongoing vulnerability detection and reporting.",
    ),
    (
        "SC-7",
        "Boundary Protection",
        "CC6.6",
        "Common Criteria 6.6",
        "related",
        "Boundary protection in SC-7 enforces the external-access criterion in CC6.6.",
    ),
    (
        "SC-13",
        "Cryptographic Protection",
        "CC6.7",
        "Common Criteria 6.7",
        "related",
        "Cryptographic protection in SC-13 secures data in transit covered by CC6.7.",
    ),
    (
        "SC-28",
        "Protection of Information at Rest",
        "CC6.7",
        "Common Criteria 6.7",
        "related",
        "Encryption at rest in SC-28 protects information governed by CC6.7.",
    ),
    (
        "SI-2",
        "Flaw Remediation",
        "CC7.1",
        "Common Criteria 7.1",
        "related",
        "Flaw remediation in SI-2 is the response activity for vulnerabilities detected under CC7.1.",
    ),
    (
        "SI-4",
        "System Monitoring",
        "CC7.2",
        "Common Criteria 7.2",
        "equivalent",
        "Both controls require continuous monitoring for security-relevant events.",
    ),
]


CROSSWALKS: list[CrosswalkSpec] = [
    CrosswalkSpec(
        source_framework="nist-csf-2.0",
        target_framework="nist-800-53-rev5",
        version="CSF 2.0 / 800-53 Rev 5",
        source="Derived from NIST OLIR informative references",
        mappings=_bare_rows(CSF_TO_800_53),
        trailing_newline=False,
    ),
    CrosswalkSpec(
        source_framework="fedramp-rev5-moderate",
        target_framework="cmmc-2-l2",
        version="FedRAMP Rev 5 / CMMC 2.0 Level 2 (2024 Final Rule)",
        source="Evidentia-authored based on DoD CMMC Assessment Guide correlations to NIST 800-171/800-53",
        mappings=_bare_rows(FEDRAMP_MOD_TO_CMMC_L2),
        trailing_newline=False,
    ),
    CrosswalkSpec(
        source_framework="nist-800-53-rev5",
        target_framework="hipaa-security",
        version="NIST 800-53 Rev 5 / HIPAA 2013 Omnibus",
        source="HHS OCR HIPAA Security Rule Crosswalk Guidance + NIST OLIR",
        mappings=_bare_rows(NIST_TO_HIPAA),
        trailing_newline=False,
    ),
    CrosswalkSpec(
        source_framework="us-va-vcdpa",
        target_framework="us-ca-ccpa-cpra",
        version="VCDPA / CCPA-CPRA 2023",
        source="Evidentia-authored based on IAPP multi-state privacy matrix",
        mappings=_bare_rows(VCDPA_TO_CCPA),
        trailing_newline=False,
    ),
    CrosswalkSpec(
        source_framework="iso-27001-2022",
        target_framework="nist-800-53-rev5",
        version="ISO 27001:2022 / NIST 800-53 Rev 5",
        source="Evidentia-authored based on ISO/IEC 27001:2022 Annex A concordance with NIST 800-53 families",
        mappings=_bare_rows(ISO_TO_NIST),
        trailing_newline=False,
    ),
    CrosswalkSpec(
        source_framework="nist-800-53-rev5",
        target_framework="soc2-tsc",
        version="1.1",
        source=(
            "Hand-curated sample crosswalk between NIST SP 800-53 Rev 5 Moderate baseline and "
            "SOC 2 Trust Services Criteria 2017. Target control titles use the generic stub "
            "titles from the bundled soc2-tsc stub catalog (AICPA control text is licensed \u2014 "
            "see license_url on the soc2-tsc catalog). Replace with the AICPA-maintained "
            "crosswalk for production use."
        ),
        mappings=_titled_rows(NIST_TO_SOC2),
        trailing_newline=True,
    ),
]


# ---------------------------------------------------------------------------
# Pure functions: build the payload dict and serialize it to on-disk bytes.
# ---------------------------------------------------------------------------


def build_payload(spec: CrosswalkSpec) -> dict[str, Any]:
    """Build the full crosswalk payload dict for one spec (stable field order)."""
    return {
        "source_framework": spec.source_framework,
        "target_framework": spec.target_framework,
        "version": spec.version,
        "generated_at": GENERATED_AT,
        "source": spec.source,
        "mappings": spec.mappings,
    }


def serialize(payload: dict[str, Any], *, trailing_newline: bool) -> str:
    """Serialize a crosswalk payload the way its committed file was written.

    ``indent=2`` and ``ensure_ascii=False`` for every file; a trailing newline
    only when ``trailing_newline`` is set (see :class:`CrosswalkSpec`).
    """
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    return text + "\n" if trailing_newline else text


def build_all() -> dict[str, str]:
    """Build every crosswalk; return ``{filename: serialized_json}``."""
    return {
        spec.filename: serialize(build_payload(spec), trailing_newline=spec.trailing_newline) for spec in CROSSWALKS
    }


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _diff_summary(expected: bytes, actual: bytes, name: str) -> str:
    """Return a short first-divergence summary between two byte strings."""
    exp_lines = expected.splitlines(keepends=True)
    act_lines = actual.splitlines(keepends=True)
    for i, (exp, act) in enumerate(zip(exp_lines, act_lines, strict=False)):
        if exp != act:
            return f"  {name}: first diff at line {i + 1}\n    committed:   {exp!r}\n    regenerated: {act!r}"
    if len(exp_lines) != len(act_lines):
        return f"  {name}: line-count differs (committed={len(exp_lines)}, regenerated={len(act_lines)})"
    # Same lines but different bytes (trailing-newline / EOL difference).
    return f"  {name}: content differs only in trailing bytes / EOL"


def _compare(generated: dict[str, str], committed_dir: Path) -> list[str]:
    """Compare regenerated crosswalk bytes against the files in ``committed_dir``.

    Normalizes only CRLF byte pairs to LF, so Git's Windows checkout
    conversion does not read as content drift. Lone CR bytes and all other
    byte differences remain visible. No writes or network access.
    """
    drift: list[str] = []
    for name, content in sorted(generated.items()):
        committed_path = committed_dir / name
        if not committed_path.exists():
            drift.append(f"  {name}: committed file missing")
            continue
        committed = committed_path.read_bytes().replace(b"\r\n", b"\n")
        regenerated = content.encode("utf-8")
        if committed != regenerated:
            drift.append(_diff_summary(committed, regenerated, name))
    return drift


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Do not write. Exit 0 if regenerated output matches the committed "
            "JSONs; exit 1 and print a per-file diff summary on drift."
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=MAPPINGS_DIR,
        help=(
            "Directory to write JSONs into (default: the in-tree mappings "
            "dir). Under --check, this is also the directory compared "
            "against, so pointing it at a copy checks the copy instead of "
            "the committed files."
        ),
    )
    args = parser.parse_args(argv)

    generated = build_all()

    if args.check:
        drift = _compare(generated, args.output_dir)
        if drift:
            print("DRIFT: regenerated crosswalks differ from committed:", file=sys.stderr)
            for line in drift:
                print(line, file=sys.stderr)
            print("\nRe-run without --check to regenerate.", file=sys.stderr)
            return 1
        print(f"OK: all {len(generated)} crosswalks match committed bytes after checkout CRLF normalization.")
        return 0

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(generated.items()):
        (args.output_dir / name).write_text(content, encoding="utf-8", newline="\n")
        print(f"  wrote {args.output_dir / name}")
    print(f"Regenerated {len(generated)} crosswalks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
