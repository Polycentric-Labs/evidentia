"""Published heading inventories and their source limits survive regeneration."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import runpy
from collections import Counter
from datetime import date
from pathlib import Path
from types import ModuleType

import pytest
from evidentia_core.catalogs.loader import load_evidentia_catalog

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts" / "catalogs"
DATA = ROOT / "packages/evidentia-core/src/evidentia_core/catalogs/data"
CISA_SOURCE = "https://www.cisa.gov/sites/default/files/2025-12/CPG_Report_2.0_508c.pdf"
CMMC_SOURCE = "https://dodcio.defense.gov/Portals/0/Documents/CMMC/AssessmentGuideL1v2.pdf"
SWIFT_SOURCE = (
    "https://www2.swift.com/knowledgecentre/rest/v1/publications/cscf_dd/"
    "_latest/CSCF_v2026_202507015.pdf?logDownload=true"
)

# These pairs were reviewed against the CISA PDF layout, not its plain text order.
CISA_HEADINGS = [
    ("1.A", "ESTABLISH CYBERSECURITY RESPONSIBILITIES"),
    ("1.B", "MANAGE CYBERSECURITY OVERSIGHT"),
    ("1.C", "MAINTAIN INCIDENT RESPONSE PLANS"),
    ("1.D", "SUPPLY CHAIN INCIDENT REPORTING & VULNERABILITY DISCLOSURE"),
    ("1.E", "MANAGE RISKS FROM MANAGED SERVICE PROVIDERS"),
    ("2.A", "MANAGE ORGANIZATIONAL ASSETS"),
    ("2.B", "MITIGATE KNOWN VULNERABILITIES"),
    ("2.C", "OBTAIN INDEPENDENT VALIDATION OF CYBERSECURITY CONTROLS"),
    ("2.D", "MAINTAIN VULNERABILITY DISCLOSURE/REPORTING PROCESS"),
    ("2.E", "DOCUMENT NETWORK TOPOLOGY"),
    ("3.A", "CHANGE DEFAULT PASSWORDS"),
    ("3.B", "ESTABLISH MINIMUM PASSWORD STRENGTH"),
    ("3.C", "CREATE UNIQUE CREDENTIALS"),
    ("3.D", "REVOKE CREDENTIALS FOR DEPARTING STAFF"),
    ("3.E", "MONITOR UNSUCCESSFUL (AUTOMATED) LOGIN ATTEMPTS"),
    ("3.F", "IMPLEMENT MULTIFACTOR AUTHENTICATION (MFA)"),
    ("3.G", "ADMINISTRATORS MAINTAIN SEPARATE USER AND PRIVILEGED ACCOUNTS"),
    ("3.H", "IMPLEMENT THE PRINCIPLES OF LEAST PRIVILEGE"),
    ("3.I", "IMPLEMENT LOGICAL/PHYSICAL NETWORK SEGMENTATION"),
    ("3.J", "IMPLEMENT CYBERSECURITY TRAINING"),
    ("3.K", "UTILIZE STRONG ENCRYPTION"),
    ("3.L", "ENABLE EMAIL SECURITY"),
    ("3.M", "DISABLE AUTORUN & MACROS BY DEFAULT"),
    ("3.N", "ESTABLISH CHANGE MANAGEMENT PROCESSES"),
    ("3.O", "MAINTAIN SYSTEM BACKUPS & RESTORATION ABILITY"),
    ("3.P", "MAINTAIN HARDWARE & SOFTWARE APPROVAL PROCESS"),
    ("3.Q", "MAINTAIN LOG COLLECTION & STORAGE"),
    ("3.R", "PROHIBIT CONNECTION OF UNAUTHORIZED DEVICES"),
    ("3.S", "SECURE INTERNET-FACING DEVICES"),
    ("4.A", "ESTABLISH MALICIOUS CODE DETECTION"),
    ("4.B", "IDENTIFY ADVERSE EVENTS"),
    ("5.A", "ESTABLISH INCIDENT COMMUNICATION PROCEDURES"),
    ("5.B", "ESTABLISH INCIDENT REPORTING PROCEDURES"),
    ("6.A", "EXECUTE INCIDENT RECOVERY PLAN"),
]

# Swift v2026, public PDF outline and the summary table on page 28.
SWIFT_HEADINGS = [
    ("1.1", "Swift Environment Protection"),
    ("1.2", "Operating System Privileged Account Control"),
    ("1.3", "Virtualisation or Cloud Platform Protection"),
    ("1.4", "Restriction of Internet Access"),
    ("1.5", "Customer Environment Protection"),
    ("2.1", "Internal Data Flow Security"),
    ("2.2", "Security Updates"),
    ("2.3", "System Hardening"),
    ("2.4", "Back Office Data Flow Security"),
    ("2.5A", "External Transmission Data Protection"),
    ("2.6", "Operator Session Confidentiality and Integrity"),
    ("2.7", "Vulnerability Scanning"),
    ("2.8", "Outsourced Critical Activity Protection"),
    ("2.9", "Transaction Business Controls"),
    ("2.10", "Application Hardening"),
    ("2.11A", "RMA Business Controls"),
    ("3.1", "Physical Security"),
    ("4.1", "Password Policy"),
    ("4.2", "Multi-Factor Authentication"),
    ("5.1", "Logical Access Control"),
    ("5.2", "Token Management"),
    ("5.3A", "Staff Screening Process"),
    ("5.4", "Password Repository Protection"),
    ("6.1", "Malware Protection"),
    ("6.2", "Software Integrity"),
    ("6.3", "Database Integrity"),
    ("6.4", "Logging and Monitoring"),
    ("6.5A", "Intrusion Detection"),
    ("7.1", "Cyber Incident Response Planning"),
    ("7.2", "Security Training and Awareness"),
    ("7.3A", "Penetration Testing"),
    ("7.4A", "Scenario-based Risk Assessment"),
]

# DoD guide version 2.13, September 2024, contents pages iii and iv.
CMMC_HEADINGS = [
    ("AC.L1-b.1.i", "Authorized Access Control [FCI Data]"),
    ("AC.L1-b.1.ii", "Transaction & Function Control [FCI Data]"),
    ("AC.L1-b.1.iii", "External Connections [FCI Data]"),
    ("AC.L1-b.1.iv", "Control Public Information [FCI Data]"),
    ("IA.L1-b.1.v", "Identification [FCI Data]"),
    ("IA.L1-b.1.vi", "Authentication [FCI Data]"),
    ("MP.L1-b.1.vii", "Media Disposal [FCI Data]"),
    ("PE.L1-b.1.viii", "Limit Physical Access [FCI Data]"),
    ("PE.L1-b.1.ix", "Manage Visitors & Physical Access [FCI Data]"),
    ("SC.L1-b.1.x", "Boundary Protection [FCI Data]"),
    ("SC.L1-b.1.xi", "Public-Access System Separation [FCI Data]"),
    ("SI.L1-b.1.xii", "Flaw Remediation [FCI Data]"),
    ("SI.L1-b.1.xiii", "Malicious Code ProTection [FCI Data]"),
    ("SI.L1-b.1.xiv", "Update Malicious Code Protection [FCI Data]"),
    ("SI.L1-b.1.xv", "System & File Scanning [FCI Data]"),
]

CURRENT = [
    ("us-federal/cisa-cpgs.json", CISA_HEADINGS, CISA_SOURCE),
    ("us-federal/cmmc-2-l1.json", CMMC_HEADINGS, CMMC_SOURCE),
    ("stubs/swift-cscf-2026.json", SWIFT_HEADINGS, SWIFT_SOURCE),
]


@pytest.mark.parametrize(("relative", "expected", "source"), CURRENT)
def test_bundled_current_heading_inventory(relative: str, expected: list[tuple[str, str]], source: str) -> None:
    catalog = load_evidentia_catalog(DATA / relative)
    assert [(control.id, control.title) for control in catalog.controls] == expected
    assert catalog.control_count == len(expected)
    assert catalog.source == source
    assert catalog.status == "current"
    assert catalog.verified_on == date(2026, 9, 9)
    assert catalog.text_depth == "headings"
    assert not any(control.enhancements or control.related_controls for control in catalog.controls)


def test_cisa_functions_and_changed_identifier_notice() -> None:
    catalog = load_evidentia_catalog(DATA / "us-federal/cisa-cpgs.json")
    families = ["Govern", "Identify", "Protect", "Detect", "Respond", "Recover"]
    assert catalog.families == families
    assert [len(catalog.get_family(family)) for family in families] == [5, 5, 19, 2, 2, 1]
    for control in catalog.controls:
        assert control.properties["function"] == families[int(control.id[0]) - 1]
        assert control.description == control.title
    assert catalog.notes and "36-goal" in catalog.notes
    assert "reused IDs" in catalog.notes
    assert "no automatic equivalence" in catalog.notes


def test_swift_designations_do_not_claim_universal_architecture_applicability() -> None:
    catalog = load_evidentia_catalog(DATA / "stubs/swift-cscf-2026.json")
    advisory = {"2.5A", "2.11A", "5.3A", "6.5A", "7.3A", "7.4A"}
    assert {control.id for control in catalog.controls if control.properties["designation"] == "advisory"} == advisory
    assert Counter(control.properties["designation"] for control in catalog.controls) == {
        "mandatory": 26,
        "advisory": 6,
    }
    assert [len(catalog.get_family(family)) for family in catalog.families] == [5, 11, 1, 2, 4, 5, 4]
    assert catalog.tier == "C" and catalog.placeholder and catalog.license_required
    assert catalog.license_url == "https://www2.swift.com/knowledgecentre/publications/cscf_dd"
    for control in catalog.controls:
        assert control.placeholder and control.license_required and control.tier == "C"
        assert control.license_url == catalog.license_url
        assert control.description == "[Licensed content. See license_url for authoritative text.]"
        assert not control.guidance and not control.assessment_objectives
    assert catalog.notes and "architecture" in catalog.notes
    assert "2026 attestation" in catalog.notes and "v2027" in catalog.notes


def test_swift_historical_rows_are_preserved_with_source_limit() -> None:
    path = DATA / "stubs/swift-cscf-2024.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    # Hash parsed control content, so checkout line endings cannot affect this assertion.
    encoded = json.dumps(raw["controls"], sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == "5b6dbf0195d7792cea90a113d399d6bc0009c3f7006741ff393d102d4aa5e3cb"
    catalog = load_evidentia_catalog(path)
    assert catalog.control_count == 33 and catalog.version == "v2024"
    assert catalog.status == "historical"
    assert catalog.verified_on is None
    assert catalog.superseded_by == "swift-cscf-2026"
    assert catalog.notes and "original v2024 source table was not verified" in catalog.notes
    assert catalog.placeholder and catalog.license_required and catalog.text_depth == "headings"


def test_cmmc_retains_handle_with_explicit_id_migration_notice() -> None:
    catalog = load_evidentia_catalog(DATA / "us-federal/cmmc-2-l1.json")
    assert catalog.framework_id == "cmmc-2-l1"
    assert "2.13" in catalog.version and "September 2024" in catalog.version
    assert [len(catalog.get_family(family)) for family in catalog.families] == [4, 2, 1, 2, 2, 4]
    for control in catalog.controls:
        assert control.properties["data_category"] == "FCI"
        assert control.properties["far_reference"] == f"52.204-21(b)(1)({control.id.rsplit('.', 1)[1]})"
        assert control.description == control.title
    assert catalog.get_control("AC.L1-3.1.1") is None
    assert catalog.notes and "content is not frozen" in catalog.notes
    assert "17 NIST-style" in catalog.notes and "15 FAR-based" in catalog.notes
    assert "no automatic equivalence or migration" in catalog.notes


@pytest.fixture
def generator(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(SCRIPTS))
    spec = importlib.util.spec_from_file_location("currency_headings_generator", SCRIPTS / "gen_currency_headings.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_compact_inputs_record_independent_primary_provenance(generator: ModuleType) -> None:
    definitions = generator.load_definitions()
    expected = {relative.rsplit("/", 1)[-1][:-5]: (headings, source) for relative, headings, source in CURRENT}
    for definition in definitions:
        framework_id = definition["metadata"]["framework_id"]
        if framework_id not in expected:
            assert framework_id == "swift-cscf-2024"
            assert definition["provenance"]["original_table_verified"] is False
            continue
        headings, source = expected[framework_id]
        assert [(row["id"], row["title"]) for row in definition["controls"]] == headings
        assert definition["metadata"]["source"] == source
        assert definition["provenance"]["verified_on"] == "2026-09-09"
        assert definition["provenance"]["source_url"] == source
        assert all("description" not in row and "guidance" not in row for row in definition["controls"])
        if framework_id == "cisa-cpgs":
            assert definition["provenance"]["sha256"] == (
                "44ace92a275468d1946868855c44cb9d914ef0ce3d6656ebca5c9b9fa879f85e"
            )
            assert "layout" in definition["provenance"]["extraction"]
        else:
            assert definition["provenance"]["sha256"] is None


@pytest.mark.parametrize(
    ("function", "expected_paths"),
    [
        ("generate_cisa_catalog", {"us-federal/cisa-cpgs.json"}),
        ("generate_cmmc_level1", {"us-federal/cmmc-2-l1.json"}),
        ("generate_swift_catalogs", {"stubs/swift-cscf-2024.json", "stubs/swift-cscf-2026.json"}),
    ],
)
def test_isolated_generation_is_deterministic_and_scoped(
    generator: ModuleType, tmp_path: Path, function: str, expected_paths: set[str]
) -> None:
    output = tmp_path / "generated"
    generate = getattr(generator, function)
    generate(output_dir=output)
    first = {path.relative_to(output).as_posix(): path.read_bytes() for path in output.rglob("*.json")}
    assert set(first) == expected_paths
    for relative, content in first.items():
        assert b"\r\n" not in content
        assert content == (DATA / relative).read_bytes().replace(b"\r\n", b"\n")
    generate(output_dir=output)
    assert first == {path.relative_to(output).as_posix(): path.read_bytes() for path in output.rglob("*.json")}


@pytest.mark.parametrize(
    ("legacy_script", "owned_paths"),
    [
        ("gen_us_regulatory.py", {"us-federal/cisa-cpgs.json"}),
        ("gen_fedramp_cmmc.py", {"us-federal/cmmc-2-l1.json"}),
        ("gen_stubs.py", {"stubs/swift-cscf-2024.json", "stubs/swift-cscf-2026.json"}),
    ],
)
def test_legacy_entry_points_emit_current_owned_catalogs(
    generator: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    legacy_script: str,
    owned_paths: set[str],
) -> None:
    monkeypatch.setattr(generator.helpers, "DATA_ROOT", tmp_path)
    runpy.run_path(str(SCRIPTS / legacy_script), run_name="__main__")
    for relative in owned_paths:
        assert (tmp_path / relative).read_bytes() == (DATA / relative).read_bytes().replace(b"\r\n", b"\n")


def test_generator_import_does_not_write_catalogs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(SCRIPTS))
    helpers = __import__("_generators")
    monkeypatch.setattr(helpers, "DATA_ROOT", tmp_path)
    runpy.run_path(str(SCRIPTS / "gen_currency_headings.py"), run_name="currency_import")
    assert list(tmp_path.iterdir()) == []


def test_duplicate_source_id_fails_before_writing(
    generator: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    definitions = generator.load_definitions()
    definitions[0]["controls"].append(definitions[0]["controls"][0].copy())
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps({"catalogs": definitions}), encoding="utf-8", newline="\n")
    monkeypatch.setattr(generator, "SOURCE_PATH", path)
    output = tmp_path / "generated"
    with pytest.raises(ValueError, match="duplicate control ID"):
        generator.generate_cisa_catalog(output_dir=output)
    assert not output.exists()
