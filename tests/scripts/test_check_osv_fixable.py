"""Tests for ``scripts/check_osv_fixable.py`` (the post-publish container
rescan FIXABLE-only policy gate).

osv-scanner v2 has NO native fixable/severity gate -- it exits non-zero on
*any* reportable advisory, which turns the published-container rescan
permanently red on day-N base-OS CVEs that have "No fix available" (a
chronically-red gate the project's own doctrine forbids;
docs/engineering-practices.md, "Fail closed"). This policy step parses
``osv-scanner ... --format json`` and fails ONLY when a detected
vulnerability has an *applicable* fix, so the rescan becomes an actionable
"a fix is now available -> rebuild" signal instead of noise.

The crux, established empirically against real ``osv-scanner v2.3.8`` output
(``osv-scanner scan image`` on the published v0.10.13 image): an OSV record
lists ``affected[]`` entries across *every* Debian release and even unrelated
source packages that share a CVE. A fix is "applicable" ONLY when the
``affected`` entry whose ``package.ecosystem`` + ``package.name`` match the
*detected* package carries a ``fixed`` event. Matching ANY ``fixed`` event
anywhere over-reports ~25x (110 vs the real 4). The committed sample fixture
(``data/osv_rescan_sample.json``) is a faithfully-trimmed slice of that real
scan -- ``libssh2`` (4 genuinely-fixable + 2 no-fix) and ``gnutls28`` (1
no-fix advisory whose record embeds an ``asterisk`` / ``Debian:11`` ``fixed``
event as a cross-package decoy that MUST be ignored).

``scripts/`` has no ``__init__.py``; the repo root is placed on ``sys.path``
so ``from scripts import ...`` resolves as a PEP 420 namespace package,
matching the gate tooling's import form.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import check_osv_fixable as c  # noqa: E402

SAMPLE = Path(__file__).parent / "data" / "osv_rescan_sample.json"

# The empirical ground truth: osv-scanner v2.3.8's own table on the published
# v0.10.13 image reported "4 vulnerabilities can be fixed", all in libssh2.
GROUND_TRUTH_FIXABLE_IDS = {
    "DEBIAN-CVE-2025-15661",
    "DEBIAN-CVE-2026-55199",
    "DEBIAN-CVE-2026-55200",
    "DEBIAN-CVE-2026-7598",
}


# --------------------------------------------------------------------------
# Synthetic fixture builders (small, explicit edge cases)
# --------------------------------------------------------------------------
def _scan(*packages: dict) -> dict:
    return {"results": [{"source": {"type": "os"}, "packages": list(packages)}]}


def _pkg(name: str, ecosystem: str, version: str, vulns: list[dict],
         groups: list[dict] | None = None) -> dict:
    return {
        "package": {"name": name, "os_package_name": name, "ecosystem": ecosystem,
                    "version": version},
        "groups": groups if groups is not None else [],
        "vulnerabilities": vulns,
    }


def _affected(ecosystem: str, name: str, events: list[dict]) -> dict:
    return {"package": {"ecosystem": ecosystem, "name": name},
            "ranges": [{"type": "ECOSYSTEM", "events": events}]}


# --------------------------------------------------------------------------
# fixed_versions_for -- the matched-affected core
# --------------------------------------------------------------------------
def test_fixed_versions_for_returns_matched_debian_release_fix() -> None:
    pkg_info = {"ecosystem": "Debian:13", "name": "libssh2"}
    vuln = {
        "id": "X",
        "affected": [
            _affected("Debian:13", "libssh2",
                      [{"introduced": "0"}, {"fixed": "1.11.1-1+deb13u1"}]),
        ],
    }
    assert c.fixed_versions_for(pkg_info, vuln) == ["1.11.1-1+deb13u1"]


def test_fixed_event_in_other_ecosystem_is_not_a_fix() -> None:
    """A fixed event for a DIFFERENT Debian release / package must not count."""
    pkg_info = {"ecosystem": "Debian:13", "name": "gnutls28"}
    vuln = {
        "id": "Y",
        "affected": [
            # the detected package: no fix in Debian:13
            _affected("Debian:13", "gnutls28", [{"introduced": "0"}]),
            # the cross-package decoy (real-world shape): asterisk in Debian:11
            _affected("Debian:11", "asterisk",
                      [{"introduced": "0"}, {"fixed": "1:13.7.2~dfsg-1"}]),
        ],
    }
    assert c.fixed_versions_for(pkg_info, vuln) == []


def test_last_affected_only_is_not_a_fix() -> None:
    pkg_info = {"ecosystem": "Debian:13", "name": "perl"}
    vuln = {
        "id": "Z",
        "affected": [
            _affected("Debian:13", "perl",
                      [{"introduced": "0"}, {"last_affected": "5.40.1-6"}]),
        ],
    }
    assert c.fixed_versions_for(pkg_info, vuln) == []


def test_cross_release_fix_for_same_package_does_not_count() -> None:
    """The ecosystem match is exact *including the release suffix* on purpose:
    a fix released for Debian:12 of the same source package does not apply to a
    Debian:13 install. Relaxing to the 'Debian' family would over-flag."""
    pkg_info = {"ecosystem": "Debian:13", "name": "curl"}
    vuln = {
        "id": "W",
        "affected": [
            _affected("Debian:13", "curl", [{"introduced": "0"}]),               # detected: no fix
            _affected("Debian:12", "curl", [{"introduced": "0"}, {"fixed": "8.x"}]),  # other release: has a fix
        ],
    }
    assert c.fixed_versions_for(pkg_info, vuln) == []


def test_empty_string_fixed_event_is_not_a_fix() -> None:
    """A `fixed: ""` event carries no actionable upgrade target — it must not be
    treated as a fix (which would over-report with a blank 'Fixed in' cell)."""
    pkg_info = {"ecosystem": "Debian:13", "name": "tar"}
    vuln = {
        "id": "V",
        "affected": [
            _affected("Debian:13", "tar", [{"introduced": "0"}, {"fixed": ""}]),
        ],
    }
    assert c.fixed_versions_for(pkg_info, vuln) == []


# --------------------------------------------------------------------------
# classify -- against the REAL trimmed fixture (the regression anchor)
# --------------------------------------------------------------------------
def test_real_fixture_reports_exactly_four_fixable() -> None:
    data = c.load_scan(SAMPLE)
    fixable, _unfixable = c.classify(data)
    assert len(fixable) == 4


def test_real_fixture_fixable_ids_match_osv_scanner_ground_truth() -> None:
    data = c.load_scan(SAMPLE)
    fixable, _ = c.classify(data)
    assert {f.vuln_id for f in fixable} == GROUND_TRUTH_FIXABLE_IDS


def test_real_fixture_unfixable_count() -> None:
    data = c.load_scan(SAMPLE)
    _fixable, unfixable = c.classify(data)
    # 2 no-fix libssh2 advisories + 1 gnutls28 advisory (decoy rejected).
    assert {f.vuln_id for f in unfixable} == {
        "DEBIAN-CVE-2011-3389",
        "DEBIAN-CVE-2026-58050",
        "DEBIAN-CVE-2026-58051",
    }


def test_real_fixture_fixable_carries_fixed_version_and_severity() -> None:
    data = c.load_scan(SAMPLE)
    fixable, _ = c.classify(data)
    by_id = {f.vuln_id: f for f in fixable}
    f = by_id["DEBIAN-CVE-2026-55200"]
    assert "1.11.1-1+deb13u1" in f.fixed_versions
    assert f.source_package == "libssh2"
    assert f.installed_version == "1.11.1-1"
    assert f.max_severity == "9.8"  # from the group's max_severity


# --------------------------------------------------------------------------
# classify -- synthetic edge cases
# --------------------------------------------------------------------------
def test_empty_scan_is_clean() -> None:
    fixable, unfixable = c.classify(_scan())
    assert fixable == [] and unfixable == []


def test_package_with_no_vulns_is_clean() -> None:
    data = _scan(_pkg("zlib", "Debian:13", "1:1.3", []))
    fixable, unfixable = c.classify(data)
    assert fixable == [] and unfixable == []


def test_same_vuln_across_multiple_package_records_is_deduped_as_fixable() -> None:
    """util-linux appears 3x (different installed versions) in a real scan;
    a vuln that is fixable on one record must be counted once, as fixable."""
    unfix_record = _pkg(
        "util-linux", "Debian:13", "2.41-5",
        [{"id": "DEBIAN-CVE-2026-0001",
          "affected": [_affected("Debian:13", "util-linux", [{"introduced": "0"}])]}],
        groups=[{"ids": ["DEBIAN-CVE-2026-0001"], "max_severity": "5.0"}],
    )
    fix_record = _pkg(
        "util-linux", "Debian:13", "1:2.41-5",
        [{"id": "DEBIAN-CVE-2026-0001",
          "affected": [_affected("Debian:13", "util-linux",
                                 [{"introduced": "0"}, {"fixed": "2.41-6"}])]}],
        groups=[{"ids": ["DEBIAN-CVE-2026-0001"], "max_severity": "5.0"}],
    )
    fixable, unfixable = c.classify(_scan(unfix_record, fix_record))
    assert [f.vuln_id for f in fixable] == ["DEBIAN-CVE-2026-0001"]
    assert unfixable == []


def test_same_vuln_fixable_record_first_still_deduped_as_fixable() -> None:
    """Mirror of the dedup test with the FIXABLE record encountered first — a
    last-write-wins regression would silently flip it to a false negative."""
    fix_record = _pkg(
        "util-linux", "Debian:13", "1:2.41-5",
        [{"id": "DEBIAN-CVE-2026-0002",
          "affected": [_affected("Debian:13", "util-linux",
                                 [{"introduced": "0"}, {"fixed": "2.41-6"}])]}],
        groups=[{"ids": ["DEBIAN-CVE-2026-0002"], "max_severity": "5.0"}],
    )
    unfix_record = _pkg(
        "util-linux", "Debian:13", "2.41-5",
        [{"id": "DEBIAN-CVE-2026-0002",
          "affected": [_affected("Debian:13", "util-linux", [{"introduced": "0"}])]}],
        groups=[{"ids": ["DEBIAN-CVE-2026-0002"], "max_severity": "5.0"}],
    )
    fixable, unfixable = c.classify(_scan(fix_record, unfix_record))
    assert [f.vuln_id for f in fixable] == ["DEBIAN-CVE-2026-0002"]
    assert unfixable == []


# --------------------------------------------------------------------------
# load_scan -- fail-closed on bad input
# --------------------------------------------------------------------------
def test_load_scan_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(c.ScanLoadError):
        c.load_scan(tmp_path / "nope.json")


def test_load_scan_malformed_json_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(c.ScanLoadError):
        c.load_scan(bad)


def test_load_scan_no_results_key_raises(tmp_path: Path) -> None:
    bad = tmp_path / "noresults.json"
    bad.write_text(json.dumps({"image_metadata": {}}), encoding="utf-8")
    with pytest.raises(c.ScanLoadError):
        c.load_scan(bad)


# --------------------------------------------------------------------------
# main -- exit codes + reporting
# --------------------------------------------------------------------------
def test_main_exits_1_when_fixable_present() -> None:
    assert c.main([str(SAMPLE)]) == 1


def test_main_exits_0_when_no_fixable(tmp_path: Path) -> None:
    nofix = tmp_path / "nofix.json"
    nofix.write_text(json.dumps(_scan(
        _pkg("perl", "Debian:13", "5.40.1-6",
             [{"id": "DEBIAN-CVE-2026-9999",
               "affected": [_affected("Debian:13", "perl", [{"introduced": "0"}])]}],
             groups=[{"ids": ["DEBIAN-CVE-2026-9999"], "max_severity": "7.5"}])
    )), encoding="utf-8")
    assert c.main([str(nofix)]) == 0


def test_main_exits_2_on_missing_file(tmp_path: Path) -> None:
    assert c.main([str(tmp_path / "absent.json")]) == 2


def test_main_exits_2_on_malformed_json(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("not json at all", encoding="utf-8")
    assert c.main([str(bad)]) == 2


def test_main_no_fail_exits_0_even_with_fixable() -> None:
    assert c.main([str(SAMPLE), "--no-fail"]) == 0


def test_main_exits_0_on_clean_empty_results(tmp_path: Path) -> None:
    """A clean image scan emits a valid `{"results": []}` — the gate passes.
    (The workflow guards the look-alike DB-error case by checking osv-scanner's
    exit code, since that empty file is indistinguishable from a true clean
    scan at the content level.)"""
    clean = tmp_path / "clean.json"
    clean.write_text('{"results": []}', encoding="utf-8")
    assert c.main([str(clean)]) == 0


def test_main_summary_file_io_error_still_gates(tmp_path: Path) -> None:
    """An unwritable --summary-file must not swallow the fixable verdict: the
    report is best-effort, the exit code is the gate."""
    unwritable = tmp_path / "missing-dir" / "summary.md"  # parent does not exist
    assert c.main([str(SAMPLE), "--summary-file", str(unwritable)]) == 1
    assert not unwritable.exists()


def test_main_writes_markdown_summary_file(tmp_path: Path) -> None:
    summary = tmp_path / "summary.md"
    c.main([str(SAMPLE), "--summary-file", str(summary)])
    text = summary.read_text(encoding="utf-8")
    # the fixable advisory, its fixed version, and the actionable verb
    assert "DEBIAN-CVE-2026-55200" in text
    assert "1.11.1-1+deb13u1" in text
    assert "rebuild" in text.lower()


def test_main_reports_to_stdout(capsys) -> None:
    c.main([str(SAMPLE)])
    out = capsys.readouterr().out
    assert "4" in out  # fixable count surfaced
    assert "libssh2" in out
