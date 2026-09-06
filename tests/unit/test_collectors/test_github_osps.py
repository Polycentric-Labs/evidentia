"""Tests for the GitHub-collector OSPS Baseline extension (v0.10.6 C6).

Covers the 16 ``populate_osps_*`` helpers in
``evidentia_collectors.github.osps``. Each helper maps GitHub REST API
state to a :class:`SecurityFinding` with the matching OSPS control
mapping and a definite :class:`ComplianceStatus`.

Mocks the :class:`GitHubClient` via ``unittest.mock.MagicMock`` rather
than ``httpx.MockTransport`` (the convention in
``test_github_collector.py``). Reason: these tests exercise the helper
function shape — input dict → finding fields — not the wire-level
transport behaviour, which is already covered upstream in the existing
client tests.

For every helper we assert:

- ``compliance_status`` is PASS / FAIL / WARNING / NOT_APPLICABLE
  (never UNKNOWN unless that's the intended "indeterminate" outcome).
- ``control_mappings`` contains a ``ControlMapping`` whose
  ``framework="osps-baseline"`` and ``control_id`` matches the helper's
  declared OSPS id.
- ``source_finding_id`` follows the deterministic
  ``osps-XX-YY.ZZ:<owner>/<repo>[:<scope>]`` pattern that drives the
  v0.10.5 P10 idempotency hardening.
- ``source_system="github"`` so the OCSF round-trip + the v0.10.5 P10
  deterministic-id derivation both pick up the right namespace.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from evidentia_collectors.github.client import GitHubApiError
from evidentia_collectors.github.osps import (
    OSPS_COVERAGE,
    _file_present_at_any,
    _FileProbeOutcome,
    populate_osps_ac_03_01,
    populate_osps_ac_03_02,
    populate_osps_br_06_01,
    populate_osps_do_02_01,
    populate_osps_gv_03_01,
    populate_osps_le_02_01,
    populate_osps_le_03_01,
    populate_osps_qa_01_01,
    populate_osps_qa_01_02,
    populate_osps_qa_02_01,
    populate_osps_qa_03_01,
    populate_osps_vm_02_01,
    populate_osps_vm_03_01,
    populate_osps_vm_04_01,
    populate_osps_vm_05_03,
    populate_osps_vm_06_02,
)
from evidentia_core.models.finding import ComplianceStatus, SecurityFinding

OWNER = "Polycentric-Labs"
REPO = "evidentia"


# ── Helpers ─────────────────────────────────────────────────────────────


def _repo_dict(
    *,
    private: bool = False,
    default_branch: str = "main",
    license_spdx: str | None = "Apache-2.0",
    has_issues: bool = True,
    security_and_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a synthetic ``GET /repos/{o}/{r}`` payload."""
    return {
        "name": REPO,
        "full_name": f"{OWNER}/{REPO}",
        "private": private,
        "visibility": "private" if private else "public",
        "default_branch": default_branch,
        "has_issues": has_issues,
        "license": ({"spdx_id": license_spdx, "key": (license_spdx or "").lower()} if license_spdx else None),
        "security_and_analysis": security_and_analysis or {},
    }


def _assert_osps_finding_shape(
    finding: SecurityFinding,
    *,
    control_id: str,
    expected_status: ComplianceStatus,
    scope_suffix: str | None = None,
) -> None:
    """Common cross-cutting assertions for every osps.py helper."""
    assert finding.source_system == "github"
    # Pydantic str-enum: the runtime type is ``str`` (value-equal) on
    # the model surface; compare via ``==`` (the enum-vs-str equality is
    # defined by the str subclass) rather than ``is``.
    assert finding.compliance_status == expected_status
    # source_finding_id pattern: osps-<id>:<owner>/<repo>[:<scope>]
    expected_prefix = f"{control_id.lower()}:{OWNER}/{REPO}"
    assert finding.source_finding_id is not None
    assert finding.source_finding_id.startswith(expected_prefix)
    if scope_suffix is not None:
        assert finding.source_finding_id.endswith(scope_suffix)
    # control_mappings contains the expected osps-baseline mapping
    osps_mappings = [m for m in finding.control_mappings if m.framework == "osps-baseline"]
    assert len(osps_mappings) >= 1, f"Expected osps-baseline mapping on {control_id} finding"
    assert any(m.control_id == control_id for m in osps_mappings)
    # resource_type / resource_id present per the impl contract
    assert finding.resource_type == "GitHub::Repository"
    assert finding.resource_id == f"{OWNER}/{REPO}"


# ── OSPS-AC-03.01 — Branch protection on primary branch ────────────────


class TestOspsAc0301:
    def test_pass_when_default_branch_is_protected(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict()
        gh.get_branch_protection.return_value = {
            "required_pull_request_reviews": {"required_approving_review_count": 1},
        }
        finding = populate_osps_ac_03_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-AC-03.01",
            expected_status=ComplianceStatus.PASS,
            scope_suffix=":main",
        )
        gh.get_branch_protection.assert_called_once_with(OWNER, REPO, "main")

    def test_fail_when_default_branch_unprotected(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict()
        # 404 → None per real client contract.
        gh.get_branch_protection.return_value = None
        finding = populate_osps_ac_03_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-AC-03.01",
            expected_status=ComplianceStatus.FAIL,
            scope_suffix=":main",
        )


# ── OSPS-AC-03.02 — Branch deletion guarded ────────────────────────────


class TestOspsAc0302:
    def test_pass_when_deletion_disallowed(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict()
        gh.get_branch_protection.return_value = {
            "allow_deletions": {"enabled": False},
        }
        finding = populate_osps_ac_03_02(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-AC-03.02",
            expected_status=ComplianceStatus.PASS,
        )

    def test_fail_when_deletion_allowed(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict()
        gh.get_branch_protection.return_value = {
            "allow_deletions": {"enabled": True},
        }
        finding = populate_osps_ac_03_02(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-AC-03.02",
            expected_status=ComplianceStatus.FAIL,
        )

    def test_fail_when_branch_completely_unprotected(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict()
        gh.get_branch_protection.return_value = None
        finding = populate_osps_ac_03_02(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-AC-03.02",
            expected_status=ComplianceStatus.FAIL,
        )


# ── OSPS-BR-06.01 — Releases signed / attested ─────────────────────────


class TestOspsBr0601:
    def test_pass_when_releases_have_signature_assets(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict()
        gh.list_releases.return_value = [
            {
                "tag_name": "v0.10.5",
                "assets": [
                    {"name": "evidentia-0.10.5.tar.gz"},
                    {"name": "evidentia-0.10.5.tar.gz.sig"},
                    {"name": "evidentia-0.10.5.intoto.jsonl"},
                ],
            }
        ]
        finding = populate_osps_br_06_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-BR-06.01",
            expected_status=ComplianceStatus.PASS,
        )

    def test_warning_when_releases_exist_but_unsigned(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict()
        gh.list_releases.return_value = [
            {
                "tag_name": "v0.1.0",
                "assets": [{"name": "evidentia-0.1.0.tar.gz"}],
            }
        ]
        finding = populate_osps_br_06_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-BR-06.01",
            expected_status=ComplianceStatus.FAIL,
        )

    def test_not_applicable_when_no_releases(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict()
        gh.list_releases.return_value = []
        finding = populate_osps_br_06_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-BR-06.01",
            expected_status=ComplianceStatus.NOT_APPLICABLE,
        )


# ── OSPS-DO-02.01 — Defect reporting mechanism ─────────────────────────


class TestOspsDo0201:
    def test_pass_when_issues_enabled(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict(has_issues=True)
        finding = populate_osps_do_02_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-DO-02.01",
            expected_status=ComplianceStatus.PASS,
        )

    def test_fail_when_issues_disabled(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict(has_issues=False)
        finding = populate_osps_do_02_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-DO-02.01",
            expected_status=ComplianceStatus.FAIL,
        )


# ── OSPS-GV-03.01 — CONTRIBUTING guide ─────────────────────────────────


class TestOspsGv0301:
    def test_pass_when_contributing_md_present(self) -> None:
        gh = MagicMock()
        gh.get_contents.side_effect = lambda owner, repo, path: (
            {"path": "CONTRIBUTING.md"} if path == "CONTRIBUTING.md" else None
        )
        finding = populate_osps_gv_03_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-GV-03.01",
            expected_status=ComplianceStatus.PASS,
        )

    def test_fail_when_contributing_missing(self) -> None:
        gh = MagicMock()
        gh.get_contents.return_value = None
        finding = populate_osps_gv_03_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-GV-03.01",
            expected_status=ComplianceStatus.FAIL,
        )


# ── OSPS-LE-02.01 — License is OSI/FSF-recognized ──────────────────────


class TestOspsLe0201:
    def test_pass_for_apache_2_0(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict(license_spdx="Apache-2.0")
        finding = populate_osps_le_02_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-LE-02.01",
            expected_status=ComplianceStatus.PASS,
        )

    def test_fail_when_no_license(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict(license_spdx=None)
        finding = populate_osps_le_02_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-LE-02.01",
            expected_status=ComplianceStatus.FAIL,
        )

    def test_warning_for_non_osi_license(self) -> None:
        gh = MagicMock()
        # SSPL is not OSI-approved as of 2026; should WARN not PASS.
        gh.get_repo.return_value = _repo_dict(license_spdx="SSPL-1.0")
        finding = populate_osps_le_02_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-LE-02.01",
            expected_status=ComplianceStatus.WARNING,
        )


# ── OSPS-LE-03.01 — LICENSE in well-known location ─────────────────────


class TestOspsLe0301:
    def test_pass_when_license_file_present(self) -> None:
        gh = MagicMock()
        gh.get_contents.side_effect = lambda owner, repo, path: {"path": "LICENSE"} if path == "LICENSE" else None
        finding = populate_osps_le_03_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-LE-03.01",
            expected_status=ComplianceStatus.PASS,
        )

    def test_fail_when_no_license_file_in_any_known_location(self) -> None:
        gh = MagicMock()
        gh.get_contents.return_value = None
        finding = populate_osps_le_03_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-LE-03.01",
            expected_status=ComplianceStatus.FAIL,
        )


# ── OSPS-QA-01.01 — Source publicly readable ───────────────────────────


class TestOspsQa0101:
    def test_pass_when_repo_is_public(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict(private=False)
        finding = populate_osps_qa_01_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-QA-01.01",
            expected_status=ComplianceStatus.PASS,
        )

    def test_fail_when_repo_is_private(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict(private=True)
        finding = populate_osps_qa_01_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-QA-01.01",
            expected_status=ComplianceStatus.FAIL,
        )


# ── OSPS-QA-01.02 — Publicly readable commit history ───────────────────


class TestOspsQa0102:
    def test_pass_when_repo_public_and_accessible(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict(private=False)
        finding = populate_osps_qa_01_02(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-QA-01.02",
            expected_status=ComplianceStatus.PASS,
        )

    def test_fail_when_repo_private(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict(private=True)
        finding = populate_osps_qa_01_02(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-QA-01.02",
            expected_status=ComplianceStatus.FAIL,
        )


# ── OSPS-QA-02.01 — Dependency manifest in repo ────────────────────────


class TestOspsQa0201:
    def test_pass_when_pyproject_toml_present(self) -> None:
        gh = MagicMock()
        gh.get_contents.side_effect = lambda owner, repo, path: (
            {"path": "pyproject.toml"} if path == "pyproject.toml" else None
        )
        finding = populate_osps_qa_02_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-QA-02.01",
            expected_status=ComplianceStatus.PASS,
        )

    def test_pass_when_package_json_present(self) -> None:
        gh = MagicMock()
        gh.get_contents.side_effect = lambda owner, repo, path: (
            {"path": "package.json"} if path == "package.json" else None
        )
        finding = populate_osps_qa_02_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-QA-02.01",
            expected_status=ComplianceStatus.PASS,
        )

    def test_fail_when_no_manifest(self) -> None:
        gh = MagicMock()
        gh.get_contents.return_value = None
        finding = populate_osps_qa_02_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-QA-02.01",
            expected_status=ComplianceStatus.FAIL,
        )


# ── OSPS-QA-03.01 — Required status checks before merge ────────────────


class TestOspsQa0301:
    def test_pass_when_required_status_checks_present(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict()
        gh.get_branch_protection.return_value = {
            "required_status_checks": {"contexts": ["ci/tests", "ci/lint"]},
        }
        finding = populate_osps_qa_03_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-QA-03.01",
            expected_status=ComplianceStatus.PASS,
        )

    def test_fail_when_no_required_checks(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict()
        gh.get_branch_protection.return_value = {
            "required_status_checks": {"contexts": []},
        }
        finding = populate_osps_qa_03_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-QA-03.01",
            expected_status=ComplianceStatus.FAIL,
        )

    def test_fail_when_branch_completely_unprotected(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict()
        gh.get_branch_protection.return_value = None
        finding = populate_osps_qa_03_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-QA-03.01",
            expected_status=ComplianceStatus.FAIL,
        )


# ── OSPS-VM-02.01 — Security contacts (SECURITY.md) ────────────────────


class TestOspsVm0201:
    def test_pass_when_security_md_present(self) -> None:
        gh = MagicMock()
        gh.get_contents.side_effect = lambda owner, repo, path: (
            {"path": "SECURITY.md"} if path == "SECURITY.md" else None
        )
        finding = populate_osps_vm_02_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-VM-02.01",
            expected_status=ComplianceStatus.PASS,
        )

    def test_fail_when_no_security_file_at_any_known_location(self) -> None:
        gh = MagicMock()
        gh.get_contents.return_value = None
        finding = populate_osps_vm_02_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-VM-02.01",
            expected_status=ComplianceStatus.FAIL,
        )


# ── OSPS-VM-03.01 — Private vulnerability reporting ────────────────────


class TestOspsVm0301:
    def test_pass_when_pvr_enabled(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict(
            security_and_analysis={"private_vulnerability_reporting": {"status": "enabled"}},
        )
        finding = populate_osps_vm_03_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-VM-03.01",
            expected_status=ComplianceStatus.PASS,
        )

    def test_fail_when_pvr_disabled(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict(
            security_and_analysis={"private_vulnerability_reporting": {"status": "disabled"}},
        )
        finding = populate_osps_vm_03_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-VM-03.01",
            expected_status=ComplianceStatus.FAIL,
        )

    def test_fail_when_security_and_analysis_missing(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict(security_and_analysis={})
        finding = populate_osps_vm_03_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-VM-03.01",
            expected_status=ComplianceStatus.FAIL,
        )


# ── OSPS-VM-04.01 — Discovered vulnerabilities published ───────────────


class TestOspsVm0401:
    def test_pass_when_security_advisories_endpoint_responds(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict(private=False)
        gh.list_security_advisories.return_value = [{"ghsa_id": "GHSA-xxxx-yyyy-zzzz"}]
        finding = populate_osps_vm_04_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-VM-04.01",
            expected_status=ComplianceStatus.PASS,
        )

    def test_pass_when_no_advisories_yet_but_endpoint_reachable(self) -> None:
        # No advisories published yet — the control evaluates the
        # mechanism's presence; an empty list at a reachable endpoint
        # counts as the mechanism being available.
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict(private=False)
        gh.list_security_advisories.return_value = []
        finding = populate_osps_vm_04_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-VM-04.01",
            expected_status=ComplianceStatus.PASS,
        )

    def test_not_applicable_when_repo_is_private(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict(private=True)
        finding = populate_osps_vm_04_01(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-VM-04.01",
            expected_status=ComplianceStatus.NOT_APPLICABLE,
        )


# ── OSPS-VM-05.03 — Dependabot dependency analysis active ──────────────


class TestOspsVm0503:
    def test_pass_when_dependabot_vulnerability_alerts_enabled(self) -> None:
        gh = MagicMock()
        gh.are_vulnerability_alerts_enabled.return_value = True
        finding = populate_osps_vm_05_03(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-VM-05.03",
            expected_status=ComplianceStatus.PASS,
        )

    def test_fail_when_vulnerability_alerts_disabled(self) -> None:
        gh = MagicMock()
        gh.are_vulnerability_alerts_enabled.return_value = False
        finding = populate_osps_vm_05_03(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-VM-05.03",
            expected_status=ComplianceStatus.FAIL,
        )


# ── OSPS-VM-06.02 — Code-scanning (SAST) status check ──────────────────


class TestOspsVm0602:
    def test_pass_when_code_scanning_alerts_endpoint_reachable(self) -> None:
        gh = MagicMock()
        gh.is_code_scanning_enabled.return_value = True
        finding = populate_osps_vm_06_02(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-VM-06.02",
            expected_status=ComplianceStatus.PASS,
        )

    def test_fail_when_code_scanning_disabled(self) -> None:
        gh = MagicMock()
        gh.is_code_scanning_enabled.return_value = False
        finding = populate_osps_vm_06_02(gh, OWNER, REPO)
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-VM-06.02",
            expected_status=ComplianceStatus.FAIL,
        )


# ── Module-level coverage registry ─────────────────────────────────────


class TestOspsCoverageRegistry:
    def test_coverage_list_size_in_target_window(self) -> None:
        """The implementation MUST cover 13-17 OSPS controls (Task 6.1)."""
        assert 13 <= len(OSPS_COVERAGE) <= 17

    def test_every_coverage_entry_has_a_callable_helper(self) -> None:
        """OSPS_COVERAGE entries point at importable, callable helpers."""
        from evidentia_collectors.github import osps as osps_module

        for control_id, helper_name in OSPS_COVERAGE.items():
            helper = getattr(osps_module, helper_name, None)
            assert callable(helper), f"OSPS_COVERAGE[{control_id!r}] -> {helper_name!r} not callable"

    def test_every_coverage_entry_is_a_real_osps_id(self) -> None:
        """Every OSPS_COVERAGE key follows the OSPS-XX-YY.ZZ shape."""
        import re

        pattern = re.compile(r"^OSPS-[A-Z]{2}-\d{2}\.\d{2}$")
        for control_id in OSPS_COVERAGE:
            assert pattern.match(control_id), f"OSPS_COVERAGE key {control_id!r} doesn't match OSPS-XX-YY.ZZ pattern"


# ── Determinism (v0.10.5 P10 idempotency) ──────────────────────────────


class TestOspsHelperIdempotency:
    """Two calls against unchanged GitHub state must produce identical
    findings on the identity axis (per v0.10.5 P10 deterministic-id)."""

    def test_ac_03_01_produces_byte_identical_id_across_calls(self) -> None:
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict()
        gh.get_branch_protection.return_value = {
            "required_pull_request_reviews": {"required_approving_review_count": 1},
        }
        first = populate_osps_ac_03_01(gh, OWNER, REPO)
        second = populate_osps_ac_03_01(gh, OWNER, REPO)
        # source_finding_id is deterministic — the SecurityFinding._derive
        # validator then derives a deterministic UUID5 id from it.
        assert first.source_finding_id == second.source_finding_id
        assert first.id == second.id


# ── Surface check on GitHubClient additive methods ─────────────────────


class TestGitHubClientAdditiveSurface:
    """v0.10.6 added 4 small additive methods on GitHubClient. Verify
    they exist and follow the expected signature shape."""

    def test_list_releases_method_exists(self) -> None:
        from evidentia_collectors.github.client import GitHubClient

        assert hasattr(GitHubClient, "list_releases")

    def test_are_vulnerability_alerts_enabled_method_exists(self) -> None:
        from evidentia_collectors.github.client import GitHubClient

        assert hasattr(GitHubClient, "are_vulnerability_alerts_enabled")

    def test_is_code_scanning_enabled_method_exists(self) -> None:
        from evidentia_collectors.github.client import GitHubClient

        assert hasattr(GitHubClient, "is_code_scanning_enabled")

    def test_list_security_advisories_method_exists(self) -> None:
        from evidentia_collectors.github.client import GitHubClient

        assert hasattr(GitHubClient, "list_security_advisories")


# ── Error handling smoke test ──────────────────────────────────────────


class TestOspsHelperErrorPaths:
    def test_ac_03_01_returns_unknown_when_branch_protection_raises(
        self,
    ) -> None:
        """A GitHubApiError on the inner call → ComplianceStatus.UNKNOWN
        rather than a thrown exception. Operators want the run to
        complete with partial evidence, not abort."""
        gh = MagicMock()
        gh.get_repo.return_value = _repo_dict()
        gh.get_branch_protection.side_effect = GitHubApiError("boom", status_code=500)
        finding = populate_osps_ac_03_01(gh, OWNER, REPO)
        # Indeterminate — neither PASS nor FAIL is honest.
        assert finding.compliance_status == ComplianceStatus.UNKNOWN

    def test_le_02_01_returns_unknown_when_repo_lookup_raises(self) -> None:
        gh = MagicMock()
        gh.get_repo.side_effect = GitHubApiError("boom", status_code=500)
        finding = populate_osps_le_02_01(gh, OWNER, REPO)
        assert finding.compliance_status == ComplianceStatus.UNKNOWN


# ── _file_present_at_any tristate (v0.10.7 D3.2) ───────────────────────


class TestFilePresentAtAnyTristate:
    """``_file_present_at_any`` must distinguish *absent* (clean 404 on
    every candidate → FAIL) from *indeterminate* (a 5xx / network error
    on a candidate with no hit → UNKNOWN). A transient server error is
    "we don't know", not "the file is definitively absent"
    (v0.10.6 C6 reviewer Important #2)."""

    def test_all_404_is_absent(self) -> None:
        """Every candidate 404s → ABSENT, no carried error."""
        gh = MagicMock()
        gh.get_contents.return_value = None  # 404 → None per client contract
        result = _file_present_at_any(gh, OWNER, REPO, ("SECURITY.md", ".github/SECURITY.md"))
        assert result.outcome is _FileProbeOutcome.ABSENT
        assert result.path is None
        assert result.error is None

    def test_one_200_is_present(self) -> None:
        """A candidate returns a body (200) → PRESENT with its path, and
        the probe short-circuits the remaining candidates."""
        gh = MagicMock()
        gh.get_contents.side_effect = lambda owner, repo, path: (
            {"path": "docs/SECURITY.md"} if path == "docs/SECURITY.md" else None
        )
        result = _file_present_at_any(
            gh,
            OWNER,
            REPO,
            ("SECURITY.md", "docs/SECURITY.md", "SECURITY"),
        )
        assert result.outcome is _FileProbeOutcome.PRESENT
        assert result.path == "docs/SECURITY.md"
        assert result.error is None

    def test_all_5xx_is_indeterminate(self) -> None:
        """Every candidate 5xx-fails with no hit → INDETERMINATE, and the
        last error is carried for the UNKNOWN finding's description."""
        gh = MagicMock()
        gh.get_contents.side_effect = GitHubApiError("upstream 503", status_code=503)
        result = _file_present_at_any(gh, OWNER, REPO, ("LICENSE", "LICENSE.md", "COPYING"))
        assert result.outcome is _FileProbeOutcome.INDETERMINATE
        assert result.path is None
        assert result.error is not None
        assert result.error.status_code == 503

    def test_mixed_404_and_5xx_is_indeterminate(self) -> None:
        """A mix of 404s and 5xx (502/503/504) with no hit → still
        INDETERMINATE: the 5xx candidate could have held the file, so
        "absent" is not provable. The last 5xx error is carried."""
        codes = {
            "CONTRIBUTING.md": 404,
            ".github/CONTRIBUTING.md": 502,
            "docs/CONTRIBUTING.md": 404,
            "CONTRIBUTING.rst": 503,
            "CONTRIBUTING": 504,
        }

        def _probe(owner: str, repo: str, path: str) -> dict[str, Any] | None:
            code = codes[path]
            if code == 404:
                return None
            raise GitHubApiError(f"upstream {code}", status_code=code)

        gh = MagicMock()
        gh.get_contents.side_effect = _probe
        result = _file_present_at_any(gh, OWNER, REPO, tuple(codes))
        assert result.outcome is _FileProbeOutcome.INDETERMINATE
        assert result.error is not None
        # Last failing probe in iteration order is the 504.
        assert result.error.status_code == 504


class TestFileProbeHelperEmitsUnknown:
    """The 4 file-probe helpers (gv/le-03/qa-02/vm-02) must emit a
    ComplianceStatus.UNKNOWN finding — not a dishonest FAIL — when the
    contents probe fails with a 5xx on every candidate."""

    def test_gv_03_01_unknown_on_all_5xx(self) -> None:
        gh = MagicMock()
        gh.get_contents.side_effect = GitHubApiError("boom", status_code=500)
        finding = populate_osps_gv_03_01(gh, OWNER, REPO)
        assert finding.compliance_status == ComplianceStatus.UNKNOWN
        _assert_osps_finding_shape(
            finding,
            control_id="OSPS-GV-03.01",
            expected_status=ComplianceStatus.UNKNOWN,
        )

    def test_vm_02_01_unknown_on_all_5xx(self) -> None:
        gh = MagicMock()
        gh.get_contents.side_effect = GitHubApiError("boom", status_code=502)
        finding = populate_osps_vm_02_01(gh, OWNER, REPO)
        assert finding.compliance_status == ComplianceStatus.UNKNOWN

    def test_le_03_01_still_fail_on_all_404(self) -> None:
        """Regression guard: a clean all-404 must remain FAIL, not get
        swept into the new UNKNOWN branch."""
        gh = MagicMock()
        gh.get_contents.return_value = None
        finding = populate_osps_le_03_01(gh, OWNER, REPO)
        assert finding.compliance_status == ComplianceStatus.FAIL


# ── Parametric severity assertion ──────────────────────────────────────


@pytest.mark.parametrize(
    "helper, control_id",
    [
        (populate_osps_ac_03_01, "OSPS-AC-03.01"),
        (populate_osps_ac_03_02, "OSPS-AC-03.02"),
        (populate_osps_br_06_01, "OSPS-BR-06.01"),
        (populate_osps_do_02_01, "OSPS-DO-02.01"),
        (populate_osps_gv_03_01, "OSPS-GV-03.01"),
        (populate_osps_le_02_01, "OSPS-LE-02.01"),
        (populate_osps_le_03_01, "OSPS-LE-03.01"),
        (populate_osps_qa_01_01, "OSPS-QA-01.01"),
        (populate_osps_qa_01_02, "OSPS-QA-01.02"),
        (populate_osps_qa_02_01, "OSPS-QA-02.01"),
        (populate_osps_qa_03_01, "OSPS-QA-03.01"),
        (populate_osps_vm_02_01, "OSPS-VM-02.01"),
        (populate_osps_vm_03_01, "OSPS-VM-03.01"),
        (populate_osps_vm_04_01, "OSPS-VM-04.01"),
        (populate_osps_vm_05_03, "OSPS-VM-05.03"),
        (populate_osps_vm_06_02, "OSPS-VM-06.02"),
    ],
)
def test_every_helper_returns_a_securityfinding(helper: Any, control_id: str) -> None:
    """Smoke test: each helper, given a permissive MagicMock, returns
    a real SecurityFinding (not None, not a dict, not an exception)."""
    gh = MagicMock()
    gh.get_repo.return_value = _repo_dict(private=False)
    gh.get_branch_protection.return_value = None
    gh.get_contents.return_value = None
    gh.list_releases.return_value = []
    gh.are_vulnerability_alerts_enabled.return_value = False
    gh.is_code_scanning_enabled.return_value = False
    gh.list_security_advisories.return_value = []

    finding = helper(gh, OWNER, REPO)
    assert isinstance(finding, SecurityFinding)
    assert any(m.framework == "osps-baseline" and m.control_id == control_id for m in finding.control_mappings)
