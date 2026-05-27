"""Integration tests for OSPS conformance schema validator + workflow logic.

The validator script lives at ``scripts/validate_osps_conformance_yaml.py``
and is invoked by ``.github/workflows/verify-osps-conformance.yml`` to
schema-check ``.local/pre-release-review/osps-conformance.yaml`` (the
machine-readable companion to ``OSPS-CONFORMANCE.md``).

The YAML companion is gitignored, so these tests synthesize valid +
invalid YAML fixtures via ``tmp_path`` rather than reading the
on-disk companion. That keeps the tests deterministic regardless of
whether a contributor has materialized the YAML companion locally.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_SCRIPT = REPO_ROOT / "scripts" / "validate_osps_conformance_yaml.py"

VALID_YAML = """\
schema_version: 1
conformance_target: osps-baseline-2026.02.19
conformance_level: maturity-2-with-partial-maturity-3
attested_at: 2026-05-27
attestation_method: self-assessment
controls:
  - id: OSPS-AC-01.01
    verdict: PASS
    evidence:
      - type: file_path
        url: https://example.com/foo
"""


def _run_validator(yaml_path: Path) -> subprocess.CompletedProcess[str]:
    """Run the validator script as a subprocess + return its CompletedProcess.

    Uses ``sys.executable`` so the test runs against the same Python
    interpreter that pytest is running under (avoids the "uv-venv
    python vs system python" PATH mismatch on Windows).
    """
    return subprocess.run(
        [sys.executable, str(VALIDATOR_SCRIPT), str(yaml_path)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_validator_exits_zero_on_valid_yaml(tmp_path: Path) -> None:
    """Schema validator exits 0 on a valid conformance YAML."""
    valid = tmp_path / "valid.yaml"
    valid.write_text(VALID_YAML, encoding="utf-8")

    result = _run_validator(valid)

    assert result.returncode == 0, (
        f"Validator failed on valid YAML.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "OK:" in result.stdout


def test_validator_exits_nonzero_on_missing_required_field(
    tmp_path: Path,
) -> None:
    """Schema validator exits non-zero on missing schema_version + other fields."""
    invalid = tmp_path / "invalid.yaml"
    invalid.write_text("controls: []\n", encoding="utf-8")

    result = _run_validator(invalid)

    assert result.returncode != 0
    assert "Missing required top-level fields" in result.stderr


def test_validator_exits_nonzero_on_invalid_verdict(tmp_path: Path) -> None:
    """Schema validator exits non-zero when a control carries an invalid verdict."""
    invalid_verdict_yaml = """\
schema_version: 1
conformance_target: osps-baseline-2026.02.19
conformance_level: maturity-2-with-partial-maturity-3
attested_at: 2026-05-27
attestation_method: self-assessment
controls:
  - id: OSPS-AC-01.01
    verdict: MAYBE
"""
    invalid = tmp_path / "invalid-verdict.yaml"
    invalid.write_text(invalid_verdict_yaml, encoding="utf-8")

    result = _run_validator(invalid)

    assert result.returncode != 0
    assert "MAYBE" in result.stderr or "verdict=" in result.stderr


def test_validator_exits_nonzero_on_missing_file(tmp_path: Path) -> None:
    """Schema validator exits 2 when the path does not exist."""
    missing = tmp_path / "does-not-exist.yaml"

    result = _run_validator(missing)

    assert result.returncode == 2
    assert "File not found" in result.stderr


def test_osps_conformance_md_has_first_mover_claim() -> None:
    """OSPS-CONFORMANCE.md MUST include the first-mover gh-api search claim.

    Guards against silent removal of the first-mover statement, which
    is the load-bearing positioning claim of v0.10.6 Phase 3 per
    docs/v0.10.6-plan.md §11.2.A.1.
    """
    doc = (REPO_ROOT / "OSPS-CONFORMANCE.md").read_text(encoding="utf-8")
    assert "First-mover claim" in doc
    assert "filename:OSPS-CONFORMANCE.md" in doc
    assert "0" in doc  # the search-result count (preserved as written)


def test_osps_conformance_md_lists_known_honest_gaps() -> None:
    """OSPS-CONFORMANCE.md MUST list all 4 plan-declared honest gaps.

    These are the structurally-unreachable-solo controls pre-declared
    in docs/v0.10.6-implementation-plan.md Task 3.1. If any goes
    missing from the conformance doc, the verify-osps-conformance.yml
    CI gate would silently accept a hollowed-out attestation.
    """
    doc = (REPO_ROOT / "OSPS-CONFORMANCE.md").read_text(encoding="utf-8")
    for ctrl in (
        "OSPS-AC-04.01",
        "OSPS-AC-04.02",
        "OSPS-GV-04.01",
        "OSPS-QA-07.01",
    ):
        assert ctrl in doc, f"Honest-gap control {ctrl} missing from OSPS-CONFORMANCE.md"


@pytest.mark.parametrize(
    "field",
    [
        "schema_version",
        "conformance_target",
        "conformance_level",
        "attested_at",
        "attestation_method",
    ],
)
def test_validator_flags_each_missing_required_field(
    tmp_path: Path, field: str
) -> None:
    """Validator flags each of the 5 non-controls required top-level fields when absent."""
    import yaml

    full = yaml.safe_load(VALID_YAML)
    full.pop(field)
    incomplete = tmp_path / "incomplete.yaml"
    incomplete.write_text(yaml.safe_dump(full), encoding="utf-8")

    result = _run_validator(incomplete)

    assert result.returncode != 0
    assert field in result.stderr
