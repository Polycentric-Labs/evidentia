"""End-to-end smoke tests for the `examples/` scenarios (v0.3.1).

These tests actually load each example's inventory + evidentia.yaml
+ system-context, run the full `gap analyze` pipeline, and (for
Meridian v2) run `gap diff` across the baseline and pr-branch
inventories. The assertion shapes are deliberately loose — the point
is "this scenario doesn't crash against the current bundled catalogs",
not to pin the exact severity counts (which would force an update
every time NIST publishes a new Rev 5 point release).

Skipped when the example dirs don't exist (e.g. running the test suite
from a wheel install without the full repo checked out).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.gap_analyzer import GapAnalyzer, load_inventory
from evidentia_core.gap_diff import compute_gap_diff

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
EXAMPLES = REPO_ROOT / "examples"


@pytest.fixture(autouse=True)
def _reset_registry():
    """Isolate the singleton registry between scenario tests."""
    FrameworkRegistry.reset_instance()
    yield
    FrameworkRegistry.reset_instance()


# -----------------------------------------------------------------------------
# Meridian v2 — comprehensive
# -----------------------------------------------------------------------------


@pytest.mark.skipif(
    not (EXAMPLES / "meridian-fintech-v2" / "my-controls.yaml").exists(),
    reason="meridian-fintech-v2 example not present",
)
def test_meridian_v2_baseline_analyze_runs() -> None:
    scenario = EXAMPLES / "meridian-fintech-v2"
    inventory = load_inventory(scenario / "my-controls.yaml")
    report = GapAnalyzer().analyze(
        inventory=inventory,
        frameworks=["nist-800-53-rev5-moderate", "soc2-tsc"],
    )
    # Loose asserts: the analyzer produced a report with real content,
    # some of our intentional gaps surfaced, and cross-framework work happened.
    assert report.total_controls_required > 100
    assert report.total_gaps > 0
    assert report.gaps, "expected at least one gap with 48 inventory controls vs 287 NIST mod"


@pytest.mark.skipif(
    not (EXAMPLES / "meridian-fintech-v2" / "my-controls-pr.yaml").exists(),
    reason="meridian-fintech-v2 pr-branch example not present",
)
def test_meridian_v2_pr_branch_analyze_runs() -> None:
    scenario = EXAMPLES / "meridian-fintech-v2"
    inventory = load_inventory(scenario / "my-controls-pr.yaml")
    report = GapAnalyzer().analyze(
        inventory=inventory,
        frameworks=["nist-800-53-rev5-moderate", "soc2-tsc"],
    )
    assert report.total_gaps > 0


@pytest.mark.skipif(
    not (EXAMPLES / "meridian-fintech-v2" / "my-controls-pr.yaml").exists(),
    reason="meridian-fintech-v2 pr-branch example not present",
)
def test_meridian_v2_gap_diff_produces_every_classification() -> None:
    """The PR-branch inventory was engineered to produce at least one of
    every diff classification. Regression guard: if someone edits the
    example inventories in a way that drops coverage of a classification,
    this test fails loudly."""
    scenario = EXAMPLES / "meridian-fintech-v2"
    base = GapAnalyzer().analyze(
        inventory=load_inventory(scenario / "my-controls.yaml"),
        frameworks=["nist-800-53-rev5-moderate", "soc2-tsc"],
    )
    head = GapAnalyzer().analyze(
        inventory=load_inventory(scenario / "my-controls-pr.yaml"),
        frameworks=["nist-800-53-rev5-moderate", "soc2-tsc"],
    )
    diff = compute_gap_diff(base, head)

    # Each classification must have at least one entry (the inventory
    # was designed to produce them)
    assert diff.summary.opened >= 1, (
        f"Expected opened >= 1; got {diff.summary.opened}. "
        "my-controls-pr.yaml should add a net-new control (e.g., AU-12)."
    )
    assert diff.summary.severity_increased >= 1, (
        f"Expected severity_increased >= 1; got {diff.summary.severity_increased}. "
        "my-controls-pr.yaml should worsen at least one control (e.g., AC-17 or CP-10)."
    )
    assert diff.summary.severity_decreased >= 1, (
        f"Expected severity_decreased >= 1; got {diff.summary.severity_decreased}. "
        "my-controls-pr.yaml should partially-improve at least one control (e.g., AU-6 or SI-4)."
    )
    assert diff.summary.closed >= 1, (
        f"Expected closed >= 1; got {diff.summary.closed}. "
        "my-controls-pr.yaml should fully-improve at least one control (e.g., AU-2)."
    )
    assert diff.summary.unchanged > 0, "Expected some unchanged gaps — the test inventories should not be 100% changed."


@pytest.mark.skipif(
    not (EXAMPLES / "meridian-fintech-v2" / "my-controls.csv").exists(),
    reason="meridian-fintech-v2 CSV inventory not present",
)
def test_meridian_v2_csv_inventory_loads() -> None:
    """The CSV inventory must parse without row-count regression."""
    csv_path = EXAMPLES / "meridian-fintech-v2" / "my-controls.csv"
    inventory = load_inventory(csv_path)
    # Matches the YAML control count (~48)
    assert len(inventory.controls) >= 40
    # CSV parser defaults to "Unknown Organization" — verify the expected
    # default behavior so downstream users of the CSV path see the clear
    # placeholder rather than a stale hardcoded string from v0.2.0.
    assert inventory.organization == "Unknown Organization"


# -----------------------------------------------------------------------------
# Acme Healthtech — HIPAA scenario
# -----------------------------------------------------------------------------


@pytest.mark.skipif(
    not (EXAMPLES / "acme-healthtech" / "my-controls.yaml").exists(),
    reason="acme-healthtech example not present",
)
def test_acme_healthtech_multi_hipaa_analyze_runs() -> None:
    scenario = EXAMPLES / "acme-healthtech"
    inventory = load_inventory(scenario / "my-controls.yaml")
    report = GapAnalyzer().analyze(
        inventory=inventory,
        frameworks=[
            "hipaa-security",
            "hipaa-privacy",
            "hipaa-breach",
            "nist-800-53-rev5-moderate",
        ],
    )
    # All 4 frameworks show up in the report
    assert set(report.frameworks_analyzed) == {
        "hipaa-security",
        "hipaa-privacy",
        "hipaa-breach",
        "nist-800-53-rev5-moderate",
    }
    # Cross-framework efficiency should kick in — IA-2(1) satisfies both
    # HIPAA and NIST, etc.
    assert report.total_gaps > 0


# -----------------------------------------------------------------------------
# DoD Northstar — CMMC scenario
# -----------------------------------------------------------------------------


@pytest.mark.skipif(
    not (EXAMPLES / "dod-contractor" / "my-controls.yaml").exists(),
    reason="dod-contractor example not present",
)
def test_dod_contractor_cmmc_plus_800_171_runs() -> None:
    scenario = EXAMPLES / "dod-contractor"
    inventory = load_inventory(scenario / "my-controls.yaml")
    report = GapAnalyzer().analyze(
        inventory=inventory,
        frameworks=["cmmc-2-l2", "nist-800-171-r2"],
    )
    # CMMC L2 and NIST 800-171 have a lot of overlap — efficiency
    # opportunities should surface if cross-framework works.
    assert report.total_gaps >= 0  # just prove it doesn't crash


# -----------------------------------------------------------------------------
# Config loader — picks up each scenario's evidentia.yaml
# -----------------------------------------------------------------------------


@pytest.mark.skipif(
    not (EXAMPLES / "meridian-fintech-v2" / "evidentia.yaml").exists(),
    reason="meridian-fintech-v2 example not present",
)
def test_meridian_v2_yaml_config_loads() -> None:
    """The v0.2.1 schema yaml in Meridian v2 must parse without warnings."""
    import warnings

    from evidentia.config import load_config

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        cfg = load_config(EXAMPLES / "meridian-fintech-v2" / "evidentia.yaml")
    # No DeprecationWarnings — we use the new schema
    deprecations = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert not deprecations, f"Meridian v2 config should NOT emit deprecations; got: {deprecations}"
    assert cfg.organization == "Meridian Financial"
    assert "nist-800-53-rev5-moderate" in cfg.frameworks
    assert cfg.llm.model == "gpt-4o"


@pytest.mark.skipif(
    not (EXAMPLES / "meridian-fintech" / "evidentia.yaml").exists(),
    reason="legacy meridian example not present",
)
def test_legacy_meridian_yaml_emits_deprecation() -> None:
    """The legacy v0.1.x schema (nested frameworks.default:) should trigger
    a DeprecationWarning — documenting that users of the old schema are on
    borrowed time."""
    import warnings

    from evidentia.config import load_config

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        load_config(EXAMPLES / "meridian-fintech" / "evidentia.yaml")
    deprecations = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert deprecations, "Legacy meridian-fintech yaml should emit DeprecationWarning (uses nested frameworks.default:)"
