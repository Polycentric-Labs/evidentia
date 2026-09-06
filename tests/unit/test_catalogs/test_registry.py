"""Smoke tests for the framework registry and crosswalk engine."""

from __future__ import annotations

import pytest
from evidentia_core.catalogs.registry import FRAMEWORK_METADATA, FrameworkRegistry


@pytest.fixture(autouse=True)
def _reset_registry():
    FrameworkRegistry.reset_instance()
    yield
    FrameworkRegistry.reset_instance()


def test_registry_singleton():
    a = FrameworkRegistry.get_instance()
    b = FrameworkRegistry.get_instance()
    assert a is b


def test_framework_metadata_includes_baseline_frameworks():
    # v0.2.0: registry is manifest-driven — FRAMEWORK_METADATA is a
    # dynamically-built view over data/frameworks.yaml. We assert that
    # the core v0.1.x frameworks remain present; the full set is
    # validated by tests/unit/test_catalogs/test_manifest.py.
    ids = set(FRAMEWORK_METADATA.keys())
    assert "nist-800-53-mod" in ids
    assert "soc2-tsc" in ids
    # Sanity — v0.2.0 ships ~50+ frameworks
    assert len(ids) >= 50, f"Expected 50+ frameworks in v0.2.0, got {len(ids)}"


def test_load_bundled_nist_catalog():
    registry = FrameworkRegistry.get_instance()
    catalog = registry.get_catalog("nist-800-53-mod")
    assert catalog.framework_id == "nist-800-53-mod"
    assert len(catalog.controls) > 0
    # Check the index works
    assert catalog.get_control("AC-2") is not None
    assert catalog.get_control("ac-2") is not None  # case-insensitive


def test_load_bundled_soc2_catalog_is_licensed_stub():
    # v0.1.1: SOC 2 TSC ships as a Tier-C stub (AICPA copyrighted text
    # is not redistributable). Verify the stub shape so a future
    # accidental re-add of paraphrased AICPA content trips this test.
    registry = FrameworkRegistry.get_instance()
    catalog = registry.get_catalog("soc2-tsc")
    assert catalog.framework_id == "soc2-tsc"
    assert catalog.tier == "C"
    assert catalog.license_required is True
    assert catalog.placeholder is True
    assert catalog.license_url  # non-empty string
    cc61 = catalog.get_control("CC6.1")
    assert cc61 is not None
    assert cc61.placeholder is True
    assert cc61.license_required is True


def test_crosswalk_loads_bundled_mappings():
    registry = FrameworkRegistry.get_instance()
    crosswalk = registry.crosswalk
    assert "nist-800-53-mod" in crosswalk.available_frameworks or "nist-800-53-rev5" in crosswalk.available_frameworks
    # Should have at least one mapping
    mapped = crosswalk.get_all_mapped_controls("nist-800-53-mod", "AC-2")
    if not mapped:
        # The bundled crosswalk uses nist-800-53-rev5 as the source key
        mapped = crosswalk.get_all_mapped_controls("nist-800-53-rev5", "AC-2")
    assert len(mapped) > 0
