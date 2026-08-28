"""Deprecated framework-id aliases keep resolving, with a warning.

V13-15: the model-risk catalog shipped as ``occ-sr-26-02``, but the real
designators carry no leading zero and no "a" suffix: the Federal Reserve
letter is SR 26-2 and the OCC bulletin is 2026-13. v0.13 renames the
catalog to ``occ-sr-26-2`` and keeps the old id as a deprecated alias per
``docs/deprecation-calendar.md`` (target removal v1.0.0). Per the calendar's
process rule 5, this test EXERCISES the deprecated surface and asserts the
warning fires, so the alias path stays covered through its maintenance
window.
"""

from __future__ import annotations

import warnings

import pytest
from evidentia_core.catalogs.loader import load_catalog

OLD_ID = "occ-sr-26-02"
NEW_ID = "occ-sr-26-2"


def test_old_id_loads_via_alias_and_warns() -> None:
    with pytest.warns(DeprecationWarning, match=OLD_ID):
        catalog = load_catalog(OLD_ID)
    assert catalog.framework_id == NEW_ID


def test_new_id_loads_without_deprecation_warning() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        catalog = load_catalog(NEW_ID)
    assert catalog.framework_id == NEW_ID
    ours = [w for w in caught if OLD_ID in str(w.message) or NEW_ID in str(w.message)]
    assert not ours, f"canonical id must load warning-free, got: {ours}"


def test_alias_and_canonical_load_the_same_catalog() -> None:
    with pytest.warns(DeprecationWarning):
        via_alias = load_catalog(OLD_ID)
    canonical = load_catalog(NEW_ID)
    assert via_alias.framework_id == canonical.framework_id
    assert len(via_alias.controls) == len(canonical.controls)
    assert "SR 26-2" in canonical.framework_name
    assert "2026-13" in canonical.framework_name
    assert "2026-13a" not in canonical.framework_name
    assert "SR 26-02" not in canonical.framework_name
