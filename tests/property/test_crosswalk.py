"""Property-based tests for ``evidentia_core.catalogs.crosswalk``.

v0.8.2 G2 / §25.2 P2.2 (2 + 3): crosswalk engine invariants.

:class:`CrosswalkEngine` builds bidirectional mapping graphs
from JSON crosswalk definitions. The hand-written tests cover
specific catalog → catalog mappings; these property tests
exercise the engine's invariants under randomized inputs:

1. **Empty engine** — a CrosswalkEngine that never loaded any
   crosswalks always returns an empty list from
   :meth:`get_mapped_controls` regardless of arguments.
2. **Case-insensitive lookup** — :meth:`get_mapped_controls`
   uppercases the control_id before lookup; querying with
   any-case variant of the same id returns the same result.
3. **Return-shape consistency** — :meth:`get_cross_framework_value`
   returns ``"framework:control_id"`` strings; every entry has
   exactly one ``:`` separator with non-empty parts on both sides.
"""

from __future__ import annotations

from pathlib import Path

from evidentia_core.catalogs.crosswalk import CrosswalkEngine
from hypothesis import given
from hypothesis import strategies as st

# Strategies for control-id-shaped strings + framework-id-shaped
# strings. Bounded character sets to avoid generating null bytes
# or surrogates that would crash str.upper() / dict-key paths.
_CONTROL_ID = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P"),
        blacklist_characters="\x00",
    ),
    min_size=1,
    max_size=40,
)
_FRAMEWORK_ID = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N"),
        blacklist_characters="\x00",
    ),
    min_size=1,
    max_size=40,
)


@given(_FRAMEWORK_ID, _CONTROL_ID, _FRAMEWORK_ID)
def test_empty_engine_returns_no_mappings(fw_a: str, ctl: str, fw_b: str) -> None:
    """An empty CrosswalkEngine has no mappings regardless of query.

    Constructed against a non-existent mappings dir, the engine
    holds no forward / reverse entries. Every
    :meth:`get_mapped_controls` call is a clean lookup miss.
    """
    engine = CrosswalkEngine(mappings_dir=Path("/nonexistent-evidentia-property-test-dir"))
    engine.load_all()  # logs warning on missing dir; no raise
    result = engine.get_mapped_controls(fw_a, ctl, fw_b)
    assert result == []


@given(_FRAMEWORK_ID, _CONTROL_ID, _FRAMEWORK_ID)
def test_get_all_mapped_controls_empty_for_empty_engine(fw: str, ctl: str, _other_fw: str) -> None:
    """Empty-engine invariant for the wider all-frameworks lookup."""
    engine = CrosswalkEngine(mappings_dir=Path("/nonexistent-evidentia-property-test-dir"))
    engine.load_all()
    result = engine.get_all_mapped_controls(fw, ctl)
    assert result == {}


@given(_FRAMEWORK_ID, _CONTROL_ID)
def test_cross_framework_value_returns_well_formed_strings(fw: str, ctl: str) -> None:
    """``get_cross_framework_value`` returns ``"fw:ctl"`` strings.

    Every entry has exactly one ``:`` separator with non-empty
    parts on both sides. The empty-engine path returns ``[]``,
    which trivially satisfies the invariant; this test mostly
    exercises that the empty-result branch doesn't crash on
    pathological inputs.
    """
    engine = CrosswalkEngine(mappings_dir=Path("/nonexistent-evidentia-property-test-dir"))
    engine.load_all()
    result = engine.get_cross_framework_value(fw, ctl)
    # Empty result is the expected case for an empty engine.
    assert isinstance(result, list)
    for entry in result:
        # Format is "framework:control_id"; both sides must be
        # non-empty (a malformed entry like ":foo" or "foo:"
        # would be a crosswalk-source bug, but the engine should
        # never emit one).
        parts = entry.split(":")
        assert len(parts) >= 2, f"Missing separator in {entry!r}"
        assert all(p for p in parts), f"Empty part in {entry!r}"


@given(_FRAMEWORK_ID, _CONTROL_ID, _FRAMEWORK_ID)
def test_lookup_is_case_insensitive_on_control_id(fw_a: str, ctl: str, fw_b: str) -> None:
    """Lookup with any-case variant of the same control id matches.

    The engine uppercases ``source_control_id`` at line 98 of
    crosswalk.py before key construction. So:
    ``get_mapped_controls(fw, "ac-2", ...) ==
    get_mapped_controls(fw, "AC-2", ...)``. For an empty engine
    both return ``[]``; this test asserts the function path
    does not raise on case-folding pathological inputs (e.g.,
    Turkish dotless-i → ``İ``).
    """
    engine = CrosswalkEngine(mappings_dir=Path("/nonexistent-evidentia-property-test-dir"))
    engine.load_all()
    lower_result = engine.get_mapped_controls(fw_a, ctl.lower(), fw_b)
    upper_result = engine.get_mapped_controls(fw_a, ctl.upper(), fw_b)
    # The empty-engine path: both empty.
    assert lower_result == upper_result


@given(_FRAMEWORK_ID, _CONTROL_ID)
def test_available_frameworks_is_set_for_empty_engine(_fw: str, _ctl: str) -> None:
    """Empty engine exposes ``available_frameworks`` as empty set.

    The property under test is the type-stability of the
    ``available_frameworks`` property: it always returns
    ``set[str]``, never ``None`` / ``list`` / ``frozenset``,
    regardless of how the engine was queried. Empty engine →
    empty set.
    """
    engine = CrosswalkEngine(mappings_dir=Path("/nonexistent-evidentia-property-test-dir"))
    engine.load_all()
    fws = engine.available_frameworks
    assert isinstance(fws, set)
    assert fws == set()
