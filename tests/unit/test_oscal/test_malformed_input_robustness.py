"""Malformed-input robustness for the OSCAL catalog loader + profile resolver.

The ClusterFuzzLite batch run (run 28161524030, 2026-06-25) surfaced two
uncaught-exception denial-of-service findings (CWE-248) once the fuzz
harnesses finally built and ran the real batch:

- ``fuzz_catalog_import`` — a catalog whose ``groups`` is a *string*
  (``{"groups": "u!"}``) iterates character-by-character, so the next
  ``.get(...)`` raised ``AttributeError: 'str' object has no attribute
  'get'`` — a type NOT in the harness allowlist.
- ``fuzz_oscal_profile`` — an import ``href`` resolving to a 200+ char
  filename raised ``OSError: [Errno 36] File name too long`` from
  ``pathlib``'s ``.exists()`` / ``.stat()`` — again NOT allowlisted.

The fix hardens every ``.get(...)``-on-untrusted-mapping choke point (via
``_require_mapping`` / ``_iter_mappings``) and converts the path-operation
exception family to the modules' declared typed errors. These tests pin
that contract two ways:

1. **Exact reproducers** — the precise inputs that crashed now raise a
   clean, declared exception.
2. **Exhaustive structural mutation** — every nested container in a rich,
   valid catalog/profile is replaced with each wrong JSON type; the loader
   must respond with *only* an allowlisted exception (or succeed), never a
   leaked ``AttributeError`` / ``OSError`` / other surprise.

The allowlists mirror the two fuzz harnesses' ``_EXPECTED`` tuples exactly
— a malformed input that resolves to one of these is a *clean rejection*;
anything else is a finding and fails the test.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from evidentia_core.catalogs.loader import load_oscal_catalog
from evidentia_core.oscal.profile import ProfileResolutionError, resolve_profile
from pydantic import ValidationError

# The harness allowlists (tests/fuzz/fuzz_catalog_import.py +
# fuzz_oscal_profile.py ``_EXPECTED``). A malformed input resolving to one
# of these is correct rejection; any other exception type is a CWE-248 leak.
CATALOG_ALLOWED: tuple[type[BaseException], ...] = (
    ValueError,  # also covers json.JSONDecodeError (subclass)
    yaml.YAMLError,
    ValidationError,
    KeyError,
    TypeError,
)
PROFILE_ALLOWED: tuple[type[BaseException], ...] = (
    ProfileResolutionError,
    FileNotFoundError,
    ValueError,  # also covers json.JSONDecodeError (subclass)
    KeyError,
    TypeError,
)

# Wrong-type values injected at every structural position. Each is valid
# JSON but the wrong shape where the loader expects an object / array /
# scalar. ``True`` exercises the bool branch (not a dict, not a list);
# ``None`` exercises the JSON-null branch.
BAD_VALUES: tuple[Any, ...] = ("a string", ["x", "y"], 123, 1.5, True, None, {})

# A rich but valid OSCAL catalog touching every nested container the
# parser walks: metadata, groups, controls, parts (incl. nested parts for
# the _extract_prose recursion), props, links, params (both ``select`` and
# ``guidelines`` shapes), and enhancement sub-controls.
VALID_CATALOG: dict[str, Any] = {
    "catalog": {
        "uuid": "11111111-1111-1111-1111-111111111111",
        "metadata": {"title": "Demo Catalog", "version": "1.0"},
        "groups": [
            {
                "id": "ac",
                "title": "Access Control",
                "controls": [
                    {
                        "id": "ac-1",
                        "title": "Policy and Procedures",
                        "parts": [
                            {
                                "name": "statement",
                                "prose": "Top prose.",
                                "parts": [{"name": "item", "prose": "Nested prose."}],
                            },
                            {"name": "assessment-objective", "prose": "Objective."},
                        ],
                        "props": [
                            {"name": "priority", "value": "P1"},
                            {"name": "baseline", "value": "low"},
                        ],
                        "links": [{"rel": "related", "href": "#ac-2"}],
                        "params": [
                            {"id": "ac-1_prm_1", "select": {"choice": ["a", "b"]}},
                            {"id": "ac-1_prm_2", "guidelines": [{"prose": "default"}]},
                        ],
                        "controls": [
                            {"id": "ac-1.1", "title": "Enhancement One"}
                        ],
                    }
                ],
            }
        ],
    }
}

# Every structural position in VALID_CATALOG that the parser dereferences.
CATALOG_PATHS: tuple[tuple[Any, ...], ...] = (
    ("catalog",),
    ("catalog", "metadata"),
    ("catalog", "groups"),
    ("catalog", "groups", 0),
    ("catalog", "groups", 0, "controls"),
    ("catalog", "groups", 0, "controls", 0),
    ("catalog", "groups", 0, "controls", 0, "id"),
    ("catalog", "groups", 0, "controls", 0, "parts"),
    ("catalog", "groups", 0, "controls", 0, "parts", 0),
    ("catalog", "groups", 0, "controls", 0, "parts", 0, "parts"),
    ("catalog", "groups", 0, "controls", 0, "props"),
    ("catalog", "groups", 0, "controls", 0, "props", 0),
    ("catalog", "groups", 0, "controls", 0, "links"),
    ("catalog", "groups", 0, "controls", 0, "links", 0),
    ("catalog", "groups", 0, "controls", 0, "links", 0, "href"),
    ("catalog", "groups", 0, "controls", 0, "params"),
    ("catalog", "groups", 0, "controls", 0, "params", 0),
    ("catalog", "groups", 0, "controls", 0, "params", 0, "select"),
    ("catalog", "groups", 0, "controls", 0, "params", 1, "guidelines"),
    ("catalog", "groups", 0, "controls", 0, "controls"),
    ("catalog", "groups", 0, "controls", 0, "controls", 0),
)

VALID_PROFILE: dict[str, Any] = {
    "profile": {
        "uuid": "22222222-2222-2222-2222-222222222222",
        "metadata": {"title": "Demo Profile", "version": "1.0"},
        "imports": [
            {"href": "catalog.json", "include-controls": [{"with-ids": ["AC-1"]}]}
        ],
        "modify": [
            {
                "set-parameters": [{"param-id": "ac-1_prm_1", "values": ["override"]}],
                "alters": [
                    {
                        "control-id": "ac-1",
                        "adds": [{"parts": [{"name": "guidance", "prose": "More."}]}],
                    }
                ],
            }
        ],
    }
}

PROFILE_PATHS: tuple[tuple[Any, ...], ...] = (
    ("profile",),
    ("profile", "metadata"),
    ("profile", "imports"),
    ("profile", "imports", 0),
    ("profile", "imports", 0, "href"),
    ("profile", "imports", 0, "include-controls"),
    ("profile", "imports", 0, "include-controls", 0),
    ("profile", "imports", 0, "include-controls", 0, "with-ids"),
    ("profile", "modify"),
    ("profile", "modify", 0),
    ("profile", "modify", 0, "set-parameters"),
    ("profile", "modify", 0, "set-parameters", 0),
    ("profile", "modify", 0, "alters"),
    ("profile", "modify", 0, "alters", 0),
    ("profile", "modify", 0, "alters", 0, "control-id"),
    ("profile", "modify", 0, "alters", 0, "adds"),
    ("profile", "modify", 0, "alters", 0, "adds", 0, "parts"),
    ("profile", "modify", 0, "alters", 0, "adds", 0, "parts", 0),
)


def _mutate(obj: dict[str, Any], path: tuple[Any, ...], value: Any) -> dict[str, Any]:
    """Deep-copy ``obj`` and set the nested ``path`` to ``value``."""
    out = copy.deepcopy(obj)
    cursor: Any = out
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return out


def _write(directory: Path, name: str, obj: Any) -> Path:
    path = directory / name
    path.write_text(json.dumps(obj), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Exact reproducers — the two inputs that crashed the 2026-06-25 batch run.
# ---------------------------------------------------------------------------


def test_reproducer_catalog_groups_as_string(tmp_path: Path) -> None:
    """``{"groups": "u!"}`` (groups is a string) raises ValueError, not AttributeError."""
    path = _write(tmp_path, "catalog.json", {"groups": "u!"})
    with pytest.raises(ValueError):
        load_oscal_catalog(path)


def test_reproducer_profile_href_too_long(tmp_path: Path) -> None:
    """An import href resolving to a 250-char filename raises ProfileResolutionError."""
    long_name = "c" * 250 + ".json"
    profile = _mutate(VALID_PROFILE, ("profile", "imports", 0, "href"), long_name)
    # No source catalog needs to exist — resolution fails on the path itself.
    path = _write(tmp_path, "profile.json", profile)
    with pytest.raises(ProfileResolutionError):
        resolve_profile(path)


def test_reproducer_profile_href_embedded_nul(tmp_path: Path) -> None:
    """An import href with an embedded NUL raises ProfileResolutionError, not ValueError leak."""
    profile = _mutate(VALID_PROFILE, ("profile", "imports", 0, "href"), "a\x00b.json")
    path = _write(tmp_path, "profile.json", profile)
    with pytest.raises(ProfileResolutionError):
        resolve_profile(path)


# ---------------------------------------------------------------------------
# Exhaustive structural mutation — no leaked, non-allowlisted exception.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", CATALOG_PATHS, ids=[".".join(map(str, p)) for p in CATALOG_PATHS])
@pytest.mark.parametrize("bad", BAD_VALUES, ids=lambda v: type(v).__name__)
def test_catalog_mutation_never_leaks(tmp_path: Path, path: tuple[Any, ...], bad: Any) -> None:
    """Any wrong-typed catalog node yields only an allowlisted exception (or success)."""
    mutated = _mutate(VALID_CATALOG, path, bad)
    catalog_path = _write(tmp_path, "catalog.json", mutated)
    try:
        load_oscal_catalog(catalog_path)
    except Exception as exc:  # broad by design: we assert the exception *type* is allowlisted
        assert isinstance(exc, CATALOG_ALLOWED), (
            f"{'.'.join(map(str, path))}={bad!r} leaked {type(exc).__name__}: {exc}"
        )


@pytest.mark.parametrize("path", PROFILE_PATHS, ids=[".".join(map(str, p)) for p in PROFILE_PATHS])
@pytest.mark.parametrize("bad", BAD_VALUES, ids=lambda v: type(v).__name__)
def test_profile_mutation_never_leaks(tmp_path: Path, path: tuple[Any, ...], bad: Any) -> None:
    """Any wrong-typed profile node yields only an allowlisted exception (or success)."""
    # A valid source catalog sits alongside so a structurally-sound profile
    # resolves; mutations must still never leak a non-allowlisted exception.
    _write(tmp_path, "catalog.json", VALID_CATALOG)
    mutated = _mutate(VALID_PROFILE, path, bad)
    profile_path = _write(tmp_path, "profile.json", mutated)
    try:
        resolve_profile(profile_path)
    except Exception as exc:  # broad by design: we assert the exception *type* is allowlisted
        assert isinstance(exc, PROFILE_ALLOWED), (
            f"{'.'.join(map(str, path))}={bad!r} leaked {type(exc).__name__}: {exc}"
        )


def test_valid_catalog_still_loads(tmp_path: Path) -> None:
    """Guards must not regress the happy path — the rich valid catalog loads."""
    catalog_path = _write(tmp_path, "catalog.json", VALID_CATALOG)
    catalog = load_oscal_catalog(catalog_path)
    assert catalog.control_count >= 1
    assert any(c.id == "AC-1" for c in catalog.controls)


def test_valid_profile_still_resolves(tmp_path: Path) -> None:
    """Guards must not regress the happy path — the valid profile resolves."""
    _write(tmp_path, "catalog.json", VALID_CATALOG)
    profile_path = _write(tmp_path, "profile.json", VALID_PROFILE)
    resolved = resolve_profile(profile_path)
    assert resolved.control_count >= 1


# ---------------------------------------------------------------------------
# CWE-674 — deeply-nested input raises a clean typed error, never RecursionError.
# Built as raw strings (json.dumps would itself recurse and RecursionError).
# ---------------------------------------------------------------------------


def _deep_control_chain(depth: int) -> str:
    """Raw JSON for a `depth`-deep nested-control catalog."""
    body = '{"id": "c", "controls": [' * depth + '{"id": "c"}' + "]}" * depth
    return '{"catalog": {"groups": [{"controls": [' + body + "]}]}}"


def _deep_part_chain(depth: int) -> str:
    """Raw JSON for a catalog whose single control has `depth`-deep parts."""
    parts = '{"name": "statement", "parts": [' * depth + '{"name": "p"}' + "]}" * depth
    return (
        '{"catalog": {"groups": [{"controls": [{"id": "c", "parts": ['
        + parts
        + "]}]}]}}"
    )


def test_deeply_nested_controls_raise_clean_error(tmp_path: Path) -> None:
    """Control nesting past the depth limit -> ValueError, not RecursionError."""
    path = tmp_path / "catalog.json"
    path.write_text(_deep_control_chain(150), encoding="utf-8")
    with pytest.raises(ValueError):
        load_oscal_catalog(path)


def test_deeply_nested_parts_raise_clean_error(tmp_path: Path) -> None:
    """Part nesting past the depth limit -> ValueError, not RecursionError."""
    path = tmp_path / "catalog.json"
    path.write_text(_deep_part_chain(150), encoding="utf-8")
    with pytest.raises(ValueError):
        load_oscal_catalog(path)


def test_deeply_nested_json_raises_clean_error(tmp_path: Path) -> None:
    """A pathologically deep JSON document -> clean error, not RecursionError."""
    path = tmp_path / "catalog.json"
    # 6000-deep arrays exceed json's recursion limit; the loader converts the
    # RecursionError (or rejects the non-mapping) -> ValueError either way.
    path.write_text("[" * 6000 + "]" * 6000, encoding="utf-8")
    with pytest.raises(ValueError):
        load_oscal_catalog(path)


def test_deeply_nested_profile_source_raises_clean_error(tmp_path: Path) -> None:
    """A profile whose source catalog over-nests -> ProfileResolutionError."""
    (tmp_path / "catalog.json").write_text(_deep_control_chain(150), encoding="utf-8")
    profile_path = _write(tmp_path, "profile.json", VALID_PROFILE)
    with pytest.raises(ProfileResolutionError):
        resolve_profile(profile_path)
