"""Tests for the OSCAL profile resolver (v0.2.1 D7).

The v0.2.1 fetch script for NIST OSCAL exercised the resolver against
real upstream content and exposed a couple of edge cases that v0.2.0
didn't handle:

- ``#uuid`` fragment refs requiring ``back-matter.resources`` lookup
- ``rlinks`` with multiple media-types where JSON isn't the first entry

These tests pin that behavior with minimal synthetic profile/catalog
fixtures so future refactors to ``_resolve_href`` don't regress.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evidentia_core.oscal.profile import (
    ProfileResolutionError,
    _resolve_href,
    resolve_profile,
)


def _write(tmp: Path, name: str, obj: dict) -> Path:
    path = tmp / name
    path.write_text(json.dumps(obj), encoding="utf-8")
    return path


# -----------------------------------------------------------------------------
# _resolve_href — link resolution edge cases
# -----------------------------------------------------------------------------


def test_resolve_relative_path(tmp_path: Path) -> None:
    """Plain relative path resolves against base_dir."""
    catalog = tmp_path / "sub" / "cat.json"
    catalog.parent.mkdir()
    catalog.write_text("{}")
    resolved = _resolve_href("sub/cat.json", tmp_path)
    assert resolved == catalog.resolve()


def test_resolve_file_uri(tmp_path: Path) -> None:
    """file:// URI returns absolute path."""
    resolved = _resolve_href("file:///tmp/x.json", tmp_path)
    assert resolved == Path("/tmp/x.json")


def test_resolve_fragment_requires_profile(tmp_path: Path) -> None:
    """Fragment-only href with no profile document errors clearly."""
    with pytest.raises(ProfileResolutionError, match="requires the full profile"):
        _resolve_href("#some-uuid", tmp_path)


def test_resolve_fragment_prefers_json_rlink(tmp_path: Path) -> None:
    """With multiple rlinks, the JSON variant wins over XML."""
    profile = {
        "profile": {
            "back-matter": {
                "resources": [
                    {
                        "uuid": "abc-uuid",
                        "rlinks": [
                            {"href": "./cat.xml", "media-type": "application/oscal.catalog+xml"},
                            {"href": "./cat.json", "media-type": "application/oscal.catalog+json"},
                        ],
                    }
                ]
            }
        }
    }
    result = _resolve_href("#abc-uuid", tmp_path, profile=profile)
    assert str(result).endswith("cat.json")


def test_resolve_fragment_falls_back_to_any_rlink(tmp_path: Path) -> None:
    """When no JSON rlink exists, pick the first non-empty href."""
    profile = {
        "profile": {
            "back-matter": {
                "resources": [
                    {
                        "uuid": "abc-uuid",
                        "rlinks": [{"href": "./cat.xml", "media-type": "application/oscal.catalog+xml"}],
                    }
                ]
            }
        }
    }
    result = _resolve_href("#abc-uuid", tmp_path, profile=profile)
    assert str(result).endswith("cat.xml")


def test_resolve_fragment_missing_uuid_raises(tmp_path: Path) -> None:
    """An unknown UUID with no matching resource raises ProfileResolutionError."""
    profile = {"profile": {"back-matter": {"resources": [{"uuid": "other-uuid", "rlinks": []}]}}}
    with pytest.raises(ProfileResolutionError, match="does not match"):
        _resolve_href("#abc-uuid", tmp_path, profile=profile)


# -----------------------------------------------------------------------------
# resolve_profile — end-to-end small profile + catalog
# -----------------------------------------------------------------------------


def _minimal_catalog() -> dict:
    return {
        "catalog": {
            "uuid": "cat-uuid-1",
            "metadata": {"title": "Test Catalog", "version": "1.0"},
            "groups": [
                {
                    "id": "ac",
                    "title": "Access Control",
                    "controls": [
                        {
                            "id": "ac-1",
                            "title": "Policy",
                            "parts": [{"name": "statement", "prose": "Establish policy."}],
                        },
                        {
                            "id": "ac-2",
                            "title": "Account Management",
                            "parts": [{"name": "statement", "prose": "Manage accounts."}],
                        },
                        {
                            "id": "ac-3",
                            "title": "Access Enforcement",
                            "parts": [{"name": "statement", "prose": "Enforce authorizations."}],
                        },
                    ],
                }
            ],
        }
    }


def _profile_select(included_ids: list[str], catalog_href: str) -> dict:
    return {
        "profile": {
            "uuid": "prof-uuid-1",
            "metadata": {"title": "Test Profile", "version": "1.0"},
            "imports": [
                {
                    "href": catalog_href,
                    "include-controls": [{"with-ids": included_ids}],
                }
            ],
        }
    }


def test_resolve_profile_filters_included_ids(tmp_path: Path) -> None:
    """Profile with include-controls resolves to only listed controls."""
    _write(tmp_path, "catalog.json", _minimal_catalog())
    profile = _profile_select(["ac-1", "ac-3"], "./catalog.json")
    profile_path = _write(tmp_path, "profile.json", profile)

    resolved = resolve_profile(profile_path)
    ids = {c.id for c in resolved.controls}
    assert ids == {"AC-1", "AC-3"}
    assert resolved.control_count == 2


def test_resolve_profile_include_all_shape(tmp_path: Path) -> None:
    """`include-all: {}` resolves every control in the source catalog."""
    _write(tmp_path, "catalog.json", _minimal_catalog())
    profile = {
        "profile": {
            "uuid": "p",
            "metadata": {"title": "All", "version": "1.0"},
            "imports": [{"href": "./catalog.json", "include-all": {}}],
        }
    }
    profile_path = _write(tmp_path, "profile.json", profile)

    resolved = resolve_profile(profile_path)
    assert resolved.control_count == 3


def test_resolve_profile_fragment_href(tmp_path: Path) -> None:
    """Profile with `#uuid` href resolves via back-matter rlinks."""
    _write(tmp_path, "catalog.json", _minimal_catalog())
    profile = {
        "profile": {
            "uuid": "p",
            "metadata": {"title": "Via fragment", "version": "1.0"},
            "imports": [
                {
                    "href": "#cat-resource",
                    "include-controls": [{"with-ids": ["ac-2"]}],
                }
            ],
            "back-matter": {
                "resources": [
                    {
                        "uuid": "cat-resource",
                        "rlinks": [
                            {
                                "href": "./catalog.json",
                                "media-type": "application/oscal.catalog+json",
                            }
                        ],
                    }
                ]
            },
        }
    }
    profile_path = _write(tmp_path, "profile.json", profile)

    resolved = resolve_profile(profile_path)
    assert resolved.control_count == 1
    assert resolved.controls[0].id == "AC-2"


def test_resolve_profile_override_ids_used(tmp_path: Path) -> None:
    """override_framework_id / _name are reflected in the resolved catalog."""
    _write(tmp_path, "catalog.json", _minimal_catalog())
    profile = _profile_select(["ac-1"], "./catalog.json")
    profile_path = _write(tmp_path, "profile.json", profile)

    resolved = resolve_profile(
        profile_path,
        override_framework_id="my-custom-id",
        override_framework_name="My Custom Baseline",
    )
    assert resolved.framework_id == "my-custom-id"
    assert resolved.framework_name == "My Custom Baseline"


def test_resolve_profile_missing_imports_raises(tmp_path: Path) -> None:
    """A profile with no imports is malformed."""
    profile = {"profile": {"metadata": {"title": "Empty", "version": "1.0"}, "imports": []}}
    profile_path = _write(tmp_path, "empty.json", profile)
    with pytest.raises(ProfileResolutionError, match="no imports"):
        resolve_profile(profile_path)


def test_resolve_profile_missing_source_raises(tmp_path: Path) -> None:
    """A profile pointing to a non-existent catalog is an error, not silent empty."""
    profile = _profile_select(["ac-1"], "./missing.json")
    profile_path = _write(tmp_path, "profile.json", profile)
    with pytest.raises(ProfileResolutionError, match="not found"):
        resolve_profile(profile_path)
