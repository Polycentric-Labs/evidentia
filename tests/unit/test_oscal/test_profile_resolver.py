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


@pytest.mark.parametrize("href", ["missing.json", "original.json", "#missing-resource"])
def test_source_catalog_override_takes_precedence(tmp_path: Path, href: str) -> None:
    """An explicit local source replaces the profile href before href resolution."""
    original = _minimal_catalog()
    original["catalog"]["groups"][0]["controls"][0]["title"] = "Original policy"
    _write(tmp_path, "original.json", original)
    source = _write(tmp_path, "source.json", _minimal_catalog())
    profile_path = _write(tmp_path, "profile.json", _profile_select(["ac-1"], href))

    resolved = resolve_profile(profile_path, source_catalog_path=source)

    assert [control.id for control in resolved.controls] == ["AC-1"]
    assert resolved.controls[0].title == "Policy"
    assert resolved.controls[0].description == "Establish policy."


@pytest.mark.parametrize("explicit_source", [False, True])
def test_source_override_preserves_positional_api(tmp_path: Path, explicit_source: bool) -> None:
    """The existing ID and name arguments retain their positional meanings."""
    source = _write(tmp_path, "source.json", _minimal_catalog())
    profile_path = _write(tmp_path, "profile.json", _profile_select(["ac-1"], "source.json"))

    if explicit_source:
        resolved = resolve_profile(profile_path, "custom-id", "Custom name", source_catalog_path=source)
    else:
        resolved = resolve_profile(profile_path, "custom-id", "Custom name")

    assert resolved.framework_id == "custom-id"
    assert resolved.framework_name == "Custom name"
    assert resolved.control_count == 1


def test_relative_source_override_uses_caller_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI-style relative source paths are relative to cwd, not the profile."""
    profile_dir = tmp_path / "profiles"
    profile_dir.mkdir()
    _write(tmp_path, "source.json", _minimal_catalog())
    profile_path = _write(profile_dir, "profile.json", _profile_select(["ac-2"], "missing.json"))
    monkeypatch.chdir(tmp_path)

    resolved = resolve_profile(profile_path, source_catalog_path=Path("source.json"))

    assert [control.id for control in resolved.controls] == ["AC-2"]


@pytest.mark.parametrize("source_kind", ["missing", "directory", "invalid-json", "invalid-catalog"])
def test_invalid_source_override_raises_typed_error(tmp_path: Path, source_kind: str) -> None:
    """An unusable override fails without falling back to a valid href."""
    _write(tmp_path, "original.json", _minimal_catalog())
    profile_path = _write(tmp_path, "profile.json", _profile_select(["ac-1"], "original.json"))
    source = tmp_path / "override.json"
    if source_kind == "directory":
        source.mkdir()
    elif source_kind == "invalid-json":
        source.write_text("not JSON", encoding="utf-8")
    elif source_kind == "invalid-catalog":
        _write(tmp_path, "override.json", {"catalog": "invalid"})

    with pytest.raises(ProfileResolutionError):
        resolve_profile(profile_path, source_catalog_path=source)


@pytest.mark.parametrize("source", ["https://example.com/catalog.json", "//example.com/share/catalog.json"])
def test_source_override_rejects_remote_paths_before_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    """The local override never attempts to resolve a URL or network share."""
    profile_path = _write(tmp_path, "profile.json", _profile_select(["ac-1"], "unused.json"))

    def unexpected_source_io(*args: object, **kwargs: object) -> None:
        pytest.fail("Remote override attempted filesystem resolution")

    with monkeypatch.context() as source_io_guard:
        source_io_guard.setattr(Path, "resolve", unexpected_source_io)
        source_io_guard.setattr(Path, "exists", unexpected_source_io)
        source_io_guard.setattr(Path, "is_file", unexpected_source_io)
        with pytest.raises(ProfileResolutionError, match="local filesystem path"):
            resolve_profile(profile_path, source_catalog_path=Path(source))


def test_source_override_rejects_multiple_imports(tmp_path: Path) -> None:
    """One explicit catalog cannot unambiguously replace several imports."""
    source = _write(tmp_path, "source.json", _minimal_catalog())
    profile = _profile_select(["ac-1"], "source.json")
    profile["profile"]["imports"].append({"href": "another.json", "include-all": {}})
    profile_path = _write(tmp_path, "profile.json", profile)

    with pytest.raises(ProfileResolutionError, match="multiple imports"):
        resolve_profile(profile_path, source_catalog_path=source)


def test_multiple_imports_without_override_preserve_existing_behavior(tmp_path: Path) -> None:
    """Legacy calls use the first source and combined filters without merging."""
    _write(tmp_path, "source.json", _minimal_catalog())
    profile = _profile_select(["ac-1"], "source.json")
    profile["profile"]["imports"].append({"href": "unused.json", "include-controls": [{"with-ids": ["ac-3"]}]})
    profile_path = _write(tmp_path, "profile.json", profile)

    resolved = resolve_profile(profile_path)

    assert [control.id for control in resolved.controls] == ["AC-1", "AC-3"]


@pytest.mark.parametrize("shape", ["top-level", "grouped", "nested"])
@pytest.mark.parametrize("with_children", [False, True])
def test_source_control_shapes_preserve_filters_and_families(tmp_path: Path, shape: str, with_children: bool) -> None:
    """Root and nested group controls retain the same selection semantics."""
    catalog = _minimal_catalog()
    group = catalog["catalog"]["groups"][0]
    group["controls"][0]["controls"] = [{"id": "ac-1.1", "title": "Policy review"}]
    if shape == "top-level":
        catalog["catalog"]["controls"] = group["controls"]
        del catalog["catalog"]["groups"]
    elif shape == "nested":
        catalog["catalog"]["groups"] = [{"id": "security", "title": "Security", "groups": [group]}]
    _write(tmp_path, "source.json", catalog)
    profile = _profile_select(["ac-1", "ac-3"], "source.json")
    source_import = profile["profile"]["imports"][0]
    source_import["include-controls"][0]["with-child-controls"] = "yes" if with_children else "no"
    source_import["exclude-controls"] = [{"with-ids": ["ac-3"]}]
    profile_path = _write(tmp_path, "profile.json", profile)

    resolved = resolve_profile(profile_path)

    assert [control.id for control in resolved.controls] == ["AC-1"]
    assert resolved.controls[0].description == "Establish policy."
    assert [child.id for child in resolved.controls[0].enhancements] == (["AC-1.1"] if with_children else [])
    family = "" if shape == "top-level" else "Access Control"
    assert resolved.controls[0].family == family
    assert resolved.families == ([family] if family else [])
    assert all(child.family == family for child in resolved.controls[0].enhancements)


def test_mixed_source_controls_preserve_order_and_nearest_family(tmp_path: Path) -> None:
    """Depth-first group traversal retains root controls and family inheritance."""
    catalog = _minimal_catalog()
    group = catalog["catalog"]["groups"][0]
    first, second, third = group["controls"]
    catalog["catalog"]["controls"] = [first]
    group["controls"] = [second]
    group["groups"] = [{"id": "nested", "controls": [third]}]
    catalog["catalog"]["groups"].append(
        {"id": "au", "title": "Audit", "controls": [{"id": "au-1", "title": "Audit policy"}]}
    )
    _write(tmp_path, "source.json", catalog)
    profile = _profile_select([], "source.json")
    profile["profile"]["imports"][0] = {"href": "source.json", "include-all": {}}
    profile_path = _write(tmp_path, "profile.json", profile)

    resolved = resolve_profile(profile_path)

    assert [control.id for control in resolved.controls] == ["AC-1", "AC-2", "AC-3", "AU-1"]
    assert [control.family for control in resolved.controls] == ["", "Access Control", "Access Control", "Audit"]
    assert resolved.families == ["Access Control", "Audit"]


@pytest.mark.parametrize("bad_collection", ["root-controls", "nested-groups", "nested-controls"])
def test_malformed_source_hierarchy_raises_typed_error(tmp_path: Path, bad_collection: str) -> None:
    """Newly traversed collections use the existing structural guards."""
    catalog = _minimal_catalog()
    if bad_collection == "root-controls":
        catalog["catalog"]["controls"] = "invalid"
    else:
        nested = {"id": "nested", "controls": "invalid"} if bad_collection == "nested-controls" else "invalid"
        catalog["catalog"]["groups"][0]["groups"] = [nested]
    _write(tmp_path, "source.json", catalog)
    profile_path = _write(tmp_path, "profile.json", _profile_select(["ac-1"], "source.json"))

    with pytest.raises(ProfileResolutionError):
        resolve_profile(profile_path)


def test_deeply_nested_source_groups_raise_typed_error(tmp_path: Path) -> None:
    """An excessive group hierarchy fails with the resolver's declared error."""
    catalog = _minimal_catalog()
    group = catalog["catalog"]["groups"][0]
    for depth in range(150):
        group = {"id": f"nested-{depth}", "title": "Security", "groups": [group]}
    catalog["catalog"]["groups"] = [group]
    _write(tmp_path, "source.json", catalog)
    profile_path = _write(tmp_path, "profile.json", _profile_select(["ac-1"], "source.json"))

    with pytest.raises(ProfileResolutionError, match="nesting"):
        resolve_profile(profile_path)
