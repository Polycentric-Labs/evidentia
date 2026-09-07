"""Text depth: the derived measure of how much control text a catalog carries.

The redistribution tier says what may be redistributed; ``text_depth`` says
what is actually in the file. It is computed from the entries and never
declared, so the manifest column is checked against the derivation here and
in ``scripts/check_catalog_truth.py``.
"""

from __future__ import annotations

import pytest
from evidentia_core.catalogs.loader import load_any_catalog
from evidentia_core.catalogs.manifest import load_manifest
from evidentia_core.models.catalog import (
    CatalogControl,
    ControlCatalog,
    StatementRow,
    derive_text_depth,
    has_statement,
)


def _row(title: str, text: str, *, placeholder: bool = False, withdrawn: bool = False) -> StatementRow:
    return StatementRow(title, text, placeholder, withdrawn)


class TestHasStatement:
    def test_real_text_counts(self) -> None:
        assert has_statement(_row("Account Management", "Manage system accounts."))

    def test_empty_text_does_not_count(self) -> None:
        assert not has_statement(_row("Account Management", ""))
        assert not has_statement(_row("Account Management", "   \n  "))

    def test_text_repeating_the_title_does_not_count(self) -> None:
        """Heading-only catalogs copy the title into the description."""
        assert not has_statement(_row("Asset Inventory", "Asset Inventory"))
        assert not has_statement(_row("Asset  Inventory", " asset inventory "))

    def test_placeholder_never_counts(self) -> None:
        assert not has_statement(_row("CC6.1", "[Licensed content, see license_url.]", placeholder=True))


class TestDeriveTextDepth:
    def test_full_when_every_row_has_text(self) -> None:
        rows = [_row("A", "text a"), _row("B", "text b")]
        assert derive_text_depth(rows) == "full"

    def test_headings_when_no_row_has_text(self) -> None:
        rows = [_row("A", "A"), _row("B", "")]
        assert derive_text_depth(rows) == "headings"

    def test_partial_in_between(self) -> None:
        rows = [_row("A", "text a"), _row("B", "B")]
        assert derive_text_depth(rows) == "partial"

    def test_withdrawn_rows_are_excluded(self) -> None:
        """A withdrawn control carries no upstream statement; it must not turn full into partial."""
        rows = [_row("A", "text a"), _row("B", "", withdrawn=True)]
        assert derive_text_depth(rows) == "full"

    def test_all_withdrawn_or_empty_is_headings(self) -> None:
        assert derive_text_depth([]) == "headings"
        assert derive_text_depth([_row("A", "", withdrawn=True)]) == "headings"


class TestControlCatalogTextDepth:
    def _catalog(self, controls: list[CatalogControl]) -> ControlCatalog:
        return ControlCatalog(
            framework_id="demo",
            framework_name="Demo",
            version="1",
            source="test",
            controls=controls,
        )

    def test_enhancements_are_counted(self) -> None:
        parent = CatalogControl(
            id="AC-2",
            title="Account Management",
            description="Manage accounts.",
            enhancements=[CatalogControl(id="AC-2(1)", title="Automated", description="Automated")],
        )
        assert self._catalog([parent]).text_depth == "partial"

    def test_withdrawn_enhancement_is_ignored(self) -> None:
        parent = CatalogControl(
            id="AC-2",
            title="Account Management",
            description="Manage accounts.",
            enhancements=[CatalogControl(id="AC-2(10)", title="Shared", description="", withdrawn=True)],
        )
        assert self._catalog([parent]).text_depth == "full"

    def test_withdrawn_defaults_false_and_round_trips(self) -> None:
        ctrl = CatalogControl(id="AC-1", title="Policy", description="Policy text.")
        assert ctrl.withdrawn is False
        assert CatalogControl.model_validate(ctrl.model_dump()).withdrawn is False


class TestBundledCatalogs:
    def test_full_nist_catalog_is_full_because_withdrawn_rows_are_excluded(self) -> None:
        catalog = load_any_catalog("nist-800-53-rev5")
        rows = catalog.statement_rows()
        assert sum(1 for row in rows if row.withdrawn) == 182
        assert catalog.text_depth == "full"

    def test_heading_only_open_license_catalog(self) -> None:
        assert load_any_catalog("cisa-cpgs").text_depth == "headings"

    def test_tier_c_stub_is_headings(self) -> None:
        assert load_any_catalog("iso-27001-2022").text_depth == "headings"

    def test_non_control_catalogs_have_a_depth(self) -> None:
        assert load_any_catalog("eu-gdpr").text_depth == "full"
        assert load_any_catalog("us-va-vcdpa").text_depth == "headings"
        assert load_any_catalog("mitre-attack-enterprise").text_depth == "full"
        assert load_any_catalog("cisa-kev").text_depth == "full"

    @pytest.mark.parametrize("entry", load_manifest().frameworks, ids=lambda e: e.id)
    def test_manifest_depth_matches_the_derivation(self, entry) -> None:  # type: ignore[no-untyped-def]
        """The manifest column is regenerated from the files; it must never drift."""
        assert entry.text_depth is not None, f"{entry.id}: regenerate the manifest"
        assert load_any_catalog(entry.id).text_depth == entry.text_depth
