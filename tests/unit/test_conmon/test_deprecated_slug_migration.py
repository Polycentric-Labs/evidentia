"""Deprecated cadence slugs in operator state files migrate on read.

V13-15: the bundled model-risk cadence shipped as
``occ-2026-13a-model-risk``, but the OCC bulletin is 2026-13 (no "a"
suffix). v0.13 renames the slug to ``occ-2026-13-model-risk``. Operator
state files are keyed by slug, so both state readers (the daemon's
``load_state_file`` and the CLI's ``--state-file`` loader) migrate the old
key to the new one on read, with a DeprecationWarning, per
``docs/deprecation-calendar.md`` (target removal v1.0.0). Writes accept the
new slug only.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from evidentia_core.conmon.calendar import migrate_deprecated_slugs
from evidentia_core.conmon.daemon import load_state_file

OLD_SLUG = "occ-2026-13a-model-risk"
NEW_SLUG = "occ-2026-13-model-risk"


def test_migrate_translates_old_slug_and_warns() -> None:
    with pytest.warns(DeprecationWarning, match=OLD_SLUG):
        out = migrate_deprecated_slugs({OLD_SLUG: date(2025, 10, 15)})
    assert out == {NEW_SLUG: date(2025, 10, 15)}


def test_migrate_keeps_new_slug_when_both_present() -> None:
    with pytest.warns(DeprecationWarning, match=OLD_SLUG):
        out = migrate_deprecated_slugs({OLD_SLUG: date(2025, 1, 1), NEW_SLUG: date(2025, 10, 15)})
    assert out == {NEW_SLUG: date(2025, 10, 15)}


def test_migrate_passes_unrelated_slugs_untouched() -> None:
    state = {"fedramp-conmon-monthly": date(2025, 6, 1)}
    assert migrate_deprecated_slugs(dict(state)) == state


def test_load_state_file_migrates_old_slug(tmp_path: Path) -> None:
    state_file = tmp_path / "state.yaml"
    state_file.write_text(f"{OLD_SLUG}: 2025-10-15\n", encoding="utf-8")
    with pytest.warns(DeprecationWarning, match=OLD_SLUG):
        loaded = load_state_file(state_file)
    assert loaded == {NEW_SLUG: date(2025, 10, 15)}
