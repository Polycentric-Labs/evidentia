"""Unit tests for evidentia_core.security.atomic_write (v0.9.5 P1.5)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from evidentia_core.security import atomic_write_text
from evidentia_core.security.atomic_write import atomic_write_text as direct_import


class TestAtomicWriteBasics:
    def test_writes_content(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        atomic_write_text(path, '{"key": "value"}')
        assert path.read_text(encoding="utf-8") == '{"key": "value"}'

    def test_overwrites_existing_file(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        path.write_text("old content", encoding="utf-8")
        atomic_write_text(path, "new content")
        assert path.read_text(encoding="utf-8") == "new content"

    def test_creates_parent_directory(self, tmp_path: Path) -> None:
        path = tmp_path / "nested" / "subdir" / "state.json"
        assert not path.parent.exists()
        atomic_write_text(path, "content")
        assert path.read_text(encoding="utf-8") == "content"
        assert path.parent.is_dir()

    def test_custom_encoding(self, tmp_path: Path) -> None:
        path = tmp_path / "state.txt"
        atomic_write_text(path, "héllo", encoding="latin-1")
        assert path.read_bytes() == b"h\xe9llo"

    def test_import_via_package_alias(self) -> None:
        """The helper is re-exported from ``evidentia_core.security``
        alongside FileLock + validate_within. Importing via the
        package surface MUST resolve to the same callable as importing
        the module directly."""
        assert atomic_write_text is direct_import


class TestAtomicWriteCleanup:
    def test_removes_orphaned_tmp_on_write_failure(
        self, tmp_path: Path
    ) -> None:
        """If the .tmp file write fails (e.g., disk full), the .tmp
        file is removed before re-raising — sidecar artifacts don't
        accumulate across failures."""
        path = tmp_path / "state.json"
        # Patch Path.write_text to raise OSError after creating the file.
        tmp_path_obj = path.with_suffix(path.suffix + ".tmp")

        original_write_text = Path.write_text

        def failing_write_text(
            self: Path, *args: object, **kwargs: object
        ) -> int:
            if self == tmp_path_obj:
                # Create the file, then fail — simulates partial-write
                # disk-full scenario.
                self.touch()
                raise OSError("simulated disk full")
            return original_write_text(self, *args, **kwargs)  # type: ignore[arg-type]

        with (
            patch.object(Path, "write_text", failing_write_text),
            pytest.raises(OSError, match="simulated disk full"),
        ):
            atomic_write_text(path, "content")

        # Both the destination and the .tmp sidecar should be absent.
        assert not path.exists()
        assert not tmp_path_obj.exists()

    def test_removes_orphaned_tmp_on_replace_failure(
        self, tmp_path: Path
    ) -> None:
        """If os.replace fails (e.g., cross-filesystem rename in some
        edge case), the .tmp sidecar is cleaned up."""
        path = tmp_path / "state.json"
        tmp_path_obj = path.with_suffix(path.suffix + ".tmp")

        original_replace = Path.replace

        def failing_replace(self: Path, target: Path) -> Path:
            if self == tmp_path_obj:
                raise OSError("simulated replace failure")
            return original_replace(self, target)

        with (
            patch.object(Path, "replace", failing_replace),
            pytest.raises(OSError, match="simulated replace failure"),
        ):
            atomic_write_text(path, "content")

        assert not path.exists()
        assert not tmp_path_obj.exists()

    def test_cleanup_suppresses_secondary_oserror(
        self, tmp_path: Path
    ) -> None:
        """If the .tmp cleanup itself fails (e.g., already-deleted by
        a parallel cleanup), the secondary OSError is suppressed and
        the original exception propagates."""
        path = tmp_path / "state.json"
        tmp_path_obj = path.with_suffix(path.suffix + ".tmp")

        original_write_text = Path.write_text
        original_unlink = Path.unlink

        def failing_write_text(
            self: Path, *args: object, **kwargs: object
        ) -> int:
            if self == tmp_path_obj:
                raise OSError("primary failure")
            return original_write_text(self, *args, **kwargs)  # type: ignore[arg-type]

        def failing_unlink(
            self: Path, missing_ok: bool = False
        ) -> None:
            if self == tmp_path_obj:
                raise OSError("secondary cleanup failure")
            return original_unlink(self, missing_ok=missing_ok)

        with (
            patch.object(Path, "write_text", failing_write_text),
            patch.object(Path, "unlink", failing_unlink),
            pytest.raises(OSError, match="primary failure"),
        ):
            # Primary exception propagates; secondary is suppressed.
            atomic_write_text(path, "content")


class TestAtomicWriteSemantics:
    def test_no_partial_writes_observable(self, tmp_path: Path) -> None:
        """Under interrupted-write scenarios, a reader sees either
        the old content or the new content, never a partial state.

        This is the core guarantee that the .tmp + os.replace dance
        provides. We model "interruption" by checking that the file
        is never observed missing after the first successful write.
        """
        path = tmp_path / "state.json"
        atomic_write_text(path, "v1")
        # File exists with v1 content
        assert path.read_text(encoding="utf-8") == "v1"
        atomic_write_text(path, "v2")
        # File still exists, now with v2 content
        assert path.exists()
        assert path.read_text(encoding="utf-8") == "v2"

    def test_tmp_path_uses_dot_tmp_suffix(self, tmp_path: Path) -> None:
        """The .tmp suffix convention is part of the helper's
        contract: operator tooling scanning for orphaned sidecars
        can rely on the .tmp extension."""
        path = tmp_path / "state.json"
        expected_tmp = path.with_suffix(path.suffix + ".tmp")
        # Spy on the .tmp write to confirm it lands at the expected path.
        write_target: list[Path] = []
        original_write_text = Path.write_text

        def spy_write_text(
            self: Path, *args: object, **kwargs: object
        ) -> int:
            write_target.append(self)
            return original_write_text(self, *args, **kwargs)  # type: ignore[arg-type]

        with patch.object(Path, "write_text", spy_write_text):
            atomic_write_text(path, "content")

        assert expected_tmp in write_target
