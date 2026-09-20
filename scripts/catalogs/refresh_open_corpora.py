"""Regenerate one pinned bundled corpus without network access.

Check mode only reads. Write mode requires an empty destination and preserves
partial outputs if an I/O failure interrupts publication to that fresh directory.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path, PureWindowsPath

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packages/evidentia-core/src"))

from evidentia_core.catalogs.loader import _native_path  # noqa: E402
from evidentia_core.catalogs.open_corpora import (  # noqa: E402
    check_package_outputs,
    package_outputs,
    read_source_directory,
)
from evidentia_core.models.open_corpora import NativeBudget, NativeSourceError, native_operation  # noqa: E402


def _ensure_directory(directory: Path, budget: NativeBudget) -> None:
    """Create missing local directories only below checked native ancestors."""
    if ".." in directory.parts or directory.drive.startswith("\\\\"):
        raise NativeSourceError()
    pending: list[Path] = []
    current = directory.absolute()
    while True:
        budget.check()
        try:
            _native_path(current, directory=True)
            break
        except FileNotFoundError:
            pending.append(current)
            if current.parent == current:
                raise NativeSourceError() from None
            current = current.parent
    for current in reversed(pending):
        budget.check()
        current.mkdir()
        _native_path(current, directory=True)


def _write_outputs(destination: Path, outputs: dict[str, bytes], budget: NativeBudget) -> None:
    """Publish only into a fresh checked directory, retaining partial failure evidence."""
    from evidentia_core.catalogs.open_corpora import _directory_names

    budget.check()
    if not outputs:
        raise NativeSourceError()
    _ensure_directory(destination, budget)
    if _directory_names(destination, 0, budget):
        raise NativeSourceError()
    with budget.publication():
        for relative, raw in outputs.items():
            path = Path(relative)
            windows = PureWindowsPath(relative)
            if path.anchor or windows.anchor or ".." in path.parts or ".." in windows.parts:
                raise NativeSourceError()
            budget.check()
            target = destination / path
            _ensure_directory(target.parent, budget)
            descriptor = os.open(
                target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            )
            primary: BaseException | None = None
            try:
                for offset in range(0, len(raw), 4096):
                    budget.check()
                    piece = raw[offset : offset + 4096]
                    if os.write(descriptor, piece) != len(piece):
                        raise OSError("short output write")
                budget.check()
            except BaseException as error:
                primary = error
                raise
            finally:
                try:
                    os.close(descriptor)
                except BaseException as cleanup:
                    if primary is not None:
                        raise primary from cleanup
                    raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline pinned open-corpus refresh")
    parser.add_argument("--profile", required=True, choices=("au-ism-2026.09.4", "cisa-scuba-m365-7ef9501d"))
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        with native_operation() as budget:
            sources = read_source_directory(args.profile, args.source_dir)
            if args.check:
                matched = check_package_outputs(args.profile, sources, args.output_root)
                print("output_matches" if matched else "output_drift")
                return 0 if matched else 1
            outputs = package_outputs(args.profile, sources)
            _write_outputs(args.output_root, outputs, budget)
            print("output_written")
            return 0
    except NativeSourceError as exc:
        print(exc.code, file=sys.stderr)
        return 1
    except OSError:
        print("output_io_failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
