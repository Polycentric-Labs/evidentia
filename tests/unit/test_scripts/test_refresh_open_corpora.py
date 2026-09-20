"""Offline driver controls use owned synthetic files and the real native guards."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from evidentia_core.models.open_corpora import NativeBudget, NativeSourceError

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def driver():
    spec = importlib.util.spec_from_file_location(
        "refresh_open_corpora_test", ROOT / "scripts/catalogs/refresh_open_corpora.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_check_mode_never_creates_an_output_or_opens_a_write(driver, tmp_path, monkeypatch, capsys):
    destination = tmp_path / "not-created"
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setattr(driver, "read_source_directory", lambda profile, directory: {"source": b"immutable"})
    observed = []

    def check(profile, sources, output):
        observed.append((profile, sources, output))
        return False

    monkeypatch.setattr(driver, "check_package_outputs", check)
    monkeypatch.setattr(driver, "_write_outputs", lambda *args: pytest.fail("check must not publish"))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "refresh",
            "--profile",
            "au-ism-2026.09.4",
            "--source-dir",
            str(source),
            "--output-root",
            str(destination),
            "--check",
        ],
    )
    assert driver.main() == 1
    assert len(observed) == 1
    assert not destination.exists()
    assert capsys.readouterr().out == "output_drift\n"


def test_new_output_keeps_exact_bytes_and_refuses_reuse(driver, tmp_path):
    destination = tmp_path / "fresh"
    outputs = {"one/a.json": b'{"value":"native"}\n', "two.txt": b"native\r\n"}
    driver._write_outputs(destination, outputs, NativeBudget())
    assert {name: (destination / name).read_bytes() for name in outputs} == outputs
    with pytest.raises(NativeSourceError):
        driver._write_outputs(destination, outputs, NativeBudget())
    assert {name: (destination / name).read_bytes() for name in outputs} == outputs


def test_write_failure_and_secondary_close_preserve_original_exception(driver, tmp_path, monkeypatch):
    primary = KeyboardInterrupt("synthetic write cancellation")
    cleanup = OSError("synthetic close error")
    close = driver.os.close

    def write(*args):
        raise primary

    def close_then_fail(descriptor):
        close(descriptor)
        raise cleanup

    monkeypatch.setattr(driver.os, "write", write)
    monkeypatch.setattr(driver.os, "close", close_then_fail)
    with pytest.raises(KeyboardInterrupt) as caught:
        driver._write_outputs(tmp_path / "fresh", {"a.txt": b"body"}, NativeBudget())
    assert caught.value is primary
    assert caught.value.__cause__ is cleanup
    assert (tmp_path / "fresh/a.txt").exists()


def test_original_budget_refuses_new_publication_after_reserve_boundary(driver, tmp_path, monkeypatch):
    from evidentia_core.models import open_corpora as model

    now = [0.0]
    monkeypatch.setattr(model.time, "monotonic", lambda: now[0])
    budget = NativeBudget()
    now[0] = 50.0
    with pytest.raises(NativeSourceError, match="processing_deadline_exceeded"):
        driver._write_outputs(tmp_path / "unwritten", {"a.txt": b"body"}, budget)
    assert not (tmp_path / "unwritten").exists()


@pytest.mark.parametrize(
    "relative",
    [
        "../outside.txt",
        "/outside.txt",
        "C:/outside.txt",
        r"..\outside.txt",
        r"\outside.txt",
        r"\\host\share\outside.txt",
        "C:outside.txt",
    ],
)
def test_driver_refuses_output_path_escape(driver, tmp_path, relative, monkeypatch):
    monkeypatch.setattr(driver.os, "open", lambda *args: pytest.fail("path admission must precede file open"))
    with pytest.raises(NativeSourceError):
        driver._write_outputs(tmp_path / "fresh", {relative: b"body"}, NativeBudget())
    assert not (tmp_path / "outside.txt").exists()


def test_unreviewed_and_external_profiles_refuse_before_source_read(driver, tmp_path, monkeypatch):
    monkeypatch.setattr(
        driver, "read_source_directory", lambda *args: pytest.fail("profile refused before source read")
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "refresh",
            "--profile",
            "bsi-grundschutz-plus-plus-367d7750",
            "--source-dir",
            str(tmp_path),
            "--output-root",
            str(tmp_path),
        ],
    )
    with pytest.raises(SystemExit) as caught:
        driver.main()
    assert caught.value.code == 2
