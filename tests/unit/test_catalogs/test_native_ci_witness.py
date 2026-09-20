"""Regression checks for native filesystem admission and CI coverage guards."""

import ctypes
import importlib.util
import platform
from pathlib import Path
from types import SimpleNamespace

import evidentia_core.catalogs.user_dir as storage
import pytest
from evidentia_core.models.open_corpora import NativeBudget


@pytest.mark.parametrize("machine,symbol", [("arm64", "fstatfs"), ("x86_64", "fstatfs$INODE64")])
@pytest.mark.parametrize("flags,result", [(0x1000, 0), (0x1001, 0), (0, 0), (0x1000, -1)])
def test_darwin_descriptor_locality_uses_native_abi(monkeypatch, machine, symbol, flags, result):
    calls = []

    class Query:
        def __call__(self, descriptor, pointer):
            value = pointer._obj
            calls.append((descriptor, ctypes.sizeof(value), type(value).f_flags.offset))
            value.f_flags = flags
            return result

    monkeypatch.setattr(storage.sys, "platform", "darwin")
    monkeypatch.setattr(platform, "machine", lambda: machine)
    monkeypatch.setattr(ctypes, "CDLL", lambda *args, **kwargs: SimpleNamespace(**{symbol: Query()}))
    if result == 0 and flags & 0x1000:
        assert storage._darwin_filesystem_flags(73, NativeBudget()) == flags
    else:
        with pytest.raises(storage.CatalogStorageError, match="catalog_storage_unsupported"):
            storage._darwin_filesystem_flags(73, NativeBudget())
    assert calls == [(73, 2168, 64)]


@pytest.mark.parametrize("refusal", ["platform", "architecture", "pointer", "alignment", "symbol", "library"])
def test_darwin_unsupported_abi_or_query_is_refused(monkeypatch, refusal):
    monkeypatch.setattr(storage.sys, "platform", "linux" if refusal == "platform" else "darwin")
    monkeypatch.setattr(platform, "machine", lambda: "unknown" if refusal == "architecture" else "arm64")
    original_sizeof = ctypes.sizeof
    if refusal == "pointer":
        monkeypatch.setattr(ctypes, "sizeof", lambda value: 4 if value is ctypes.c_void_p else original_sizeof(value))
    if refusal == "alignment":
        monkeypatch.setattr(ctypes, "alignment", lambda value: 4)

    def library(*args, **kwargs):
        if refusal == "library":
            raise OSError("synthetic unavailable system library")
        assert refusal == "symbol"
        return SimpleNamespace()

    monkeypatch.setattr(ctypes, "CDLL", library)
    with pytest.raises(storage.CatalogStorageError, match="catalog_storage_unsupported"):
        storage._darwin_filesystem_flags(73, NativeBudget())


def witness():
    path = Path(__file__).resolve().parents[3] / "scripts/catalogs/verify_native_ci.py"
    spec = importlib.util.spec_from_file_location("native_ci_witness_guard", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("version,name", [((3, 12), "CTracer"), ((3, 14), "SysMonitor")])
def test_native_coverage_accepts_only_the_required_tracer_type(version, name):
    guard = witness().coverage_tracer_names
    tracer = type(name, (), {})
    active = SimpleNamespace(
        config=SimpleNamespace(branch=False), _collector=SimpleNamespace(tracers=[tracer(), tracer()])
    )
    assert guard(active, version) == [name, name]
    for invalid in ([], [type("PyTracer", (), {})()], [tracer(), type("Unexpected", (), {})()]):
        active._collector.tracers = invalid
        with pytest.raises(RuntimeError, match="Coverage tracer changed"):
            guard(active, version)
    active.config.branch = True
    with pytest.raises(RuntimeError, match="Normal statement coverage"):
        guard(active, version)
    with pytest.raises(RuntimeError, match="Normal statement coverage"):
        guard(None, version)
