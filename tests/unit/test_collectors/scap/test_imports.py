"""The declared Python surface imports without loading optional XML support."""

from __future__ import annotations

import subprocess
import sys

from evidentia_collectors import scap
from evidentia_collectors.scap import collector


def test_declared_functions_and_models_are_the_only_exports():
    assert set(scap.__all__) == {
        "ScapCollectionResult",
        "ScapCompletionAssertion",
        "ScapError",
        "ScapSourceProfile",
        "collect_scap_bytes",
        "collect_scap_file",
    }
    assert scap.collect_scap_bytes is collector.collect_scap_bytes
    assert scap.collect_scap_file is collector.collect_scap_file


def test_fresh_import_never_loads_or_discovers_the_optional_xml_dependency(tmp_path):
    script = r"""
import builtins
import importlib.util
import socket

original_import = builtins.__import__
original_find = importlib.util.find_spec

def importing(name, *args, **kwargs):
    if name == "defusedxml" or name.startswith("defusedxml."):
        raise AssertionError("SCAP import attempted to load optional XML support")
    return original_import(name, *args, **kwargs)

def finding(name, *args, **kwargs):
    if name == "defusedxml" or name.startswith("defusedxml."):
        raise AssertionError("SCAP import attempted optional dependency discovery")
    return original_find(name, *args, **kwargs)

def denied(*args, **kwargs):
    raise AssertionError("SCAP import attempted a network operation")

builtins.__import__ = importing
importlib.util.find_spec = finding
socket.getaddrinfo = denied
socket.socket.connect = denied
from evidentia_collectors.scap import collect_scap_bytes, collect_scap_file, ScapCollectionResult
assert callable(collect_scap_bytes) and callable(collect_scap_file)
assert ScapCollectionResult.__name__ == "ScapCollectionResult"
print("Optional XML support was neither discovered nor imported.")
"""
    result = subprocess.run(
        [sys.executable, "-B", "-c", script],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert result.stdout.strip() == b"Optional XML support was neither discovered nor imported."
