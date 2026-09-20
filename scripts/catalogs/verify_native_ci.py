"""Fetch selected publisher inputs or verify native catalog storage in CI."""

import argparse
import ctypes
import hashlib
import http.client
import json
import os
import platform
import socket
import sys
import time
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
INPUT_SHA256 = "4e8527816510ba62820e8de4c568b26b06d9f2ac9f790d99c69d9b21fbc81fbb"
NATIVE_TESTS = [
    "test_f2_manifest_save_replaces_one_complete_file",
    "test_f2_legacy_generations_retain_prior_and_remove_does_not_open_payload",
    "test_f2_stable_lock_busy_is_one_nonblocking_attempt",
    "test_f2_nonempty_and_hardlinked_lock_targets_are_refused",
    "test_f2_process_contention_and_native_owner_cleanup",
    "test_f2_capacity_manifest_exact_bytes_and_plus_one",
    "test_f2_capacity_manifest_entry_count",
    "test_f2_capacity_legacy_exact_bytes_and_plus_one",
    "test_f2_actual_import_remove_interleaving_uses_fresh_manifest",
    "test_f2_remove_confirmation_rechecks_after_actual_force_import",
    "test_f2_reader_spanning_replace_keeps_complete_old_manifest_and_payload",
    "test_f2_unrelated_and_colliding_temporary_paths_are_never_adopted_or_deleted",
    "test_f2_generation_move_failure_preserves_primary_and_retained_generation",
    "test_f2_actual_temporary_cleanup_failure_cannot_replace_primary",
    "test_f2_lock_is_not_inherited_and_repeated_cleanup_keeps_stable_object",
    "test_f2_two_actual_transactions_contend_through_independent_handles",
]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def binding(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def load_inputs():
    raw = (HERE / "native_ci_inputs.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest() == INPUT_SHA256, "Input contract changed")
    return json.loads(raw)


def save(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def fetch(destination, spec):
    """Fetch only the three pinned HTTPS paths; reject redirects and changed bytes."""
    destination.mkdir()
    results = []
    for row in spec["files"]:
        url_path = "/" + spec["repository"] + "/" + spec["commit"] + "/" + quote(row["upstream_path"], safe="/")
        connection = http.client.HTTPSConnection("raw.githubusercontent.com", timeout=45)
        try:
            connection.request("GET", url_path, headers={"Accept-Encoding": "identity"})
            response = connection.getresponse()
            require(response.status == 200, "Publisher response was not HTTP 200")
            require(response.getheader("Content-Encoding", "identity") == "identity", "Unexpected content encoding")
            raw = response.read(row["bytes"] + 1)
            require(len(raw) == row["bytes"], "Publisher byte count changed")
            require(hashlib.sha256(raw).hexdigest() == row["sha256"], "Publisher hash changed")
            with (destination / row["name"]).open("xb") as stream:
                stream.write(raw)
            results.append({"name": row["name"], "bytes": len(raw), "sha256": row["sha256"]})
        finally:
            connection.close()
    return results


def filesystem_facts(directory):
    import evidentia_core.catalogs.user_dir as storage
    from evidentia_core.models.open_corpora import NativeBudget

    require(sys.platform in {"linux", "darwin"}, "This witness requires native Linux or macOS")
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        facts = {
            "platform": sys.platform,
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
            "device": info.st_dev,
            "pointer_bytes": ctypes.sizeof(ctypes.c_void_p),
            "long_bytes": ctypes.sizeof(ctypes.c_long),
        }
        if sys.platform == "linux":
            facts["filesystem_magic"] = storage._linux_filesystem_type(descriptor, NativeBudget())
            require(facts["filesystem_magic"] == 0xEF53, "An ext-family filesystem is required")
            library = ctypes.CDLL(None)
            library.gnu_get_libc_version.restype = ctypes.c_char_p
            facts["glibc"] = library.gnu_get_libc_version().decode("ascii")
        else:
            facts["mnt_local"] = 0x1000
            facts["filesystem_flags"] = storage._darwin_filesystem_flags(descriptor, NativeBudget())
            require(facts["filesystem_flags"] & facts["mnt_local"], "The filesystem is not local")
        return facts
    finally:
        os.close(descriptor)


def coverage_tracer_names(active, version):
    require(active is not None and not active.config.branch, "Normal statement coverage is required")
    require(version in {(3, 12), (3, 14)}, "Unsupported coverage interpreter")
    tracers = [type(tracer).__name__ for tracer in active._collector.tracers]
    expected = "CTracer" if version == (3, 12) else "SysMonitor"
    require(tracers and all(name == expected for name in tracers), "Coverage tracer changed")
    return tracers


def verify(checkout, source_dir, output, spec):
    import resource

    import coverage
    import pytest

    require(sys.platform in {"linux", "darwin"}, "Native operating system required")
    require(not sys.flags.optimize, "Assertions must remain enabled")
    require(coverage.__version__ == "7.13.5", "Requalify a changed coverage runtime")
    for row in spec["files"]:
        require(binding(source_dir / row["name"]) == {"bytes": row["bytes"], "sha256": row["sha256"]}, "Input changed")
    output.mkdir()
    work = output / "work"
    work.mkdir()
    report = {"status": "STARTED", "started": datetime.now(UTC).isoformat(), "tests": [], "network_attempts": 0}
    paths = [
        checkout / "packages/evidentia-core/src/evidentia_core/catalogs/user_dir.py",
        checkout / "packages/evidentia-core/src/evidentia_core/catalogs/manifest.py",
        checkout / "packages/evidentia-core/src/evidentia_core/catalogs/open_corpora.py",
        checkout / "packages/evidentia-core/src/evidentia_core/models/open_corpora.py",
        checkout / "tests/unit/test_catalogs/test_user_dir.py",
        checkout / "pyproject.toml",
        HERE / "native_storage_witness.py",
        HERE / "native_ci_inputs.json",
        Path(__file__),
    ]
    before = [binding(p) for p in paths]
    report["source_hashes"] = [{"file": p.name, **row} for p, row in zip(paths, before, strict=True)]
    budgets = []

    class Observations:
        current = None

        def pytest_sessionstart(self, session):
            import evidentia_core.catalogs.user_dir as storage
            from evidentia_core.models.open_corpora import NativeBudget

            require(Path(storage.__file__).resolve() == paths[0].resolve(), "Wrong production source origin")
            original = NativeBudget.__init__

            @wraps(original)
            def observed(budget):
                original(budget)
                budgets.append((budget, budget._deadline, self.current))

            self.original = original
            NativeBudget.__init__ = observed

        @pytest.hookimpl(hookwrapper=True)
        def pytest_runtest_call(self, item):
            self.current = item.nodeid
            started = time.perf_counter()
            active = coverage.Coverage.current()
            tracers = coverage_tracer_names(active, sys.version_info[:2])
            yield
            report["tests"].append(
                {
                    "id": item.nodeid,
                    "elapsed_seconds": time.perf_counter() - started,
                    "coverage_tracers": tracers,
                    "process_peak_rss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                    "rss_unit": "bytes" if sys.platform == "darwin" else "KiB",
                }
            )
            self.current = None

        def pytest_sessionfinish(self, session, exitstatus):
            from evidentia_core.models.open_corpora import NativeBudget

            NativeBudget.__init__ = self.original
            report.update(collected=session.testscollected, failed=session.testsfailed)

    def deny_network(*args, **kwargs):
        report["network_attempts"] += 1
        raise RuntimeError("Network is disabled during native verification")

    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_lookup = socket.getaddrinfo
    try:
        report["filesystem"] = filesystem_facts(work)
        socket.socket.connect = deny_network
        socket.socket.connect_ex = deny_network
        socket.getaddrinfo = deny_network
        os.environ["EVIDENTIA_NATIVE_CI_INPUTS"] = str(source_dir)
        os.environ["COVERAGE_FILE"] = str(output / ".coverage")
        target = str(checkout / "tests/unit/test_catalogs/test_user_dir.py")
        args = [
            "-q",
            "-x",
            "--tb=short",
            "--assert=plain",
            "-c",
            str(checkout / "pyproject.toml"),
            "--rootdir",
            str(checkout),
            "--cov",
            "--cov-report=",
            "-p",
            "no:cacheprovider",
            "--basetemp",
            str(work / "pytest"),
            "--junitxml",
            str(output / "junit.xml"),
            *[target + "::" + name for name in NATIVE_TESTS],
            str(HERE / "native_storage_witness.py"),
        ]
        report["exit_code"] = int(pytest.main(args, plugins=[Observations()]))
        require(report["exit_code"] == 0, "Native witness failed")
        from xml.etree import ElementTree as ET

        cases = list(ET.fromstring((output / "junit.xml").read_bytes()).iter("testcase"))
        require(len(cases) == report["collected"] and len(cases) >= len(NATIVE_TESTS) + 1, "Incomplete test inventory")
        require(
            not any(c.findall("failure") or c.findall("error") or c.findall("skipped") for c in cases),
            "Test failed or skipped",
        )
        require(all(any(name in c.attrib["name"] for c in cases) for name in NATIVE_TESTS), "Native case absent")
        require(
            any(c.attrib["name"] == "test_full_pinned_bsi_import_repeat_and_cold_registered_read" for c in cases),
            "Full capacity witness absent",
        )
        require(
            budgets and all(budget._deadline == deadline for budget, deadline, _ in budgets),
            "An operation deadline changed",
        )
        report["unchanged_operation_deadlines"] = len(budgets)
        require([binding(p) for p in paths] == before, "Source changed during verification")
        for row in spec["files"]:
            require(
                binding(source_dir / row["name"]) == {"bytes": row["bytes"], "sha256": row["sha256"]}, "Input changed"
            )
        require(report["network_attempts"] == 0, "Unexpected network activity")
        report["status"] = "PASS"
    finally:
        socket.socket.connect = original_connect
        socket.socket.connect_ex = original_connect_ex
        socket.getaddrinfo = original_lookup
        report["operation_deadlines"] = [
            {"test": test, "original": deadline, "final": budget._deadline, "unchanged": budget._deadline == deadline}
            for budget, deadline, test in budgets
        ]
        report["finished"] = datetime.now(UTC).isoformat()
        if report["status"] != "PASS":
            report["status"] = "FAILED_PRESERVED"
        save(output / "receipt.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("fetch", "verify"))
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checkout", type=Path, default=HERE.parents[1])
    args = parser.parse_args()
    spec = load_inputs()
    if args.mode == "fetch":
        record = {"status": "FAILED_PRESERVED", "contract_sha256": INPUT_SHA256}
        try:
            record["files"] = fetch(args.inputs, spec)
            record["status"] = "PASS"
        finally:
            save(args.output, record)
    else:
        verify(args.checkout.resolve(), args.inputs.resolve(), args.output.resolve(), spec)


if __name__ == "__main__":
    main()
