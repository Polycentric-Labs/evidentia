"""Unit tests for ``scripts/demo/gen_cast.py`` (Tier-0 demo cast).

The generator runs the real Meridian-v2 ``evidentia`` sequence and emits an
asciicast v2 file. These tests exercise the pure builders against a *stubbed*
command runner — they never invoke the real CLI (that happens only in the
manual ``gen_cast.py <out>`` gen step). The module is loaded via importlib
because ``scripts/`` is not an importable package.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GEN_PATH = REPO_ROOT / "scripts" / "demo" / "gen_cast.py"


def _load_gen_module() -> Any:
    mod_name = "gen_cast_under_test"
    spec = importlib.util.spec_from_file_location(mod_name, GEN_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gen() -> Any:
    return _load_gen_module()


def _stub_runner(_argv: list[str]) -> bytes:
    # A canned frame with a Rich-ish box char + ANSI to mimic real output.
    return "\x1b[32mOK\x1b[0m ─ captured frame\n".encode()


class TestBuildEvents:
    def test_emits_at_least_one_output_event(self, gen: Any) -> None:
        events = gen.build_events([["doctor"]], _stub_runner)
        o_events = [e for e in events if e[1] == "o"]
        assert len(o_events) >= 1

    def test_event_shape_is_v2_triplet(self, gen: Any) -> None:
        events = gen.build_events([["doctor"]], _stub_runner)
        for ev in events:
            assert isinstance(ev, list) and len(ev) == 3
            assert isinstance(ev[0], (int, float))  # timestamp
            assert ev[1] == "o"  # output stream
            assert isinstance(ev[2], str)  # data

    def test_timestamps_monotonic_nondecreasing(self, gen: Any) -> None:
        events = gen.build_events([["doctor"], ["catalog", "list", "--tier", "A"]], _stub_runner)
        times = [ev[0] for ev in events]
        assert times == sorted(times)
        assert times[0] == 0.0

    def test_deterministic_across_runs(self, gen: Any) -> None:
        a = gen.build_events([["doctor"]], _stub_runner)
        b = gen.build_events([["doctor"]], _stub_runner)
        assert a == b  # no wall-clock — identical inputs -> identical timeline

    def test_typed_prompt_animates_the_command(self, gen: Any) -> None:
        events = gen.build_events([["doctor"]], _stub_runner)
        typed = "".join(ev[2] for ev in events)
        assert "$ evidentia doctor" in typed

    def test_output_targets_are_scrubbed_from_the_prompt(self, gen: Any) -> None:
        # The temp output paths must never leak into the displayed prompt.
        cmd = [
            "gap",
            "analyze",
            "--inventory",
            "x.yaml",
            "--frameworks",
            "nist-800-53-rev5-moderate,soc2-tsc",
            "--output",
            "{report}",
        ]
        events = gen.build_events([cmd], _stub_runner)
        typed = "".join(ev[2] for ev in events)
        assert gen.REPORT_OUT in typed
        assert "{report}" not in typed


class TestRenderCast:
    def test_header_is_valid_v2(self, gen: Any) -> None:
        cast = gen.render_cast(gen.build_events([["doctor"]], _stub_runner))
        first = cast.splitlines()[0]
        header = json.loads(first)
        assert header["version"] == 2
        assert header["width"] == gen.WIDTH
        assert header["height"] == gen.HEIGHT
        assert header["title"]

    def test_every_line_is_valid_json(self, gen: Any) -> None:
        cast = gen.render_cast(gen.build_events([["doctor"]], _stub_runner))
        lines = [ln for ln in cast.splitlines() if ln]
        # Header parses as an object; the rest parse as event arrays.
        assert isinstance(json.loads(lines[0]), dict)
        for ln in lines[1:]:
            ev = json.loads(ln)
            assert isinstance(ev, list) and len(ev) == 3

    def test_roundtrips_a_unicode_frame(self, gen: Any) -> None:
        cast = gen.render_cast(gen.build_events([["doctor"]], _stub_runner))
        # The box char from the stub survives serialization.
        assert "─" in cast


class TestRedactOutput:
    def test_scratch_paths_collapse_to_filenames(self, gen: Any) -> None:
        tmp = Path("/scratch/evidentia-democast")
        raw = f"Report exported: {tmp / gen.REPORT_OUT} (json)\n{tmp / gen.OSCAL_OUT} — PASS\n"
        out = gen.redact_output(raw, tmp)
        assert str(tmp) not in out
        assert f"Report exported: {gen.REPORT_OUT} (json)" in out
        assert f"{gen.OSCAL_OUT} — PASS" in out

    def test_gap_store_path_collapses_to_placeholder(self, gen: Any) -> None:
        raw = "Gap store snapshot: /home/u/.local/Evidentia/gap_store/ab12cd34.json (used)\n"
        out = gen.redact_output(raw, Path("/scratch"))
        assert "gap_store" not in out
        assert "<gap-store>/<snapshot>.json" in out

    def test_log_timestamp_prefix_is_normalized(self, gen: Any) -> None:
        raw = "2026-06-15 18:33:34,396 [INFO] evidentia_core: loaded\n"
        out = gen.redact_output(raw, Path("/scratch"))
        assert "2026-06-15 18:33:34,396" not in out
        assert out.startswith("[demo] [INFO]")

    def test_repo_root_prefix_is_stripped_native_form(self, gen: Any) -> None:
        import os

        # The Rich/UserWarning echo prints the repo root in native (os.sep)
        # form — strip it so no absolute home path reaches the cast.
        raw = f"{gen.REPO_ROOT}{os.sep}packages{os.sep}x.py:208: UserWarning\n"
        out = gen.redact_output(raw, Path("/scratch"))
        assert str(gen.REPO_ROOT) not in out
        assert out.startswith(f"packages{os.sep}x.py:208")

    def test_repo_root_prefix_is_stripped_posix_form(self, gen: Any) -> None:
        raw = f"see {gen.REPO_ROOT.as_posix()}/examples/x.yaml\n"
        out = gen.redact_output(raw, Path("/scratch"))
        assert gen.REPO_ROOT.as_posix() not in out
        assert "see examples/x.yaml" in out


class TestMainArgs:
    def test_missing_arg_returns_usage_code(self, gen: Any) -> None:
        assert gen.main([]) == 2
