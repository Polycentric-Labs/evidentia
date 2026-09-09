"""Tests for ``scripts/catalogs/gen_crosswalks.py``.

The script used to write its six bundled crosswalk JSONs as import-time side
effects, with no way to verify the committed files still matched the data
that produced them. It is now pure data (:data:`CROSSWALKS`, one
``CrosswalkSpec`` per output file) plus ``build_all`` / ``serialize`` and a
small CLI. These tests pin:

1. ``build_all`` emits all six filenames, including the four whose framework
   id the v0.13 catalog-truth work re-keyed from ``nist-800-53-mod`` to
   ``nist-800-53-rev5``.
2. ``serialize`` honors the per-file trailing-newline flag (five of the six
   committed files have none; ``nist-800-53-rev5_to_soc2-tsc.json`` does).
3. The payload field order the committed files were written with.
4. ``--check`` passes against the real committed tree.
5. ``--check`` against a directory holding a one-byte-mutated copy fails and
   names the mutated file, without flagging the untouched ones.
6. ``--output-dir`` writes all six files with the same bytes ``build_all``
   returns.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
GEN_PATH = REPO_ROOT / "scripts" / "catalogs" / "gen_crosswalks.py"


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register before exec: the module uses `@dataclass` under `from
    # __future__ import annotations`, and dataclasses resolves its
    # (stringified) field annotations by looking the module up in
    # sys.modules by name. Skipping this line makes that lookup return
    # None and crash inside dataclasses.py.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gen() -> Any:
    """Import scripts/catalogs/gen_crosswalks.py (no __init__.py).

    The module computes its own ``MAPPINGS_DIR`` from ``__file__`` and does
    not import the sibling ``_generators`` helper, so it loads cleanly via
    importlib without putting ``scripts/catalogs/`` on ``sys.path``.
    """
    return _load_module("gen_crosswalks_under_test", GEN_PATH)


# The four files the v0.13 catalog-truth work re-keyed to the full
# nist-800-53-rev5 catalog (previously keyed on the retired 16-control
# nist-800-53-mod sample).
RE_KEYED_FILENAMES = {
    "nist-csf-2.0_to_nist-800-53-rev5.json",
    "nist-800-53-rev5_to_hipaa-security.json",
    "iso-27001-2022_to_nist-800-53-rev5.json",
    "nist-800-53-rev5_to_soc2-tsc.json",
}

# The other two shipped crosswalks are untouched by the re-key.
UNCHANGED_FILENAMES = {
    "fedramp-rev5-moderate_to_cmmc-2-l2.json",
    "us-va-vcdpa_to_us-ca-ccpa-cpra.json",
}

ALL_SIX_FILENAMES = RE_KEYED_FILENAMES | UNCHANGED_FILENAMES


def test_build_all_emits_six_filenames_with_the_rekeyed_ids(gen: Any) -> None:
    generated = gen.build_all()
    assert set(generated) == ALL_SIX_FILENAMES
    for name in RE_KEYED_FILENAMES:
        payload = json.loads(generated[name])
        ids = (payload["source_framework"], payload["target_framework"])
        assert "nist-800-53-rev5" in ids
        assert "nist-800-53-mod" not in ids


def test_unchanged_crosswalks_keep_their_original_framework_ids(gen: Any) -> None:
    generated = gen.build_all()
    fedramp = json.loads(generated["fedramp-rev5-moderate_to_cmmc-2-l2.json"])
    assert fedramp["source_framework"] == "fedramp-rev5-moderate"
    assert fedramp["target_framework"] == "cmmc-2-l2"
    vcdpa = json.loads(generated["us-va-vcdpa_to_us-ca-ccpa-cpra.json"])
    assert vcdpa["source_framework"] == "us-va-vcdpa"
    assert vcdpa["target_framework"] == "us-ca-ccpa-cpra"


def test_serialize_honors_trailing_newline_flag(gen: Any) -> None:
    payload = {"a": 1, "b": [2, 3]}
    with_newline = gen.serialize(payload, trailing_newline=True)
    without_newline = gen.serialize(payload, trailing_newline=False)
    assert with_newline.endswith("\n")
    assert not without_newline.endswith("\n")
    assert with_newline == without_newline + "\n"
    assert json.loads(with_newline) == json.loads(without_newline) == payload


def test_build_payload_field_order_matches_shipped_files(gen: Any) -> None:
    spec = gen.CROSSWALKS[0]
    payload = gen.build_payload(spec)
    assert list(payload.keys()) == [
        "source_framework",
        "target_framework",
        "version",
        "generated_at",
        "source",
        "mappings",
    ]


def test_soc2_spec_carries_explicit_control_titles(gen: Any) -> None:
    # The SOC2 table was never produced by this script before v0.13 (the
    # committed file was hand-authored JSON); unlike the other five tables,
    # its rows carry real titles rather than empty-string placeholders.
    soc2_spec = next(s for s in gen.CROSSWALKS if s.target_framework == "soc2-tsc")
    assert soc2_spec.trailing_newline is True
    assert len(soc2_spec.mappings) == 17
    for row in soc2_spec.mappings:
        assert row["source_control_title"] != ""
        assert row["target_control_title"] != ""


def test_check_against_the_real_tree_exits_0(gen: Any) -> None:
    assert gen.main(["--check"]) == 0


def test_check_against_a_mutated_copy_exits_1_and_names_only_that_file(
    gen: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    generated = gen.build_all()
    for name, content in generated.items():
        (tmp_path / name).write_text(content, encoding="utf-8", newline="\n")
    drifted_name = "nist-800-53-rev5_to_soc2-tsc.json"
    mutated = json.loads((tmp_path / drifted_name).read_text(encoding="utf-8"))
    mutated["mappings"][0]["target_control_id"] = "MUTATED.0.0"
    (tmp_path / drifted_name).write_text(gen.serialize(mutated, trailing_newline=True), encoding="utf-8", newline="\n")

    exit_code = gen.main(["--check", "--output-dir", str(tmp_path)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert drifted_name in captured.err
    # None of the five untouched files are reported as drifted.
    for other in ALL_SIX_FILENAMES - {drifted_name}:
        assert other not in captured.err


@pytest.mark.parametrize(("replacement", "expected_exit"), [(b"\r\n", 0), (b"\r", 1)])
def test_check_distinguishes_checkout_crlf_from_lone_cr(
    gen: Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    replacement: bytes,
    expected_exit: int,
) -> None:
    generated = gen.build_all()
    for name, content in generated.items():
        (tmp_path / name).write_bytes(content.encode("utf-8"))
    changed_name = "nist-800-53-rev5_to_soc2-tsc.json"
    original = generated[changed_name].encode("utf-8")
    (tmp_path / changed_name).write_bytes(original.replace(b"\n", replacement, 1))

    assert gen.main(["--check", "--output-dir", str(tmp_path)]) == expected_exit
    captured = capsys.readouterr()
    if expected_exit:
        assert changed_name in captured.err
    else:
        assert captured.err == ""


def test_check_reports_a_missing_committed_file(gen: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    generated = gen.build_all()
    # Write only one of the six files; the rest are "missing" from tmp_path.
    only = "us-va-vcdpa_to_us-ca-ccpa-cpra.json"
    (tmp_path / only).write_text(generated[only], encoding="utf-8", newline="\n")

    exit_code = gen.main(["--check", "--output-dir", str(tmp_path)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "missing" in captured.err


def test_output_dir_writes_six_files(gen: Any, tmp_path: Path) -> None:
    exit_code = gen.main(["--output-dir", str(tmp_path)])
    assert exit_code == 0
    written = {p.name for p in tmp_path.iterdir()}
    assert written == ALL_SIX_FILENAMES
    generated = gen.build_all()
    for name in written:
        assert (tmp_path / name).read_bytes() == generated[name].encode("utf-8")


def test_gate_passes_on_the_real_repo_via_subprocess() -> None:
    """The same invocation the pre-push/consistency gate runs."""
    import subprocess

    proc = subprocess.run(
        [sys.executable, str(GEN_PATH), "--check"],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
