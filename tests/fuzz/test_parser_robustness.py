"""Hypothesis property tests: parser robustness on arbitrary input.

These are the cross-platform complement to the atheris harnesses in
this directory (``fuzz_*.py``). atheris is Linux/CI-only; these
Hypothesis tests run everywhere under plain ``uv run pytest`` and
encode the SAME invariant each harness enforces:

    A parser fed arbitrary / malformed input must only raise one of its
    *declared* exception types. Any other exception type escaping is a
    robustness bug (the property fails and names the offending type).

Each test mirrors one harness:

  test_parser_robustness        harness file
  ----------------------------  -------------------------------
  catalog import                fuzz_catalog_import.py
  oscal profile                 fuzz_oscal_profile.py
  oscal verify (digests)        fuzz_oscal_verify.py
  ocsf ingest                   fuzz_ocsf_ingest.py
  gap report loader             fuzz_gap_report.py
  tprm questionnaire            fuzz_tprm_questionnaire.py

The strategies bias toward *structurally plausible* documents (JSON
text, dict roots, partial OSCAL / OCSF shapes) so the property exercises
the parse logic rather than just the json.loads reject path — while
still including raw-text and wrong-type inputs.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

# ── Shared strategies ────────────────────────────────────────────────────

# Small JSON-ish values (recursion-bounded to keep examples cheap).
_json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(10**6), max_value=10**6),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    st.text(max_size=40),
)
_json_values = st.recursive(
    _json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.text(max_size=12), children, max_size=5),
    ),
    max_leaves=20,
)
_json_objects = st.dictionaries(st.text(max_size=12), _json_values, max_size=6)

# Raw text: arbitrary unicode plus a slug of structural punctuation so the
# fuzzer regularly produces *almost*-JSON the parsers must reject cleanly.
_raw_text = st.one_of(
    st.text(max_size=200),
    st.text(alphabet='{}[]":,0123456789.eEtruefalsn \t\n-', max_size=200),
)


def _json_text() -> st.SearchStrategy[str]:
    """JSON documents (valid serialization of arbitrary JSON values)."""
    return _json_values.map(lambda v: json.dumps(v))


# ── 1. Catalog import (evidentia_core.catalogs.loader) ───────────────────


def test_catalog_loader_robustness(tmp_path: Path) -> None:
    from evidentia_core.catalogs.loader import (
        _load_catalog_data,
        load_evidentia_catalog,
        load_non_control_catalog,
        load_oscal_catalog,
    )

    declared = (
        ValueError,
        json.JSONDecodeError,
        ValidationError,
        KeyError,
        TypeError,
    )
    # yaml.YAMLError is a declared type too; import lazily for the union.
    import yaml

    declared = (*declared, yaml.YAMLError)

    @given(ext=st.sampled_from((".json", ".yaml", ".yml")), body=st.one_of(_json_text(), _raw_text))
    def _check(ext: str, body: str) -> None:
        path = tmp_path / f"cat{ext}"
        path.write_text(body, encoding="utf-8")
        for fn in (_load_catalog_data, load_oscal_catalog, load_evidentia_catalog, load_non_control_catalog):
            try:
                fn(path)
            except declared:
                pass

    _check()


# ── 2. OSCAL profile (evidentia_core.oscal.profile) ──────────────────────


def test_oscal_profile_robustness(tmp_path: Path) -> None:
    from evidentia_core.oscal.profile import (
        ProfileResolutionError,
        _load_oscal_json,
        resolve_profile,
    )

    declared = (
        ProfileResolutionError,
        json.JSONDecodeError,
        FileNotFoundError,
        ValueError,
        KeyError,
        TypeError,
    )

    @given(body=st.one_of(_json_text(), _raw_text))
    def _check(body: str) -> None:
        path = tmp_path / "profile.json"
        path.write_text(body, encoding="utf-8")
        try:
            _load_oscal_json(path)
        except declared:
            pass
        try:
            resolve_profile(path)
        except declared:
            pass

    _check()


# ── 3. OSCAL verify digests (evidentia_core.oscal.verify) ────────────────


def test_oscal_verify_digests_robustness() -> None:
    # WS-D Q1: the fuzz scaffold surfaced an undeclared AttributeError in
    # verify_digests when back-matter.resources held a non-dict entry or was
    # itself a non-list (CWE-248 uncaught exception / DoS via `oscal verify`
    # on a malformed-but-valid-JSON OSCAL doc). Fixed in
    # evidentia_core/oscal/verify.py (coerce `resources` to a list + skip
    # non-dict entries); this now asserts the parser degrades gracefully.
    from evidentia_core.oscal.verify import verify_digests

    declared = (ValueError, TypeError, KeyError)

    # verify_digests takes an already-parsed dict; feed arbitrary dicts
    # plus partially-shaped OSCAL AR documents.
    _ar_like = st.fixed_dictionaries(
        {
            "assessment-results": st.fixed_dictionaries(
                {
                    "back-matter": st.fixed_dictionaries(
                        {"resources": st.lists(_json_values, max_size=4)}
                    )
                }
            )
        }
    )

    @given(doc=st.one_of(_json_objects, _ar_like))
    def _check(doc: dict) -> None:
        try:
            verify_digests(doc)
        except declared:
            pass

    _check()


# ── 4. OCSF ingest (evidentia_collectors.ocsf.collector) ─────────────────


def test_ocsf_ingest_robustness() -> None:
    pytest.importorskip(
        "py_ocsf_models",
        reason="py-ocsf-models not installed; install the [ocsf] extra",
    )
    from evidentia_collectors.ocsf.collector import (
        OCSFIngestError,
        _convert_ocsf_payload,
    )

    # _convert_ocsf_payload wraps every declared malformed-input case as
    # OCSFIngestError. Bias toward OCSF-shaped objects (class_uid present)
    # so the mapping path is reached, not just the JSON-reject path.
    _ocsf_like = st.fixed_dictionaries(
        {"class_uid": st.sampled_from((2003, 2004, 9999, None))},
    ).flatmap(
        lambda base: _json_objects.map(lambda extra: {**extra, **base})
    )
    bodies = st.one_of(
        _json_text(),
        _ocsf_like.map(lambda d: json.dumps(d)),
        _raw_text,
    )

    @given(raw=bodies)
    def _check(raw: str) -> None:
        try:
            _convert_ocsf_payload(raw, source="hypothesis")
        except OCSFIngestError:
            pass

    _check()


# ── 5. Gap-report loader (evidentia_core.models.gap) ─────────────────────


def test_gap_report_loader_robustness() -> None:
    from evidentia_core.models.gap import GapAnalysisReport

    declared = (ValidationError, ValueError)

    @given(raw=st.one_of(_json_text(), _raw_text))
    def _check(raw: str) -> None:
        try:
            GapAnalysisReport.model_validate_json(raw)
        except declared:
            pass

    _check()


# ── 6. TPRM questionnaire (evidentia_core.tprm.questionnaire) ────────────


def test_tprm_questionnaire_robustness(tmp_path: Path) -> None:
    from evidentia_core.tprm.questionnaire import (
        _parse_completed_csv,
        _parse_completed_json,
        parse_completed_questionnaire,
    )

    declared = (
        ValueError,
        json.JSONDecodeError,
        csv.Error,
        UnicodeDecodeError,
        KeyError,
        TypeError,
        ValidationError,
    )

    @given(
        ext_idx=st.sampled_from((0, 1)),
        body=st.one_of(_json_text(), _raw_text),
    )
    def _check(ext_idx: int, body: str) -> None:
        ext, sub = ((".json", _parse_completed_json), (".csv", _parse_completed_csv))[ext_idx]
        path = tmp_path / f"q{ext}"
        path.write_text(body, encoding="utf-8")
        try:
            parse_completed_questionnaire(path)
        except declared:
            pass
        try:
            sub(path)
        except declared:
            pass

    _check()
