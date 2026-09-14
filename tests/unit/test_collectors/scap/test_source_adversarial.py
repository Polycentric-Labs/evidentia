"""Small source-derived refusals at the complete import boundary."""

from __future__ import annotations

from typing import Any, cast

import pytest
from evidentia_collectors.scap._limits import ScapFailure

from .test_source_conformance import (
    OVAL_PROFILES,
    PROFILES,
    completion_claim,
    import_source,
    source_fixture,
    xccdf_document,
)


@pytest.mark.parametrize("profile", OVAL_PROFILES)
@pytest.mark.parametrize("bad", (b"2000-02-30T00:00:00Z", b"0000-01-01T00:00:00Z", b"2024-01-01T24:01:00Z"))
def test_invalid_unselected_generator_prevents_asserted_selected_success(profile: str, bad: bytes) -> None:
    raw = source_fixture(profile)
    begin, end = raw.index(b"    <system>"), raw.index(b"    </system>") + len(b"    </system>")
    invalid = raw[begin:end]
    time_begin = invalid.index(b"<oval:timestamp>") + len(b"<oval:timestamp>")
    time_end = invalid.index(b"</oval:timestamp>")
    invalid = invalid[:time_begin] + bad + invalid[time_end:]
    raw = raw[:end] + invalid + raw[end:]
    with pytest.raises(ScapFailure) as raised:
        import_source(
            raw, profile, 0, completion_assertion=completion_claim(raw, profile), asserted_by="Synthetic operator"
        )
    assert cast(str, raised.value.code) == "source_contract_invalid"


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("envelope", ("dtd", "entity", "wrong_namespace"))
def test_profile_and_defused_source_boundaries_apply_before_success(profile: str, envelope: str) -> None:
    raw = source_fixture(profile)
    if envelope == "wrong_namespace":
        raw = raw.replace(b"http://checklists.nist.gov/xccdf/1.2", b"urn:synthetic:wrong").replace(
            b"http://oval.mitre.org/XMLSchema/oval-results-5", b"urn:synthetic:wrong"
        )
    else:
        position = raw.index(b"?>") + 2
        declaration = (
            b'<!DOCTYPE synthetic [<!ENTITY local "synthetic">]>' if envelope == "entity" else b"<!DOCTYPE synthetic>"
        )
        raw = raw[:position] + declaration + raw[position:]
    with pytest.raises(ScapFailure) as raised:
        import_source(raw, profile)
    assert cast(str, raised.value.code) == (
        "source_contract_invalid" if envelope == "wrong_namespace" else "unsafe_xml"
    )


@pytest.mark.parametrize("profile", OVAL_PROFILES)
@pytest.mark.parametrize("mutation", ("duplicate", "wrong_instance", "wrong_version", "cross_system"))
def test_oval_full_keys_are_local_canonical_identities(profile: str, mutation: str) -> None:
    raw = source_fixture(profile)
    test_start = raw.index(b"        <test test_id=")
    test_end = raw.index(b"/>", test_start) + 2
    original = raw[test_start:test_end]
    if mutation == "duplicate":
        raw = (
            raw[:test_end] + original.replace(b'version="0"', b'version="+00" variable_instance="01"') + raw[test_end:]
        )
    elif mutation in ("wrong_instance", "wrong_version"):
        replacement = original.replace(
            b'version="0"', b'version="1"' if mutation == "wrong_version" else b'version="0" variable_instance="0"'
        )
        raw = raw[:test_start] + replacement + raw[test_end:]
    else:
        begin, end = raw.index(b"    <system>"), raw.index(b"    </system>") + len(b"    </system>")
        second = raw[begin:end]
        first = raw[begin:end].replace(original, original.replace(b":tst:", b":tst:other"))
        raw = raw[:begin] + first + second + raw[end:]
    with pytest.raises(ScapFailure) as raised:
        import_source(raw, profile)
    assert cast(str, raised.value.code) == "source_contract_invalid"


@pytest.mark.parametrize(
    "replacement",
    (
        b'<check system="urn:synthetic:check"/>',
        b'<override time="2024-03-01T00:00:00Z" authority="Synthetic operator"><old-result>fail</old-result><new-result>error</new-result><remark>source inconsistency</remark></override>',
    ),
)
def test_publisher_result_consistency_and_present_check_semantics(replacement: bytes) -> None:
    raw = xccdf_document().replace(b"</rule-result>", replacement + b"</rule-result>")
    with pytest.raises(ScapFailure) as raised:
        import_source(raw)
    assert cast(str, raised.value.code) == "source_contract_invalid"


@pytest.mark.parametrize("field", ("profile", "index", "raw", "claim", "actor"))
def test_custom_native_types_are_rejected_without_conversion_callbacks(field: str) -> None:
    called: list[str] = []

    class Text(str):
        def __str__(self) -> str:
            called.append("str")
            return super().__str__()

        def __eq__(self, other: object) -> bool:
            called.append("eq")
            return super().__eq__(other)

        __hash__ = str.__hash__

    class Number(int):
        def __int__(self) -> int:
            called.append("int")
            return super().__int__()

    class Raw(bytes):
        def __bytes__(self) -> bytes:
            called.append("bytes")
            return bytes(bytearray(self))

    raw: Any = source_fixture(OVAL_PROFILES[0])
    profile: Any = OVAL_PROFILES[0]
    index: Any = 0
    options: dict[str, Any] = {}
    if field == "profile":
        profile = Text(profile)
    elif field == "index":
        index = Number(0)
    elif field == "raw":
        raw = Raw(raw)
    else:
        claim = completion_claim(raw, profile)
        if field == "claim":
            claim["reference"] = Text("Synthetic reference")
        options = {
            "completion_assertion": claim,
            "asserted_by": Text("Synthetic operator") if field == "actor" else "Synthetic operator",
        }
    with pytest.raises(ScapFailure) as raised:
        import_source(raw, profile, index, **options)
    assert cast(str, raised.value.code) == {
        "profile": "unsupported_profile",
        "claim": "completion_assertion_invalid",
    }.get(field, "invalid_request")
    assert called == []


@pytest.mark.parametrize("bad", (True, -1, 0.0, "0", None))
def test_occurrence_selection_never_coerces_native_input(bad: Any) -> None:
    with pytest.raises(ScapFailure) as raised:
        import_source(source_fixture(PROFILES[0]), index=bad)
    assert cast(str, raised.value.code) == "invalid_request"


@pytest.mark.parametrize("profile", OVAL_PROFILES)
def test_valid_claim_cannot_repair_a_malformed_selected_source(profile: str) -> None:
    raw = source_fixture(profile).replace(b'result="', b'result="not-an-outcome-', 1)
    with pytest.raises(ScapFailure) as raised:
        import_source(
            raw, profile, completion_assertion=completion_claim(raw, profile), asserted_by="Synthetic operator"
        )
    assert cast(str, raised.value.code) == "source_contract_invalid"
