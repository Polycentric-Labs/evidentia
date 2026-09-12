"""Selected registry requests reject ambiguity before any provider work."""

from __future__ import annotations

import json

import pytest
from evidentia_collectors.registries._contracts import (
    CertificateTarget,
    RegistryContext,
    RegistryInputError,
    RegistryLookupRequest,
    normalized_organization_name,
    parse_request,
    request_identity,
    validated_request,
)
from jsonschema import Draft202012Validator
from pydantic import BaseModel
from pydantic.json_schema import JsonSchemaMode


def request(registry: str, target: dict[str, object]) -> dict[str, object]:
    return {"registry": registry, "target": target}


@pytest.mark.parametrize(
    ("registry", "target", "identity"),
    [
        ("tls", {"hostname": "EXAMPLE.COM."}, "example.com"),
        ("rdap", {"domain": "example.com"}, "example.com"),
        ("sam-entity", {"uei": "ABCDEFGHIJK1"}, "ABCDEFGHIJK1"),
        ("sam-exclusions", {"uei": "ABCDEFGHIJK1"}, "ABCDEFGHIJK1"),
        ("sam-exclusions", {"organization_name": "  Example,  Inc. "}, "example, inc."),
        ("gleif", {"lei": "1234567890ABCDEFGHIJ"}, "1234567890ABCDEFGHIJ"),
        ("fedramp", {"product_id": "FR1234567890"}, "FR1234567890"),
        ("cmvp", {"certificate_number": "00123"}, "00123"),
        (
            "fcc-covered-list",
            {"organization_name": "Example", "query_scope": "named_organization_entries"},
            "example",
        ),
        ("incommon", {"entity_id": "urn:example:opaque?id=1"}, "urn:example:opaque?id=1"),
        ("ssl-labs", {"hostname": "example.com", "endpoint_ip": "8.8.8.8"}, "example.com|8.8.8.8"),
        ("security-txt", {"hostname": "example.com"}, "example.com"),
    ],
)
def test_selected_request_round_trip(registry: str, target: dict[str, object], identity: str) -> None:
    raw = request(registry, target)
    native = validated_request(raw)
    assert request_identity(native) == identity
    encoded = native.model_dump_json()
    reparsed = parse_request(encoded.encode("utf-8"))
    assert reparsed.model_dump() == native.model_dump()
    assert json.loads(encoded)["target"] == target
    assert native.root.registry == registry


@pytest.mark.parametrize(
    "hostname",
    [
        "",
        "example.com/path",
        "user@example.com",
        "example.com:443",
        "127.0.0.1",
        "127.1",
        "2130706433",
        "0x7f000001",
        "example..com",
        "example.com..",
        "-example.com",
        "example-.com",
        "ex ample.com",
        "example.com\n",
        "\N{LATIN SMALL LETTER E WITH ACUTE}xample.com",
        "a" * 64 + ".com",
        "a." * 127 + "com",
    ],
)
def test_hostname_is_a_dns_identity_not_a_fetch_instruction(hostname: str) -> None:
    with pytest.raises(RegistryInputError):
        validated_request(request("tls", {"hostname": hostname}))


@pytest.mark.parametrize(
    "target",
    [
        {"uei": "ABCDEFGHIJK1", "organization_name": "Example"},
        {"organization_name": ""},
        {"organization_name": "   "},
        {"organization_name": "\t"},
        {"organization_name": "Example\nInc"},
        {"organization_name": "Example AND (other)"},
        {"organization_name": "Example*"},
        {"organization_name": "... ---"},
        {"organization_name": "a" * 513},
        {"organization_name": False},
        {"uei": 123456789012},
    ],
)
def test_sam_name_and_identity_ambiguity_refused(target: dict[str, object]) -> None:
    with pytest.raises(RegistryInputError):
        validated_request(request("sam-exclusions", target))


def test_organization_normalization_preserves_punctuation_and_diacritics() -> None:
    assert (
        normalized_organization_name("  Caf\N{LATIN SMALL LETTER E WITH ACUTE},  Inc. ")
        == "caf\N{LATIN SMALL LETTER E WITH ACUTE}, inc."
    )
    assert normalized_organization_name("Cafe\N{COMBINING ACUTE ACCENT}") == "caf\N{LATIN SMALL LETTER E WITH ACUTE}"
    with pytest.raises(RegistryInputError):
        normalized_organization_name("\N{LATIN CAPITAL LETTER I WITH DOT ABOVE}" * 171)


@pytest.mark.parametrize("scope", [None, "", "all", 1, False])
def test_fcc_named_scope_is_mandatory_and_literal(scope: object) -> None:
    target: dict[str, object] = {"organization_name": "Example"}
    if scope is not None:
        target["query_scope"] = scope
    with pytest.raises(RegistryInputError):
        validated_request(request("fcc-covered-list", target))


@pytest.mark.parametrize("raw", [None, [], True, 1, "{}", {"registry": "tls"}])
def test_non_request_native_shapes_refused(raw: object) -> None:
    with pytest.raises(RegistryInputError):
        validated_request(raw)


@pytest.mark.parametrize("extra", ["base_url", "credential", "proxy", "timeout", "live_access"])
def test_request_cannot_override_runtime_policy(extra: str) -> None:
    raw = request("tls", {"hostname": "example.com"})
    raw[extra] = "unexpected"
    with pytest.raises(RegistryInputError):
        validated_request(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"registry":"tls","registry":"rdap","target":{"domain":"example.com"}}',
        b'{"registry":"tls","target":{"hostname":"example.com","hostna\\u006de":"other.com"}}',
        b'{"registry":"tls","target":{"hostname":"\\ud800"}}',
        b'{"registry":"tls","target":{"hostname":NaN}}',
        b" " * 65537,
    ],
    ids=["duplicate-registry", "decoded-key-collision", "surrogate", "nonfinite", "byte-limit"],
)
def test_json_preflight_precedes_discriminator_validation(raw: bytes) -> None:
    with pytest.raises(RegistryInputError):
        parse_request(raw)


def test_constructed_copied_and_mutated_objects_are_not_authoritative() -> None:
    original = validated_request(request("tls", {"hostname": "example.com"}))
    forged = RegistryLookupRequest.model_construct(root=original.root)
    forged.__dict__["extra"] = "unreviewed"
    with pytest.raises(RegistryInputError):
        validated_request(forged)
    with pytest.raises(RegistryInputError):
        original.model_copy(update={"root": request("tls", {"hostname": "127.0.0.1"})})
    original.root.target.__dict__["hostname"] = "127.0.0.1"
    with pytest.raises((RegistryInputError, ValueError)):
        original.model_dump_json()


def test_caller_cannot_relax_native_validation() -> None:
    raw = request("tls", {"hostname": "example.com"})
    with pytest.raises(RegistryInputError):
        RegistryLookupRequest.model_validate(raw, strict=False)
    with pytest.raises(RegistryInputError):
        RegistryLookupRequest.model_validate(raw, extra="ignore")


def test_input_detached_and_schema_has_all_selectors() -> None:
    target: dict[str, object] = {"hostname": "example.com"}
    checked = validated_request(request("tls", target))
    target["hostname"] = "changed.example"
    assert request_identity(checked) == "example.com"
    schema = RegistryLookupRequest.model_json_schema()
    assert set(schema["discriminator"]["mapping"]) == {
        "tls",
        "rdap",
        "sam-entity",
        "sam-exclusions",
        "gleif",
        "fedramp",
        "cmvp",
        "fcc-covered-list",
        "incommon",
        "ssl-labs",
        "security-txt",
    }


def test_native_key_subclasses_are_refused_before_hash_callbacks() -> None:
    calls: list[str] = []

    class Key(str):
        def __hash__(self) -> int:
            calls.append("hash")
            return super().__hash__()

    raw: dict[str, object] = {Key("registry"): "tls", "target": {"hostname": "example.com"}}
    calls.clear()
    with pytest.raises(RegistryInputError):
        validated_request(raw)
    assert calls == []


def test_constructed_extras_are_refused_before_truth_callbacks() -> None:
    calls: list[str] = []

    class Extra:
        def __bool__(self) -> bool:
            calls.append("truth")
            return False

    checked = validated_request(request("tls", {"hostname": "example.com"}))
    object.__setattr__(checked, "__pydantic_extra__", Extra())
    with pytest.raises(RegistryInputError):
        validated_request(checked)
    assert calls == []


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize(
    ("model", "field", "accepted", "rejected"),
    [
        (CertificateTarget, "certificate_number", ["00123", "0"], ["", " ", "\u00a0", "123.0", "-1", "ABC"]),
        (RegistryContext, "collector_version", ["0.12.1", "1.0+local"], ["", " ", "\u0085", "a/b", "1" * 33]),
    ],
)
def test_non_blank_schema_preserves_narrower_identity_and_version_patterns(
    mode: JsonSchemaMode,
    model: type[BaseModel],
    field: str,
    accepted: list[str],
    rejected: list[str],
) -> None:
    schema = model.model_json_schema(mode=mode)["properties"][field]
    validator = Draft202012Validator(schema)
    assert all(validator.is_valid(value) for value in accepted)
    assert all(not validator.is_valid(value) for value in rejected)
