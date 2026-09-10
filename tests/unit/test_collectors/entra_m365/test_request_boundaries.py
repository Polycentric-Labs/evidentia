"""Independent constructor and revalidation checks against the frozen request scope."""

from __future__ import annotations

import itertools

import pytest
from evidentia_collectors.entra_m365._contracts import EntraM365CollectRequest as Request
from pydantic import ValidationError

CAPABILITIES = (
    "conditional-access",
    "authentication-registration",
    "sign-ins",
    "directory-roles",
    "managed-devices",
    "retention-labels",
    "dlp-export",
    "defender-alerts",
    "defender-incidents",
)


@pytest.mark.parametrize("field,low,high", [("lookback_days", 1, 30), ("max_items", 1, 10000), ("max_pages", 1, 100)])
@pytest.mark.parametrize("edge", ["low", "high"])
def test_exact_numeric_boundaries(field, low, high, edge):
    value = low if edge == "low" else high
    result = Request(tenant_label="synthetic", **{field: value})
    assert getattr(result, field) == value
    assert type(getattr(result, field)) is int


@pytest.mark.parametrize("label", ["A", "0", "A" * 64, "A_.-0"])
def test_exact_alias_boundaries(label):
    assert Request(tenant_label=label).tenant_label == label


@pytest.mark.parametrize("field", ["lookback_days", "max_items", "max_pages"])
@pytest.mark.parametrize("value", [None, True, False, 1.0, "1", b"1", [], {}, float("nan"), float("inf")])
def test_strict_numeric_types(field, value):
    with pytest.raises(ValidationError):
        Request(tenant_label="synthetic", **{field: value})


@pytest.mark.parametrize(
    "value",
    [None, True, 1, b"alias", [], {}, "a\x00", "a\r", "a\t", "a\u0085", "a\u2028", "a\u00a0", "\uff21", "a" * 65],
)
def test_alias_is_literal_bounded_ascii(value):
    with pytest.raises(ValidationError):
        Request(tenant_label=value)


def test_every_nonempty_capability_subset_is_canonical_and_detached():
    for count in range(1, len(CAPABILITIES) + 1):
        for subset in itertools.combinations(CAPABILITIES, count):
            supplied = list(reversed(subset))
            result = Request(tenant_label="synthetic", capabilities=supplied)
            assert result.capabilities == list(subset)
            assert result.capabilities is not supplied
            supplied.clear()
            assert result.capabilities == list(subset)


@pytest.mark.parametrize(
    "value",
    [
        [],
        None,
        "sign-ins",
        ("sign-ins",),
        {"sign-ins"},
        [1],
        [b"sign-ins"],
        [None],
        [True],
        ["sign-ins", "sign-ins"],
        ["sign-ins"] * 10,
    ],
)
def test_capability_type_and_cardinality(value):
    with pytest.raises(ValidationError):
        Request(tenant_label="synthetic", capabilities=value)


@pytest.mark.parametrize("width,char", [(1, "x"), (2, "\u00e9"), (3, "\u20ac"), (4, "\U0001f642")])
def test_utf8_limit_for_all_sequence_widths(width, char):
    text = char * (4194304 // width) + "x" * (4194304 % width)
    assert len(text.encode("utf-8")) == 4194304
    result = Request(tenant_label="synthetic", capabilities=["dlp-export"], dlp_content=text)
    assert result.dlp_content == text
    with pytest.raises(ValidationError):
        Request(tenant_label="synthetic", capabilities=["dlp-export"], dlp_content=text + "x")


@pytest.mark.parametrize("position", [0, 4095, 4096, 8191])
@pytest.mark.parametrize("surrogate", ["\ud800", "\udfff"])
def test_invalid_utf8_across_chunk_boundaries(position, surrogate):
    with pytest.raises(ValidationError):
        Request(tenant_label="synthetic", dlp_content="a" * position + surrogate)


INVALID_STATES = [
    ("tenant_label", "bad alias"),
    ("lookback_days", True),
    ("lookback_days", 31),
    ("max_items", "1"),
    ("max_items", 10001),
    ("max_pages", 0),
    ("capabilities", []),
    ("capabilities", ["sign-ins", "sign-ins"]),
    ("capabilities", ["outside-contract"]),
    ("dlp_content", "\ud800"),
    ("dlp_format", "outside-contract"),
    ("dlp_format", "scubagear-provider-v1"),
]


@pytest.mark.parametrize("field,value", INVALID_STATES)
@pytest.mark.parametrize("method", ["assignment", "copy", "construct"])
def test_invalid_instances_are_rejected_at_revalidation(field, value, method):
    if method == "construct":
        unsafe = (
            Request.model_construct(tenant_label="synthetic", **{field: value})
            if field != "tenant_label"
            else Request.model_construct(tenant_label=value)
        )
    else:
        unsafe = Request(tenant_label="synthetic")
        if method == "copy":
            unsafe = unsafe.model_copy(update={field: value})
        else:
            setattr(unsafe, field, value)
    with pytest.raises(ValidationError):
        Request.model_validate(unsafe)


def test_revalidation_detaches_valid_nested_data():
    original = Request(tenant_label="synthetic", capabilities=["sign-ins", "defender-alerts"])
    checked = Request.model_validate(original)
    original.capabilities.append("invalid-after-check")
    assert checked.capabilities == ["sign-ins", "defender-alerts"]
    assert "dlp_format" not in checked.model_fields_set


def test_revalidation_does_not_mutate_invalid_instance():
    original = Request(tenant_label="synthetic", capabilities=["defender-alerts", "sign-ins"])
    original.capabilities.append("invalid-before-check")
    before = original.capabilities.copy()
    with pytest.raises(ValidationError):
        Request.model_validate(original)
    assert original.capabilities == before


@pytest.mark.parametrize("mode", ["copy", "dict"])
def test_untrusted_extra_cannot_survive_revalidation(mode):
    original = Request(tenant_label="synthetic")
    if mode == "copy":
        unsafe = original.model_copy(update={"unknown_option": "synthetic-marker"})
    else:
        original.__dict__["unknown_option"] = "synthetic-marker"
        unsafe = original
    with pytest.raises(ValidationError):
        Request.model_validate(unsafe)


def test_required_field_removed_from_instance_is_rejected():
    original = Request(tenant_label="synthetic")
    del original.tenant_label
    with pytest.raises(ValidationError):
        Request.model_validate(original)


@pytest.mark.parametrize("format_name", ["evidentia-dlp-v1", "scubagear-provider-v1"])
def test_explicit_format_requires_content_after_revalidation(format_name):
    original = Request(tenant_label="synthetic", dlp_content="{}", dlp_format=format_name)
    original.dlp_content = None
    with pytest.raises(ValidationError):
        Request.model_validate(original)


def test_json_revalidation_round_trip_preserves_unset_semantics():
    original = Request(tenant_label="synthetic", capabilities=["sign-ins"])
    checked = Request.model_validate_json(original.model_dump_json(exclude_unset=True))
    assert checked.model_dump() == original.model_dump()
    assert "dlp_format" not in checked.model_fields_set


def test_constructor_does_not_change_caller_mapping():
    original = {"tenant_label": "synthetic", "capabilities": ["defender-alerts", "sign-ins"]}
    Request.model_validate(original)
    assert original == {"tenant_label": "synthetic", "capabilities": ["defender-alerts", "sign-ins"]}


def test_unknown_field_names_are_still_untrusted_error_location_data():
    marker = "SYNTHETIC_UNKNOWN_FIELD_SENTINEL\n"
    with pytest.raises(ValidationError) as captured:
        Request.model_validate({"tenant_label": "synthetic", marker: "discarded"})
    errors = captured.value.errors(include_input=False, include_context=False, include_url=False)
    assert errors[0]["type"] == "extra_forbidden"
    assert errors[0]["loc"] == (marker,)
    assert "input" not in errors[0]
