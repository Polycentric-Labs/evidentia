"""Request validation and revalidation for Entra and Microsoft 365."""

import pytest
from evidentia_collectors.entra_m365._contracts import EntraM365CollectRequest as Request


def test_accepts_literal_operator_alias():
    request = Request(tenant_label="Synthetic_Tenant-1")
    assert request.tenant_label == "Synthetic_Tenant-1"


CAPABILITIES = [
    "conditional-access",
    "authentication-registration",
    "sign-ins",
    "directory-roles",
    "managed-devices",
    "retention-labels",
    "dlp-export",
    "defender-alerts",
    "defender-incidents",
]


def test_defaults_are_explicit_and_detached():
    first = Request(tenant_label="one")
    second = Request(tenant_label="two")
    assert getattr(first, "capabilities", None) == CAPABILITIES
    assert first.capabilities is not second.capabilities
    assert first.lookback_days == 30 and first.max_items == 10000 and first.max_pages == 100
    assert first.dlp_content is None and first.dlp_format == "evidentia-dlp-v1"


@pytest.mark.parametrize(
    "fields",
    [
        {"tenant_label": ""},
        {"tenant_label": " invalid"},
        {"tenant_label": "invalid "},
        {"tenant_label": "invalid alias"},
        {"tenant_label": "-first"},
        {"tenant_label": "a" * 65},
        {"tenant_label": "tenant\u00e9"},
        {"tenant_label": "alias\n"},
        {"lookback_days": True},
        {"lookback_days": 1.0},
        {"lookback_days": "1"},
        {"lookback_days": 0},
        {"lookback_days": 31},
        {"max_items": False},
        {"max_items": 1.0},
        {"max_items": "1"},
        {"max_items": 0},
        {"max_items": 10001},
        {"max_pages": True},
        {"max_pages": 1.0},
        {"max_pages": "1"},
        {"max_pages": 0},
        {"max_pages": 101},
        {"capabilities": []},
        {"capabilities": None},
        {"capabilities": "sign-ins"},
        {"capabilities": ("sign-ins",)},
        {"capabilities": ["sign-ins", "sign-ins"]},
        {"capabilities": [None]},
        {"capabilities": [False]},
        {"capabilities": ["not-a-capability"]},
        {"dlp_format": "evidentia-dlp-v1"},
        {"dlp_format": "scubagear-provider-v1"},
        {"dlp_format": None},
        {"dlp_content": 1},
        {"capabilities": ["sign-ins"], "dlp_content": "{}"},
        {"token": "synthetic-unaccepted-input"},
        {"base_url": "https://graph.microsoft.com"},
        {"auth_mode": "delegated"},
        {"token_env": "SYNTHETIC_ENV_REFERENCE"},
    ],
)
def test_rejects_invalid_requests(fields):
    with pytest.raises(ValueError):
        Request(**{"tenant_label": "synthetic", **fields})


def test_capabilities_normalize_to_the_frozen_execution_order():
    request = Request(tenant_label="synthetic", capabilities=["defender-incidents", "sign-ins"])
    assert getattr(request, "capabilities", None) == ["sign-ins", "defender-incidents"]


def test_utf8_limit_uses_encoded_bytes():
    exact = "\u00e9" * 2097152
    request = Request(tenant_label="synthetic", capabilities=["dlp-export"], dlp_content=exact)
    assert getattr(request, "dlp_content", None) == exact
    with pytest.raises(ValueError):
        Request(tenant_label="synthetic", capabilities=["dlp-export"], dlp_content=exact + "a")


def test_surrogate_input_is_not_valid_utf8():
    with pytest.raises(ValueError):
        Request(tenant_label="synthetic", capabilities=["dlp-export"], dlp_content="\ud800")


def test_a_supplied_format_with_content_is_valid():
    request = Request(
        tenant_label="synthetic", capabilities=["dlp-export"], dlp_content="{}", dlp_format="scubagear-provider-v1"
    )
    assert getattr(request, "dlp_format", None) == "scubagear-provider-v1"


def test_constructed_invalid_values_are_revalidated():
    contract = Request
    unsafe = contract.model_construct(tenant_label="synthetic", max_items=True)
    with pytest.raises(ValueError):
        contract.model_validate(unsafe)


def test_model_copy_does_not_bypass_revalidation():
    contract = Request
    original = contract(tenant_label="synthetic")
    unsafe = original.model_copy(update={"lookback_days": "2"})
    with pytest.raises(ValueError):
        contract.model_validate(unsafe)


def test_nested_mutation_is_revalidated():
    contract = Request
    original = contract(tenant_label="synthetic")
    original.capabilities.append("unreviewed-capability")
    with pytest.raises(ValueError):
        contract.model_validate(original)


def test_revalidation_preserves_absence_and_detaches_values():
    contract = Request
    original = contract(tenant_label="synthetic", capabilities=["sign-ins"])
    checked = contract.model_validate(original)
    assert checked is not original
    assert checked.capabilities == ["sign-ins"]
    assert checked.capabilities is not original.capabilities
    assert "dlp_format" not in checked.model_fields_set
