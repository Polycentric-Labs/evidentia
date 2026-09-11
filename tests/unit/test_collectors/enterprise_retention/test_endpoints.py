"""Synthetic fixed-template checks with no provider or network access."""

from __future__ import annotations

import copy
import socket
from collections.abc import Iterator
from typing import Literal, Never, cast
from urllib.parse import parse_qsl, quote, urlsplit

import httpx
import pytest
from evidentia_collectors.enterprise_retention._client import EndpointError, build_read_url
from evidentia_collectors.enterprise_retention._contracts import ProviderName, ReadKey, ReadKind
from evidentia_collectors.enterprise_retention._credentials import EnvironmentCredentialResolver
from evidentia_collectors.enterprise_retention._profiles import AddressPolicy, FrozenProfile

CASES: tuple[tuple[ReadKind, ProviderName, str, str], ...] = (
    ("vault-matter", "google-vault", "matter_1-2", "/v1/matters/matter_1-2?view=BASIC"),
    ("vault-holds", "google-vault", "matter_1-2", "/v1/matters/matter_1-2/holds?view=FULL_HOLD&pageSize=100"),
    (
        "splunk-index",
        "splunk-enterprise",
        "_internal",
        "/services/data/indexes/_internal?output_mode=json&summarize=false",
    ),
    (
        "elastic-explain",
        "elastic-ilm",
        ".hidden-index",
        "/.hidden-index/_ilm/explain?only_managed=false&only_errors=false",
    ),
    ("elastic-policy", "elastic-ilm", ".Policy_1-2", "/_ilm/policy/.Policy_1-2"),
    ("elastic-status", "elastic-ilm", "service", "/_ilm/status"),
)
PROVIDERS: tuple[ProviderName, ...] = ("google-vault", "splunk-enterprise", "elastic-ilm")


def profile(provider: ProviderName) -> FrozenProfile:
    origin = {
        "google-vault": "https://vault.googleapis.com:443",
        "splunk-enterprise": "https://splunk.example.invalid:8089",
        "elastic-ilm": "https://elastic.example.invalid:9200",
    }[provider]
    return FrozenProfile(
        alias="selected",
        provider=provider,
        origin=origin,
        credential_ref="ENTERPRISE_RETENTION_SYNTHETIC_TOKEN",
        address_policy=AddressPolicy("public"),
    )


@pytest.fixture(autouse=True)
def no_external_operations(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def forbidden(*args: object, **kwargs: object) -> Never:
        raise AssertionError("unexpected_external_operation")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(httpx.Client, "send", forbidden)
    monkeypatch.setattr(httpx.AsyncClient, "send", forbidden)
    monkeypatch.setattr(EnvironmentCredentialResolver, "resolve", forbidden)
    yield


def refusal(selected: object, key: object, continuation: object = None, *, code: str = "destination_refused") -> None:
    with pytest.raises(EndpointError) as raised:
        build_read_url(cast(FrozenProfile, selected), cast(ReadKey, key), continuation=cast(str | None, continuation))
    assert raised.value.code == code
    assert str(raised.value) == code
    assert raised.value.args == (code,)
    assert raised.value.__suppress_context__


@pytest.mark.parametrize(("kind", "provider", "identity", "suffix"), CASES)
def test_all_six_templates(kind: ReadKind, provider: ProviderName, identity: str, suffix: str) -> None:
    selected = profile(provider)
    key = ReadKey(kind=kind, source_id=identity)
    result = build_read_url(selected, key)
    assert type(result) is str
    assert result == selected.origin + suffix
    request = httpx.Request("GET", result)
    assert request.method == "GET"
    assert request.url.scheme == "https"
    assert request.url.host == selected.host
    assert (request.url.port or 443) == selected.port
    assert request.url.raw_path == suffix.encode("ascii")
    assert request.url.query == suffix.partition("?")[2].encode("ascii")
    assert request.url.userinfo == b""
    assert request.url.fragment == ""
    assert urlsplit(result).netloc == urlsplit(selected.origin).netloc


@pytest.mark.parametrize(("kind", "expected", "identity", "suffix"), CASES)
@pytest.mark.parametrize("supplied", PROVIDERS)
def test_provider_correspondence(
    kind: ReadKind, expected: ProviderName, identity: str, suffix: str, supplied: ProviderName
) -> None:
    selected = profile(supplied)
    key = ReadKey(kind=kind, source_id=identity)
    if supplied == expected:
        assert build_read_url(selected, key) == selected.origin + suffix
    else:
        refusal(selected, key)


@pytest.mark.parametrize(
    ("kind", "provider", "identity"),
    [
        ("vault-matter", "google-vault", "a"),
        ("vault-matter", "google-vault", "A" * 128),
        ("vault-holds", "google-vault", "_" * 128),
        ("splunk-index", "splunk-enterprise", "a"),
        ("splunk-index", "splunk-enterprise", "a" * 80),
        ("elastic-explain", "elastic-ilm", "a" * 255),
        ("elastic-explain", "elastic-ilm", ".hidden"),
        ("elastic-explain", "elastic-ilm", "..."),
        ("elastic-explain", "elastic-ilm", "a..b"),
        ("elastic-policy", "elastic-ilm", "Z" * 255),
        ("elastic-policy", "elastic-ilm", "..."),
        ("elastic-policy", "elastic-ilm", ".hidden"),
        ("elastic-policy", "elastic-ilm", "_allx"),
    ],
)
def test_identity_boundaries(kind: ReadKind, provider: ProviderName, identity: str) -> None:
    selected = profile(provider)
    result = build_read_url(selected, ReadKey(kind=kind, source_id=identity))
    request = httpx.Request("GET", result)
    assert identity in request.url.path.split("/")
    assert request.url.raw_path == result.removeprefix(selected.origin).encode("ascii")


INJECTIONS = (
    "",
    ".",
    "..",
    "a/b",
    "a\\b",
    "a%2fb",
    "%2e%2e",
    "a?x=y",
    "a#fragment",
    "a,b",
    "*",
    "a*",
    "a b",
    "a\n",
    "a\x00",
    "a\u00e9",
    "https://other.example.invalid",
    "a/../b",
)


@pytest.mark.parametrize("kind,provider,identity,suffix", CASES[:5])
@pytest.mark.parametrize("bad", INJECTIONS)
def test_constructed_keys_cannot_inject_paths(
    kind: ReadKind, provider: ProviderName, identity: str, suffix: str, bad: str
) -> None:
    key = ReadKey.model_construct(kind=kind, source_id=bad)
    refusal(profile(provider), key)


@pytest.mark.parametrize(
    ("kind", "provider", "bad"),
    [
        ("vault-matter", "google-vault", "a" * 129),
        ("vault-holds", "google-vault", "a" * 129),
        ("splunk-index", "splunk-enterprise", "a" * 81),
        ("splunk-index", "splunk-enterprise", "_new"),
        ("splunk-index", "splunk-enterprise", "_ReLoAd"),
        ("splunk-index", "splunk-enterprise", "_ALL"),
        ("elastic-explain", "elastic-ilm", "a" * 256),
        ("elastic-explain", "elastic-ilm", "UPPER"),
        ("elastic-explain", "elastic-ilm", "_all"),
        ("elastic-explain", "elastic-ilm", "-bad"),
        ("elastic-policy", "elastic-ilm", "a" * 256),
        ("elastic-policy", "elastic-ilm", "_ALL"),
        ("elastic-status", "elastic-ilm", "other"),
    ],
)
def test_ineligible_names(kind: ReadKind, provider: ProviderName, bad: str) -> None:
    refusal(profile(provider), ReadKey.model_construct(kind=kind, source_id=bad))


class StringSubclass(str):
    pass


@pytest.mark.parametrize("bad", [None, False, 0, 1.0, b"a", [], {}, StringSubclass("a")])
def test_exact_native_key_fields(bad: object) -> None:
    key = ReadKey(kind="vault-matter", source_id="matter")
    object.__setattr__(key, "source_id", bad)
    refusal(profile("google-vault"), key)


@pytest.mark.parametrize("bad", [None, False, 0, "other", StringSubclass("vault-matter")])
def test_invalid_kinds(bad: object) -> None:
    key = ReadKey(kind="vault-matter", source_id="matter")
    object.__setattr__(key, "kind", bad)
    refusal(profile("google-vault"), key)


@pytest.mark.parametrize("case", ["missing", "extra", "pydantic-extra", "hostile-key"])
def test_constructed_key_storage(case: str) -> None:
    key = ReadKey(kind="vault-matter", source_id="matter")
    if case == "missing":
        del key.__dict__["source_id"]
    elif case == "extra":
        key.__dict__["unknown"] = "MARKER"
    elif case == "pydantic-extra":
        object.__setattr__(key, "__pydantic_extra__", {"unknown": "MARKER"})
    else:
        object.__setattr__(key, "__dict__", {StringSubclass("kind"): "vault-matter", "source_id": "matter"})
    refusal(profile("google-vault"), key)


@pytest.mark.parametrize("copier", [copy.copy, copy.deepcopy])
def test_valid_copied_and_constructed_inputs(copier: object) -> None:
    selected = profile("google-vault")
    key = ReadKey.model_construct(kind="vault-holds", source_id="matter")
    if copier is copy.copy:
        selected, key = copy.copy(selected), copy.copy(key)
    else:
        selected, key = copy.deepcopy(selected), copy.deepcopy(key)
    assert build_read_url(selected, key).endswith("/v1/matters/matter/holds?view=FULL_HOLD&pageSize=100")


@pytest.mark.parametrize("bad", [None, False, {}, "profile", object()])
def test_wrong_profile_objects(bad: object) -> None:
    refusal(bad, ReadKey(kind="vault-matter", source_id="matter"))


@pytest.mark.parametrize("bad", [None, False, {}, "key", object()])
def test_wrong_key_objects(bad: object) -> None:
    refusal(profile("google-vault"), bad)


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("alias", " bad"),
        ("alias", StringSubclass("selected")),
        ("provider", "other"),
        ("provider", StringSubclass("google-vault")),
        ("credential_ref", "UNAPPROVED_REFERENCE"),
        ("address_policy", {}),
        ("api_principals", {"actor"}),
        ("allow_local_cli", 1),
        ("ca_bytes", "not-bytes"),
    ],
)
def test_corrupted_profile_fields(field: str, bad: object) -> None:
    selected = profile("google-vault")
    object.__setattr__(selected, field, bad)
    refusal(selected, ReadKey(kind="vault-matter", source_id="matter"))


@pytest.mark.parametrize(
    "origin",
    [
        "https://other.example.invalid:443",
        "http://vault.googleapis.com:443",
        "https://vault.googleapis.com",
        "https://vault.googleapis.com:443/",
        "https://vault.googleapis.com:443/path",
        "https://vault.googleapis.com:443?x=y",
        "https://vault.googleapis.com:443#fragment",
        "https://user@vault.googleapis.com:443",
        "https://VAULT.googleapis.com:443",
        "https://vault.googleapis.com:443\\x",
        "https://vault.googleapis.com%2e:443",
        "https://vault.googleapis.com:0",
        "https://vault.googleapis.com:65536",
        "https://[fd12::1%25zone]:443",
        StringSubclass("https://vault.googleapis.com:443"),
    ],
)
def test_corrupted_origin(origin: str) -> None:
    selected = profile("google-vault")
    object.__setattr__(selected, "origin", origin)
    refusal(selected, ReadKey(kind="vault-matter", source_id="matter"))


@pytest.mark.parametrize("port", [1, 443, 8443, 65535])
@pytest.mark.parametrize("host", ["elastic.example.invalid", "[fd12::1]", "10.1.2.3"])
def test_ipv6_literal_and_custom_port(host: str, port: int) -> None:
    policy = (
        AddressPolicy("public") if host.endswith("invalid") else AddressPolicy("private", ("fd12::/64", "10.0.0.0/8"))
    )
    selected = FrozenProfile(
        "selected", "elastic-ilm", f"https://{host}:{port}", "ENTERPRISE_RETENTION_SYNTHETIC_TOKEN", policy
    )
    result = build_read_url(selected, ReadKey(kind="elastic-policy", source_id=".policy"))
    assert result == f"https://{host}:{port}/_ilm/policy/.policy"
    request = httpx.Request("GET", result)
    assert request.url.host == host.strip("[]")
    assert (request.url.port or 443) == port
    assert request.url.raw_path == b"/_ilm/policy/.policy"
    assert request.headers["host"] == host + (f":{port}" if port != 443 else "")


TOKENS = (
    "token",
    "a" * 4096,
    "\U0001f642" * 1024,
    "\u00e9\u4e2d\U0001f642",
    " ",
    "\t\r\n\x00",
    "a+b/c==&x=y?#%25",
    "https://other.example.invalid/path?x=y#z",
    "../%2e%2e/",
)


@pytest.mark.parametrize("token", TOKENS)
def test_continuation_roundtrip(token: str) -> None:
    selected = profile("google-vault")
    result = build_read_url(selected, ReadKey(kind="vault-holds", source_id="matter"), continuation=token)
    expected = "view=FULL_HOLD&pageSize=100&pageToken=" + quote(token, safe="")
    assert result == selected.origin + "/v1/matters/matter/holds?" + expected
    request = httpx.Request("GET", result)
    assert request.url.query == expected.encode("ascii")
    assert parse_qsl(request.url.query.decode("ascii"), keep_blank_values=True) == [
        ("view", "FULL_HOLD"),
        ("pageSize", "100"),
        ("pageToken", token),
    ]
    assert request.url.host == "vault.googleapis.com"
    assert request.url.raw_path.partition(b"?")[0] == b"/v1/matters/matter/holds"
    assert request.url.fragment == ""


@pytest.mark.parametrize(
    "token",
    [
        "",
        "x" * 4097,
        "\U0001f642" * 1025,
        "\ud800",
        "\udfff",
        "x\ud800y",
        False,
        0,
        [],
        {},
        b"token",
        StringSubclass("token"),
    ],
)
def test_invalid_holds_continuation(token: object) -> None:
    refusal(profile("google-vault"), ReadKey(kind="vault-holds", source_id="matter"), token, code="token_invalid")


@pytest.mark.parametrize("kind,provider,identity,suffix", [case for case in CASES if case[0] != "vault-holds"])
def test_non_holds_rejects_continuation(kind: ReadKind, provider: ProviderName, identity: str, suffix: str) -> None:
    refusal(profile(provider), ReadKey(kind=kind, source_id=identity), "token")


def test_original_inputs_are_detached_before_url_interpretation(monkeypatch: pytest.MonkeyPatch) -> None:
    selected = profile("google-vault")
    key = ReadKey(kind="vault-holds", source_id="matter")
    original_url = httpx.URL
    seen = 0

    def mutate(value: str) -> httpx.URL:
        nonlocal seen
        seen += 1
        object.__setattr__(selected, "origin", "https://other.example.invalid:444")
        object.__setattr__(selected.address_policy, "mode", "private")
        object.__setattr__(key, "source_id", "bad/path")
        object.__setattr__(key, "kind", "elastic-status")
        return original_url(value)

    monkeypatch.setattr(httpx, "URL", mutate)
    assert (
        build_read_url(selected, key, continuation="opaque")
        == "https://vault.googleapis.com:443/v1/matters/matter/holds?view=FULL_HOLD&pageSize=100&pageToken=opaque"
    )
    assert seen >= 1


@pytest.mark.parametrize(
    "replacement",
    [
        "http://vault.googleapis.com:443/v1/matters/matter?view=BASIC",
        "https://other.example.invalid:443/v1/matters/matter?view=BASIC",
        "https://vault.googleapis.com:444/v1/matters/matter?view=BASIC",
        "https://user@vault.googleapis.com:443/v1/matters/matter?view=BASIC",
        "https://vault.googleapis.com:443/v1/matters/changed?view=BASIC",
        "https://vault.googleapis.com:443/v1/matters/matter?view=FULL",
        "https://vault.googleapis.com:443/v1/matters/matter?view=BASIC#extra",
    ],
)
def test_actual_httpx_interpretation_must_match(monkeypatch: pytest.MonkeyPatch, replacement: str) -> None:
    original_url = httpx.URL

    def changed(value: str) -> httpx.URL:
        return original_url(replacement if "/v1/" in value else value)

    monkeypatch.setattr(httpx, "URL", changed)
    refusal(profile("google-vault"), ReadKey(kind="vault-matter", source_id="matter"))


@pytest.mark.parametrize(
    "code", ["destination_refused", "token_invalid", "MARKER", StringSubclass("token_invalid"), None, False]
)
def test_error_constructor_is_closed(code: object) -> None:
    error = EndpointError(cast(Literal["destination_refused", "token_invalid"], code))
    expected = code if type(code) is str and code in ("destination_refused", "token_invalid") else "destination_refused"
    assert error.args == (expected,)
    assert error.code == expected
    assert "MARKER" not in repr(error)


@pytest.mark.parametrize("which", ["profile", "key"])
def test_foreign_properties_are_never_invoked(which: str) -> None:
    calls: list[str] = []

    class Foreign:
        @property
        def provider(self) -> Never:
            calls.append("provider")
            raise AssertionError("unexpected_property")

        @property
        def kind(self) -> Never:
            calls.append("kind")
            raise AssertionError("unexpected_property")

        def __str__(self) -> Never:
            calls.append("str")
            raise AssertionError("unexpected_formatting")

        def __repr__(self) -> Never:
            calls.append("repr")
            raise AssertionError("unexpected_formatting")

    if which == "profile":
        refusal(Foreign(), ReadKey(kind="vault-matter", source_id="matter"))
    else:
        refusal(profile("google-vault"), Foreign())
    assert calls == []


def test_model_and_profile_subclasses_are_refused() -> None:
    class KeySubclass(ReadKey):
        pass

    class ProfileSubclass(FrozenProfile):
        pass

    refusal(profile("google-vault"), KeySubclass(kind="vault-matter", source_id="matter"))
    refusal(object.__new__(ProfileSubclass), ReadKey(kind="vault-matter", source_id="matter"))
    refusal(object.__new__(FrozenProfile), ReadKey(kind="vault-matter", source_id="matter"))


def test_hostile_string_subclasses_do_not_run_callbacks() -> None:
    calls: list[str] = []

    class HostileString(str):
        def __str__(self) -> Never:
            calls.append("str")
            raise AssertionError("unexpected_formatting")

        def __repr__(self) -> Never:
            calls.append("repr")
            raise AssertionError("unexpected_formatting")

        def __eq__(self, other: object) -> Never:
            calls.append("eq")
            raise AssertionError("unexpected_comparison")

        __hash__ = str.__hash__

    key = ReadKey(kind="vault-holds", source_id="matter")
    refusal(profile("google-vault"), key, HostileString("opaque"), code="token_invalid")
    object.__setattr__(key, "source_id", HostileString("matter"))
    refusal(profile("google-vault"), key)
    object.__setattr__(key, "__dict__", {HostileString("kind"): "vault-holds", "source_id": "matter"})
    refusal(profile("google-vault"), key)
    assert calls == []


def test_diagnostics_and_stderr_exclude_input_values(capsys: pytest.CaptureFixture[str]) -> None:
    selected = profile("google-vault")
    object.__setattr__(selected, "origin", "https://MARKER.example.invalid:443")
    refusal(selected, ReadKey(kind="vault-matter", source_id="matter"))
    refusal(profile("google-vault"), ReadKey.model_construct(kind="vault-matter", source_id="MARKER/path"))
    refusal(
        profile("google-vault"), ReadKey(kind="vault-holds", source_id="matter"), "MARKER\ud800", code="token_invalid"
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
