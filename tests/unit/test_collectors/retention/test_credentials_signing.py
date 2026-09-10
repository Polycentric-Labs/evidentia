"""Synthetic credential and S3 signing controls with no provider requests."""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import importlib.metadata
import json
import logging
import os
import socket
import subprocess
import sys
import traceback
from collections.abc import Iterator
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import ModuleType
from typing import Any, Literal, cast
from unittest.mock import patch

import botocore.auth as auth
import botocore.session
import httpx
import pytest
from botocore.awsrequest import AWSResponse
from botocore.config import Config
from evidentia_collectors.retention import _aws_signing as signing
from evidentia_collectors.retention import _credentials as credentials_module
from evidentia_collectors.retention._credentials import (
    AwsCredentials,
    BearerCredentials,
    CredentialResolution,
    EnvironmentCredentialProvider,
)

ACCESS = "synthetic-access-identifier"
SECRET = "synthetic-secret-material"
TOKEN = "synthetic-session-material"
OWNER = "123456789012"
URL = "https://s3.us-west-2.amazonaws.com/synthetic.bucket?object-lock"
FIXED = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.UTC)
EXPECTED_REGIONS = frozenset(
    [
        "af-south-1",
        "ap-east-1",
        "ap-east-2",
        "ap-northeast-1",
        "ap-northeast-2",
        "ap-northeast-3",
        "ap-south-1",
        "ap-south-2",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-southeast-3",
        "ap-southeast-4",
        "ap-southeast-5",
        "ap-southeast-6",
        "ap-southeast-7",
        "ca-central-1",
        "ca-west-1",
        "eu-central-1",
        "eu-central-2",
        "eu-north-1",
        "eu-south-1",
        "eu-south-2",
        "eu-west-1",
        "eu-west-2",
        "eu-west-3",
        "il-central-1",
        "me-central-1",
        "me-south-1",
        "mx-central-1",
        "sa-east-1",
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
    ]
)


def require(condition: bool, label: str) -> None:
    """Keep synthetic credential values out of assertion output."""
    if not condition:
        raise AssertionError(label)


def material() -> AwsCredentials:
    return AwsCredentials(ACCESS, SECRET, TOKEN)


def sign(**kwargs: Any) -> dict[str, str]:
    values: dict[str, Any] = {"url": URL, "region": "us-west-2", "expected_owner": OWNER, "credentials": material()}
    values.update(kwargs)
    return signing.sign_s3_get(**values)


class TextSubclass(str):
    pass


BAD_TEXT: tuple[object, ...] = (
    None,
    False,
    1,
    b"bytes",
    "",
    " ",
    "prefix suffix",
    "\t",
    "\r",
    "\n",
    "\v",
    "\f",
    "\x00",
    "\x1f",
    "\x7f",
    "\x80",
    "\u200b",
    TextSubclass("synthetic"),
)


@pytest.mark.parametrize("field", ["access_key_id", "secret_access_key", "session_token"])
@pytest.mark.parametrize("value", BAD_TEXT, ids=[f"invalid-{i}" for i in range(len(BAD_TEXT))])
def test_aws_material_rejects_invalid_text(field: str, value: object) -> None:
    if field == "session_token" and value is None:
        require(AwsCredentials(ACCESS, SECRET, None).session_token is None, "optional token remains absent")
        return
    values: dict[str, Any] = {"access_key_id": ACCESS, "secret_access_key": SECRET, "session_token": TOKEN}
    values[field] = value
    with pytest.raises(ValueError, match=r"^configuration_invalid$"):
        AwsCredentials(**values)


@pytest.mark.parametrize("value", BAD_TEXT, ids=[f"invalid-{i}" for i in range(len(BAD_TEXT))])
def test_bearer_material_rejects_invalid_text(value: object) -> None:
    with pytest.raises(ValueError, match=r"^configuration_invalid$"):
        BearerCredentials(cast(str, value))


def test_exact_material_bounds_and_literal_values() -> None:
    aws = AwsCredentials("a" * 2048, "s" * 2048, "t" * 16384)
    bearer = BearerCredentials("b" * 16384)
    require(len(aws.access_key_id) == 2048 and len(aws.secret_access_key) == 2048, "key boundary")
    require(len(cast(str, aws.session_token)) == 16384 and len(bearer.token) == 16384, "token boundary")
    punctuation = "!#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
    require(BearerCredentials(punctuation).token == punctuation, "literal header-safe ASCII retained")
    for field in ("access_key_id", "secret_access_key", "session_token"):
        values: dict[str, Any] = {"access_key_id": ACCESS, "secret_access_key": SECRET, "session_token": TOKEN}
        values[field] = "x" * (16385 if field == "session_token" else 2049)
        with pytest.raises(ValueError, match=r"^configuration_invalid$"):
            AwsCredentials(**values)
    with pytest.raises(ValueError, match=r"^configuration_invalid$"):
        BearerCredentials("x" * 16385)


@pytest.mark.parametrize("factory", ["aws", "bearer"])
@pytest.mark.parametrize(
    "expiry",
    [
        dt.datetime(2026, 1, 2),
        dt.date(2026, 1, 2),
        "future",
        True,
        dt.datetime(1, 1, 1, tzinfo=dt.timezone(dt.timedelta(hours=1))),
    ],
    ids=["naive", "date", "text", "boolean", "utc-overflow"],
)
def test_expiry_rejects_invalid_inputs(factory: str, expiry: object) -> None:
    with pytest.raises(ValueError, match=r"^configuration_invalid$"):
        if factory == "aws":
            AwsCredentials(ACCESS, SECRET, expires_at=cast(dt.datetime, expiry))
        else:
            BearerCredentials(TOKEN, expires_at=cast(dt.datetime, expiry))


class MutableZone(dt.tzinfo):
    def __init__(self) -> None:
        self.offset = dt.timedelta(hours=5)

    def utcoffset(self, value: dt.datetime | None) -> dt.timedelta:
        return self.offset

    def dst(self, value: dt.datetime | None) -> dt.timedelta:
        return dt.timedelta(0)

    def tzname(self, value: dt.datetime | None) -> str:
        return "synthetic-zone"


def test_expiry_is_detached_aware_utc_and_unknown_stays_unknown() -> None:
    zone = MutableZone()
    expiry = dt.datetime(2026, 1, 2, 8, 4, 5, 123456, tzinfo=zone)
    aws = AwsCredentials(ACCESS, SECRET, expires_at=expiry)
    bearer = BearerCredentials(TOKEN, expires_at=expiry)
    zone.offset = dt.timedelta(hours=10)
    expected = dt.datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=dt.UTC)
    require(aws.expires_at == expected and bearer.expires_at == expected, "detached UTC expiry")
    require(aws.expires_at is not None and aws.expires_at.tzinfo is dt.UTC, "canonical UTC timezone")
    require(AwsCredentials(ACCESS, SECRET).expires_at is None, "unknown expiry")
    require(BearerCredentials(TOKEN, FIXED).expires_at == FIXED, "expiry comparison belongs to session")


def test_material_repr_and_resolution_repr_are_value_free() -> None:
    values = [material(), BearerCredentials(TOKEN), CredentialResolution(material(), None)]
    require(
        all(all(secret not in repr(value) for secret in (ACCESS, SECRET, TOKEN)) for value in values),
        "repr contains no material",
    )
    for value, field in zip(values, ("access_key_id", "token", "material"), strict=True):
        with pytest.raises(FrozenInstanceError):
            setattr(value, field, None)


@pytest.mark.parametrize(
    "material_value,diagnostic",
    [(None, None), (material(), "configuration_missing"), ("source-value", None), (None, "source-value"), (None, True)],
    ids=["neither", "both", "wrong-material", "unknown-diagnostic", "wrong-diagnostic"],
)
def test_resolution_requires_material_xor_closed_diagnostic(material_value: object, diagnostic: object) -> None:
    with pytest.raises(ValueError, match=r"^configuration_invalid$"):
        CredentialResolution(cast(AwsCredentials | None, material_value), cast(str | None, diagnostic))


@pytest.mark.parametrize("diagnostic", ["configuration_missing", "configuration_invalid", "credential_unavailable"])
def test_resolution_accepts_only_fixed_configuration_diagnostics(diagnostic: str) -> None:
    resolution = CredentialResolution(None, diagnostic)
    require(resolution.material is None and resolution.diagnostic == diagnostic, "fixed resolution diagnostic")


def test_resolution_detaches_and_revalidates_material() -> None:
    original = material()
    resolution = CredentialResolution(original, None)
    object.__setattr__(original, "session_token", "changed")
    require(
        isinstance(resolution.material, AwsCredentials) and resolution.material.session_token == TOKEN,
        "resolution detaches caller object",
    )
    object.__setattr__(original, "access_key_id", "\n")
    with pytest.raises(ValueError, match=r"^configuration_invalid$"):
        CredentialResolution(original, None)


class EnvironmentRead:
    def __init__(self, values: dict[str, str | None]) -> None:
        self.values = values
        self.names: list[str] = []

    def __call__(self, name: str) -> str | None:
        self.names.append(name)
        if name not in self.values:
            raise AssertionError("unexpected environment reference")
        return self.values[name]


@pytest.mark.parametrize(
    "provider,names",
    [
        ("s3", ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")),
        ("azure", ("STORAGE_RETENTION_AZURE_ACCESS_TOKEN",)),
        ("gcs", ("STORAGE_RETENTION_GCS_ACCESS_TOKEN",)),
    ],
)
def test_provider_reads_only_selected_fixed_references(
    provider: str, names: tuple[str, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    lookup = EnvironmentRead(dict(zip(names, (ACCESS, SECRET, TOKEN) if provider == "s3" else (TOKEN,), strict=True)))
    monkeypatch.setattr(credentials_module, "_environment_value", lookup)
    with (
        patch("socket.create_connection", side_effect=AssertionError("network forbidden")) as network,
        patch("subprocess.run", side_effect=AssertionError("subprocess forbidden")) as command,
        patch("builtins.open", side_effect=AssertionError("file lookup forbidden")) as file_open,
    ):
        resolved = EnvironmentCredentialProvider().resolve(cast(Literal["s3", "azure", "gcs"], provider))
    require(tuple(lookup.names) == names, "only fixed selected references read once")
    require(resolved.material is not None and resolved.diagnostic is None, "selected credentials resolve")
    require(network.call_count == command.call_count == file_open.call_count == 0, "no ambient side effects")


@pytest.mark.parametrize(
    "values,expected",
    [
        ((None, None, None), "configuration_missing"),
        ((ACCESS, None, None), "configuration_invalid"),
        ((None, SECRET, None), "configuration_invalid"),
        ((None, None, TOKEN), "configuration_invalid"),
        (("", SECRET, None), "configuration_invalid"),
        ((ACCESS, SECRET, ""), "configuration_invalid"),
        ((ACCESS, SECRET, "\n"), "configuration_invalid"),
    ],
    ids=["missing", "key-only", "secret-only", "token-only", "blank-key", "blank-token", "unsafe-token"],
)
def test_aws_provider_fixed_failures(
    values: tuple[str | None, ...], expected: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    lookup = EnvironmentRead(
        dict(zip(("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"), values, strict=True))
    )
    monkeypatch.setattr(credentials_module, "_environment_value", lookup)
    result = EnvironmentCredentialProvider().resolve("s3")
    require(result.material is None and result.diagnostic == expected, "fixed provider failure")


@pytest.mark.parametrize("provider", ["azure", "gcs"])
@pytest.mark.parametrize(
    "value,expected",
    [(None, "configuration_missing"), ("", "configuration_invalid"), ("\n", "configuration_invalid")],
    ids=["missing", "blank", "unsafe"],
)
def test_bearer_provider_fixed_failures(
    provider: str, value: str | None, expected: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = f"STORAGE_RETENTION_{provider.upper()}_ACCESS_TOKEN"
    monkeypatch.setattr(credentials_module, "_environment_value", EnvironmentRead({name: value}))
    result = EnvironmentCredentialProvider().resolve(cast(Literal["azure", "gcs"], provider))
    require(result.material is None and result.diagnostic == expected, "fixed bearer failure")


def test_provider_does_not_cache_or_inspect_unrelated_values(monkeypatch: pytest.MonkeyPatch) -> None:
    lookup = EnvironmentRead({"STORAGE_RETENTION_GCS_ACCESS_TOKEN": TOKEN})
    monkeypatch.setattr(credentials_module, "_environment_value", lookup)
    provider = EnvironmentCredentialProvider()
    first = provider.resolve("gcs")
    lookup.values["STORAGE_RETENTION_GCS_ACCESS_TOKEN"] = "new-synthetic-token"
    second = provider.resolve("gcs")
    require(first.material != second.material and len(lookup.names) == 2, "run caching belongs to session")
    lookup.names.clear()
    invalid = provider.resolve(cast(Literal["s3"], "unknown-provider"))
    require(invalid.diagnostic == "configuration_invalid" and not lookup.names, "invalid provider reads nothing")


def test_provider_lookup_exception_is_value_free(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(name: str) -> str | None:
        raise RuntimeError(TOKEN)

    monkeypatch.setattr(credentials_module, "_environment_value", fail)
    result = EnvironmentCredentialProvider().resolve("gcs")
    require(result.diagnostic == "credential_unavailable" and TOKEN not in repr(result), "lookup failure is sanitized")


BAD_URLS = (
    "http://s3.us-west-2.amazonaws.com/synthetic.bucket?object-lock",
    "HTTPS://s3.us-west-2.amazonaws.com/synthetic.bucket?object-lock",
    "https://user@s3.us-west-2.amazonaws.com/synthetic.bucket?object-lock",
    "https://s3.us-west-2.amazonaws.com:443/synthetic.bucket?object-lock",
    "https://s3.us-west-2.amazonaws.com./synthetic.bucket?object-lock",
    "https://s3.us-west-2.amazonaws.com.evil.invalid/synthetic.bucket?object-lock",
    "https://s3.us-west-2.amazonaws.com/synthetic.bucket/object?object-lock",
    "https://s3.us-west-2.amazonaws.com/synthetic.bucket?object-lock=",
    "https://s3.us-west-2.amazonaws.com/synthetic.bucket?object-lock&versioning",
    "https://s3.us-west-2.amazonaws.com/synthetic.bucket?versioning#fragment",
    "https://s3.us-west-2.amazonaws.com/synthetic.bucket?versioning\n",
    "https://s3.us-west-2.amazonaws.com/synthetic%2ebucket?versioning",
    "https://s3.us-west-2.amazonaws.com//synthetic.bucket?versioning",
    "https://s3.us-west-2.amazonaws.com/synthetic.bucket/?versioning",
    "https://s3.us-west-2.amazonaws.com/synthetic.bucket?acl",
    "https://s3.us-east-1.amazonaws.com/synthetic.bucket?versioning",
    " https://s3.us-west-2.amazonaws.com/synthetic.bucket?versioning",
    "https://S3.us-west-2.amazonaws.com/synthetic.bucket?versioning",
)


@pytest.mark.parametrize("url", BAD_URLS, ids=[f"url-{i}" for i in range(len(BAD_URLS))])
def test_signer_rejects_nonliteral_destinations_before_sdk(url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    touched: list[str] = []

    def forbidden(name: str) -> ModuleType:
        touched.append(name)
        raise AssertionError("SDK imported for invalid input")

    monkeypatch.setattr(signing, "_import_module", forbidden)
    with pytest.raises(signing.SigningError, match=r"^configuration_invalid$"):
        sign(url=url)
    require(not touched, "invalid URL never reaches SDK")


@pytest.mark.parametrize(
    "bucket",
    [
        "ab",
        "a" * 64,
        "Uppercase",
        "-start",
        "end-",
        "two..dots",
        "192.168.0.1",
        "192.168.000.1",
        "999.999.999.999",
        "xn--name",
        "sthree-name",
        "amzn-s3-demo-name",
        "name-s3alias",
        "name--ol-s3",
        "name.mrap",
        "name--x-s3",
        "name--table-s3",
        "name_under",
    ],
    ids=[f"bucket-{i}" for i in range(18)],
)
def test_signer_rejects_unsupported_bucket_shapes(bucket: str) -> None:
    with pytest.raises(signing.SigningError, match=r"^configuration_invalid$"):
        sign(url=f"https://s3.us-west-2.amazonaws.com/{bucket}?versioning")


@pytest.mark.parametrize(
    "region",
    ["", "us-east-99", "cn-north-1", "us-gov-west-1", "US-WEST-2", "us-west-2\n", None, False],
    ids=[f"region-{i}" for i in range(8)],
)
def test_signer_rejects_regions(region: object) -> None:
    with pytest.raises(signing.SigningError, match=r"^configuration_invalid$"):
        sign(region=region)


@pytest.mark.parametrize(
    "owner",
    ["", "123", "1" * 13, " " + OWNER, OWNER + "\n", "a" * 12, 123456789012, False, "\uff11" * 12],
    ids=[f"owner-{i}" for i in range(9)],
)
def test_signer_rejects_expected_owner(owner: object) -> None:
    with pytest.raises(signing.SigningError, match=r"^configuration_invalid$"):
        sign(expected_owner=owner)


def test_signer_revalidates_mutated_and_fabricated_material() -> None:
    value = material()
    object.__setattr__(value, "secret_access_key", "\n")
    for invalid in (value, object.__new__(AwsCredentials), BearerCredentials(TOKEN), {"access_key_id": ACCESS}):
        with pytest.raises(signing.SigningError, match=r"^configuration_invalid$"):
            sign(credentials=invalid)


@pytest.mark.parametrize(
    "version",
    ["1.43.88", "1.43.90", "1.44.0", "1.43.89+local", None],
    ids=["older", "newer", "minor", "local", "invalid"],
)
def test_version_refusal_precedes_helper_import(version: object, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(signing, "_package_version", lambda name: version)
    touched: list[str] = []

    def forbidden(name: str) -> ModuleType:
        touched.append(name)
        raise AssertionError("unsupported helper import")

    monkeypatch.setattr(signing, "_import_module", forbidden)
    with pytest.raises(signing.SigningError, match=r"^signing_unsupported$"):
        sign()
    require(not touched, "version refusal precedes SDK import")


def test_module_and_distribution_versions_must_agree(monkeypatch: pytest.MonkeyPatch) -> None:
    module = ModuleType("botocore")
    module.__dict__["__version__"] = "1.43.90"
    touched: list[str] = []

    def fake_import(name: str) -> ModuleType:
        touched.append(name)
        return module

    monkeypatch.setattr(signing, "_package_version", lambda name: "1.43.89")
    monkeypatch.setattr(signing, "_import_module", fake_import)
    with pytest.raises(signing.SigningError, match=r"^signing_unsupported$"):
        sign()
    require(touched == ["botocore"], "mixed SDK installation refused before helpers")


def test_missing_distribution_is_exact_optional_absence(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError("botocore")

    monkeypatch.setattr(signing, "_package_version", missing)
    with pytest.raises(ModuleNotFoundError) as caught:
        sign()
    require(caught.value.name == "botocore", "exact optional name")


@pytest.mark.parametrize("name", ["botocore", "jmespath", "botocore.auth"])
def test_missing_import_identity_is_preserved(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(module_name: str) -> ModuleType:
        raise ModuleNotFoundError("synthetic module failure", name=name)

    monkeypatch.setattr(signing, "_package_version", lambda package_name: "1.43.89")
    monkeypatch.setattr(signing, "_import_module", missing)
    with pytest.raises(ModuleNotFoundError) as caught:
        sign()
    require(caught.value.name == name, "missing transitive is not feature absence")


def test_plain_import_error_remains_broken_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(name: str) -> ModuleType:
        raise ImportError("synthetic broken dependency")

    monkeypatch.setattr(signing, "_import_module", broken)
    with pytest.raises(ImportError) as caught:
        sign()
    require(not isinstance(caught.value, ModuleNotFoundError), "broken import remains distinct")


def test_base_import_never_imports_optional_sdk(tmp_path: Path) -> None:
    code = """
import importlib.abc,json,sys
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname.split(".")[0] in {"botocore","boto3","defusedxml"}:
            raise AssertionError("optional import at base import")
        return None
sys.meta_path.insert(0,Block())
sys.path.insert(0,sys.argv[1])
from evidentia_collectors.retention import _aws_signing,_credentials
print(json.dumps({"base_import":True}))
"""
    run = subprocess.run(
        [sys.executable, "-I", "-B", "-c", code, str(Path(signing.__file__).resolve().parents[2])],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    require(run.returncode == 0, "base import requires no optional dependencies")
    require(json.loads(run.stdout) == {"base_import": True}, "base import child control")


class LogCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


class EarlyFilter(logging.Filter):
    def __init__(self) -> None:
        super().__init__()
        self.count = 0

    def filter(self, record: logging.LogRecord) -> bool:
        self.count += 1
        return True


def test_signing_creates_no_debug_records_or_logging_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    logger = logging.getLogger("botocore.auth")
    original = logger.level, logger.propagate, logger.disabled, list(logger.filters)
    handler, early = LogCapture(), EarlyFilter()
    factory = logging.getLogRecordFactory()
    counts: list[str] = []

    def observing_factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = factory(*args, **kwargs)
        if record.name == "botocore.auth":
            counts.append(record.name)
        return record

    logger.setLevel(logging.DEBUG)
    logger.disabled = False
    logger.propagate = False
    logger.addHandler(handler)
    logger.addFilter(early)
    logging.setLogRecordFactory(observing_factory)
    state = logger.level, logger.disabled, logger.propagate, tuple(logger.filters)
    try:
        headers = sign()
        require(bool(headers.get("Authorization")), "signed request exists")
        require(not handler.messages and not counts and early.count == 0, "no DEBUG records at every stage")
        require(
            state == (logger.level, logger.disabled, logger.propagate, tuple(logger.filters)),
            "logger configuration unchanged",
        )
    finally:
        logging.setLogRecordFactory(factory)
        logger.removeHandler(handler)
        logger.filters[:] = original[3]
        logger.setLevel(original[0])
        logger.propagate = original[1]
        logger.disabled = original[2]


def test_signing_helper_failure_uses_fixed_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(self: Any, request: Any) -> str:
        raise ValueError(TOKEN)

    monkeypatch.setattr(auth.S3SigV4Auth, "canonical_request", fail)
    with pytest.raises(signing.SigningError) as caught:
        sign()
    rendered = "".join(traceback.format_exception(caught.value))
    require(caught.value.code == "signing_unsupported", "fixed unsupported helper failure")
    require(all(value not in rendered for value in (ACCESS, SECRET, TOKEN)), "no underlying exception value")
    require(caught.value.__suppress_context__, "raw exception context suppressed")


class RawResponse:
    def __init__(self, value: bytes) -> None:
        self.value = value

    def stream(self) -> Iterator[bytes]:
        yield self.value


def header_map(headers: Any) -> dict[str, str]:
    return {
        str(key).lower(): value.decode("utf-8") if isinstance(value, bytes) else str(value)
        for key, value in headers.items()
    }


@pytest.mark.parametrize("region", ["us-east-1", "us-west-2", "ap-southeast-7"])
@pytest.mark.parametrize("bucket", ["synthetic-bucket", "synthetic.bucket"])
@pytest.mark.parametrize("operation", ["object-lock", "versioning"])
@pytest.mark.parametrize("with_token", [False, True], ids=["no-session", "session"])
@pytest.mark.parametrize("with_owner", [False, True], ids=["no-owner", "owner"])
def test_actual_normal_sdk_request_parity(
    region: str,
    bucket: str,
    operation: str,
    with_token: bool,
    with_owner: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty = tmp_path / "empty-sdk-config"
    empty.write_bytes(b"")
    for name in tuple(os.environ):
        if name.startswith("AWS_"):
            monkeypatch.delenv(name)
    for name in ("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "BOTO_CONFIG"):
        monkeypatch.setenv(name, str(empty))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setattr(auth, "get_current_datetime", lambda: FIXED)
    captured: list[Any] = []

    def respond(request: Any, **kwargs: Any) -> AWSResponse:
        captured.append(request)
        body = (
            b'<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            b"<ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>"
            if operation == "object-lock"
            else b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            b"<Status>Enabled</Status></VersioningConfiguration>"
        )
        return AWSResponse(request.url, 200, {"content-type": "application/xml"}, RawResponse(body))

    with (
        patch("botocore.httpsession.URLLib3Session.send", side_effect=AssertionError("SDK network forbidden")) as send,
        patch(
            "botocore.credentials.CredentialResolver.load_credentials", side_effect=AssertionError("chain forbidden")
        ) as chain,
        patch.object(socket.socket, "connect", side_effect=AssertionError("socket forbidden")) as connect,
    ):
        client = botocore.session.Session().create_client(
            "s3",
            region_name=region,
            endpoint_url=f"https://s3.{region}.amazonaws.com",
            aws_access_key_id=ACCESS,
            aws_secret_access_key=SECRET,
            aws_session_token=TOKEN if with_token else None,
            config=Config(
                signature_version="s3v4",
                s3={"addressing_style": "path", "us_east_1_regional_endpoint": "regional"},
                proxies={},
                retries={"total_max_attempts": 1},
            ),
        )
        event = "GetObjectLockConfiguration" if operation == "object-lock" else "GetBucketVersioning"
        client.meta.events.register(f"before-send.s3.{event}", respond)
        kwargs = {"Bucket": bucket}
        if with_owner:
            kwargs["ExpectedBucketOwner"] = OWNER
        try:
            if operation == "object-lock":
                client.get_object_lock_configuration(**kwargs)
            else:
                client.get_bucket_versioning(**kwargs)
        finally:
            client.close()
        url = f"https://s3.{region}.amazonaws.com/{bucket}?{operation}"
        headers = sign(
            url=url,
            region=region,
            expected_owner=OWNER if with_owner else None,
            credentials=AwsCredentials(ACCESS, SECRET, TOKEN if with_token else None),
        )
        require(len(captured) == 1, "one SDK prepared request")
        sdk = captured[0]
        expected, actual = header_map(sdk.headers), header_map(headers)
        require(actual["authorization"] == expected["authorization"], "exact SDK Authorization bytes")
        require(sdk.method == "GET" and sdk.url == url and (sdk.body or b"") == b"", "exact SDK URL and empty body")
        signed_names = expected["authorization"].split("SignedHeaders=")[1].split(",")[0].split(";")
        require("host" in actual and actual["host"] == f"s3.{region}.amazonaws.com", "complete signed Host returned")
        wire = httpx.Request("GET", url, headers=headers)
        for name in signed_names:
            expected_value = expected.get(name, f"s3.{region}.amazonaws.com" if name == "host" else "")
            require(
                actual[name] == expected_value and wire.headers[name] == expected_value, "signed header bytes unchanged"
            )
        require(wire.url.raw_path == f"/{bucket}?{operation}".encode("ascii"), "literal HTTPX path/query")
        expected_keys = {"authorization", "host", "x-amz-date", "x-amz-content-sha256"}
        if with_owner:
            expected_keys.add("x-amz-expected-bucket-owner")
        if with_token:
            expected_keys.add("x-amz-security-token")
        require(set(actual) == expected_keys, "only fixed signed header set")
        require(send.call_count == chain.call_count == connect.call_count == 0, "no provider transport or chain")


def test_supported_region_oracle_and_new_account_regional_suffix() -> None:
    require(signing.S3_REGIONS == EXPECTED_REGIONS, "exact independent region oracle")
    for region in EXPECTED_REGIONS:
        headers = sign(url=f"https://s3.{region}.amazonaws.com/synthetic-bucket?versioning", region=region)
        require(headers.get("Host") == f"s3.{region}.amazonaws.com", "all reviewed regions accepted")
    require(len(EXPECTED_REGIONS) == 34, "independent region oracle length")
    headers = sign(url="https://s3.us-west-2.amazonaws.com/synthetic-account-an?versioning")
    require(bool(headers.get("Authorization")), "account-regional suffix is not guessed invalid")


def test_repeated_and_concurrent_calls_share_no_request_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth, "get_current_datetime", lambda: FIXED)
    first = sign()
    first["Authorization"] = "changed"

    def execute(index: int) -> bool:
        token = f"synthetic-concurrent-token-{index}"
        headers = sign(credentials=AwsCredentials(ACCESS, SECRET, token), expected_owner=None)
        return headers.get("X-Amz-Security-Token") == token and headers.get("Authorization") != "changed"

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        checks = list(pool.map(execute, range(12)))
    require(all(checks), "fresh request and material per call")
    next_time = FIXED + dt.timedelta(seconds=1)
    monkeypatch.setattr(auth, "get_current_datetime", lambda: next_time)
    second = sign()
    require(second.get("X-Amz-Date") == "20260102T030406Z", "each call signs with a new timestamp")


@pytest.mark.parametrize(
    "url", [None, False, 1, b"bytes", TextSubclass(URL)], ids=["null", "boolean", "integer", "bytes", "subclass"]
)
def test_signer_url_type_is_strict(url: object) -> None:
    with pytest.raises(signing.SigningError, match=r"^configuration_invalid$"):
        sign(url=url)


def test_signing_error_cannot_retain_an_arbitrary_message() -> None:
    error = signing.SigningError(TOKEN)
    require(error.code == "configuration_invalid" and TOKEN not in repr(error), "closed public exception code")


@pytest.mark.parametrize("factory", [AwsCredentials, BearerCredentials], ids=["aws", "bearer"])
def test_resolution_rejects_uninitialized_material(factory: type[Any]) -> None:
    value = object.__new__(factory)
    with pytest.raises(ValueError, match=r"^configuration_invalid$"):
        CredentialResolution(value, None)


def test_unrelated_missing_distribution_is_not_optional_absence(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError("unrelated-package")

    monkeypatch.setattr(signing, "_package_version", missing)
    with pytest.raises(importlib.metadata.PackageNotFoundError):
        sign()


def test_invalid_material_precedes_all_sdk_loading(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(name: str) -> str:
        raise AssertionError("metadata inspected before invalid credential refusal")

    monkeypatch.setattr(signing, "_package_version", forbidden)
    value = material()
    object.__setattr__(value, "expires_at", dt.datetime(2026, 1, 2))
    with pytest.raises(signing.SigningError, match=r"^configuration_invalid$"):
        sign(credentials=value)
