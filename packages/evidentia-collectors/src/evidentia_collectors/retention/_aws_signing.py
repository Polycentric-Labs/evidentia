"""Fixed-route S3 signing through an explicitly supported SDK helper surface."""

from __future__ import annotations

import re
from collections.abc import MutableMapping
from datetime import datetime
from importlib import import_module as _import_module
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _package_version
from typing import Literal, Protocol, cast

from ._contracts import S3_REGIONS as S3_REGIONS
from ._credentials import AwsCredentials

SUPPORTED_BOTOCORE_VERSION = "1.43.89"
_BUCKET_PATTERN = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
_RESERVED_PREFIXES = ("xn--", "sthree-", "amzn-s3-demo-")
_RESERVED_SUFFIXES = ("-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3")


class SigningError(ValueError):
    """A closed signing diagnostic without underlying SDK error text."""

    def __init__(self, code: str) -> None:
        self.code: Literal["signing_unsupported", "configuration_invalid"] = (
            "signing_unsupported" if type(code) is str and code == "signing_unsupported" else "configuration_invalid"
        )
        super().__init__(self.code)


class _Request(Protocol):
    headers: MutableMapping[str, str]
    context: dict[str, object]


class _Signer(Protocol):
    def _modify_request_before_signing(self, request: _Request) -> None: ...
    def canonical_request(self, request: _Request) -> str: ...
    def string_to_sign(self, request: _Request, canonical_request: str) -> str: ...
    def signature(self, string_to_sign: str, request: _Request) -> str: ...
    def _inject_signature_to_request(self, request: _Request, signature: str) -> object: ...


class _AuthModule(Protocol):
    SIGV4_TIMESTAMP: str

    def get_current_datetime(self) -> datetime: ...
    def S3SigV4Auth(self, credentials: object, service_name: str, region_name: str) -> _Signer: ...


class _RequestsModule(Protocol):
    def AWSRequest(self, *, method: str, url: str, headers: dict[str, str], data: bytes) -> _Request: ...


class _CredentialsModule(Protocol):
    def Credentials(self, access_key: str, secret_key: str, token: str | None) -> object: ...


def _load_sdk() -> tuple[_AuthModule, _RequestsModule, _CredentialsModule]:
    try:
        version = _package_version("botocore")
    except PackageNotFoundError as error:
        if error.name != "botocore":
            raise
        raise ModuleNotFoundError("Optional dependency unavailable: botocore", name="botocore") from None
    if type(version) is not str or version != SUPPORTED_BOTOCORE_VERSION:
        raise SigningError("signing_unsupported")
    package = _import_module("botocore")
    if getattr(package, "__version__", None) != SUPPORTED_BOTOCORE_VERSION:
        raise SigningError("signing_unsupported")
    return (
        cast(_AuthModule, _import_module("botocore.auth")),
        cast(_RequestsModule, _import_module("botocore.awsrequest")),
        cast(_CredentialsModule, _import_module("botocore.credentials")),
    )


def _validated_inputs(
    url: str, region: str, expected_owner: str | None, credentials: AwsCredentials
) -> tuple[str, AwsCredentials]:
    if type(url) is not str or len(url) > 256 or type(region) is not str or region not in S3_REGIONS:
        raise SigningError("configuration_invalid")
    host = f"s3.{region}.amazonaws.com"
    prefix = f"https://{host}/"
    if not url.startswith(prefix):
        raise SigningError("configuration_invalid")
    bucket, separator, query = url[len(prefix) :].partition("?")
    labels = bucket.split(".")
    if (
        not separator
        or query not in {"object-lock", "versioning"}
        or _BUCKET_PATTERN.fullmatch(bucket) is None
        or ".." in bucket
        or bucket.startswith(_RESERVED_PREFIXES)
        or bucket.endswith(_RESERVED_SUFFIXES)
        or (len(labels) == 4 and all(label.isascii() and label.isdecimal() for label in labels))
    ):
        raise SigningError("configuration_invalid")
    if expected_owner is not None and (
        type(expected_owner) is not str or re.fullmatch(r"[0-9]{12}", expected_owner) is None
    ):
        raise SigningError("configuration_invalid")
    try:
        if type(credentials) is not AwsCredentials:
            raise ValueError
        copied = AwsCredentials(
            credentials.access_key_id,
            credentials.secret_access_key,
            credentials.session_token,
            credentials.expires_at,
        )
    except (AttributeError, TypeError, ValueError):
        raise SigningError("configuration_invalid") from None
    return host, copied


def sign_s3_get(url: str, *, region: str, expected_owner: str | None, credentials: AwsCredentials) -> dict[str, str]:
    """Sign only a selected fixed S3 GET without emitting SDK signing traces.

    The two private preparation/injection hooks and their order are reviewed
    with each supported SDK version. All signing computations stay in botocore.
    Destination guards, expiry comparison and transport belong to the caller.
    """
    host, copied = _validated_inputs(url, region, expected_owner, credentials)
    auth, requests, materials = _load_sdk()
    try:
        headers = {"Host": host}
        if expected_owner is not None:
            headers["x-amz-expected-bucket-owner"] = expected_owner
        request = requests.AWSRequest(method="GET", url=url, headers=headers, data=b"")
        material = materials.Credentials(copied.access_key_id, copied.secret_access_key, copied.session_token)
        signer = auth.S3SigV4Auth(material, "s3", region)
        request.context["timestamp"] = auth.get_current_datetime().strftime(auth.SIGV4_TIMESTAMP)
        signer._modify_request_before_signing(request)
        canonical_request = signer.canonical_request(request)
        string_to_sign = signer.string_to_sign(request, canonical_request)
        signature = signer.signature(string_to_sign, request)
        signer._inject_signature_to_request(request, signature)
        return dict(request.headers)
    except Exception:
        raise SigningError("signing_unsupported") from None
