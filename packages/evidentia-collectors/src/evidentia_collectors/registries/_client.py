"""Own non-SAM HTTP connections and finite registry read sessions."""

from __future__ import annotations

import hashlib
import http.cookiejar
import math
import ssl
import time
from collections.abc import Callable, Iterator
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast, get_args
from urllib.parse import urljoin, urlsplit

import httpx

from evidentia_collectors.retention._client import ClientFault, read_bounded_body, retry_delay

from ._contracts import (
    _TEMPLATES,
    CapacityPlan,
    CollectionStatus,
    DiagnosticCode,
    DomainTarget,
    EndpointTarget,
    EntityTarget,
    Freshness,
    HostnameTarget,
    LEITarget,
    MatchBasis,
    RegistryDiagnostic,
    RegistryInputError,
    RegistryLookupRequest,
    RegistryLookupResult,
    RegistryName,
    RegistryObservation,
    SAMOrganizationTarget,
    SourceRead,
    UEITarget,
    _CapacityLimits,
    canonical_hostname,
    clock_text,
    diagnostic,
    make_observation,
    make_result,
    normalized_organization_name,
    normalized_source_time,
    read_identifier,
    request_identity,
    validated_request,
)
from ._credentials import CredentialError, Resolver, SamCredentialCache, environment_resolver
from ._http_backend import OwnedHTTPTransport, OwnedState
from ._parsing import canonical_json, checked_json, parse_strict_json
from ._sam_http import SamAttempt, SamTransportError
from ._snapshots import (
    RDAPBootstrap,
    RegistrySnapshot,
    SnapshotFault,
    SnapshotRegistry,
    SnapshotTarget,
    load_bootstrap,
    load_snapshot,
)
from ._source_adapters import AdapterCandidate, AdapterError, adapt_incommon, adapt_security_txt, mdq_url
from ._source_fields import expected_fields, field_coverage, source_times, validate_fields
from ._tls import ApprovedHost, TLSAttempt, TransportError, approved_destination, public_url, tls_context
from ._xml_signature import XMLSignatureError, _TrustedCertificate, require_xml_extra

_HTTP_ERRORS = frozenset(
    {
        "offline_refused",
        "destination_refused",
        "dns_failure",
        "tls_failure",
        "connection_failure",
        "timeout",
        "invalid_response",
        "redirect_refused",
        "http_error",
        "body_limit",
        "cleanup_failure",
    }
)


class HttpFault(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in _HTTP_ERRORS else "invalid_response"
        super().__init__(self.code)


class _RejectCookies(http.cookiejar.CookieJar):
    def set_cookie(self, cookie: Any) -> None:
        pass

    def extract_cookies(self, response: Any, request: Any) -> None:
        pass

    def add_cookie_header(self, request: Any) -> None:
        pass


def _http_transport(context: ssl.SSLContext, approved: ApprovedHost, owned: OwnedState) -> httpx.BaseTransport:
    return OwnedHTTPTransport(context, approved, owned)


class _ClosedStream(httpx.SyncByteStream):
    def __init__(self, stream: httpx.SyncByteStream, close: Callable[[Callable[[], Any]], None]) -> None:
        self._stream, self._close = stream, close
        self._closed = False

    def __iter__(self) -> Iterator[bytes]:
        yield from self._stream

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._close(self._stream.close)


class HttpAttempt:
    """One approved destination and one fresh client, with no automatic traversal."""

    def __init__(self) -> None:
        self.status_code: int | None = None
        self.location: tuple[str, ...] = ()
        self.content_types: tuple[str, ...] = ()
        self.retry_after: tuple[str, ...] = ()
        self.cleanup_failed = False
        self._used = False
        self._cleanup_cancellation: BaseException | None = None
        self._callback_error: BaseException | None = None

    def _close(self, operation: Callable[[], Any]) -> None:
        try:
            operation()
        except BaseException as error:
            self.cleanup_failed = True
            if not isinstance(error, Exception) and self._cleanup_cancellation is None:
                self._cleanup_cancellation = error

    def _remaining(self, callback: Callable[[], float]) -> float:
        try:
            value = callback()
        except BaseException as error:
            self._callback_error = error
            raise
        if (type(value) is not int and type(value) is not float) or not math.isfinite(value) or value <= 0:
            raise HttpFault("timeout")
        return value

    def fetch(
        self,
        url: str,
        *,
        remaining: Callable[[], float],
        consume: Callable[[int, int], None],
        max_bytes: int = 1_048_576,
    ) -> bytes:
        if self._used:
            raise HttpFault("invalid_response")
        self._used = True
        clean_url, host = public_url(url)
        # SAM must never reach HTTPX or HTTPcore, even through a later redirect.
        if host == "sam.gov" or host.endswith(".sam.gov"):
            raise HttpFault("destination_refused")
        response: httpx.Response | None = None
        transport: httpx.BaseTransport | None = None
        client: httpx.Client | None = None
        primary: BaseException | None = None
        fixed_error: str | None = None
        result: bytes | None = None
        owned = OwnedState(lambda: self._remaining(remaining))

        def charge(raw: int, decoded: int) -> None:
            try:
                consume(raw, decoded)
            except BaseException as error:
                self._callback_error = error
                raise
            self._remaining(remaining)

        def status(received: httpx.Response) -> None:
            nonlocal response
            response = received
            if not isinstance(received.stream, httpx.SyncByteStream):
                raise HttpFault("invalid_response")
            received.stream = _ClosedStream(received.stream, self._close)
            code = received.status_code
            if type(code) is not int or not 100 <= code <= 599:
                raise HttpFault("invalid_response")
            self.status_code = code
            self._remaining(remaining)
            self.retry_after = tuple(received.headers.get_list("retry-after"))
            self.content_types = tuple(received.headers.get_list("content-type"))
            if 300 <= code < 400:
                self.location = tuple(received.headers.get_list("location"))
                raise HttpFault("redirect_refused")
            if code != 200:
                raise HttpFault("http_error")
            if len(received.headers.get_list("content-encoding")) > 1:
                raise HttpFault("invalid_response")

        try:
            self._remaining(remaining)
            with approved_destination(clean_url) as approved:
                transport = _http_transport(tls_context(), approved, owned)
                cookies = _RejectCookies()
                client = httpx.Client(
                    transport=transport,
                    trust_env=False,
                    http1=True,
                    http2=False,
                    follow_redirects=False,
                    auth=None,
                    cookies=cookies,
                    event_hooks={"response": [status]},
                )
                if client.cookies.jar is not cookies:
                    raise HttpFault("invalid_response")
                available = self._remaining(remaining)
                request = httpx.Request(
                    "GET",
                    clean_url,
                    headers={
                        "Accept": "application/json, application/xml, text/plain",
                        "Accept-Encoding": "gzip, identity",
                        "Connection": "close",
                    },
                    content=b"",
                    extensions={
                        "timeout": {
                            "connect": min(5.0, available),
                            "pool": min(5.0, available),
                            "read": min(10.0, available),
                            "write": min(10.0, available),
                        }
                    },
                )
                response = client.send(request, stream=True, auth=None, follow_redirects=False)
                result = read_bounded_body(response, consume=charge, max_bytes=max_bytes)
                self._remaining(remaining)
        except BaseException as error:
            if error is self._callback_error or not isinstance(error, Exception):
                primary = error
            elif isinstance(error, (HttpFault, TransportError)):
                fixed_error = error.code
            elif isinstance(error, ClientFault):
                fixed_error = "body_limit" if error.code == "response_limit" else "invalid_response"
            elif isinstance(error, (httpx.ConnectTimeout, httpx.ReadTimeout)):
                fixed_error = "timeout"
            elif isinstance(error, (httpx.TimeoutException, TimeoutError)):
                fixed_error = "connection_failure"
            elif isinstance(error, ssl.SSLError):
                fixed_error = "tls_failure"
            elif isinstance(error, httpx.ConnectError):
                fixed_error = "connection_failure"
                cause: BaseException | None = error
                for _ in range(8):
                    if isinstance(cause, ssl.SSLError):
                        fixed_error = "tls_failure"
                        break
                    if cause is not None:
                        cause = cause.__cause__ if cause.__cause__ is not None else cause.__context__
            else:
                fixed_error = "invalid_response"
        finally:
            if response is not None:
                self._close(response.close)
            if client is not None:
                self._close(client.close)
            if transport is not None:
                self._close(transport.close)
            owned.close_all()
            self.cleanup_failed = self.cleanup_failed or owned.cleanup_failed
            if self._cleanup_cancellation is None:
                self._cleanup_cancellation = owned.cleanup_cancellation
            if owned.primary is not None:
                primary = owned.primary
        if primary is not None and not isinstance(primary, Exception):
            raise primary
        if self._cleanup_cancellation is not None:
            raise self._cleanup_cancellation
        if primary is not None:
            raise primary
        if fixed_error is not None:
            raise HttpFault(fixed_error)
        if self.cleanup_failed or result is None:
            raise HttpFault("cleanup_failure" if self.cleanup_failed else "invalid_response")
        return result


Projector = Callable[[dict[str, Any]], dict[str, Any]]
_RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
_RUN_HTTP_BYTES = 8_388_608
# The owned HTTP/1 and SAM streams deliver at most 65,536 bytes per raw chunk.
# Reserve a complete response plus its rejected final chunk before starting I/O.
_ATTEMPT_OBSERVED_BYTES = 1_048_576 + 65_536


class ReadFault(ValueError):
    def __init__(self, code: DiagnosticCode) -> None:
        self.code: DiagnosticCode = (
            code if type(code) is str and code in get_args(DiagnosticCode) else "invalid_response"
        )
        super().__init__(self.code)


def _retry_wait(values: tuple[str, ...], *, attempt: int, now: datetime, remaining: float) -> float:
    clock_text(now)
    if (
        type(values) is not tuple
        or len(values) > 1
        or any(type(value) is not str or not value.isascii() or len(value) > 128 for value in values)
        or type(attempt) is not int
        or attempt not in (1, 2)
    ):
        raise ReadFault("retry_exhausted")
    failure: DiagnosticCode | None = None
    delay = 0.0
    try:
        delay = retry_delay(values[0] if values else None, attempt=attempt, now=now, remaining=30.0)
    except ClientFault:
        failure = "retry_exhausted"
    if failure is not None or delay > 10.0:
        raise ReadFault("retry_exhausted")
    if not math.isfinite(remaining) or remaining <= 0 or delay > remaining:
        raise ReadFault("deadline_exceeded")
    return delay


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class _Admission:
    source: dict[str, Any]
    identity: dict[str, Any]
    shape: str
    matched_identity: str
    match_basis: MatchBasis = "exact_identifier"


def _redirect_target(current: str, location: str, *, service_base: str | None) -> str:
    """Admit only canonical same-origin paths, with a fixed RDAP base fence."""
    if type(location) is not str or not 1 <= len(location) <= 8192 or not location.isascii():
        raise ReadFault("redirect_refused")
    try:
        if any(ord(char) < 33 or ord(char) > 126 for char in location) or any(char in location for char in "\\%?#"):
            raise ValueError()
        relative = urlsplit(location)
        if relative.scheme and (
            relative.scheme != "https" or not relative.netloc or not location.startswith("https://")
        ):
            raise ValueError()
        if relative.netloc and not location.startswith("https://"):
            raise ValueError()
        if any(part in {".", ".."} for part in relative.path.split("/")):
            raise ValueError()
        target, host = public_url(urljoin(current, location))
        parts, original = urlsplit(target), urlsplit(current)
        if parts.netloc not in {host, host + ":443"} or host != original.hostname or parts.query or parts.fragment:
            raise ValueError()
        if not parts.path.startswith("/") or any(not part for part in parts.path.split("/")[1:-1]):
            raise ValueError()
        if service_base is not None and not parts.path.startswith(urlsplit(service_base).path):
            raise ValueError()
        return "https://" + host + parts.path
    except ValueError:
        raise ReadFault("redirect_refused") from None


class RegistryReadSession:
    """Keep source authority, clocks, byte accounting and publication in one run."""

    def __init__(
        self,
        request: object,
        *,
        _monotonic: Callable[[], float] = time.monotonic,
        _utc: Callable[[], datetime] = _utc_now,
        _sleep: Callable[[float], None] = time.sleep,
        _http_factory: Callable[[], HttpAttempt] = HttpAttempt,
        _tls_factory: Callable[[], TLSAttempt] = TLSAttempt,
        _capacity_limits: _CapacityLimits | None = None,
        _sam_factory: Callable[[], SamAttempt] = SamAttempt,
        _sam_resolver: Resolver = environment_resolver,
        _snapshot_factory: Callable[[SnapshotRegistry], RegistrySnapshot] = load_snapshot,
        _bootstrap_factory: Callable[[], RDAPBootstrap] = load_bootstrap,
        _xml_trust: _TrustedCertificate | None = None,
    ) -> None:
        self._request = validated_request(request)
        self._monotonic, self._utc, self._sleep = _monotonic, _utc, _sleep
        self._http_factory, self._tls_factory = _http_factory, _tls_factory
        self._sam_factory, self._snapshot_factory = _sam_factory, _snapshot_factory
        self._credentials = SamCredentialCache(_sam_resolver)
        self._bootstrap_factory, self._xml_trust = _bootstrap_factory, _xml_trust
        self._http_location: tuple[str, ...] = ()
        self._http_content_types: tuple[str, ...] = ()
        self._quarantined: set[bytes] = set()
        self._begun = False
        self._started_at = self._now()
        self._deadline = self._tick() + 60.0
        self._capacity = CapacityPlan(self.request, _limits=_capacity_limits)
        self._reads: list[dict[str, Any]] = []
        self._observations: list[RegistryObservation] = []
        self._diagnostics: list[RegistryDiagnostic] = []
        self._attempts = 0
        self._raw_bytes = self._decoded_bytes = 0
        self._active = False
        self._result: RegistryLookupResult | None = None

    @property
    def request(self) -> RegistryLookupRequest:
        return validated_request(self._request)

    def _tick(self) -> float:
        value = self._monotonic()
        if (type(value) is not int and type(value) is not float) or not math.isfinite(value):
            raise RegistryInputError("invalid_result")
        return value

    def _now(self) -> datetime:
        value = self._utc()
        clock_text(value)
        return value

    def _remaining(self) -> float:
        value = self._deadline - self._tick()
        if value <= 0:
            raise ReadFault("deadline_exceeded")
        return value

    def _begin(self, registry: RegistryName, target: object) -> RegistryLookupResult | None:
        check = validated_request(
            {"registry": registry, "target": target, "scope_label": self.request.root.scope_label}
        )
        if check.model_dump(mode="json") != self.request.model_dump(mode="json") or self._active:
            raise RegistryInputError("invalid_request")
        if self._result is not None:
            return RegistryLookupResult.model_validate(self._result)
        if self._begun:
            raise RegistryInputError("invalid_request")
        self._begun = True
        self._active = True
        return None

    def _read(self, *, kind: str, method: str) -> dict[str, Any]:
        if len(self._reads) >= 24:
            raise ReadFault("read_limit")
        ordinal = len(self._reads)
        read: dict[str, Any] = {
            "read_id": read_identifier(self.request, ordinal),
            "registry": self.request.root.registry,
            "ordinal": ordinal,
            "method": method,
            "template": _TEMPLATES[self.request.root.registry],
            "query_scope": self.request,
            "transport_kind": kind,
            "status": "unavailable",
            "freshness": "unknown",
            "http_status": None,
            "network_attempts": 0,
            "attempted_pages": 0,
            "accepted_pages": 0,
            "source_records": 0,
            "admitted_records": 0,
            "raw_bytes": None if kind in {"tls", "none"} else 0,
            "decoded_bytes": None if kind in {"tls", "none"} else 0,
            "body_complete": False,
            "source_digest": None,
            "retrieved_at": self._now(),
            "publisher_date": None,
            "publisher_version": None,
            "snapshot_source": None,
            "cache_state": "not_applicable",
            "transport_verified": None,
            "source_signature": "not_applicable",
        }
        self._reads.append(read)
        return read

    def _diagnose(self, code: DiagnosticCode, read: dict[str, Any] | None = None) -> None:
        read_id = None if read is None else read["read_id"]
        item = diagnostic(code, read_id)
        if any(previous.code == code and previous.source_read_id == read_id for previous in self._diagnostics):
            return
        if len(self._diagnostics) < 63:
            self._diagnostics.append(item)
        elif len(self._diagnostics) == 63:
            self._diagnostics.append(diagnostic("diagnostic_limit"))

    def _charge(self, read: dict[str, Any], raw: int, decoded: int) -> None:
        if any(type(value) is not int or value < 0 for value in (raw, decoded)):
            raise RegistryInputError("invalid_result")
        read["raw_bytes"] += raw
        read["decoded_bytes"] += decoded
        self._raw_bytes += raw
        self._decoded_bytes += decoded
        if max(self._raw_bytes, self._decoded_bytes) > _RUN_HTTP_BYTES:
            raise RegistryInputError("invalid_result")
        self._remaining()

    def _http(self, read: dict[str, Any], url: str) -> bytes:
        self._http_location = self._http_content_types = ()
        for ordinal in range(1, 4):
            self._remaining()
            if self._attempts >= 64:
                raise ReadFault("attempt_limit")
            if max(self._raw_bytes, self._decoded_bytes) + _ATTEMPT_OBSERVED_BYTES > _RUN_HTTP_BYTES:
                raise ReadFault("run_byte_limit")
            attempt = self._http_factory()
            self._attempts += 1
            read["network_attempts"] += 1
            read["attempted_pages"] += 1
            code: DiagnosticCode | None = None
            content: bytes | None = None
            try:
                content = attempt.fetch(
                    url,
                    remaining=self._remaining,
                    consume=lambda raw, decoded: self._charge(read, raw, decoded),
                    max_bytes=65_536 if self.request.root.registry == "security-txt" else 1_048_576,
                )
            except (HttpFault, TransportError) as error:
                code = cast(DiagnosticCode, error.code)
                if code == "offline_refused":
                    self._attempts -= 1
                    read["network_attempts"] -= 1
            finally:
                read["http_status"] = attempt.status_code
                self._http_location, self._http_content_types = attempt.location, attempt.content_types
                if attempt.cleanup_failed:
                    self._diagnose("cleanup_failure", read)
            if content is not None:
                read["body_complete"] = True
                read["source_digest"] = hashlib.sha256(content).hexdigest()
                read["retrieved_at"] = self._now()
                read["transport_verified"] = True
                return content
            if code is None:
                raise ReadFault("invalid_response")
            retryable = code == "timeout" or (code == "http_error" and attempt.status_code in _RETRY_STATUSES)
            if not retryable:
                raise ReadFault(code)
            if ordinal == 3:
                raise ReadFault("retry_exhausted")
            delay = _retry_wait(attempt.retry_after, attempt=ordinal, now=self._now(), remaining=self._remaining())
            self._sleep(delay)
        raise ReadFault("retry_exhausted")

    def _http_redirected(
        self, read: dict[str, Any], url: str, *, service_base: str | None = None
    ) -> tuple[bytes, str, list[dict[str, Any]]]:
        current = url
        visited = {(urlsplit(url).hostname, urlsplit(url).path)}
        redirects: list[dict[str, Any]] = []
        while True:
            try:
                return self._http(read, current), current, redirects
            except ReadFault as error:
                if error.code != "redirect_refused":
                    raise
                if read["http_status"] not in {301, 302, 303, 307, 308} or len(redirects) >= 3:
                    raise ReadFault("redirect_refused") from None
                if len(self._http_location) != 1:
                    raise ReadFault("redirect_refused") from None
                target = _redirect_target(current, self._http_location[0], service_base=service_base)
                key = (urlsplit(target).hostname, urlsplit(target).path)
                if key in visited:
                    raise ReadFault("redirect_refused") from None
                visited.add(key)
                redirects.append({"from": current, "to": target, "status": read["http_status"]})
                current = target

    def _admit_adapter(
        self,
        read: dict[str, Any],
        candidate: AdapterCandidate,
        *,
        identity: dict[str, Any],
        shape: str,
        matched: str,
        projector: Projector,
        freshness: Freshness = "current_observation",
    ) -> None:
        identity["source_correspondence"] = candidate.correspondence
        identity["controller_checks"] = candidate.checks
        identity["source_syntax_issues"] = list(candidate.diagnostics)
        if candidate.diagnostics:
            self._diagnose("syntax_invalid", read)
        self._admit_page(
            read, [_Admission(candidate.selected, identity, shape, matched)], projector, freshness=freshness
        )

    def read_incommon(self, target: EntityTarget, projector: Projector) -> RegistryLookupResult:
        cached = self._begin("incommon", target)
        if cached is not None:
            return cached
        target = cast(EntityTarget, self.request.root.target)
        read = self._read(kind="https", method="GET")
        try:
            require_xml_extra()
            self._remaining()
            url = mdq_url(target.entity_id)
            content = self._http(read, url)
            candidate = adapt_incommon(content, target.entity_id, self._now(), _trust=self._xml_trust)
            self._remaining()
            read["source_signature"] = "verified"
            read["source_records"] = 1
            self._admit_adapter(
                read,
                candidate,
                identity={"entityID": target.entity_id, "retrieval_uri": url},
                shape="verified_entity_descriptor_adapter",
                matched=target.entity_id,
                projector=projector,
            )
        except (ReadFault, XMLSignatureError) as error:
            self._diagnose(error.code, read)
        except ValueError:
            self._diagnose("invalid_response", read)
        finally:
            self._active = False
        return self._finish()

    def read_security_txt(self, target: HostnameTarget, projector: Projector) -> RegistryLookupResult:
        cached = self._begin("security-txt", target)
        if cached is not None:
            return cached
        target = cast(HostnameTarget, self.request.root.target)
        query_hostname = canonical_hostname(target.hostname)
        read = self._read(kind="https", method="GET")
        try:
            original = "https://" + query_hostname + "/.well-known/security.txt"
            content, final_url, redirects = self._http_redirected(read, original)
            if len(self._http_content_types) != 1:
                raise ReadFault("invalid_response")
            candidate = adapt_security_txt(content, self._http_content_types[0], self._now(), retrieved_url=final_url)
            checks = candidate.checks
            if (
                not checks["contact_present"]
                or not checks["expires_single"]
                or not checks["preferred_languages_at_most_one"]
            ):
                self._diagnose("syntax_invalid", read)
            if checks["canonical_lists_retrieval_uri"] is False:
                self._diagnose("syntax_invalid", read)
            if checks["expires_stale"] is True:
                freshness: Freshness = "stale"
                self._diagnose("expired_source", read)
            elif checks["expires_future"] is None:
                freshness = "unknown"
                self._diagnose("source_time_unsupported", read)
            else:
                freshness = "current_observation"
            if checks["expiry_beyond_365_days"] is True:
                self._diagnose("expiry_beyond_one_year", read)
            if candidate.selected["signed"]:
                read["source_signature"] = "unverified"
                self._diagnose("signature_unverified", read)
            read["source_records"] = 1
            self._admit_adapter(
                read,
                candidate,
                identity={
                    "hostname": query_hostname,
                    "initial_retrieval_uri": original,
                    "retrieval_uri": final_url,
                    "redirects": redirects,
                },
                shape="security_text_adapter",
                matched=query_hostname,
                projector=projector,
                freshness=freshness,
            )
        except ReadFault as error:
            self._diagnose(error.code, read)
        except AdapterError as error:
            self._diagnose("body_limit" if error.code.endswith("capacity_exceeded") else "invalid_response", read)
        except ValueError:
            self._diagnose("invalid_response", read)
        finally:
            self._active = False
        return self._finish()

    def read_rdap(self, target: DomainTarget, projector: Projector) -> RegistryLookupResult:
        cached = self._begin("rdap", target)
        if cached is not None:
            return cached
        target = cast(DomainTarget, self.request.root.target)
        query_domain = canonical_hostname(target.domain)
        read = self._read(kind="https", method="GET")
        try:
            self._remaining()
            bootstrap = self._bootstrap_factory()
            self._remaining()
            read["snapshot_source"] = "data/rdap/bootstrap.json"
            read["publisher_date"] = bootstrap.publication
            read["publisher_version"] = "1.0"
            try:
                selection = bootstrap.select(query_domain)
            except SnapshotFault:
                raise ReadFault("destination_refused") from None
            publication = normalized_source_time(selection.publication)
            now = self._now()
            if publication is None or datetime.fromisoformat(publication.replace("Z", "+00:00")) > now:
                freshness: Freshness = "unknown"
                self._diagnose("source_time_unsupported", read)
            elif now - datetime.fromisoformat(publication.replace("Z", "+00:00")) > timedelta(days=30):
                freshness = "stale"
            else:
                freshness = "current_observation"
            content, url, redirects = self._http_redirected(
                read, selection.service_base + "domain/" + query_domain, service_base=selection.service_base
            )
            body = parse_strict_json(content)
            if type(body) is not dict:
                raise ReadFault("invalid_response")
            read["source_records"] = 1
            if body.get("objectClassName") != "domain" or type(body.get("ldhName")) is not str:
                raise ReadFault("identity_mismatch")
            ldh = cast(str, body["ldhName"])
            if not ldh.isascii() or canonical_hostname(ldh) != query_domain:
                raise ReadFault("identity_mismatch")
            unicode_name = body.get("unicodeName")
            if type(unicode_name) is str:
                if not unicode_name.isascii():
                    self._diagnose("source_name_comparison_unsupported", read)
                else:
                    try:
                        agrees = canonical_hostname(unicode_name) == query_domain
                    except ValueError:
                        agrees = False
                    if not agrees:
                        self._diagnose("source_name_conflict", read)
            identity = {
                "domain": query_domain,
                "ldhName": ldh,
                "bootstrap": {
                    "sha256": selection.bootstrap_sha256,
                    "publication": selection.publication,
                    "matched_suffix": selection.suffix,
                    "selected_service_base": selection.service_base,
                    "alternatives": list(selection.alternatives),
                    "source": parse_strict_json(selection.source_bytes),
                },
                "retrieval_uri": url,
                "redirects": redirects,
            }
            self._admit_page(
                read, [_Admission(body, identity, "domain_record", query_domain)], projector, freshness=freshness
            )
        except (ReadFault, SnapshotFault) as error:
            self._diagnose(error.code, read)
        except ValueError:
            self._diagnose("invalid_response", read)
        finally:
            self._active = False
        return self._finish()

    def _quarantine(self, identities: set[bytes], read: dict[str, Any]) -> None:
        if not identities:
            return
        self._quarantined.update(identities)
        self._observations = [
            item
            for item in self._observations
            if canonical_json(checked_json(item.model_dump(mode="json")["source_identity"])) not in identities
        ]
        self._recount()
        self._diagnose("duplicate_conflict", read)

    def _recount(self) -> None:
        for read in self._reads:
            read["admitted_records"] = sum(item.source_read_id == read["read_id"] for item in self._observations)

    def _admit_page(
        self,
        read: dict[str, Any],
        rows: list[_Admission],
        projector: Projector,
        *,
        freshness: Freshness = "current_observation",
        status: CollectionStatus = "complete",
    ) -> None:
        self._remaining()
        if sum(item["accepted_pages"] for item in self._reads) >= 20:
            raise ReadFault("page_limit")
        frozen = []
        for row in rows:
            source_bytes = canonical_json(checked_json(row.source))
            expected_bytes = canonical_json(
                checked_json(expected_fields(self.request.root.registry, row.shape, row.source))
            )
            identity_bytes = canonical_json(checked_json(row.identity))
            frozen.append(
                (source_bytes, expected_bytes, identity_bytes, row.shape, row.matched_identity, row.match_basis)
            )
        existing = {
            canonical_json(checked_json(item.model_dump(mode="json")["source_identity"])): canonical_json(
                checked_json(item.model_dump(mode="json")["fields"])
            )
            for item in self._observations
        }
        conflicts: set[bytes] = set()
        selected = dict(existing)
        for _, fields, identity, _, _, _ in frozen:
            if identity in selected and selected[identity] != fields:
                conflicts.add(identity)
            selected[identity] = fields
        # A contradictory identity remains quarantined even if this page cannot be admitted.
        self._quarantine(conflicts, read)
        candidate = list(self._observations)
        seen = {canonical_json(checked_json(item.model_dump(mode="json")["source_identity"])) for item in candidate}
        for source_bytes, expected_bytes, identity_bytes, shape, matched_identity, basis in frozen:
            view = parse_strict_json(source_bytes)
            if type(view) is not dict:
                raise ReadFault("invalid_response")
            projection: dict[str, Any] | None = None
            with suppress(Exception):
                projection = validate_fields(self.request.root.registry, shape, projector(view))
            if projection is None or canonical_json(checked_json(projection)) != expected_bytes:
                raise ReadFault("projection_mismatch")
            if identity_bytes in self._quarantined or identity_bytes in seen:
                continue
            literal_identity = parse_strict_json(identity_bytes)
            if type(literal_identity) is not dict:
                raise ReadFault("invalid_response")
            try:
                observation = make_observation(
                    self.request.root.registry,
                    read["read_id"],
                    source_identity=literal_identity,
                    matched_identity=matched_identity,
                    fields=projection,
                    field_coverage=field_coverage(self.request.root.registry, shape, projection),
                    source_times=source_times(self.request.root.registry, shape, projection),
                    match_basis=basis,
                    transport_verified=read["transport_verified"],
                    source_signature=read["source_signature"],
                )
            except RegistryInputError as error:
                raise ReadFault(
                    "observation_limit" if error.code == "observation_limit" else "invalid_response"
                ) from None
            candidate.append(observation)
            seen.add(identity_bytes)
        refusal = self._capacity.refusal(candidate)
        if refusal is not None:
            raise ReadFault(refusal)
        self._remaining()
        self._observations = candidate
        read["accepted_pages"] += 1
        read["status"] = status
        read["freshness"] = freshness
        self._recount()
        if any(
            stamp.literal is not None and stamp.representation != "source_text" and stamp.normalized_utc is None
            for observation in candidate
            if observation.source_read_id == read["read_id"]
            for stamp in observation.source_times
        ):
            self._diagnose("source_time_unsupported", read)

    def _admit_one(
        self,
        read: dict[str, Any],
        source: dict[str, Any],
        *,
        identity: dict[str, Any],
        shape: str,
        projector: Projector,
    ) -> None:
        self._admit_page(read, [_Admission(source, identity, shape, request_identity(self.request))], projector)

    def _sam(self, read: dict[str, Any], page: int) -> bytes:
        self._remaining()
        if self._attempts >= 64:
            raise ReadFault("attempt_limit")
        if max(self._raw_bytes, self._decoded_bytes) + _ATTEMPT_OBSERVED_BYTES > _RUN_HTTP_BYTES:
            raise ReadFault("run_byte_limit")
        attempt = self._sam_factory()
        self._attempts += 1
        read["network_attempts"] += 1
        read["attempted_pages"] += 1
        try:
            content = attempt.fetch(
                self.request,
                page=page,
                credentials=self._credentials,
                remaining=self._remaining,
                utc_now=self._now,
                consume=lambda raw, decoded: self._charge(read, raw, decoded),
            )
        except (SamTransportError, TransportError, CredentialError) as error:
            if error.code == "offline_refused":
                self._attempts -= 1
                read["network_attempts"] -= 1
            raise ReadFault(cast(DiagnosticCode, error.code)) from None
        finally:
            read["http_status"] = attempt.status_code
            if attempt.cleanup_failed:
                self._diagnose("cleanup_failure", read)
        read["body_complete"] = True
        read["source_digest"] = hashlib.sha256(content).hexdigest()
        read["retrieved_at"] = self._now()
        read["transport_verified"] = True
        return content

    @staticmethod
    def _occurrence(read: dict[str, Any], page: int, index: int) -> dict[str, Any]:
        return {
            "locator_type": "local_response_occurrence",
            "body_sha256": read["source_digest"],
            "request_page": page,
            "source_row": index,
        }

    def read_sam_entity(self, target: UEITarget, projector: Projector) -> RegistryLookupResult:
        cached = self._begin("sam-entity", target)
        if cached is not None:
            return cached
        target = cast(UEITarget, self.request.root.target)
        read = self._read(kind="https", method="GET")
        try:
            body = parse_strict_json(self._sam(read, 0))
            if type(body) is not dict or type(body.get("entityData")) is not list:
                raise ReadFault("invalid_response")
            rows = cast(list[Any], body["entityData"])
            if len(rows) > 10:
                raise ReadFault("invalid_response")
            read["source_records"] = len(rows)
            admissions = []
            for index, row in enumerate(rows):
                if type(row) is not dict or type(row.get("entityRegistration")) is not dict:
                    raise ReadFault("invalid_response")
                source = row["entityRegistration"]
                if source.get("ueiSAM") != target.uei or source.get("samRegistered") != "Yes":
                    raise ReadFault("identity_mismatch")
                identity = self._occurrence(read, 0, index)
                identity["ueiSAM"] = source["ueiSAM"]
                if "entityEFTIndicator" in source:
                    identity["entityEFTIndicator"] = source["entityEFTIndicator"]
                matched = "sam-entity:occurrence:" + hashlib.sha256(canonical_json(checked_json(identity))).hexdigest()
                admissions.append(_Admission(source, identity, "registered_entity_occurrence", matched))
            self._admit_page(read, admissions, projector, status="partial" if admissions else "unavailable")
        except ReadFault as error:
            self._diagnose(error.code, read)
        except ValueError:
            self._diagnose("invalid_response", read)
        finally:
            self._active = False
        self._diagnose("source_terminal_unproven", read)
        self._diagnose("traversal_incomplete")
        return self._finish()

    def read_sam_exclusions(
        self, target: UEITarget | SAMOrganizationTarget, projector: Projector
    ) -> RegistryLookupResult:
        cached = self._begin("sam-exclusions", target)
        if cached is not None:
            return cached
        target = cast(UEITarget | SAMOrganizationTarget, self.request.root.target)
        total: int | None = None
        signatures: set[str] = set()
        read: dict[str, Any] | None = None
        try:
            for page in range(20):
                read = self._read(kind="https", method="GET")
                body = parse_strict_json(self._sam(read, page))
                if (
                    type(body) is not dict
                    or type(body.get("totalRecords")) is not int
                    or cast(int, body["totalRecords"]) < 0
                    or type(body.get("excludedEntity")) is not list
                ):
                    raise ReadFault("invalid_response")
                declared = cast(int, body["totalRecords"])
                rows = cast(list[Any], body["excludedEntity"])
                read["source_records"] = len(rows)
                if total is not None and declared != total:
                    raise ReadFault("total_changed")
                total = declared
                if len(rows) != min(10, max(declared - 10 * page, 0)):
                    raise ReadFault("traversal_incomplete")
                signature = hashlib.sha256(canonical_json(checked_json(rows))).hexdigest()
                if signature in signatures:
                    raise ReadFault("repeated_page")
                signatures.add(signature)
                admissions = []
                for index, source in enumerate(rows):
                    if type(source) is not dict:
                        raise ReadFault("invalid_response")
                    expected_fields("sam-exclusions", "firm_exclusion_occurrence", source)
                    details, identification = source.get("exclusionDetails"), source.get("exclusionIdentification")
                    if (
                        type(details) is not dict
                        or details.get("classificationType") != "Firm"
                        or type(identification) is not dict
                    ):
                        raise ReadFault("identity_mismatch")
                    if type(target) is UEITarget:
                        if identification.get("ueiSAM") != target.uei:
                            raise ReadFault("identity_mismatch")
                        basis: MatchBasis = "exact_identifier"
                    else:
                        if type(identification.get("entityName")) is not str:
                            raise ReadFault("identity_mismatch")
                        if normalized_organization_name(identification["entityName"]) != normalized_organization_name(
                            cast(SAMOrganizationTarget, target).organization_name
                        ):
                            continue
                        basis = "exact_normalized_name"
                    identity = self._occurrence(read, page, index)
                    matched = (
                        "sam-exclusions:occurrence:"
                        + hashlib.sha256(canonical_json(checked_json(identity))).hexdigest()
                    )
                    admissions.append(_Admission(source, identity, "firm_exclusion_occurrence", matched, basis))
                self._admit_page(read, admissions, projector)
                if (page + 1) * 10 >= declared:
                    break
            else:
                raise ReadFault("page_limit")
        except ReadFault as error:
            self._diagnose(error.code, read)
        except ValueError:
            self._diagnose("invalid_response", read)
        finally:
            self._active = False
        if type(target) is SAMOrganizationTarget and not self._observations:
            self._diagnose("source_match_scope_limited")
        return self._finish()

    def read_snapshot(self, target: SnapshotTarget, projector: Projector) -> RegistryLookupResult:
        registry = self.request.root.registry
        if registry not in {"fedramp", "cmvp", "fcc-covered-list"}:
            raise RegistryInputError()
        cached = self._begin(registry, target)
        if cached is not None:
            return cached
        target = cast(SnapshotTarget, self.request.root.target)
        read = self._read(kind="snapshot", method="LOCAL")
        try:
            self._remaining()
            snapshot = self._snapshot_factory(registry)
            self._remaining()
            manifest = snapshot.manifest()
            storage = snapshot.storage()
            read["raw_bytes"] = snapshot.byte_count if storage is None else storage["bytes"]
            read["decoded_bytes"] = snapshot.byte_count
            read["body_complete"] = True
            read["source_digest"] = snapshot.sha256 if storage is None else storage["sha256"]
            read["retrieved_at"] = self._now()
            read["publisher_date"] = manifest["as_of"]["literal"]
            versions = {source["publisher_version"] for source in manifest["sources"]}
            read["publisher_version"] = next(iter(versions)) if len(versions) == 1 else "multiple_source_versions"
            read["snapshot_source"] = snapshot.path if storage is None else storage["path"]
            read["attempted_pages"] = 1
            family = {"fedramp": "products", "cmvp": "certificates", "fcc-covered-list": "named_entries"}[registry]
            read["source_records"] = len(snapshot.family(family))
            freshness = snapshot.freshness(self._now())
            if freshness == "unknown":
                self._diagnose("source_time_unsupported", read)
            admissions = []
            for fact in snapshot.lookup(target):
                source = fact.detached()
                identity: dict[str, Any] = {
                    "snapshot_sha256": snapshot.sha256,
                    "full_tuple_sha256": snapshot.tuple_sha256,
                    "fact_family": family,
                    "source_index": fact.source_index,
                }
                if storage is not None:
                    identity["snapshot_storage"] = storage
                if registry == "fedramp":
                    matched = source["fields"]["id"]
                    shape, basis = "fedramp_product_record", "exact_identifier"
                    identity["product_id"] = matched
                elif registry == "cmvp":
                    matched = source["certificate_number"]
                    shape, basis = "cmvp_certificate_record", "exact_identifier"
                    identity["certificate_number"] = matched
                else:
                    ordinal = source["derived_appendix_a_row_ordinal"]
                    identity["derived_appendix_a_row_ordinal"] = ordinal
                    identity["publisher_row_identifier_presence"] = "absent"
                    matched = "fcc-covered-list:DA-26-957:appendix-A:row-" + str(ordinal)
                    shape, basis = "fcc_named_entry_observation", "exact_normalized_name"
                    source = snapshot.fcc_source(fact)
                admissions.append(_Admission(source, identity, shape, matched, cast(MatchBasis, basis)))
            self._admit_page(read, admissions, projector, freshness=freshness)
            if registry == "fcc-covered-list":
                self._diagnose("category_applicability_not_assessed", read)
                self._diagnose("indirect_affiliate_applicability_not_assessed", read)
                self._diagnose("conditional_approval_applicability_not_assessed", read)
        except (ReadFault, SnapshotFault) as error:
            self._diagnose(error.code, read)
        except ValueError:
            self._diagnose("snapshot_invalid", read)
        finally:
            self._active = False
        return self._finish()

    def _finish(self) -> RegistryLookupResult:
        finished_at = self._now()

        def result(run_id: str | None = None) -> RegistryLookupResult:
            return make_result(
                self.request,
                reads=[SourceRead.model_validate(read) for read in self._reads],
                observations=self._observations,
                diagnostics=self._diagnostics,
                started_at=self._started_at,
                finished_at=finished_at,
                run_id=run_id,
            )

        final = result()
        outward = RegistryLookupResult.model_validate(final)
        if self._tick() >= self._deadline:
            self._diagnose("deadline_exceeded")
            final = result(final.run_id)
            outward = RegistryLookupResult.model_validate(final)
        self._active = False
        self._result = final
        return outward

    def read_tls(self, target: HostnameTarget, projector: Projector) -> RegistryLookupResult:
        cached = self._begin("tls", target)
        if cached is not None:
            return cached
        target = cast(HostnameTarget, self.request.root.target)
        query_hostname = canonical_hostname(target.hostname)
        read = self._read(kind="tls", method="TLS")
        attempt = self._tls_factory()
        try:
            self._remaining()
            self._attempts += 1
            read["network_attempts"] = read["attempted_pages"] = 1
            source = attempt.fetch(query_hostname, remaining=self._remaining)
            read["source_records"] = 1
            read["retrieved_at"] = self._now()
            read["transport_verified"] = True
            read["body_complete"] = True
            read["source_digest"] = source["der_sha256"]
            self._admit_one(
                read, source, identity={"hostname": query_hostname}, shape="verified_tls_adapter", projector=projector
            )
        except (ReadFault, TransportError) as error:
            if error.code == "offline_refused":
                read["network_attempts"] = 0
                self._attempts -= 1
            self._diagnose(error.code, read)
        finally:
            if attempt.cleanup_failed:
                self._diagnose("cleanup_failure", read)
            self._active = False
        return self._finish()

    def read_gleif(self, target: LEITarget, projector: Projector) -> RegistryLookupResult:
        cached = self._begin("gleif", target)
        if cached is not None:
            return cached
        target = cast(LEITarget, self.request.root.target)
        read = self._read(kind="https", method="GET")
        try:
            body = parse_strict_json(self._http(read, "https://api.gleif.org/api/v1/lei-records/" + target.lei))
            if type(body) is not dict or type(body.get("data")) is not dict:
                raise ReadFault("invalid_response")
            source = cast(dict[str, Any], body["data"])
            read["source_records"] = 1
            attributes = source.get("attributes")
            if (
                source.get("id") != target.lei
                or source.get("type") != "lei-records"
                or type(attributes) is not dict
                or attributes.get("lei") != target.lei
            ):
                raise ReadFault("identity_mismatch")
            self._admit_one(read, source, identity={"lei": target.lei}, shape="lei_record", projector=projector)
        except ReadFault as error:
            self._diagnose(error.code, read)
        except ValueError:
            self._diagnose("invalid_response", read)
        finally:
            self._active = False
        return self._finish()

    def read_ssl_labs(self, target: EndpointTarget, projector: Projector) -> RegistryLookupResult:
        cached = self._begin("ssl-labs", target)
        if cached is not None:
            return cached
        target = cast(EndpointTarget, self.request.root.target)
        read = self._read(kind="none", method="DISABLED")
        self._diagnose("live_disabled", read)
        return self._finish()
