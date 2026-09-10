"""Bounded synchronous reads for selected storage configuration."""

from __future__ import annotations

import logging
import math
import re
import threading
import time
import zlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast, get_args
from urllib.parse import urlsplit
from xml.etree.ElementTree import Element

import httpx
from evidentia_core import network_guard
from evidentia_core.audit.provenance import new_run_id

from ._contracts import (
    ComponentId,
    DiagnosticCode,
    ProjectedComponent,
    ProviderName,
    S3Target,
    StorageRetentionCollectRequest,
    StorageRetentionComponentResult,
    StorageRetentionDiagnostic,
    StorageRetentionInputError,
    StorageTarget,
    build_component_url,
    component_ids,
    make_component_result,
    parse_request,
    projection_size,
    target_identity,
    target_provider,
    validated_request,
)
from ._credentials import AwsCredentials, BearerCredentials, CredentialResolution, StorageCredentialProvider
from ._parsing import JsonValue, ParsingError, parse_strict_json, parse_strict_xml

RESPONSE_MAX_BYTES = 1_048_576
RUN_MAX_BYTES = 16_777_216
RUN_MAX_SECONDS = 120.0
PROJECTION_RUN_MAX_BYTES = 1_048_576


class ClientFault(ValueError):
    """A fixed diagnostic with no request or provider payload."""

    def __init__(self, code: str, status: int | None = None) -> None:
        self.code: DiagnosticCode = (
            cast(DiagnosticCode, code) if type(code) is str and code in get_args(DiagnosticCode) else "internal_error"
        )
        self.status = status if type(status) is int and 100 <= status <= 599 else None
        super().__init__(self.code)


_TRANSPORT_LOGGERS = (
    "httpx",
    "httpcore.connection",
    "httpcore.http11",
    "httpcore.http2",
    "httpcore.proxy",
    "httpcore.socks",
    "http.cookiejar",
)
_QUIET: ContextVar[bool] = ContextVar("storage_retention_transport_logs", default=False)
_FILTER_LOCK = threading.Lock()


class _ScopedTransportFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not _QUIET.get()


_FILTER = _ScopedTransportFilter()


@contextmanager
def quiet_transport_logs() -> Iterator[None]:
    """Suppress this operation's ordinary traces without hiding other threads."""
    with _FILTER_LOCK:
        for name in _TRANSPORT_LOGGERS:
            logger = logging.getLogger(name)
            if _FILTER not in logger.filters:
                logger.addFilter(_FILTER)
    token = _QUIET.set(True)
    try:
        yield
    finally:
        _QUIET.reset(token)


def read_bounded_body(
    response: httpx.Response,
    *,
    consume: Callable[[int, int], None],
    max_bytes: int = RESPONSE_MAX_BYTES,
) -> bytes:
    """Count delivered bytes before rejecting a response or allocating its body."""
    if type(max_bytes) is not int or not 1 <= max_bytes <= RESPONSE_MAX_BYTES:
        raise ClientFault("internal_error")
    output = bytearray()
    raw_count = 0
    encoding = response.headers.get("content-encoding", "identity").strip(" \t").lower()
    if encoding not in {"identity", "gzip"}:
        raise ClientFault("invalid_response")
    decoder = zlib.decompressobj(zlib.MAX_WBITS | 16) if encoding == "gzip" else None
    iterator = iter(response.iter_raw())
    while True:
        consume(0, 0)
        try:
            raw = next(iterator)
        except StopIteration:
            break
        raw_count += len(raw)
        consume(len(raw), len(raw) if decoder is None else 0)
        if raw_count > max_bytes:
            raise ClientFault("response_limit")
        if decoder is None:
            if len(output) + len(raw) > max_bytes:
                raise ClientFault("response_limit")
            output.extend(raw)
            continue
        if decoder.eof and raw:
            raise ClientFault("invalid_response")
        pending = raw
        while pending:
            consume(0, 0)
            try:
                decoded = decoder.decompress(pending, max_length=min(65_536, max_bytes - len(output) + 1))
            except zlib.error:
                raise ClientFault("invalid_response") from None
            remaining = decoder.unconsumed_tail
            consume(0, len(decoded))
            if len(output) + len(decoded) > max_bytes:
                raise ClientFault("response_limit")
            output.extend(decoded)
            if decoder.unused_data or (remaining == pending and not decoded):
                raise ClientFault("invalid_response")
            pending = remaining
    if decoder is not None and not decoder.eof:
        raise ClientFault("invalid_response")
    consume(0, 0)
    return bytes(output)


_SHORT_DAY = r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)"


_LONG_DAY = r"(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)"


_MONTH_NAMES = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


_MONTH = r"(?P<month>" + "|".join(_MONTH_NAMES) + ")"


_TIME = r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"


_HTTP_DATES = (
    re.compile(_SHORT_DAY + r", (?P<day>[0-9]{2}) " + _MONTH + r" (?P<year>[0-9]{4}) " + _TIME + r" GMT"),
    re.compile(_LONG_DAY + r", (?P<day>[0-9]{2})-" + _MONTH + r"-(?P<year>[0-9]{2}) " + _TIME + r" GMT"),
    re.compile(_SHORT_DAY + " " + _MONTH + r" (?P<day>[ 0-9][0-9]) " + _TIME + r" (?P<year>[0-9]{4})"),
)


def _http_date(value: str, now: datetime) -> datetime:
    for index, pattern in enumerate(_HTTP_DATES):
        match = pattern.fullmatch(value)
        if match is None:
            continue
        year = int(match["year"])
        month = _MONTH_NAMES.index(match["month"]) + 1
        day, hour, minute, second = (int(match[field]) for field in ("day", "hour", "minute", "second"))
        if second > 60:
            raise ClientFault("retry_after_invalid")
        try:
            if index == 1:
                year += now.year // 100 * 100
                if year < now.year - 50:
                    year += 100
                # A leap reference year allows calendar rollover before the century decision.
                candidate = datetime(2000, month, day, hour, minute, min(second, 59), tzinfo=UTC)
                candidate += timedelta(seconds=1 if second == 60 else 0)
                instant = (
                    year + candidate.year - 2000,
                    candidate.month,
                    candidate.day,
                    candidate.hour,
                    candidate.minute,
                    candidate.second,
                    0,
                )
                limit = (now.year + 50, now.month, now.day, now.hour, now.minute, now.second, now.microsecond)
                if instant > limit:
                    year -= 100
            result = datetime(year, month, day, hour, minute, min(second, 59), tzinfo=UTC)
            return result + timedelta(seconds=1 if second == 60 else 0)
        except (ValueError, OverflowError):
            raise ClientFault("retry_after_invalid") from None
    raise ClientFault("retry_after_invalid")


def retry_delay(header: str | None, *, attempt: int, now: datetime, remaining: float) -> float:
    """Honor Retry-After only when the next wait fits the collector budget."""
    if attempt not in {1, 2} or now.tzinfo is None or now.utcoffset() is None or not math.isfinite(remaining):
        raise ClientFault("internal_error")
    try:
        now = now.astimezone(UTC)
    except (ValueError, OverflowError):
        raise ClientFault("internal_error") from None
    if header is None:
        delay = float(attempt)
    else:
        value = header.strip(" \t")
        if not value or len(value) > 128:
            raise ClientFault("retry_after_invalid")
        if re.fullmatch(r"[0-9]+", value):
            significant = value.lstrip("0") or "0"
            if len(significant) > 2:
                raise ClientFault("run_budget_exhausted")
            delay = float(int(significant))
        else:
            delay = max(0.0, (_http_date(value, now) - now).total_seconds())
    if delay > 30 or delay > remaining:
        raise ClientFault("run_budget_exhausted")
    return delay


def _utc_now() -> datetime:
    return datetime.now(UTC)


class StorageRunContext:
    """Per-run clocks, counters and a detached validated request."""

    def __init__(
        self,
        request: object,
        *,
        utc_clock: Callable[[], datetime] = _utc_now,
        monotonic_clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        run_id_factory: Callable[[], str] = new_run_id,
    ) -> None:
        validated = validated_request(request)
        self._request_bytes = validated.model_dump_json(warnings="error").encode("utf-8")
        self._utc_clock = utc_clock
        self._monotonic_clock = monotonic_clock
        self._sleep = sleep
        self._last_tick: float | None = None
        self._last_utc: datetime | None = None
        self.started_at = self.utc_now()
        self._started_tick = self.tick()
        self.run_id = run_id_factory()
        if type(self.run_id) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", self.run_id):
            raise ClientFault("internal_error")
        self.raw_bytes = 0
        self.decoded_bytes = 0
        self.projection_bytes = 0
        self.exhausted = False

    @property
    def request(self) -> StorageRetentionCollectRequest:
        return parse_request(self._request_bytes)

    def utc_now(self) -> datetime:
        value = self._utc_clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ClientFault("internal_error")
        try:
            result = value.astimezone(UTC)
        except (ValueError, OverflowError):
            raise ClientFault("internal_error") from None
        if self._last_utc is not None and result < self._last_utc:
            raise ClientFault("internal_error")
        self._last_utc = result
        return result

    def tick(self) -> float:
        value = self._monotonic_clock()
        if type(value) not in {int, float}:
            raise ClientFault("internal_error")
        try:
            result = float(value)
        except (ValueError, OverflowError):
            raise ClientFault("internal_error") from None
        if not math.isfinite(result) or (self._last_tick is not None and result < self._last_tick):
            raise ClientFault("internal_error")
        self._last_tick = result
        return result

    def remaining(self) -> float:
        remaining = RUN_MAX_SECONDS - (self.tick() - self._started_tick)
        if self.exhausted or remaining <= 0:
            self.exhausted = True
            raise ClientFault("run_budget_exhausted")
        return remaining

    def consume(self, raw: int, decoded: int) -> None:
        if type(raw) is not int or type(decoded) is not int or raw < 0 or decoded < 0:
            raise ClientFault("internal_error")
        self.raw_bytes += raw
        self.decoded_bytes += decoded
        if self.raw_bytes > RUN_MAX_BYTES or self.decoded_bytes > RUN_MAX_BYTES:
            self.exhausted = True
            raise ClientFault("run_budget_exhausted")
        self.remaining()

    def wait(self, delay: float) -> None:
        if not math.isfinite(delay) or delay < 0 or delay > 30 or delay > self.remaining():
            raise ClientFault("run_budget_exhausted")
        self._sleep(delay)
        self.remaining()


@dataclass(frozen=True)
class ComponentResponse:
    """A bounded parsed response supplied to one pure field projector."""

    component_id: ComponentId
    http_status: int
    body: JsonValue | Element = field(repr=False)
    source_etag: str | None = field(default=None, repr=False)


class ComponentProjector(Protocol):
    def __call__(self, response: ComponentResponse, target: StorageTarget) -> ProjectedComponent: ...


@dataclass
class _Reading:
    attempts: int = 0
    raw_bytes: int = 0
    decoded_bytes: int = 0
    started_at: datetime | None = None
    finished_at: datetime | None = None
    http_status: int | None = None
    cleanup_failed: bool = False


class _ObservedCloseStream(httpx.SyncByteStream):
    """Separate cleanup failure from an incomplete body read."""

    def __init__(self, stream: httpx.SyncByteStream, reading: _Reading) -> None:
        self._stream = stream
        self._reading = reading
        self._closed = False

    def __iter__(self) -> Iterator[bytes]:
        yield from self._stream

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._stream.close()
        except Exception:
            self._reading.cleanup_failed = True


def _s3_error_code(root: Element) -> str:
    namespaces = {"", "{http://s3.amazonaws.com/doc/2006-03-01/}"}
    prefix = next((prefix for prefix in namespaces if root.tag == prefix + "Error"), None)
    if prefix is None or root.attrib or (root.text or "").strip() or (root.tail or "").strip():
        raise ClientFault("invalid_response")
    allowed = {"Code", "Message", "Resource", "RequestId", "HostId", "BucketName"}
    found: dict[str, str] = {}
    for child in root:
        if not isinstance(child.tag, str) or not child.tag.startswith(prefix):
            raise ClientFault("invalid_response")
        name = child.tag[len(prefix) :]
        if name not in allowed or name in found or child.attrib or len(child) or (child.tail or "").strip():
            raise ClientFault("invalid_response")
        found[name] = child.text or ""
    code = found.get("Code", "")
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,127}", code) is None:
        raise ClientFault("invalid_response")
    return code


class StorageReadSession:
    """One owned transport and credential resolution for a finite read plan."""

    def __init__(
        self,
        request: object,
        *,
        credentials: StorageCredentialProvider,
        transport_factory: Callable[[], httpx.BaseTransport] | None = None,
        utc_clock: Callable[[], datetime] = _utc_now,
        monotonic_clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        run_id_factory: Callable[[], str] = new_run_id,
    ) -> None:
        self.context = StorageRunContext(
            request,
            utc_clock=utc_clock,
            monotonic_clock=monotonic_clock,
            sleep=sleep,
            run_id_factory=run_id_factory,
        )
        self._credentials = credentials
        self._transport_factory = transport_factory
        self._client: httpx.Client | None = None
        self._resolution: CredentialResolution | None = None
        self._rejected = False
        self._closed = False
        plan_request = self.context.request.root
        self._plan = tuple(
            (target_identity(target), component)
            for target in plan_request.targets
            for component in component_ids(plan_request.provider)
        )
        self._next_component = 0
        self.cleanup_failed = False

    def _material(self, provider: ProviderName) -> AwsCredentials | BearerCredentials:
        self.context.remaining()
        if self._rejected:
            raise ClientFault("credential_rejected")
        if self._resolution is None:
            try:
                selected = self._credentials.resolve(provider)
                if type(selected) is not CredentialResolution:
                    raise ValueError
                self._resolution = CredentialResolution(selected.material, selected.diagnostic)
            except Exception:
                self._resolution = CredentialResolution(None, "credential_unavailable")
            self.context.remaining()
        selected = self._resolution
        if selected.material is None:
            raise ClientFault(selected.diagnostic or "credential_unavailable")
        material = selected.material
        if provider == "s3" and type(material) is AwsCredentials:
            material = AwsCredentials(
                material.access_key_id, material.secret_access_key, material.session_token, material.expires_at
            )
        elif provider != "s3" and type(material) is BearerCredentials:
            material = BearerCredentials(material.token, material.expires_at)
        else:
            raise ClientFault("configuration_invalid")
        if material.expires_at is not None and material.expires_at <= self.context.utc_now():
            raise ClientFault("credential_unavailable")
        return material

    def _owned_client(self) -> httpx.Client:
        if self._client is None:
            transport = (
                self._transport_factory()
                if self._transport_factory is not None
                else httpx.HTTPTransport(trust_env=False, http1=True, http2=False, retries=0)
            )
            try:
                self._client = httpx.Client(
                    transport=transport, trust_env=False, http1=True, http2=False, follow_redirects=False
                )
            except Exception:
                try:
                    transport.close()
                except Exception:
                    self.cleanup_failed = True
                raise ClientFault("internal_error") from None
        return self._client

    def _send_once(
        self, component_id: ComponentId, target: StorageTarget, reading: _Reading
    ) -> tuple[int, bytes, str | None, str | None]:
        from ._aws_signing import SigningError, sign_s3_get

        provider = target_provider(target)
        self.context.remaining()
        if self._rejected or self._resolution is not None:
            self._material(provider)
        url = build_component_url(component_id, target)
        parsed = httpx.URL(url)
        parts = urlsplit(url)
        expected_path = (parts.path + "?" + parts.query).encode("ascii")
        if parsed.scheme != "https" or parsed.raw_path != expected_path or str(parsed) != url:
            raise ClientFault("endpoint_mismatch")
        self.context.remaining()
        try:
            network_guard.check_url(url, subsystem="storage-retention")
            addresses = network_guard.enforce_public_host(url, subsystem="storage-retention")
        except network_guard.OfflineViolationError:
            raise ClientFault("offline_refused") from None
        except network_guard.SSRFBlockedError:
            raise ClientFault("unsafe_destination") from None
        self.context.remaining()
        if not addresses:
            raise ClientFault("unsafe_destination")
        self._material(provider)
        response: httpx.Response | None = None

        def received(value: httpx.Response) -> None:
            nonlocal response
            response = value
            if not isinstance(value.stream, httpx.SyncByteStream):
                raise ClientFault("invalid_response")
            value.stream = _ObservedCloseStream(value.stream, reading)
            status = value.status_code
            if type(status) is not int or not 100 <= status <= 599:
                raise ClientFault("invalid_response")
            reading.http_status = status
            # Refuse before HTTPX prepares a redirect request from Location.
            if 300 <= status <= 399:
                raise ClientFault("redirect_refused", status)
            if status == 401:
                self._rejected = True
                raise ClientFault("credential_rejected", status)

        try:
            with quiet_transport_logs(), network_guard.pin_resolved_host(parsed.host, addresses):
                owned = self._owned_client()
                material = self._material(provider)
                if provider == "s3":
                    if not isinstance(material, AwsCredentials) or not isinstance(target, S3Target):
                        raise ClientFault("configuration_invalid")
                    try:
                        headers = sign_s3_get(
                            url, region=target.region, expected_owner=target.expected_owner, credentials=material
                        )
                    except SigningError as exc:
                        raise ClientFault(exc.code) from None
                else:
                    if not isinstance(material, BearerCredentials):
                        raise ClientFault("configuration_invalid")
                    headers = {"Authorization": "Bearer " + material.token, "Host": parts.netloc}
                headers = dict(headers)
                headers["Accept"] = "application/xml" if provider == "s3" else "application/json"
                headers["Accept-Encoding"] = "gzip, identity"
                request = httpx.Request("GET", parsed, headers=headers)
                allowed = {"host", "authorization", "accept", "accept-encoding"}
                if provider == "s3":
                    allowed |= {
                        "x-amz-date",
                        "x-amz-content-sha256",
                        "x-amz-security-token",
                        "x-amz-expected-bucket-owner",
                    }
                if (
                    request.method != "GET"
                    or request.url.raw_path != expected_path
                    or request.content != b""
                    or request.headers["host"] != parts.netloc
                    or not set(request.headers) <= allowed
                    or any(request.headers.get(name) != value for name, value in headers.items())
                ):
                    raise ClientFault("endpoint_mismatch")
                started = self.context.utc_now() if reading.started_at is None else reading.started_at
                self._material(provider)
                remaining = self.context.remaining()
                request.extensions["timeout"] = {
                    "connect": min(5.0, remaining),
                    "pool": min(5.0, remaining),
                    "read": min(20.0, remaining),
                    "write": min(20.0, remaining),
                }
                owned.event_hooks["response"] = [received]
                reading.started_at = started
                reading.attempts += 1
                response = owned.send(request, stream=True, auth=None, follow_redirects=False)
                status = reading.http_status
                if status is None:
                    raise ClientFault("internal_error")
                self.context.remaining()

                def consume(raw: int, decoded: int) -> None:
                    reading.raw_bytes += raw
                    reading.decoded_bytes += decoded
                    self.context.consume(raw, decoded)

                body = read_bounded_body(response, consume=consume)
                etags = response.headers.get_list("etag")
                if len(etags) > 1:
                    raise ClientFault("invalid_response", status)
                etag = etags[0] if etags else None
                if etag is not None and (
                    not etag or len(etag) > 1024 or any(ord(ch) < 32 or ord(ch) >= 127 for ch in etag)
                ):
                    raise ClientFault("invalid_response", status)
                return status, body, response.headers.get("retry-after"), etag
        finally:
            with quiet_transport_logs():
                if response is not None:
                    try:
                        response.close()
                    except Exception:
                        reading.cleanup_failed = True
                if self._client is not None:
                    try:
                        self._client.event_hooks["response"] = []
                        self._client.cookies.clear()
                    except Exception:
                        reading.cleanup_failed = True

    def read_component(
        self, component_id: ComponentId, target: StorageTarget, projector: ComponentProjector
    ) -> StorageRetentionComponentResult:
        if self._closed:
            raise ClientFault("internal_error")
        provider = self.context.request.root.provider
        selected = next((item for item in self.context.request.root.targets if item == target), None)
        if selected is None or target_provider(target) != provider or component_id not in component_ids(provider):
            raise ClientFault("endpoint_mismatch")
        key = (target_identity(target), component_id)
        if self._next_component >= len(self._plan) or self._plan[self._next_component] != key:
            raise ClientFault("endpoint_mismatch")
        self._next_component += 1
        reading = _Reading()
        projection: ProjectedComponent | None = None
        diagnostics: list[StorageRetentionDiagnostic] = []
        try:
            for attempt in range(1, 4):
                self.context.remaining()
                try:
                    status, body, retry_after, etag = self._send_once(component_id, selected, reading)
                except (httpx.ConnectTimeout, httpx.ReadTimeout):
                    if attempt == 3:
                        raise ClientFault("timeout") from None
                    self.context.wait(
                        retry_delay(
                            None, attempt=attempt, now=self.context.utc_now(), remaining=self.context.remaining()
                        )
                    )
                    continue
                except httpx.HTTPError:
                    raise ClientFault("upstream_error") from None
                if status in {408, 429, 500, 502, 503, 504}:
                    if attempt == 3:
                        raise ClientFault(
                            "rate_limited" if status == 429 else "timeout" if status == 408 else "upstream_error",
                            status,
                        )
                    self.context.wait(
                        retry_delay(
                            retry_after, attempt=attempt, now=self.context.utc_now(), remaining=self.context.remaining()
                        )
                    )
                    continue
                self.context.remaining()
                if provider != "s3" and status != 200:
                    raise ClientFault(
                        "forbidden" if status == 403 else "resource_not_found" if status == 404 else "upstream_error",
                        status,
                    )
                parsed = parse_strict_xml(body) if provider == "s3" else parse_strict_json(body)
                if provider == "s3" and status != 200:
                    if not isinstance(parsed, Element):
                        raise ClientFault("invalid_response", status)
                    code = _s3_error_code(parsed)
                    if (status, code) in {(400, "ExpiredToken"), (400, "InvalidToken"), (403, "InvalidAccessKeyId")}:
                        self._rejected = True
                        raise ClientFault("credential_rejected", status)
                    if not (
                        status == 404
                        and component_id == "s3-object-lock"
                        and code == "ObjectLockConfigurationNotFoundError"
                    ):
                        raise ClientFault(
                            "forbidden"
                            if status == 403
                            else "resource_not_found"
                            if status == 404
                            else "upstream_error",
                            status,
                        )
                self.context.remaining()
                projection_target = type(selected).model_validate(selected)
                candidate = projector(ComponentResponse(component_id, status, parsed, etag), projection_target)
                if type(candidate) is not ProjectedComponent:
                    raise ClientFault("invalid_response", status)
                try:
                    amount = projection_size(candidate)
                except StorageRetentionInputError as exc:
                    raise ClientFault(
                        "projection_limit" if exc.code == "projection_limit" else "invalid_response", status
                    ) from None
                except (ValueError, TypeError, AttributeError):
                    raise ClientFault("invalid_response", status) from None
                if self.context.projection_bytes + amount > PROJECTION_RUN_MAX_BYTES:
                    self.context.exhausted = True
                    raise ClientFault("projection_limit", status)
                self.context.remaining()
                self.context.projection_bytes += amount
                projection = candidate
                break
        except ClientFault as exc:
            projection = None
            diagnostics.append(StorageRetentionDiagnostic(code=exc.code, http_status=exc.status))
        except (ParsingError, StorageRetentionInputError):
            projection = None
            diagnostics.append(StorageRetentionDiagnostic(code="invalid_response", http_status=reading.http_status))
        except ImportError:
            raise
        except Exception:
            projection = None
            diagnostics.append(StorageRetentionDiagnostic(code="internal_error", http_status=reading.http_status))
        if reading.cleanup_failed:
            diagnostics.append(StorageRetentionDiagnostic(code="cleanup_failed", http_status=reading.http_status))
        if reading.attempts:
            reading.finished_at = self.context.utc_now()
        return make_component_result(
            component_id,
            selected,
            attempts=reading.attempts,
            raw_bytes=reading.raw_bytes,
            decoded_bytes=reading.decoded_bytes,
            started_at=reading.started_at,
            finished_at=reading.finished_at,
            http_status=reading.http_status,
            projection=projection,
            diagnostics=tuple(diagnostics),
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with quiet_transport_logs():
            if self._client is not None:
                try:
                    self._client.close()
                except Exception:
                    self.cleanup_failed = True
        self._resolution = None
