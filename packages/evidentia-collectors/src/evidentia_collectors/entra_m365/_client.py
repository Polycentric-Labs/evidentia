"""Fixed Graph collection routes with bounded, guarded HTTP reads."""

from __future__ import annotations

import logging
import math
import os
import re
import threading
import zlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol, cast, get_args
from urllib.parse import quote, unquote, urlencode, urlsplit
from weakref import WeakKeyDictionary

import httpx
from evidentia_core import network_guard
from evidentia_core.audit.retry import build_retrying
from tenacity import RetryCallState

from ._contracts import (
    PAGE_MAX_BYTES,
    AuthMode,
    CapabilityName,
    DiagnosticCode,
    EntraM365CollectRequest,
    EntraM365RunContext,
    EntraM365SourceRead,
    _Reading,
    clock_text,
    parse_strict_json,
    project_record,
)

GRAPH_ORIGIN = "https://graph.microsoft.com"


ROUTES: dict[CapabilityName, str] = {
    "conditional-access": "/v1.0/identity/conditionalAccess/policies",
    "authentication-registration": "/v1.0/reports/authenticationMethods/userRegistrationDetails",
    "sign-ins": "/v1.0/auditLogs/signIns",
    "directory-roles": "/v1.0/directoryRoles",
    "managed-devices": "/v1.0/deviceManagement/managedDevices",
    "retention-labels": "/v1.0/security/labels/retentionLabels",
    "defender-alerts": "/v1.0/security/alerts_v2",
    "defender-incidents": "/v1.0/security/incidents",
}


_EXCLUDED_QUERY_NAMES = frozenset({"$expand", "$batch", "$delta", "$deltatoken"})


def validate_destination(capability: CapabilityName, url: str) -> httpx.URL:
    """Refuse normalization tricks before credentials or sockets are used."""
    try:
        if capability not in ROUTES or not isinstance(url, str) or len(url.encode("utf-8")) > 16384:
            raise ValueError
        if any(ord(c) <= 32 or ord(c) >= 127 for c in url) or "\\" in url or "#" in url:
            raise ValueError
        if re.search(r"%(?![0-9A-Fa-f]{2})", url):
            raise ValueError
        parts = urlsplit(url)
        if (
            parts.scheme != "https"
            or parts.netloc not in {"graph.microsoft.com", "graph.microsoft.com:443"}
            or parts.path != ROUTES[capability]
        ):
            raise ValueError
        names = set()
        if parts.query:
            for item in parts.query.split("&"):
                name = item.partition("=")[0]
                decoded = unquote(name, encoding="utf-8", errors="strict")
                if re.fullmatch(r"[$@]?[A-Za-z_][A-Za-z0-9_.-]*", decoded) is None:
                    raise ValueError
                normalized = decoded.casefold()
                if normalized in names or normalized in _EXCLUDED_QUERY_NAMES:
                    raise ValueError
                names.add(normalized)
        result = httpx.URL(url)
        expected = (parts.path + ("?" + parts.query if "?" in url else "")).encode("ascii")
        if result.raw_path != expected:
            raise ValueError
        return result
    except (ValueError, UnicodeError, httpx.InvalidURL):
        raise ValueError("unsafe_destination") from None


_TRANSPORT_LOGGERS = (
    "httpx",
    "httpcore.connection",
    "httpcore.http11",
    "httpcore.http2",
    "httpcore.proxy",
    "httpcore.socks",
)


_QUIET: ContextVar[bool] = ContextVar("entra_m365_transport_logs", default=False)


_FILTER_LOCK = threading.Lock()


class _ScopedTransportFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not _QUIET.get()


_FILTER = _ScopedTransportFilter()


@contextmanager
def quiet_transport_logs() -> Iterator[None]:
    """Protect this operation's library traces while retaining audit events."""
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
    response: httpx.Response, *, consume: Callable[[int, int], None], max_bytes: int = PAGE_MAX_BYTES
) -> bytes:
    """Count received bytes and bound each decompression allocation."""
    output = bytearray()
    raw_count = 0
    with quiet_transport_logs():
        try:
            encoding = response.headers.get("content-encoding", "identity").strip(" \t").lower()
            if encoding not in {"identity", "gzip"}:
                raise ValueError("invalid_envelope")
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
                    raise ValueError("response_limit")
                if decoder is None:
                    if len(output) + len(raw) > max_bytes:
                        raise ValueError("response_limit")
                    output.extend(raw)
                    continue
                if decoder.eof and raw:
                    raise ValueError("invalid_envelope")
                pending = raw
                while pending:
                    consume(0, 0)
                    try:
                        decoded = decoder.decompress(pending, max_length=min(65536, max_bytes - len(output) + 1))
                    except zlib.error:
                        raise ValueError("invalid_envelope") from None
                    remaining = decoder.unconsumed_tail
                    consume(0, len(decoded))
                    if len(output) + len(decoded) > max_bytes:
                        raise ValueError("response_limit")
                    output.extend(decoded)
                    if decoder.unused_data or (remaining == pending and not decoded):
                        raise ValueError("invalid_envelope")
                    pending = remaining
            if decoder is not None and not decoder.eof:
                raise ValueError("invalid_envelope")
            consume(0, 0)
            return bytes(output)
        finally:
            response.close()


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
            raise ValueError("retry_after_invalid")
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
            raise ValueError("retry_after_invalid") from None
    raise ValueError("retry_after_invalid")


def retry_delay(header: str | None, *, attempt: int, now: datetime, remaining: float) -> float:
    """Honor Retry-After only when the next wait fits the collector budget."""
    if attempt not in {1, 2} or now.tzinfo is None or now.utcoffset() is None or not math.isfinite(remaining):
        raise ValueError("internal_error")
    try:
        now = now.astimezone(UTC)
    except (ValueError, OverflowError):
        raise ValueError("internal_error") from None
    if header is None:
        delay = float(attempt)
    else:
        value = header.strip(" \t")
        if not value or len(value) > 128:
            raise ValueError("retry_after_invalid")
        if re.fullmatch(r"[0-9]+", value):
            significant = value.lstrip("0") or "0"
            if len(significant) > 2:
                raise ValueError("retry_after_budget")
            delay = float(int(significant))
        else:
            delay = max(0.0, (_http_date(value, now) - now).total_seconds())
    if delay > 10 or delay > remaining:
        raise ValueError("retry_after_budget")
    return delay


CredentialGroup = Literal["primary", "retention"]


@dataclass(frozen=True)
class _CredentialResolution:
    token: str | None = field(repr=False)
    declared_auth_mode: AuthMode | None
    diagnostic: DiagnosticCode | None = None


class _CredentialProvider(Protocol):
    def resolve(self, group: CredentialGroup) -> _CredentialResolution: ...


class _EnvironmentCredentials:
    def resolve(self, group: CredentialGroup) -> _CredentialResolution:
        if group == "retention":
            return _CredentialResolution(os.environ.get("ENTRA_M365_RETENTION_ACCESS_TOKEN"), "delegated")
        if group != "primary":
            raise ValueError("configuration_invalid")
        mode = os.environ.get("ENTRA_M365_AUTH_MODE", "application")
        if mode not in {"application", "delegated"}:
            return _CredentialResolution(None, None, "configuration_invalid")
        declared: AuthMode = "application" if mode == "application" else "delegated"
        return _CredentialResolution(os.environ.get("ENTRA_M365_ACCESS_TOKEN"), declared)


@dataclass
class _CredentialState:
    resolutions: dict[CredentialGroup, _CredentialResolution] = field(default_factory=dict)
    primary_denied: bool = False


class _Fault(ValueError):
    def __init__(self, code: DiagnosticCode, status: int | None = None) -> None:
        self.code = code
        self.status = status
        super().__init__(code)


class _Retryable(Exception):
    def __init__(self, delay: float) -> None:
        self.delay = delay
        super().__init__("transient_graph_failure")


def _wait_value(state: RetryCallState) -> float:
    error = state.outcome.exception() if state.outcome is not None else None
    if not isinstance(error, _Retryable):
        raise _Fault("internal_error")
    return error.delay


def _safe_code(error: ValueError) -> DiagnosticCode:
    for code in get_args(DiagnosticCode.__value__):
        if error.args == (code,):
            return cast(DiagnosticCode, code)
    return "internal_error"


class EntraM365GraphReader:
    def __init__(self, *, credentials: _CredentialProvider, client: httpx.Client | None = None) -> None:
        self._credentials = credentials
        self._client = client
        self._owned = client is None
        self._closed = False
        self._states: WeakKeyDictionary[EntraM365RunContext, _CredentialState] = WeakKeyDictionary()
        self._state_lock = threading.Lock()

    def _state(self, context: EntraM365RunContext) -> _CredentialState:
        with self._state_lock:
            if context not in self._states:
                self._states[context] = _CredentialState()
            return self._states[context]

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._states.clear()
        if self._owned and self._client is not None:
            try:
                with quiet_transport_logs():
                    self._client.close()
            except Exception:
                raise ValueError("internal_error") from None

    def _resolve(self, group: CredentialGroup, state: _CredentialState, read: _Reading) -> str:
        if group not in state.resolutions:
            value = self._credentials.resolve(group)
            if not isinstance(value, _CredentialResolution):
                raise _Fault("configuration_invalid")
            state.resolutions[group] = value
        resolution = state.resolutions[group]
        read.mode = resolution.declared_auth_mode
        if resolution.diagnostic is not None:
            code = (
                resolution.diagnostic
                if resolution.diagnostic in {"configuration_invalid", "credentials_missing"}
                else "configuration_invalid"
            )
            raise _Fault(code)
        if resolution.declared_auth_mode not in {"application", "delegated"} or (
            group == "retention" and resolution.declared_auth_mode != "delegated"
        ):
            raise _Fault("configuration_invalid")
        if resolution.token is None or resolution.token == "":
            raise _Fault("credentials_missing")
        if (
            not isinstance(resolution.token, str)
            or len(resolution.token) > 16384
            or any(ord(char) < 33 or ord(char) > 126 for char in resolution.token)
        ):
            raise _Fault("configuration_invalid")
        return resolution.token

    def _send_once(self, url: str, read: _Reading, state: _CredentialState, attempt: int) -> bytes:
        target = validate_destination(read.name, url)
        read.remaining()
        try:
            network_guard.check_url(GRAPH_ORIGIN, subsystem="entra-m365")
            addresses = network_guard.enforce_public_host(GRAPH_ORIGIN, subsystem="entra-m365")
        except network_guard.OfflineViolationError:
            raise _Fault("configuration_invalid") from None
        except network_guard.SSRFBlockedError:
            raise _Fault("unsafe_destination") from None
        group: CredentialGroup = "retention" if read.name == "retention-labels" else "primary"
        token = self._resolve(group, state, read)
        remaining = read.remaining()
        request = httpx.Request(
            "GET",
            target,
            headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/json",
                "Accept-Encoding": "gzip, identity",
            },
            extensions={
                "timeout": {
                    "connect": min(5.0, remaining),
                    "pool": min(5.0, remaining),
                    "read": min(20.0, remaining),
                    "write": min(20.0, remaining),
                }
            },
        )
        if self._client is None:
            transport = httpx.HTTPTransport(trust_env=False, http2=False, retries=0)
            self._client = httpx.Client(transport=transport, trust_env=False, http2=False, follow_redirects=False)
        try:
            with quiet_transport_logs(), network_guard.pin_resolved_host("graph.microsoft.com", addresses):
                read.note_attempt()
                response = self._client.send(request, stream=True, follow_redirects=False, auth=None)
                status = response.status_code
                if 300 <= status < 400 or status in {401, 403}:
                    if status == 401 and group == "primary":
                        state.primary_denied = True
                    response.close()
                    raise _Fault(
                        "redirect_refused"
                        if status < 400
                        else "authentication_failed"
                        if status == 401
                        else "permission_denied",
                        status,
                    )
                header = response.headers.get("retry-after")
                body = read_bounded_body(response, consume=read.consume)
        except (httpx.ConnectError, httpx.TimeoutException):
            if attempt >= 3:
                raise _Fault("retry_exhausted") from None
            delay = retry_delay(None, attempt=attempt, now=read.context.utc_now(), remaining=read.remaining())
            raise _Retryable(delay) from None
        except httpx.HTTPError:
            raise _Fault("upstream_error") from None
        if status in {429, 500, 502, 503, 504}:
            if attempt >= 3:
                raise _Fault("retry_exhausted", status)
            delay = retry_delay(header, attempt=attempt, now=read.context.utc_now(), remaining=read.remaining())
            raise _Retryable(delay)
        if status != 200:
            raise _Fault("upstream_error", status)
        return body

    def _read_page(self, url: str, read: _Reading, state: _CredentialState) -> bytes:
        retrying = build_retrying(function_name="entra_m365_graph_get", max_attempts=3, retry_on=(_Retryable,))
        retrying.wait = _wait_value
        retrying.sleep = read.wait
        for attempt in retrying:
            with attempt:
                return self._send_once(url, read, state, attempt.retry_state.attempt_number)
        raise _Fault("internal_error")

    def read_collection(
        self, capability: CapabilityName, request: EntraM365CollectRequest, run_context: EntraM365RunContext
    ) -> EntraM365SourceRead:
        request = EntraM365CollectRequest.model_validate(request)
        if (
            self._closed
            or capability not in ROUTES
            or capability not in request.capabilities
            or request != run_context.request
        ):
            raise ValueError("invalid_collection_request")
        state = self._state(run_context)
        group: CredentialGroup = "retention" if capability == "retention-labels" else "primary"
        mode = (
            state.resolutions[group].declared_auth_mode
            if group in state.resolutions
            else "delegated"
            if group == "retention"
            else None
        )
        read = run_context.begin(capability, mode)
        try:
            if read.started_at is None:
                return read.finish_source()
            if group == "primary" and state.primary_denied:
                raise _Fault("authentication_failed", 401)
            url = GRAPH_ORIGIN + ROUTES[capability]
            if capability == "sign-ins":
                query = (
                    "createdDateTime ge "
                    + clock_text(run_context.window_start)
                    + " and createdDateTime le "
                    + clock_text(run_context.window_end)
                )
                url += "?" + urlencode({"$filter": query}, quote_via=quote, safe="$")
            seen: set[tuple[str, bytes]] = set()
            while True:
                target = validate_destination(capability, url)
                key = (str(target.host), target.raw_path)
                if key in seen:
                    raise _Fault("continuation_loop")
                seen.add(key)
                data = parse_strict_json(self._read_page(url, read, state))
                if not isinstance(data, dict):
                    raise _Fault("invalid_envelope")
                rows = data.get("value")
                if not isinstance(rows, list) or len(rows) > 10000:
                    raise _Fault("invalid_envelope")
                records = [project_record(capability, row) for row in rows]
                next_link = data.get("@odata.nextLink")
                if next_link is not None:
                    if capability == "directory-roles" or not isinstance(next_link, str) or not next_link:
                        raise _Fault("continuation_invalid")
                    following = validate_destination(capability, next_link)
                    if (str(following.host), following.raw_path) in seen:
                        raise _Fault("continuation_loop")
                can_continue = read.admit_page(records, continuation=next_link is not None)
                if next_link is None or not can_continue:
                    break
                url = next_link
        except _Fault as error:
            read.add_diagnostic(error.code, status=error.status)
        except ValueError as error:
            read.add_diagnostic(_safe_code(error))
        except Exception:
            read.add_diagnostic("internal_error")
        return read.finish_source()
