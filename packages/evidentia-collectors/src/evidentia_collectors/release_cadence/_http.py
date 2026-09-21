"""One bounded release page using the existing pinned public transport."""

from __future__ import annotations

import hashlib
import re
import ssl
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from typing import cast

import httpx
from evidentia_core.release_cadence._limits import (
    MAX_PAGES,
    MAX_SAFE_INTEGER,
    PAGE_BYTES,
    RAW_CHUNK_BYTES,
    TOTAL_BYTES,
    Budget,
    ReleaseFailure,
    integer,
)
from evidentia_core.release_cadence._source import canonical_repository

from ..registries._http_backend import OwnedHTTPTransport, OwnedState
from ..registries._tls import TransportError, approved_destination, tls_context

_LINK = re.compile(
    r'[ \t]*<([^<>\r\n]+)>[ \t]*;[ \t]*rel[ \t]*=[ \t]*(next|prev|first|last|"next"|"prev"|"first"|"last")[ \t]*'
)
_TARGET = re.compile(r"https://api[.]github[.]com/repos/([^/?#]+)/([^/?#]+)/releases[?]([^#]+)")
_MEDIA = re.compile(
    rb'(application/json|application/vnd[.]github[+]json)(?:[ \t]*;[ \t]*charset[ \t]*=[ \t]*(?:utf-8|"utf-8"))?',
    re.IGNORECASE,
)
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def request_url(owner: str, repository: str, page: int) -> str:
    canonical_owner, canonical_repo = canonical_repository(owner, repository)
    integer(page, 1, MAX_PAGES)
    return f"https://api.github.com/repos/{canonical_owner}/{canonical_repo}/releases?per_page=100&page={page}"


def link_relations(values: tuple[bytes, ...], owner: str, repository: str, page: int) -> dict[str, int]:
    """Validate every Link field, relation and target before following next."""
    owner, repository = canonical_repository(owner, repository)
    integer(page, 1, MAX_PAGES)
    if type(values) is not tuple or len(values) > 4:
        raise ReleaseFailure("unsupported_link")
    relations: dict[str, int] = {}
    size = 0
    for raw in values:
        if type(raw) is not bytes:
            raise ReleaseFailure("unsupported_link")
        size += len(raw)
        if not raw or size > 8192 or any(byte > 126 or (byte < 32 and byte != 9) for byte in raw):
            raise ReleaseFailure("unsupported_link")
        text = raw.decode("ascii")
        position = 0
        while position < len(text):
            match = _LINK.match(text, position)
            if match is None or len(relations) >= 4:
                raise ReleaseFailure("unsupported_link")
            target, relation = match.groups()
            relation = relation.strip('"')
            if len(target) > 2048 or relation in relations:
                raise ReleaseFailure("unsupported_link")
            parsed = _TARGET.fullmatch(target)
            if parsed is None:
                raise ReleaseFailure("unsupported_link")
            native_owner, native_repo, query = parsed.groups()
            try:
                if canonical_repository(native_owner, native_repo) != (owner, repository):
                    raise ReleaseFailure("unsupported_link")
            except ReleaseFailure:
                raise ReleaseFailure("unsupported_link") from None
            pairs = query.split("&")
            if len(pairs) != 2 or "per_page=100" not in pairs:
                raise ReleaseFailure("unsupported_link")
            other = pairs[1] if pairs[0] == "per_page=100" else pairs[0]
            if re.fullmatch(r"page=[1-9][0-9]{0,15}", other) is None:
                raise ReleaseFailure("unsupported_link")
            number = int(other[5:])
            if number > MAX_SAFE_INTEGER:
                raise ReleaseFailure("unsupported_link")
            relations[relation] = number
            position = match.end()
            if position == len(text):
                break
            if text[position] != "," or position + 1 == len(text):
                raise ReleaseFailure("unsupported_link")
            position += 1
    following = relations.get("next")
    if (
        ("first" in relations and relations["first"] != 1)
        or ("prev" in relations and (page == 1 or relations["prev"] != page - 1))
        or (following is not None and following != page + 1)
        or ("last" in relations and relations["last"] < max(page, following or page))
        or (following is None and relations.get("last", page) > page)
    ):
        raise ReleaseFailure("unsupported_link")
    return relations


def next_page(values: tuple[bytes, ...], owner: str, repository: str, page: int) -> int | None:
    return link_relations(values, owner, repository, page).get("next")


@dataclass(slots=True)
class EntityTotals:
    """Observed delivery counters, including the first refused unit."""

    raw: int = 0
    decoded: int = 0


@dataclass(frozen=True, slots=True)
class _Metadata:
    links: tuple[bytes, ...]
    encoding: str
    content_length: int | None


def _metadata(response: httpx.Response, raw_remaining: int) -> _Metadata:
    if type(response.headers) is not httpx.Headers:
        raise ReleaseFailure("invalid_response")
    headers = response.headers.raw
    if type(headers) is not list or len(headers) > 64:
        raise ReleaseFailure("invalid_response")
    retained: dict[bytes, list[bytes]] = {}
    total = 0
    for pair in headers:
        if type(pair) is not tuple or len(pair) != 2:
            raise ReleaseFailure("invalid_response")
        name, value = pair
        if type(name) is not bytes or type(value) is not bytes:
            raise ReleaseFailure("invalid_response")
        total += len(name) + len(value)
        if total > 32768 or not _HEADER_NAME.fullmatch(name) or b"\r" in value or b"\n" in value:
            raise ReleaseFailure("invalid_response")
        folded = name.lower()
        if folded in {b"link", b"content-type", b"content-encoding", b"content-length", b"transfer-encoding"}:
            retained.setdefault(folded, []).append(value)
    media = retained.get(b"content-type", [])
    if len(media) != 1 or _MEDIA.fullmatch(media[0].strip(b" \t")) is None:
        raise ReleaseFailure("unsupported_media")
    encodings = retained.get(b"content-encoding", [])
    if len(encodings) > 1 or (encodings and encodings[0].strip(b" \t").lower() not in (b"identity", b"gzip")):
        raise ReleaseFailure("unsupported_encoding")
    encoding = encodings[0].strip(b" \t").decode("ascii").lower() if encodings else "identity"
    lengths = retained.get(b"content-length", [])
    length = None
    if lengths:
        if len(lengths) != 1 or b"transfer-encoding" in retained:
            raise ReleaseFailure("invalid_response")
        spelling = lengths[0].strip(b" \t")
        if re.fullmatch(rb"[0-9]{1,16}", spelling) is None:
            raise ReleaseFailure("invalid_response")
        length = int(spelling)
        if length > MAX_SAFE_INTEGER:
            raise ReleaseFailure("invalid_response")
        if length > raw_remaining:
            raise ReleaseFailure("raw_limit")
    links = retained.get(b"link", [])
    if len(links) > 4 or sum(map(len, links)) > 8192:
        raise ReleaseFailure("unsupported_link")
    return _Metadata(tuple(links), encoding, length)


def _status_reason(status: int) -> str:
    if 300 <= status <= 399:
        return "redirect_refused"
    if 500 <= status <= 599:
        return "upstream_server_error"
    return {
        401: "upstream_unauthorized",
        403: "upstream_forbidden",
        404: "upstream_not_found",
        429: "upstream_rate_limited",
    }.get(status, "upstream_http_error")


def _classify(error: Exception) -> ReleaseFailure:
    if isinstance(error, ReleaseFailure):
        return error
    if isinstance(error, TransportError):
        code = error.code
        if type(code) is str and code in {
            "offline_refused",
            "destination_refused",
            "dns_failure",
            "tls_failure",
            "connection_failure",
            "timeout",
            "invalid_response",
        }:
            return ReleaseFailure(code)
    if isinstance(error, (httpx.TimeoutException, TimeoutError)):
        return ReleaseFailure("timeout")
    if isinstance(error, ssl.SSLError):
        return ReleaseFailure("tls_failure")
    if isinstance(error, (httpx.NetworkError, OSError)):
        cause: BaseException | None = error
        for _ in range(8):
            if isinstance(cause, ssl.SSLError):
                return ReleaseFailure("tls_failure")
            if cause is not None:
                cause = cause.__cause__ if cause.__cause__ is not None else cause.__context__
        return ReleaseFailure("connection_failure")
    return ReleaseFailure("invalid_response")


class _ClosingStream(httpx.SyncByteStream):
    def __init__(self, stream: httpx.SyncByteStream, state: OwnedState) -> None:
        self._stream = stream
        self._state = state
        self._closed = False

    def __iter__(self) -> Iterator[bytes]:
        yield from self._stream

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._state.close(self._stream.close)


class HttpAttempt:
    """A single-use, unauthenticated page attempt with explicit cleanup ownership."""

    def __init__(self) -> None:
        self.status_code: int | None = None
        self.links: tuple[bytes, ...] = ()
        self.raw = 0
        self.decoded = 0
        self.links_available = False
        self.raw_body_complete = False
        self.raw_body_sha256: str | None = None
        self.body_complete = False
        self.body_sha256: str | None = None
        self.cleanup_failed = False
        self._used = False

    def fetch(self, owner: str, repository: str, page: int, *, budget: Budget, totals: EntityTotals) -> bytes:
        if (
            type(self) is not HttpAttempt
            or self._used
            or type(budget) is not Budget
            or type(totals) is not EntityTotals
        ):
            raise ReleaseFailure("invalid_response")
        self._used = True
        integer(totals.raw, 0, TOTAL_BYTES)
        integer(totals.decoded, 0, TOTAL_BYTES)
        deadline = budget.deadline
        if type(deadline) is not float:
            raise ReleaseFailure("clock_invalid")

        def remaining() -> float:
            if type(budget.deadline) is not float or budget.deadline != deadline:
                raise ReleaseFailure("clock_invalid")
            budget.check(15)
            available = budget.remaining() - 15
            if available <= 0:
                raise ReleaseFailure("deadline_exceeded")
            return available

        def charge(raw: int, decoded: int) -> None:
            self.raw += raw
            self.decoded += decoded
            totals.raw += raw
            totals.decoded += decoded
            if self.raw > PAGE_BYTES or totals.raw > TOTAL_BYTES:
                raise ReleaseFailure("raw_limit")
            if self.decoded > PAGE_BYTES or totals.decoded > TOTAL_BYTES:
                raise ReleaseFailure("decoded_limit")
            remaining()

        owned = OwnedState(remaining)
        response: httpx.Response | None = None
        transport: OwnedHTTPTransport | None = None
        primary: BaseException | None = None
        result: bytes | None = None
        chunks: list[bytes] = []
        raw_digest = hashlib.sha256()
        url = request_url(owner, repository, page)
        try:
            remaining()
            with approved_destination(url) as approved:
                try:
                    remaining()
                    context = tls_context()
                    remaining()
                    transport = OwnedHTTPTransport(context=context, approved=approved, state=owned)
                    available = remaining()
                    request = httpx.Request(
                        "GET",
                        url,
                        headers={
                            "Accept": "application/vnd.github+json",
                            "X-GitHub-Api-Version": "2026-03-10",
                            "User-Agent": "evidentia-collectors",
                            "Accept-Encoding": "gzip, identity",
                            "Connection": "close",
                        },
                        extensions={
                            "timeout": {
                                "connect": min(5.0, available),
                                "pool": min(5.0, available),
                                "read": min(10.0, available),
                                "write": min(10.0, available),
                            }
                        },
                    )
                    response = transport.handle_request(request)
                    if (
                        type(response) is not httpx.Response
                        or type(response.status_code) is not int
                        or not 100 <= response.status_code <= 599
                    ):
                        raise ReleaseFailure("invalid_response")
                    if not isinstance(response.stream, httpx.SyncByteStream):
                        raise ReleaseFailure("invalid_response")
                    response.stream = _ClosingStream(response.stream, owned)
                    self.status_code = response.status_code
                    remaining()
                    if self.status_code != 200:
                        raise ReleaseFailure(_status_reason(self.status_code))
                    metadata = _metadata(response, min(PAGE_BYTES, TOTAL_BYTES - totals.raw))
                    self.links = metadata.links
                    self.links_available = True
                    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if metadata.encoding == "gzip" else None
                    iterator = iter(response.iter_raw())
                    while True:
                        remaining()
                        try:
                            raw = next(iterator)
                        except StopIteration:
                            break
                        if type(raw) is not bytes or len(raw) > RAW_CHUNK_BYTES:
                            raise ReleaseFailure("invalid_response")
                        if decoder is None:
                            charge(len(raw), len(raw))
                            raw_digest.update(raw)
                            chunks.append(raw)
                        else:
                            charge(len(raw), 0)
                            raw_digest.update(raw)
                            pending = raw
                            while pending:
                                remaining()
                                capacity = min(PAGE_BYTES - self.decoded, TOTAL_BYTES - totals.decoded)
                                try:
                                    decoded = decoder.decompress(pending, capacity + 1)
                                except zlib.error:
                                    raise ReleaseFailure("invalid_response") from None
                                charge(0, len(decoded))
                                chunks.append(decoded)
                                if decoder.unused_data:
                                    raise ReleaseFailure("invalid_response")
                                pending = decoder.unconsumed_tail
                    if metadata.content_length is not None and self.raw != metadata.content_length:
                        raise ReleaseFailure("invalid_response")
                    self.raw_body_complete = True
                    self.raw_body_sha256 = raw_digest.hexdigest()
                    if decoder is not None and not decoder.eof:
                        raise ReleaseFailure("invalid_response")
                    remaining()
                    result = b"".join(chunks)
                    self.body_sha256 = hashlib.sha256(result).hexdigest()
                    self.body_complete = True
                    remaining()
                except BaseException as error:
                    primary = error
                    raise
        except BaseException as error:
            if primary is None:
                primary = error
        finally:
            if response is not None:
                owned.close(response.close)
            if transport is not None:
                owned.close(transport.close)
            owned.close_all()
            self.cleanup_failed = owned.cleanup_failed
            chunks.clear()
        if primary is None:
            primary = owned.primary or owned.cleanup_cancellation
        if primary is not None:
            if not isinstance(primary, Exception):
                raise primary
            raise _classify(primary) from None
        if self.cleanup_failed or result is None:
            raise ReleaseFailure("cleanup_failure" if self.cleanup_failed else "invalid_response")
        remaining()
        return cast(bytes, result)
