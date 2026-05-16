"""BaseSaaSCollector ABC + canonical exception hierarchy
(v0.8.0 P0.4 + M-4 closure)."""

from __future__ import annotations

import contextlib
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Self

if TYPE_CHECKING:
    import httpx


class SaaSCollectorError(Exception):
    """Base class for SaaS collector failures.

    Subclass-specific exceptions inherit from this for typed
    error handling in callers.
    """


class SaaSAuthError(SaaSCollectorError):
    """Authentication / authorization failure.

    Maps to HTTP 401 / 403 from upstream APIs. Indicates the
    operator's credential is missing / invalid / scope-deficient.
    """


class SaaSConnectionError(SaaSCollectorError):
    """Network / TLS / DNS / timeout failure.

    Maps to httpx connection-class exceptions. Indicates the
    upstream API was unreachable or the request timed out.
    """


class SaaSQueryError(SaaSCollectorError):
    """API-side error (HTTP 4xx other than 401/403, or 5xx).

    Indicates the request reached the API but the API rejected
    it (validation error, rate-limit, server error, etc.).
    """


class BaseSaaSCollector(ABC):
    """Common scaffolding for SaaS API collectors.

    Provides:
      - Token validation (strip whitespace; reject empty)
      - httpx.Client lifecycle (lazy creation; context-manager
        cleanup on `with` block exit)
      - GET + auth/connection/query error normalization

    Subclasses must:
      - Set ``COLLECTOR_ID`` (class attribute; short identifier
        for audit-log + manifest)
      - Set ``DEFAULT_BASE_URL`` (class attribute)
      - Set ``TOKEN_ENV_VAR`` (class attribute; for error messages)
      - Optionally override ``_make_user_agent`` for customization
      - Provide their own ``collect()`` method that calls
        ``self._get(path, ...)`` for HTTP work

    Subclasses may use the generic ``SaaSAuthError`` /
    ``SaaSConnectionError`` / ``SaaSQueryError`` exceptions
    directly, OR define their own subclasses for typed
    inheritance (e.g., ``class VantaAuthError(SaaSAuthError):
    pass``).

    Example:
        class MyCollector(BaseSaaSCollector):
            COLLECTOR_ID = "mycollector"
            DEFAULT_BASE_URL = "https://api.example.com"
            TOKEN_ENV_VAR = "MY_API_TOKEN"

            def collect(self) -> list[Finding]:
                data = self._get("/v1/things")
                return [...]
    """

    # Subclasses MUST override these.
    COLLECTOR_ID: str = ""
    DEFAULT_BASE_URL: str = ""
    TOKEN_ENV_VAR: str = ""

    # Subclasses MAY override these.
    DEFAULT_TIMEOUT_SECONDS: float = 30.0

    # Subclasses MAY override these to use their own typed
    # exception classes (preserves `pytest.raises(MyAuthError)`
    # in subclass-specific test suites). Defaults to the
    # generic SaaS* hierarchy.
    AUTH_ERROR_CLASS: type[SaaSAuthError] = SaaSAuthError
    CONNECTION_ERROR_CLASS: type[SaaSConnectionError] = SaaSConnectionError
    QUERY_ERROR_CLASS: type[SaaSQueryError] = SaaSQueryError

    def __init__(
        self,
        *,
        api_token: str | None = None,
        base_url: str | None = None,
        timeout_seconds: float | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        # v0.7.10 P3 closure of v0.7.9 M-1: whitespace-only tokens
        # bypass the truthiness check (`not " "` is False); strip
        # before validating so accidental "  " or "\n" envs surface
        # as a clear error rather than later opaque 401s.
        if api_token is not None:
            api_token = api_token.strip() or None
        if not api_token and client is None:
            raise self.AUTH_ERROR_CLASS(
                f"{type(self).__name__} requires either an "
                f"api_token or a pre-configured httpx.Client. "
                f"The token is sourced from the "
                f"{self.TOKEN_ENV_VAR} env var per the secret-"
                f"handling protocol."
            )
        self._api_token = api_token
        self._base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self._timeout_seconds = (
            timeout_seconds if timeout_seconds is not None
            else self.DEFAULT_TIMEOUT_SECONDS
        )
        self._client = client
        self._owns_client = client is None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        if self._owns_client and self._client is not None:
            with contextlib.suppress(Exception):
                self._client.close()
            self._client = None

    def _make_user_agent(self) -> str:
        """Build the User-Agent string for outbound requests.

        Subclasses MAY override to add product-specific
        identification. Default returns
        ``evidentia-collectors/<version> (<COLLECTOR_ID>; <repo URL>)``.
        """
        # Lazy-import to avoid circular dep with evidentia_core.__version__
        from evidentia_core import __version__

        return (
            f"evidentia-collectors/{__version__} "
            f"({type(self).__name__}; "
            f"https://github.com/polycentric-labs/evidentia)"
        )

    def _auth_header(self) -> str:
        """Build the ``Authorization`` request-header value.

        Default returns ``Bearer <api_token>`` — covers the
        majority of SaaS APIs (Vanta, Drata, GitHub, Jira,
        Atlassian, Okta, etc.).

        Subclasses MAY override for collectors that use a
        different auth scheme (e.g., HTTP Basic with a
        token-in-username convention like BitSight, or
        custom prefixes like SecurityScorecard's ``Token <key>``).
        """
        return f"Bearer {self._api_token}"

    def _ensure_client(self) -> httpx.Client:
        """Lazy httpx.Client creation with auth + UA configured."""
        if self._client is not None:
            return self._client
        # Caller-owned construction: build an httpx.Client with
        # the auth header + base URL. The token never appears
        # in logs because we use httpx's auth-header injection,
        # not a URL query parameter.
        if self._api_token is None:  # defensive — checked in __init__
            raise self.AUTH_ERROR_CLASS(
                f"{type(self).__name__}: missing api_token"
            )
        # Lazy-import httpx so the base class doesn't force
        # the import at evidentia_core.plugins level.
        import httpx

        self._client = httpx.Client(
            base_url=self._base_url,
            headers={
                "Authorization": self._auth_header(),
                "Accept": "application/json",
                "User-Agent": self._make_user_agent(),
            },
            timeout=self._timeout_seconds,
        )
        return self._client

    def _get(self, path: str, **params: Any) -> dict[str, Any]:
        """GET + JSON-decode + auth/connection/query error normalization.

        Args:
            path: API path (relative to ``base_url``).
            **params: Query-string parameters.

        Returns:
            Parsed JSON response (must be a JSON object; lists
            are wrapped in ``{"items": ...}`` by some APIs and
            decoded as-is here).

        Raises:
            SaaSAuthError: HTTP 401 or 403.
            SaaSConnectionError: network/TLS/DNS/timeout.
            SaaSQueryError: HTTP >= 400 (other than 401/403).
        """
        # Lazy-import httpx (matches _ensure_client).
        import httpx

        client = self._ensure_client()
        try:
            resp = client.get(path, params=params)
        except httpx.TimeoutException as exc:
            raise self.CONNECTION_ERROR_CLASS(
                f"{type(self).__name__} API timeout after "
                f"{self._timeout_seconds}s on GET {path}"
            ) from exc
        except httpx.HTTPError as exc:
            # Network / TLS / DNS / connection-refused etc.
            raise self.CONNECTION_ERROR_CLASS(
                f"{type(self).__name__} API connection failure "
                f"on GET {path}: {type(exc).__name__}"
            ) from exc
        if resp.status_code in (401, 403):
            raise self.AUTH_ERROR_CLASS(
                f"{type(self).__name__} API auth failure on GET "
                f"{path}: HTTP {resp.status_code}. Verify "
                f"{self.TOKEN_ENV_VAR} scope + expiration."
            )
        if resp.status_code >= 400:
            raise self.QUERY_ERROR_CLASS(
                f"{type(self).__name__} API error on GET {path}: "
                f"HTTP {resp.status_code}"
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise self.QUERY_ERROR_CLASS(
                f"{type(self).__name__} API returned non-JSON "
                f"response on GET {path}: {exc}"
            ) from exc
        if not isinstance(data, dict):
            # v0.8.1 F-V08-CR-3: previously the base wrapped
            # non-dict responses as ``{"items": data}``. None of
            # the 4 vendor-risk collectors (Vanta/Drata/BitSight/
            # SecurityScorecard) actually consume list responses;
            # the wrap silently masked non-conformant API
            # responses (e.g., a 200 with JSON string ``"OK"``).
            # The collector's downstream ``data.get("results", [])``
            # would yield ``[]`` and produce zero findings without
            # surfacing the anomaly. Now: raise a typed query
            # error so the operator sees the malformed response.
            #
            # If a future collector legitimately needs to consume
            # top-level list responses, it should override _get to
            # implement the wrap explicitly (the override stays
            # narrow + documented), or use a different parsing
            # path that handles list responses outside _get.
            raise self.QUERY_ERROR_CLASS(
                f"{type(self).__name__} API returned non-object "
                f"JSON on GET {path}: {type(data).__name__}. "
                f"Subclasses needing list-response handling must "
                f"override _get explicitly."
            )
        return data

    @abstractmethod
    def collect(self) -> Any:
        """Run the collector + return findings.

        Subclasses define the return type (typically
        ``list[SecurityFinding]`` or
        ``tuple[list[SecurityFinding], CollectionManifest]``).

        v0.8.1 F-V08-CR-10 design note: unlike :class:`StorageBackend[T]`,
        ``BaseSaaSCollector`` does NOT use a PEP 695 generic
        ``collect()`` return type. Rationale: the v0.8.0 collectors
        return polymorphic shapes (``list[SecurityFinding]`` for
        legacy ``collect()``; ``tuple[list[SecurityFinding],
        CollectionManifest]`` for the v2 manifest-aware
        ``collect_v2()`` contract). A single generic type
        parameter wouldn't capture both. Subclasses document
        their own return type via the override's annotation.
        """
        raise NotImplementedError
