"""httpx-based GitHub REST client — minimal surface for evidence collection.

v0.5.0 covers three endpoints:

- ``GET /repos/{owner}/{repo}`` — repo metadata (default branch, visibility)
- ``GET /repos/{owner}/{repo}/branches/{branch}/protection`` — branch
  protection rules (404 if not protected)
- ``GET /repos/{owner}/{repo}/contents/{path}`` — test CODEOWNERS
  existence at ``.github/CODEOWNERS``, ``docs/CODEOWNERS``, or root

All methods are synchronous. An async client lands in v0.5.1 along
with the multi-repo batch collector.

Credentials are per-call via the ``Authorization`` header; the client
never logs the token value. A ``GitHubApiError`` exception wraps
non-2xx responses with the response status + reason phrase, never the
outbound headers.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class GitHubApiError(Exception):
    """Raised on GitHub REST API non-2xx responses."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        body_excerpt: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.body_excerpt = body_excerpt
        super().__init__(f"[HTTP {status_code}] {message}")


class GitHubClient:
    """Minimal GitHub REST client backed by httpx.

    Usage::

        with GitHubClient(token="ghp_...") as gh:
            repo = gh.get_repo("polycentric-labs", "evidentia")
            protection = gh.get_branch_protection("polycentric-labs", "evidentia", "main")
    """

    BASE_URL = "https://api.github.com"
    API_VERSION = "2022-11-28"

    def __init__(
        self,
        *,
        token: str | None = None,
        http: httpx.Client | None = None,
        base_url: str | None = None,
    ) -> None:
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.API_VERSION,
            "User-Agent": "evidentia-collectors",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        self._http = http or httpx.Client(
            base_url=base_url or self.BASE_URL,
            headers=headers,
            timeout=20.0,
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> GitHubClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        expected_status: set[int] | None = None,
    ) -> dict[str, Any] | None:
        """Issue a request; translate non-2xx into :class:`GitHubApiError`.

        ``expected_status`` lets callers treat specific non-2xx codes
        (e.g. 404 for "not found, that's informative") as signal —
        those return ``None`` instead of raising.
        """
        try:
            response = self._http.request(method, path)
        except httpx.HTTPError as e:
            raise GitHubApiError(
                f"GitHub request failed: {e}", status_code=0
            ) from e

        if 200 <= response.status_code < 300:
            try:
                body = response.json()
                return body if isinstance(body, dict) else {"_raw": body}
            except ValueError:
                return None

        if expected_status and response.status_code in expected_status:
            return None

        excerpt = response.text[:200]
        raise GitHubApiError(
            f"{method.upper()} {path}",
            status_code=response.status_code,
            body_excerpt=excerpt,
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        expected_status: set[int] | None = None,
    ) -> Any:
        """Issue a request; return the decoded JSON body as-is.

        Added in v0.7.0 for endpoints that return JSON arrays (e.g.,
        GitHub's Dependabot alerts endpoint at
        ``/repos/{owner}/{repo}/dependabot/alerts``). The pre-existing
        :meth:`_request` only handled dict responses; this method
        returns whatever httpx decodes (list or dict) and honors
        ``params`` for query-string pagination.
        """
        try:
            response = self._http.request(method, path, params=params)
        except httpx.HTTPError as e:
            raise GitHubApiError(
                f"GitHub request failed: {e}", status_code=0
            ) from e

        if 200 <= response.status_code < 300:
            try:
                return response.json()
            except ValueError:
                return None

        if expected_status and response.status_code in expected_status:
            return None

        excerpt = response.text[:200]
        raise GitHubApiError(
            f"{method.upper()} {path}",
            status_code=response.status_code,
            body_excerpt=excerpt,
        )

    # ── High-level operations ───────────────────────────────────────

    def get_repo(self, owner: str, repo: str) -> dict[str, Any]:
        """Return repo metadata (default branch, visibility, pushed_at, etc)."""
        result = self._request("GET", f"/repos/{owner}/{repo}")
        if result is None:
            raise GitHubApiError(
                f"Empty response for repo {owner}/{repo}", status_code=0
            )
        return result

    def get_branch_protection(
        self, owner: str, repo: str, branch: str
    ) -> dict[str, Any] | None:
        """Return branch protection rules, or ``None`` if branch is unprotected.

        A 404 response (common for unprotected branches) returns ``None``;
        every other error raises :class:`GitHubApiError`.
        """
        return self._request(
            "GET",
            f"/repos/{owner}/{repo}/branches/{branch}/protection",
            expected_status={404},
        )

    def get_contents(
        self, owner: str, repo: str, path: str
    ) -> dict[str, Any] | None:
        """Return file contents metadata or ``None`` if the path doesn't exist."""
        return self._request(
            "GET",
            f"/repos/{owner}/{repo}/contents/{path}",
            expected_status={404},
        )
