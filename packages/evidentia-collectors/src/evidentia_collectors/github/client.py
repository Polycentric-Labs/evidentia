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
        block_private_ips: bool = True,
    ) -> None:
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.API_VERSION,
            "User-Agent": "evidentia-collectors",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        effective_base_url = base_url or self.BASE_URL
        # SECURE-BY-DEFAULT (threat-model T2): when the client owns its
        # own httpx.Client (no injected `http`), refuse a base_url that
        # resolves to a private / loopback / link-local / metadata
        # address before binding it. The default api.github.com is
        # public so this is a no-op for the common path; a GitHub
        # Enterprise base_url pointed at an internal host must opt out
        # via block_private_ips=False (--allow-private-ips on the CLI).
        # An injected `http` client skips the check — the caller owns it.
        if http is None:
            from evidentia_core.network_guard import (
                SSRFBlockedError,
                enforce_public_host,
            )

            try:
                enforce_public_host(
                    effective_base_url,
                    subsystem="github-repo-scan",
                    block_private=block_private_ips,
                )
            except SSRFBlockedError as exc:
                raise GitHubApiError(str(exc), status_code=0) from exc

        self._http = http or httpx.Client(
            base_url=effective_base_url,
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

    # ── v0.10.6 additive surface (OSPS extension) ───────────────────

    def list_releases(self, owner: str, repo: str) -> list[dict[str, Any]]:
        """Return the repository's releases list.

        Added v0.10.6 for the OSPS-BR-06.01 (signed/attested releases)
        helper in ``evidentia_collectors.github.osps``. Returns an empty
        list on 404 (repo has no releases yet) rather than raising,
        which lets the helper map "no releases" to
        :class:`ComplianceStatus.NOT_APPLICABLE`.

        GitHub paginates releases at 30/page by default. The helper
        callsite only needs the most recent N releases (where the
        signing convention is verified), so we read the first page only;
        upgrade to cursor pagination if a future callsite needs more.
        """
        response = self.request(
            "GET",
            f"/repos/{owner}/{repo}/releases",
            params={"per_page": 30},
            expected_status={404},
        )
        if not isinstance(response, list):
            return []
        return [item for item in response if isinstance(item, dict)]

    def are_vulnerability_alerts_enabled(
        self, owner: str, repo: str
    ) -> bool:
        """Return True iff Dependabot vulnerability alerts are enabled.

        Added v0.10.6 for the OSPS-VM-05.03 helper. GitHub's
        ``GET /repos/{owner}/{repo}/vulnerability-alerts`` endpoint
        returns 204 if enabled, 404 if disabled (no body in either case).
        Any other status code is treated as "indeterminate" and surfaced
        upward as a :class:`GitHubApiError` so callers can flag
        :class:`ComplianceStatus.UNKNOWN`.
        """
        try:
            response = self._http.request(
                "GET", f"/repos/{owner}/{repo}/vulnerability-alerts"
            )
        except httpx.HTTPError as e:
            raise GitHubApiError(
                f"vulnerability-alerts probe failed: {e}", status_code=0
            ) from e
        if response.status_code == 204:
            return True
        if response.status_code == 404:
            return False
        excerpt = response.text[:200]
        raise GitHubApiError(
            f"GET /repos/{owner}/{repo}/vulnerability-alerts",
            status_code=response.status_code,
            body_excerpt=excerpt,
        )

    def is_code_scanning_enabled(self, owner: str, repo: str) -> bool:
        """Return True iff code-scanning is enabled for the repo.

        Added v0.10.6 for the OSPS-VM-06.02 helper. We probe
        ``GET /repos/{owner}/{repo}/code-scanning/alerts?per_page=1`` —
        a 200 means the feature is enabled and the operator has API
        access; 403 / 404 mean either disabled or no permission, both of
        which are functionally "not enabled" from an external-audit
        perspective. We collapse them to ``False`` rather than splitting
        into UNKNOWN, because the OSPS-VM-06.02 control evaluates
        observable enablement, not the operator's permission scope.
        """
        try:
            response = self._http.request(
                "GET",
                f"/repos/{owner}/{repo}/code-scanning/alerts",
                params={"per_page": 1},
            )
        except httpx.HTTPError as e:
            raise GitHubApiError(
                f"code-scanning probe failed: {e}", status_code=0
            ) from e
        if 200 <= response.status_code < 300:
            return True
        if response.status_code in {403, 404}:
            return False
        excerpt = response.text[:200]
        raise GitHubApiError(
            f"GET /repos/{owner}/{repo}/code-scanning/alerts",
            status_code=response.status_code,
            body_excerpt=excerpt,
        )

    def list_security_advisories(
        self, owner: str, repo: str
    ) -> list[dict[str, Any]]:
        """Return published repository security advisories.

        Added v0.10.6 for the OSPS-VM-04.01 helper. The endpoint
        ``GET /repos/{owner}/{repo}/security-advisories`` returns the
        list of repository-level GHSAs (private + public depending on
        token scope). A 404 (advisories feature unavailable on the
        plan or repo) returns an empty list, which the helper interprets
        as "no advisories yet, but the feature surface is intact" — we
        leave the PASS/FAIL judgement to the helper.
        """
        response = self.request(
            "GET",
            f"/repos/{owner}/{repo}/security-advisories",
            params={"per_page": 30},
            expected_status={404},
        )
        if not isinstance(response, list):
            return []
        return [item for item in response if isinstance(item, dict)]
