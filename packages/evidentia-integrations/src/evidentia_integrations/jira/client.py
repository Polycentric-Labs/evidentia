"""httpx-based Jira Cloud REST client.

We use ``httpx`` directly rather than the official ``jira`` PyPI SDK to
keep the dependency footprint small (Pillow, defusedxml, keyring get
pulled in otherwise) and because our three use cases — create issue,
get issue, transition issue — are well within REST reach.

All methods are synchronous for v0.5.0. An async variant lands in v0.5.1
alongside the gap-batch-push UI flow (generates one issue per gap with
progress feedback — SSE-style on the GUI path).

**Secret handling.** The ``api_token`` from :class:`JiraConfig` is sent
as HTTP basic-auth's password field, never logged, never returned in
any method's output. Exceptions carry the HTTP status code + the Jira
``errorMessages`` array but never echo the outbound headers.
"""

from __future__ import annotations

import base64
import logging
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from evidentia_integrations.jira.config import JiraConfig

logger = logging.getLogger(__name__)


class JiraApiError(Exception):
    """Raised when the Jira REST API returns a non-2xx response.

    Carries the HTTP status code and the ``errorMessages`` array (or a
    raw body excerpt if Jira returned something unexpected). Never
    carries request headers — avoids accidentally leaking the
    Authorization value into a log aggregator.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        errors: list[str] | None = None,
        body_excerpt: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.errors = errors or []
        self.body_excerpt = body_excerpt
        detail = f"[HTTP {status_code}] {message}"
        if errors:
            detail += f" -- {'; '.join(errors)}"
        super().__init__(detail)


class JiraIssue(BaseModel):
    """Typed Jira issue — narrowed to the fields Evidentia cares about."""

    model_config = ConfigDict(extra="allow")

    key: str = Field(description="Issue key, e.g. 'SEC-42'.")
    id: str = Field(description="Internal numeric id.")
    summary: str = Field(description="Issue summary.")
    status_name: str = Field(
        description="Current workflow status name, e.g. 'To Do', 'In Progress', 'Done'.",
    )
    status_category: str = Field(
        description="Jira status category: 'new', 'indeterminate', 'done', 'undefined'.",
    )
    url: str = Field(description="Public issue URL for browser access.")


class JiraClient:
    """Thin Jira Cloud REST v3 client.

    Usage::

        cfg = JiraConfig.from_env()
        client = JiraClient(cfg)
        issue = client.create_issue(summary="...", description="...")
        remote = client.get_issue(issue.key)
        client.transition_issue(issue.key, target_status="Done")
    """

    def __init__(
        self,
        config: JiraConfig,
        *,
        http: httpx.Client | None = None,
    ) -> None:
        """Build a client.

        Parameters
        ----------
        config
            Validated :class:`JiraConfig`.
        http
            Optional pre-built httpx client — tests inject one backed by
            ``httpx.MockTransport`` so they don't make network calls.
        """
        self._config = config
        basic = base64.b64encode(f"{config.email}:{config.api_token}".encode()).decode("ascii")
        self._http = http or httpx.Client(
            base_url=config.base_url,
            headers={
                "Authorization": f"Basic {basic}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            timeout=config.timeout_seconds,
        )

    @property
    def config(self) -> JiraConfig:
        """Expose the config for callers (tests, CLI, etc.)."""
        return self._config

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._http.close()

    def __enter__(self) -> JiraClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ── Low-level request ───────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Issue a request + raise :class:`JiraApiError` on non-2xx."""
        try:
            response = self._http.request(method, path, json=json, params=params)
        except httpx.HTTPError as e:
            raise JiraApiError(f"Jira request failed: {e}", status_code=0) from e

        if response.status_code == 204:
            return {}

        try:
            body = response.json()
        except ValueError:
            body = None

        if not 200 <= response.status_code < 300:
            errors: list[str] = []
            if isinstance(body, dict):
                errors = list(body.get("errorMessages", []))
                error_field = body.get("errors")
                if isinstance(error_field, dict):
                    errors.extend(f"{k}: {v}" for k, v in error_field.items())
            excerpt = response.text[:200] + ("..." if len(response.text) > 200 else "") if not errors else None
            raise JiraApiError(
                f"{method.upper()} {path}",
                status_code=response.status_code,
                errors=errors,
                body_excerpt=excerpt,
            )

        return body if isinstance(body, dict) else {}

    # ── High-level operations ───────────────────────────────────────

    def test_connection(self) -> dict[str, str]:
        """Verify credentials + project access.

        Returns the authenticated user's display name + the project
        name. Raises :class:`JiraApiError` if either call fails.
        """
        me = self._request("GET", "/rest/api/3/myself")
        project = self._request("GET", f"/rest/api/3/project/{self._config.project_key}")
        return {
            "user": str(me.get("displayName") or me.get("emailAddress") or "unknown"),
            "project_key": self._config.project_key,
            "project_name": str(project.get("name") or ""),
            "base_url": self._config.base_url,
        }

    def create_issue(
        self,
        *,
        summary: str,
        description: str,
        labels: list[str] | None = None,
        extra_fields: dict[str, Any] | None = None,
    ) -> JiraIssue:
        """Create a new issue in the configured project.

        ``description`` uses Jira's Atlassian Document Format (ADF) — we
        wrap a plain-text paragraph automatically. Callers who want
        richer formatting pass the ADF dict via ``extra_fields``.
        """
        adf_description: dict[str, Any] = {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": description}],
                }
            ],
        }
        fields: dict[str, Any] = {
            "project": {"key": self._config.project_key},
            "issuetype": {"name": self._config.issue_type},
            "summary": summary,
            "description": adf_description,
            "labels": labels or [],
        }
        if extra_fields:
            fields.update(extra_fields)
        result = self._request("POST", "/rest/api/3/issue", json={"fields": fields})
        key = str(result["key"])
        return self.get_issue(key)

    def get_issue(self, key: str) -> JiraIssue:
        """Fetch a single issue by key."""
        body = self._request(
            "GET",
            f"/rest/api/3/issue/{key}",
            params={"fields": "summary,status"},
        )
        fields = body.get("fields") or {}
        status = fields.get("status") or {}
        status_name = str(status.get("name") or "unknown")
        status_category = str((status.get("statusCategory") or {}).get("key") or "undefined")
        return JiraIssue(
            key=str(body["key"]),
            id=str(body["id"]),
            summary=str(fields.get("summary") or ""),
            status_name=status_name,
            status_category=status_category,
            url=f"{self._config.base_url}/browse/{body['key']}",
        )

    def list_transitions(self, key: str) -> list[dict[str, Any]]:
        """Return the transitions currently available on this issue."""
        body = self._request("GET", f"/rest/api/3/issue/{key}/transitions")
        transitions = body.get("transitions", [])
        return [t for t in transitions if isinstance(t, dict)]

    def transition_issue(self, key: str, *, target_status: str) -> None:
        """Transition the issue to a target workflow status by name.

        Looks up the available transitions for this issue, finds one
        whose ``to.name`` matches ``target_status`` case-insensitively,
        and POSTs to ``/transitions`` with its id. Raises
        :class:`JiraApiError` if no matching transition exists (e.g.
        the workflow doesn't allow that move from the current state).
        """
        target_lower = target_status.lower()
        for tr in self.list_transitions(key):
            to_block = tr.get("to") or {}
            if str(to_block.get("name", "")).lower() == target_lower:
                self._request(
                    "POST",
                    f"/rest/api/3/issue/{key}/transitions",
                    json={"transition": {"id": str(tr["id"])}},
                )
                return
        raise JiraApiError(
            f"No transition to status {target_status!r} available from this issue's current state",
            status_code=409,
        )
