"""Typed Jira client configuration.

Mirrors the minimal subset of Jira configuration we need for gap-push +
status-sync workflows. Secrets come from environment variables; the
config object exists to centralize URL / project / mapping settings
that are fine to commit to ``evidentia.yaml``.

Env vars (resolved at :meth:`JiraConfig.from_env`):

- ``JIRA_BASE_URL``       — e.g. ``https://acme.atlassian.net``
- ``JIRA_EMAIL``          — the API user's email (basic-auth username)
- ``JIRA_API_TOKEN``      — the API user's token (basic-auth password).
  Never logged; never returned in any Evidentia API response.
- ``JIRA_PROJECT_KEY``    — e.g. ``SEC`` or ``COMPLIANCE``.
- ``JIRA_ISSUE_TYPE``     — default ``Task``; commonly ``Task`` / ``Story`` /
  ``Bug`` depending on org conventions.

CLI / API callers that need to override any of these pass kwargs to
:meth:`JiraConfig.from_env`.
"""

from __future__ import annotations

import os

from pydantic import BaseModel, ConfigDict, Field, field_validator


class JiraConfig(BaseModel):
    """Typed Jira client configuration.

    The ``api_token`` field is stored on the in-memory instance so the
    client can attach it to outbound requests, but Pydantic's
    ``model_dump`` / ``model_dump_json`` never serialize it — it's marked
    ``exclude=True`` so ``JiraConfig(...).model_dump()`` returns only the
    safe, committable subset.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    base_url: str = Field(
        description=("Jira base URL, e.g. 'https://acme.atlassian.net'. No trailing slash."),
    )
    email: str = Field(description="Jira user email (basic-auth username).")
    api_token: str = Field(
        exclude=True,
        description=(
            "Jira API token (basic-auth password). Excluded from model_dump() "
            "output so it never accidentally lands in a log or API response."
        ),
    )
    project_key: str = Field(
        description="Jira project key (all caps), e.g. 'SEC', 'COMPLIANCE'.",
    )
    issue_type: str = Field(
        default="Task",
        description="Jira issue type to create — Task / Story / Bug / etc.",
    )
    timeout_seconds: float = Field(
        default=20.0,
        gt=0,
        description="httpx per-request timeout.",
    )

    @field_validator("base_url")
    @classmethod
    def _strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

    @classmethod
    def from_env(
        cls,
        *,
        base_url: str | None = None,
        email: str | None = None,
        api_token: str | None = None,
        project_key: str | None = None,
        issue_type: str | None = None,
    ) -> JiraConfig:
        """Build a :class:`JiraConfig` from env vars + optional overrides.

        Raises :class:`ValueError` listing every missing required field
        so the CLI can print a single actionable error message instead
        of a sequence of single-missing-var complaints.
        """
        resolved_url = base_url or os.environ.get("JIRA_BASE_URL")
        resolved_email = email or os.environ.get("JIRA_EMAIL")
        resolved_token = api_token or os.environ.get("JIRA_API_TOKEN")
        resolved_project = project_key or os.environ.get("JIRA_PROJECT_KEY")
        resolved_type = issue_type or os.environ.get("JIRA_ISSUE_TYPE") or "Task"

        missing: list[str] = []
        if not resolved_url:
            missing.append("JIRA_BASE_URL")
        if not resolved_email:
            missing.append("JIRA_EMAIL")
        if not resolved_token:
            missing.append("JIRA_API_TOKEN")
        if not resolved_project:
            missing.append("JIRA_PROJECT_KEY")

        if missing:
            raise ValueError(
                "Jira is not configured. Set these environment variables: "
                + ", ".join(missing)
                + ". See docs/integrations/jira.md."
            )

        # At this point mypy knows the optionals are populated, but the
        # type checker can't narrow through the `missing` list branch.
        assert resolved_url and resolved_email and resolved_token and resolved_project
        return cls(
            base_url=resolved_url,
            email=resolved_email,
            api_token=resolved_token,
            project_key=resolved_project,
            issue_type=resolved_type,
        )
