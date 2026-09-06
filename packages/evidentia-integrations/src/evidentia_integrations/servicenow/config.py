"""Typed ServiceNow integration configuration.

Mirrors the JiraConfig pattern. Credentials come from env vars;
the config object centralizes URL / table / field-mapping settings
that are fine to commit to ``evidentia.yaml``.

Env vars (resolved at :meth:`ServiceNowConfig.from_env`):

- ``EVIDENTIA_SERVICENOW_INSTANCE_URL`` — e.g. ``https://acme.service-now.com``
- ``EVIDENTIA_SERVICENOW_USER``         — basic-auth username
- ``EVIDENTIA_SERVICENOW_PASSWORD``     — basic-auth password
- ``EVIDENTIA_SERVICENOW_TABLE``        — default ``incident``;
  override to ``sn_grc_issue`` (GRC plugin) or a custom table.
"""

from __future__ import annotations

import os

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ServiceNowConfig(BaseModel):
    """Typed ServiceNow integration config.

    ``password`` is excluded from ``model_dump`` output so it never
    accidentally lands in a log or API response.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    instance_url: str = Field(
        description=("ServiceNow instance URL, e.g. 'https://acme.service-now.com'. MUST be HTTPS. No trailing slash."),
    )
    user: str = Field(description="ServiceNow basic-auth username.")
    password: str = Field(
        exclude=True,
        description=(
            "ServiceNow basic-auth password. Excluded from "
            "model_dump() output so it never accidentally lands in a "
            "log or API response."
        ),
    )
    table_name: str = Field(
        default="incident",
        description=(
            "Target table for created records. Default 'incident' "
            "is universal; switch to 'sn_grc_issue' (GRC plugin) "
            "or a custom table for production GRC workflows."
        ),
    )
    timeout_seconds: float = Field(
        default=20.0,
        gt=0,
        description="httpx per-request timeout.",
    )

    @field_validator("instance_url")
    @classmethod
    def _validate_https_and_strip_slash(cls, v: str) -> str:
        v = v.rstrip("/")
        if not v.startswith("https://"):
            raise ValueError("instance_url must use https:// — refusing to send credentials over a non-TLS channel.")
        return v

    @classmethod
    def from_env(
        cls,
        *,
        instance_url: str | None = None,
        user: str | None = None,
        password: str | None = None,
        table_name: str | None = None,
    ) -> ServiceNowConfig:
        resolved_url = instance_url or os.environ.get("EVIDENTIA_SERVICENOW_INSTANCE_URL")
        resolved_user = user or os.environ.get("EVIDENTIA_SERVICENOW_USER")
        resolved_pwd = password or os.environ.get("EVIDENTIA_SERVICENOW_PASSWORD")
        resolved_table = table_name or os.environ.get("EVIDENTIA_SERVICENOW_TABLE") or "incident"

        missing: list[str] = []
        if not resolved_url:
            missing.append("EVIDENTIA_SERVICENOW_INSTANCE_URL")
        if not resolved_user:
            missing.append("EVIDENTIA_SERVICENOW_USER")
        if not resolved_pwd:
            missing.append("EVIDENTIA_SERVICENOW_PASSWORD")

        if missing:
            raise ValueError(
                "ServiceNow is not configured. Set these env vars: "
                + ", ".join(missing)
                + ". See docs/sql-collectors.md (parallel pattern)."
            )

        assert resolved_url and resolved_user and resolved_pwd
        return cls(
            instance_url=resolved_url,
            user=resolved_user,
            password=resolved_pwd,
            table_name=resolved_table,
        )
