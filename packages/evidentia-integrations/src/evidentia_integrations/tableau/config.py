"""Tableau integration configuration (v0.7.8 P1.1).

Defines :class:`TableauConfig` — a typed configuration object that
holds *names of environment variables* rather than secret values
themselves. The actual token is resolved by :class:`TableauClient`
at call time.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class TableauConfig(BaseModel):
    """Tableau integration configuration.

    Holds enough information to identify a Tableau Server / Cloud
    site + the project to publish into, plus the names of the env
    vars where the PAT token name + secret live.

    Per ``~/.claude/CLAUDE.md`` secret-handling protocol, this
    object NEVER stores the token secret directly.
    """

    model_config = ConfigDict(frozen=True)

    server_url: str = Field(
        description=(
            "Tableau Server / Cloud base URL. "
            "Example: 'https://us-east-1.online.tableau.com' for "
            "Tableau Cloud, 'https://tableau.acme.example.com' for "
            "Tableau Server. NO trailing slash."
        ),
    )
    site_id: str = Field(
        default="",
        description=(
            "Tableau site identifier (the URL slug — typically the "
            "second path segment after `/site/`). For Tableau Server "
            "default site, leave empty string. For Tableau Cloud, "
            "this is the site you signed up for."
        ),
    )
    project_name: str = Field(
        default="default",
        description=(
            "Project name to publish into. Tableau projects are "
            "Tableau's namespacing primitive. 'default' is "
            "auto-created on every site."
        ),
    )
    pat_name_env: str = Field(
        default="TABLEAU_PAT_NAME",
        description=(
            "Name of the env var holding the Personal Access Token "
            "name (NOT the secret — just the human-readable name "
            "the operator gave the token in Tableau settings). "
            "Defaults to TABLEAU_PAT_NAME."
        ),
    )
    pat_secret_env: str = Field(
        default="TABLEAU_PAT_SECRET",
        description=(
            "Name of the env var holding the Personal Access Token "
            "secret. The integration reads this env var at "
            "client-instantiation time and never persists the "
            "value. Defaults to TABLEAU_PAT_SECRET."
        ),
    )
    api_version: str = Field(
        default="3.21",
        description=(
            "Tableau REST API version to use. The "
            "tableauserverclient library defaults to a sensible "
            "minimum; we pin a recent version here so behavior is "
            "deterministic across releases."
        ),
    )
