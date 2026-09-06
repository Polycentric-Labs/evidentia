"""Power BI integration configuration (v0.7.8 P1.2)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PowerBIConfig(BaseModel):
    """Power BI integration configuration.

    Holds workspace identity + Azure AD service-principal
    identifiers + the env-var name where the client secret lives.
    Per ``~/.claude/CLAUDE.md`` secret-handling protocol, the
    config object NEVER stores the secret value itself.
    """

    model_config = ConfigDict(frozen=True)

    workspace_id: str = Field(
        description=("Power BI workspace ID (a UUID). The dataset is created in this workspace."),
    )
    tenant_id: str = Field(
        description=("Azure AD tenant ID (a UUID). Required for the OAuth2 client-credentials flow."),
    )
    client_id: str = Field(
        description=(
            "Azure AD service-principal application (client) ID. "
            "The principal MUST have Dataset.ReadWrite.All "
            "permission on the target workspace."
        ),
    )
    client_secret_env: str = Field(
        default="POWERBI_CLIENT_SECRET",
        description=(
            "Name of the env var holding the service-principal "
            "client secret. The client reads this env var at "
            "instantiation time and never persists the value. "
            "Defaults to POWERBI_CLIENT_SECRET."
        ),
    )
    api_base_url: str = Field(
        default="https://api.powerbi.com/v1.0/myorg",
        description=(
            "Power BI REST API base URL. Almost always the public "
            "endpoint; sovereign clouds (Power BI for US Gov, China) "
            "have different roots which can be overridden here."
        ),
    )
    authority_url: str = Field(
        default="https://login.microsoftonline.com",
        description=(
            "Azure AD authority URL. Sovereign clouds use a different authority — overridable for those tenants."
        ),
    )
    api_scope: str = Field(
        default="https://analysis.windows.net/powerbi/api/.default",
        description=("OAuth2 scope for the Power BI service. Service-principal flow uses /.default."),
    )
