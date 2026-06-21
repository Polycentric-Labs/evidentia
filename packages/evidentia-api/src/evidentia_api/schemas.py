"""Request/response Pydantic schemas for the FastAPI layer.

Response models reuse core Evidentia types from ``evidentia_core.models``
wherever possible. Only request-body wrappers and response-framing helpers
are defined here — keeping the surface small means new core features
flow through without an API-layer edit.
"""

from __future__ import annotations

from pathlib import Path

from evidentia_core.models.gap import GapAnalysisReport
from pydantic import BaseModel, ConfigDict, Field

# Engine-supported export formats, mirrored from
# ``evidentia_core.gap_analyzer.reporter.OutputFormat``. Kept as a
# module constant so the router can validate the requested format
# against the same set the CLI's ``--format`` honors without importing
# a private Literal alias. ``console`` / ``github`` are gap-*diff*
# formats, not gap-*report* formats, so they are intentionally absent.
GAP_EXPORT_FORMATS: tuple[str, ...] = (
    "json",
    "csv",
    "markdown",
    "oscal-ar",
    "sarif",
    "ocsf",
    "ocsf-detection",
    "cyclonedx-vex",
)


class HealthResponse(BaseModel):
    """Basic health probe response — used by the `/api/health` endpoint."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(description="'ok' when the server is serving requests.")
    version: str = Field(description="Installed Evidentia API version.")
    auth_configured: bool = Field(
        default=False,
        description=(
            "True when an API AuthProvider is configured. False = an anonymous "
            "deployment; the web console reads this to gate credentialed / "
            "network-egress actions (collect, integrations) per the v0.10.12 "
            "threat model and to show an unsecured-deployment notice."
        ),
    )


class VersionResponse(BaseModel):
    """Version detail returned by `/api/version`."""

    model_config = ConfigDict(extra="forbid")

    api_version: str
    core_version: str
    ai_version: str
    python_version: str


class GapAnalyzeRequest(BaseModel):
    """Body of `POST /api/gap/analyze`.

    Either ``inventory_path`` (server-side file) or ``inventory_content``
    (inline YAML/JSON uploaded from the browser) must be provided.
    """

    model_config = ConfigDict(extra="forbid")

    frameworks: list[str] = Field(
        min_length=1,
        description="One or more framework IDs to analyze against.",
    )
    inventory_path: Path | None = Field(
        default=None,
        description="Absolute path to inventory file (server-side).",
    )
    inventory_content: str | None = Field(
        default=None,
        description="Inline inventory YAML/JSON (browser upload).",
    )
    inventory_format: str = Field(
        default="yaml",
        description="One of: yaml, json, csv.",
    )
    organization: str | None = Field(
        default=None,
        description="Override inventory.organization.",
    )
    system_name: str | None = Field(
        default=None,
        description="Override inventory.system_name.",
    )


class GapDiffRequest(BaseModel):
    """Body of `POST /api/gap/diff`."""

    model_config = ConfigDict(extra="forbid")

    base_key: str = Field(description="gap_store SHA-16 key of the base report.")
    head_key: str = Field(description="gap_store SHA-16 key of the head report.")


class GapExportRequest(BaseModel):
    """Body of `POST /api/gap/export`.

    Carries a full :class:`GapAnalysisReport` (the object the UI already
    holds after `POST /api/gap/analyze`) plus a target ``format``. The
    endpoint reuses the CLI's :func:`evidentia_core.gap_analyzer.export_report`
    emitters and streams the serialized artifact back as a download — no
    re-implementation of any format on the API side.

    ``report_key`` is accepted as an alternative source so a caller can
    export a report already persisted in the gap store without re-sending
    the whole body. Exactly one of ``report`` / ``report_key`` must be set.
    """

    model_config = ConfigDict(extra="forbid")

    format: str = Field(
        default="json",
        description=(
            "One of: " + ", ".join(GAP_EXPORT_FORMATS) + ". "
            "OCSF formats (ocsf, ocsf-detection) require the server's "
            "[ocsf] extra; cyclonedx-vex / oscal-ar are always available."
        ),
    )
    report: GapAnalysisReport | None = Field(
        default=None,
        description="Inline report to export (as returned by /api/gap/analyze).",
    )
    report_key: str | None = Field(
        default=None,
        description="gap_store SHA-16 key of a saved report to export instead.",
    )


class RiskGenerateRequest(BaseModel):
    """Body of `POST /api/risk/generate` — SSE endpoint.

    Accepts either a list of explicit gap IDs or a report key + filter to
    select gaps. The stream emits one event per gap:
    `{gap_id, status: "generating"|"done"|"error", risk?: RiskStatement}`.
    """

    model_config = ConfigDict(extra="forbid")

    report_key: str = Field(description="gap_store SHA-16 key of the source report.")
    gap_ids: list[str] | None = Field(
        default=None,
        description="Explicit gap IDs. Omit to auto-pick top-N by priority score.",
    )
    top_n: int = Field(
        default=10,
        ge=1,
        le=50,
        description="When gap_ids is omitted, process this many highest-priority gaps.",
    )
    model: str | None = Field(
        default=None,
        description="LLM model override; falls back to EVIDENTIA_LLM_MODEL / config.",
    )
    context_path: Path | None = Field(
        default=None,
        description="Path to system-context.yaml. Defaults to CWD lookup.",
    )


class InitWizardRequest(BaseModel):
    """Body of `POST /api/init/wizard` — generate starter YAML files."""

    model_config = ConfigDict(extra="forbid")

    organization: str
    system_name: str | None = None
    industry: str | None = Field(
        default=None,
        description="One of: fintech, healthtech, saas, ecommerce, govcon, other.",
    )
    hosting: str | None = Field(
        default=None,
        description="One of: aws, azure, gcp, on-prem, hybrid.",
    )
    data_classification: list[str] = Field(
        default_factory=list,
        description="Data types (e.g. PII, PCI-CDE, PHI, CUI).",
    )
    regulatory_requirements: list[str] = Field(
        default_factory=list,
        description="Frameworks the user thinks apply.",
    )
    preset: str = Field(
        default="soc2-starter",
        description="One of: soc2-starter, nist-moderate-starter, hipaa-starter, empty.",
    )


class InitWizardResponse(BaseModel):
    """Response from `POST /api/init/wizard`."""

    model_config = ConfigDict(extra="forbid")

    evidentia_yaml: str
    my_controls_yaml: str
    system_context_yaml: str
    recommended_frameworks: list[str]


class LlmStatusResponse(BaseModel):
    """Response from `GET /api/llm-status`.

    Never includes key values — only booleans and source identifiers.
    Honors the CLAUDE.md secrets-through-context rule strictly.
    """

    model_config = ConfigDict(extra="forbid")

    providers: dict[str, LlmProviderState]
    configured_model: str = Field(description="Default model from env/yaml/fallback.")


class LlmProviderState(BaseModel):
    """Per-provider configuration state (no key values)."""

    model_config = ConfigDict(extra="forbid")

    configured: bool
    source: str | None = Field(
        default=None,
        description="Where the key is sourced: 'env:OPENAI_API_KEY', '.env file', or None.",
    )


class AirGapCheckResponse(BaseModel):
    """Response from `POST /api/doctor/check-air-gap`."""

    model_config = ConfigDict(extra="forbid")

    air_gapped: bool
    checks: list[AirGapCheck]


class AirGapCheck(BaseModel):
    """One subsystem's air-gap posture."""

    model_config = ConfigDict(extra="forbid")

    subsystem: str = Field(description="'llm_client', 'catalog_loader', etc.")
    status: str = Field(description="'ok', 'would_leak', or 'skipped'.")
    detail: str
