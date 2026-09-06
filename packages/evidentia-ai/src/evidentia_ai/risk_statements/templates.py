"""System context model — the user-provided description of their environment.

Used by the AI risk statement generator to produce contextually relevant
risk statements. Loaded from a YAML file (system-context.yaml).
"""

from __future__ import annotations

from pathlib import Path

import yaml
from evidentia_core.models.common import EvidentiaModel
from pydantic import Field


class SystemComponent(EvidentiaModel):
    """A component of the system being assessed."""

    name: str = Field(description="Component name, e.g. 'Web Application'")
    type: str = Field(
        description=("Component type: 'web_app', 'api', 'database', 'network', 'identity_provider', 'ci_cd'")
    )
    technology: str = Field(description="Technology stack, e.g. 'React + Node.js', 'Amazon Redshift'")
    data_handled: list[str] = Field(
        default_factory=list,
        description="Types of data this component processes, e.g. ['PII', 'PCI-CDE']",
    )
    location: str | None = Field(
        default=None,
        description="Hosting location, e.g. 'AWS us-east-1', 'On-premises datacenter'",
    )
    notes: str | None = Field(default=None)


class SystemContext(EvidentiaModel):
    """Complete system context for risk statement generation.

    Provided by the user in a system-context.yaml file. Describes the
    organization, system, data, hosting, components, threat actors,
    existing controls, and risk tolerance.

    This context is included in the LLM prompt to generate risk statements
    that are specific to the user's environment.
    """

    organization: str = Field(description="Organization name")
    system_name: str = Field(description="Name of the system being assessed")
    system_description: str = Field(
        description="Free-text description of the system's purpose, scope, and architecture"
    )
    data_classification: list[str] = Field(
        default_factory=list,
        description="Types of data processed: 'PII', 'PHI', 'PCI-CDE', 'CUI', 'public'",
    )
    hosting: str = Field(description="Hosting environment description, e.g. 'AWS (us-east-1, eu-west-1)'")
    components: list[SystemComponent] = Field(
        default_factory=list,
        description="System components with their technology stacks",
    )
    threat_actors: list[str] = Field(
        default_factory=list,
        description=(
            "Relevant threat actor categories. E.g. ['External threat actors (financial)', 'Nation-state', 'Insider']"
        ),
    )
    existing_controls: list[str] = Field(
        default_factory=list,
        description="Control IDs already implemented (used for context in risk generation)",
    )
    frameworks: list[str] = Field(
        default_factory=list,
        description="Target compliance frameworks",
    )
    risk_tolerance: str = Field(
        default="medium",
        description="Organization's risk tolerance: 'low', 'medium', 'high'",
    )
    regulatory_requirements: list[str] = Field(
        default_factory=list,
        description="Applicable regulations: 'HIPAA', 'PCI DSS', 'GDPR', 'CCPA', 'ITAR'",
    )
    annual_revenue: str | None = Field(
        default=None,
        description="Annual revenue range (used for impact assessment)",
    )
    employee_count: int | None = Field(
        default=None,
        description="Number of employees",
    )
    customer_count: int | None = Field(
        default=None,
        description="Number of customers/users",
    )
    notes: str | None = Field(default=None)

    @classmethod
    def from_yaml(cls, path: str | Path) -> SystemContext:
        """Load a SystemContext from a YAML file."""
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(data)
