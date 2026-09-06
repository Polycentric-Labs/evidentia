"""Starter-file generators shared by ``evidentia init`` and the web UI.

v0.4.0 extracts the starter-YAML templates and framework-recommendation
rules from ``evidentia.cli.init`` into this module so:

- The CLI's Typer-prompt flow (``evidentia init``) continues to work
  with no user-visible change.
- The FastAPI endpoint ``POST /api/init/wizard`` generates identical
  files for the web UI's "Start from scratch" onboarding path.

The module exposes **pure functions** with no I/O — callers handle file
writes. Each generator returns a ``str`` containing the YAML.

Framework recommendation is a deterministic rule-based function. No LLM
is involved; advanced content-aware recommendation is an aspirational
v0.7.0 item (see docs/ROADMAP.md).
"""

from __future__ import annotations

from typing import Literal

__all__ = [
    "Preset",
    "generate_evidentia_yaml",
    "generate_my_controls_yaml",
    "generate_system_context_yaml",
    "recommend_frameworks",
]


Preset = Literal[
    "soc2-starter",
    "nist-moderate-starter",
    "hipaa-starter",
    "cmmc-starter",
    "empty",
]
"""Preset identifiers understood by :func:`generate_my_controls_yaml`."""


# ── evidentia.yaml ────────────────────────────────────────────────────

_EVIDENTIA_YAML_TEMPLATE = """\
# Evidentia project configuration.
#
# v0.2.1: this file is read by every `evidentia` command (was
# decorative in v0.1.x/v0.2.0). Precedence for every setting:
#   CLI flag > EVIDENTIA_* env var > this file > built-in default
#
# Supported keys as of v0.4.0 \u2014 everything else is accepted (for legacy
# compatibility) but ignored.

# Organization and system identity \u2014 overrides inventory-file values.
# Pairs with `gap analyze --organization` / `--system-name`.
organization: "{organization}"
{system_name_line}

# Default framework set for `gap analyze` when --frameworks is omitted.
# Populate with the canonical compliance scope for this project. CLI
# `--frameworks` replaces this list entirely (it does not union).
# Warning fires if this list has more than 5 frameworks.
frameworks:
{frameworks_block}

# LLM defaults for `risk generate`. Flag and
# EVIDENTIA_LLM_MODEL / EVIDENTIA_LLM_TEMPERATURE env vars win.
llm:
  model: "{llm_model}"
  temperature: {llm_temperature}

# ${{ENV_VAR}} interpolation is supported in any string value, e.g.:
#   organization: "${{ORG_NAME}}"
# so secrets and per-env settings can be hydrated from .env without
# committing them.
"""


def generate_evidentia_yaml(
    organization: str,
    frameworks: list[str],
    *,
    system_name: str | None = None,
    llm_model: str = "gpt-4o",
    llm_temperature: float = 0.1,
) -> str:
    """Render a ``evidentia.yaml`` starter file.

    The resulting string is ready to ``.write_text()`` into a project
    directory. Both the CLI ``init`` command and the GUI's onboarding
    wizard call this with the same arguments and produce identical files.
    """
    framework_list = [f for f in (fw.strip() for fw in frameworks) if f]
    frameworks_block = "\n".join(f"  - {fw}" for fw in framework_list)
    if not frameworks_block:
        frameworks_block = "  # Add at least one framework ID here."

    system_name_line = f'system_name: "{system_name}"' if system_name else '# system_name: "Your System Name"'

    return _EVIDENTIA_YAML_TEMPLATE.format(
        organization=organization,
        system_name_line=system_name_line,
        frameworks_block=frameworks_block,
        llm_model=llm_model,
        llm_temperature=llm_temperature,
    )


# ── my-controls.yaml presets ──────────────────────────────────────────────

_MY_CONTROLS_HEADER = """\
# Sample control inventory \u2014 replace with your organization's controls.
# Each entry's `id` should match a control ID in one of the frameworks
# you listed in evidentia.yaml (NIST 800-53, SOC 2, HIPAA, etc.).
#
# Status values: implemented | partially_implemented | planned | not_implemented | not_applicable
organization: "{organization}"
controls:
"""

_PRESET_CONTROLS: dict[Preset, str] = {
    "soc2-starter": """\
  - id: CC6.1
    title: "Logical and Physical Access Controls"
    status: partially_implemented
    implementation_notes: "RBAC in app layer; physical access managed by AWS."
    owner: "Security Team"

  - id: CC6.2
    title: "Prior to Issuing System Credentials"
    status: implemented
    implementation_notes: "New-hire checklist enforced via Okta HR integration."

  - id: CC6.3
    title: "Role-Based Access Control"
    status: partially_implemented
    implementation_notes: "Production RBAC deployed; staging migration planned for Q3."

  - id: CC6.6
    title: "Transmission of Information"
    status: implemented
    implementation_notes: "TLS 1.2+ enforced on all edges via ALB policy."

  - id: CC7.2
    title: "System Monitoring"
    status: planned
    implementation_notes: "SIEM deployment scheduled; currently using CloudTrail + manual review."
""",
    "nist-moderate-starter": """\
  - id: AC-2
    title: "Account Management"
    status: implemented
    implementation_notes: "Managed via Okta with quarterly access reviews."
    owner: "IAM Team"

  - id: AC-3
    title: "Access Enforcement"
    status: partially_implemented
    implementation_notes: "RBAC for production; permission model migration in progress."

  - id: AU-2
    title: "Audit Events"
    status: planned
    implementation_notes: "Centralized logging deployment scheduled for Q3."

  - id: AU-6
    title: "Audit Review, Analysis, and Reporting"
    status: planned
    implementation_notes: "Awaiting SIEM deployment."

  - id: IA-2
    title: "Identification and Authentication"
    status: implemented
    implementation_notes: "MFA enforced on all employee accounts via Okta."

  - id: SC-8
    title: "Transmission Confidentiality and Integrity"
    status: implemented
    implementation_notes: "TLS 1.2+ enforced across all data flows."

  - id: SI-4
    title: "System Monitoring"
    status: partially_implemented
    implementation_notes: "CloudWatch alarms deployed; anomaly detection pending."
""",
    "hipaa-starter": """\
  - id: 164.308(a)(1)(i)
    title: "Security Management Process"
    status: implemented
    implementation_notes: "Annual risk assessment conducted; policies approved by CISO."

  - id: 164.308(a)(3)(i)
    title: "Workforce Security"
    status: implemented
    implementation_notes: "Background checks required for all PHI-accessing roles."

  - id: 164.308(a)(5)(i)
    title: "Security Awareness and Training"
    status: partially_implemented
    implementation_notes: "Annual training rolled out; phishing simulations scheduled for Q4."

  - id: 164.312(a)(1)
    title: "Access Control"
    status: implemented
    implementation_notes: "Unique user IDs + automatic logoff + encryption in place."

  - id: 164.312(b)
    title: "Audit Controls"
    status: planned
    implementation_notes: "SIEM deployment planned for Q3."

  - id: 164.312(e)(1)
    title: "Transmission Security"
    status: implemented
    implementation_notes: "TLS 1.2+ enforced; VPN for admin access."
""",
    "cmmc-starter": """\
  - id: 3.1.1
    title: "Limit System Access"
    status: implemented
    implementation_notes: "RBAC deployed; privileged access via jump host."

  - id: 3.1.2
    title: "Limit System Access to Authorized Transactions"
    status: partially_implemented
    implementation_notes: "Function-based access on engineering systems; finance systems pending migration."

  - id: 3.3.1
    title: "Create and Retain System Audit Logs"
    status: implemented
    implementation_notes: "CloudWatch + S3 retention 7 years."

  - id: 3.4.1
    title: "Establish and Maintain Baseline Configurations"
    status: partially_implemented
    implementation_notes: "AWS Config rules enforced in production; dev environments pending."

  - id: 3.13.8
    title: "Implement Cryptographic Mechanisms"
    status: implemented
    implementation_notes: "TLS 1.2+ everywhere; S3 SSE-KMS with customer-managed keys."
""",
    "empty": "  # Add your controls here. Run `evidentia catalog show <framework>` to see available IDs.\n",
}


def generate_my_controls_yaml(
    preset: Preset = "nist-moderate-starter",
    *,
    organization: str = "Your Organization",
) -> str:
    """Render a starter ``my-controls.yaml``.

    Valid presets: ``soc2-starter``, ``nist-moderate-starter``,
    ``hipaa-starter``, ``cmmc-starter``, ``empty``.
    """
    if preset not in _PRESET_CONTROLS:
        raise ValueError(f"Unknown preset {preset!r}. Choose one of: {sorted(_PRESET_CONTROLS)}")
    body = _PRESET_CONTROLS[preset]
    return _MY_CONTROLS_HEADER.format(organization=organization) + body


# ── system-context.yaml ───────────────────────────────────────────────────

_SYSTEM_CONTEXT_TEMPLATE = """\
# System context for AI risk statement generation.
# This file describes the system the inventory applies to; the LLM uses
# it to frame risk statements (threat sources, impact analysis).
organization: "{organization}"
system_name: "{system_name}"
system_description: |
{system_description_block}
data_classification:
{data_classification_block}
hosting: "{hosting}"
risk_tolerance: "{risk_tolerance}"
regulatory_requirements:
{regulatory_block}
employee_count: {employee_count}
customer_count: {customer_count}
threat_actors:
{threat_actors_block}
existing_controls:
  # Reference control IDs the org already has in place.
components:
  # Describe the major components of the system.
  - name: "Web Application"
    type: web_app
    technology: "(stack)"
    data_handled: []
    location: "(region)"
"""


_DEFAULT_THREAT_ACTORS = [
    "External threat actors (financial motivation)",
    "Insider",
    "Opportunistic ransomware groups",
]


def generate_system_context_yaml(
    *,
    organization: str,
    system_name: str = "Your System",
    system_description: str | None = None,
    data_classification: list[str] | None = None,
    hosting: str = "(cloud provider + region)",
    risk_tolerance: Literal["low", "moderate", "high"] = "low",
    regulatory_requirements: list[str] | None = None,
    employee_count: int = 100,
    customer_count: int = 10_000,
    threat_actors: list[str] | None = None,
) -> str:
    """Render a starter ``system-context.yaml``.

    All defaults produce a sensible generic template; pass specific values
    to bias the output toward a given industry (fintech / healthtech / etc.).
    """
    desc_lines = (
        system_description or f"SaaS platform operated by {organization}.\nScope: authoritative business system."
    ).splitlines() or ["(Add a system description.)"]
    system_description_block = "\n".join(f"  {line}" for line in desc_lines)

    dc = data_classification or ["PII"]
    data_classification_block = "\n".join(f"  - {item}" for item in dc)

    rr = regulatory_requirements or []
    regulatory_block = "\n".join(f"  - {item}" for item in rr) if rr else "  # - SOC 2\n  # - GDPR"

    ta = threat_actors or _DEFAULT_THREAT_ACTORS
    threat_actors_block = "\n".join(f'  - "{item}"' for item in ta)

    return _SYSTEM_CONTEXT_TEMPLATE.format(
        organization=organization,
        system_name=system_name,
        system_description_block=system_description_block,
        data_classification_block=data_classification_block,
        hosting=hosting,
        risk_tolerance=risk_tolerance,
        regulatory_block=regulatory_block,
        employee_count=employee_count,
        customer_count=customer_count,
        threat_actors_block=threat_actors_block,
    )


# ── Framework recommendation rules ────────────────────────────────────────


def recommend_frameworks(
    *,
    industry: str | None = None,
    hosting: str | None = None,
    data_classification: list[str] | None = None,
    regulatory_requirements: list[str] | None = None,
) -> list[str]:
    """Recommend a starter framework set given lightweight org context.

    Deterministic rule-based — no LLM involved. Returns a de-duplicated,
    stable-ordered list of framework IDs from the bundled catalog set.

    Recommendation rules (additive, any match contributes):

    - Industry ``fintech``/``ecommerce`` + ``PCI-CDE`` data → ``pci-dss-v4``
    - Industry ``healthtech`` or ``PHI`` data → ``hipaa-security``, ``hipaa-privacy``
    - Industry ``govcon`` or ``CUI`` data → ``cmmc-l2``, ``nist-800-171-rev2``
    - Regulatory ``GDPR`` → ``eu-gdpr``
    - Regulatory ``SOC 2`` or default for SaaS → ``soc2-tsc``
    - Regulatory ``FedRAMP-moderate`` → ``fedramp-rev5-moderate``
    - Cloud hosting or default baseline → ``nist-800-53-rev5-moderate``
    """
    recommendations: list[str] = []

    ind = (industry or "").lower().strip()
    dc = {item.upper() for item in (data_classification or [])}
    rr = {item.upper().strip() for item in (regulatory_requirements or [])}

    # Industry / data-classification rules
    if ind in {"fintech", "ecommerce"} or "PCI-CDE" in dc or "PCI" in dc:
        recommendations.append("pci-dss-v4")

    if ind == "healthtech" or "PHI" in dc:
        recommendations.extend(["hipaa-security", "hipaa-privacy"])

    if ind == "govcon" or "CUI" in dc:
        recommendations.extend(["cmmc-l2", "nist-800-171-rev2"])

    # Regulatory hints
    if any(k in rr for k in ("GDPR", "EU-GDPR")):
        recommendations.append("eu-gdpr")

    if any(k in rr for k in ("SOC 2", "SOC2", "SOC-2")):
        recommendations.append("soc2-tsc")

    if any(k in rr for k in ("FEDRAMP", "FEDRAMP-MODERATE", "FEDRAMP MODERATE")):
        recommendations.append("fedramp-rev5-moderate")

    # Cloud hosting gets a NIST moderate baseline by default; pure on-prem
    # with no other hints still gets it as the most universally applicable
    # framework.
    recommendations.append("nist-800-53-rev5-moderate")

    # SaaS default when no industry signal
    if ind in {"saas", ""} and "soc2-tsc" not in recommendations:
        recommendations.append("soc2-tsc")

    # Deduplicate preserving order of first occurrence.
    seen: set[str] = set()
    ordered: list[str] = []
    for framework in recommendations:
        if framework not in seen:
            ordered.append(framework)
            seen.add(framework)
    return ordered
