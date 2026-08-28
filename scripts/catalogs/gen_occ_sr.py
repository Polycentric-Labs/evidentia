"""Generate OCC Bulletin 2026-13 / FRB SR 26-2 model-risk catalog.

Authoritative source: OCC Bulletin 2026-13 + FRB SR 26-2
("Supervisory Guidance on Model Risk Management"), April 17, 2026
supersession of OCC Bulletin 2011-12 / FRB SR 11-7.

Designator note (v0.13, V13-15): the catalog originally shipped as
``occ-sr-26-02`` naming "OCC Bulletin 2026-13a / FRB SR 26-02". Both
designators were wrong: the FRB letter carries no leading zero (SR 26-2,
matching the SR 11-7 style) and the OCC bulletin number carries no "a"
suffix (2026-13). The id is now ``occ-sr-26-2``; the old id resolves
through a deprecated alias in ``evidentia_core.catalogs.loader`` until
v1.0.0 per docs/deprecation-calendar.md.

Public domain — works of US federal government per 17 USC §105.

The 2026 guidance carries forward the SR 11-7 framework structure:
§II Model definition + materiality, §III Model Development +
Implementation + Use (Conceptual Soundness + Outcomes Analysis +
Validation), §IV Validation requirements + cadence, §V Vendor
Models, §VI Governance.

The 2026 supersession **explicitly excludes generative AI and
agentic AI from scope**. Banks deploying LLM-driven controls
operate without a regulatory framework — Evidentia's
GenerationContext provenance chain (v0.7.1) + the v0.7.10 P0.6.4
RiskStatement.model_inventory_ref linkage produce SR-replacement-
grade audit evidence for those deployments. See
docs/financial-sector-overlay.md "GenAI regulator-vacuum
positioning" + docs/positioning-and-value.md §4.6.
"""

from __future__ import annotations

from _generators import emit_control_catalog  # type: ignore[import-not-found]


def _ctl(id_: str, title: str, description: str, family: str) -> dict[str, str]:
    return {"id": id_, "title": title, "description": description, "family": family}


OCC_SR_URL = (
    "https://www.federalreserve.gov/supervisionreg/srletters/sr2602.htm "
    "(parallel: OCC Bulletin 2026-13)"
)


OCC_SR_26_2_CONTROLS: list[dict[str, str]] = [
    # --- I. Scope + Definitions ---
    _ctl("I.1", "Model Definition",
         "Quantitative method, system, or approach that applies "
         "statistical, economic, financial, or mathematical theories, "
         "techniques, + assumptions to process input data into "
         "quantitative estimates. Excludes generative AI + agentic AI "
         "per the April 2026 supersession.",
         "I. Scope + Definitions"),
    _ctl("I.2", "Model Risk Definition",
         "Potential for adverse consequences from decisions based on "
         "incorrect or misused model outputs + reports — includes "
         "fundamental errors, applied outside intended environment, + "
         "inappropriate management application.",
         "I. Scope + Definitions"),
    _ctl("I.3", "GenAI / Agentic AI Out of Scope",
         "Generative AI + agentic AI models are explicitly excluded "
         "from the SR 26-2 / OCC 2026-13 framework as 'novel + "
         "rapidly evolving'; future RFI promised. Operators should apply "
         "self-imposed discipline pending regulatory clarification.",
         "I. Scope + Definitions"),
    # --- II. Materiality + Tiering ---
    _ctl("II.1", "Materiality Assessment",
         "Each model's potential impact on the institution is assessed "
         "against quantitative + qualitative criteria (size of "
         "exposure, decision criticality, regulatory significance).",
         "II. Materiality + Tiering"),
    _ctl("II.2", "Tier-Driven Risk Management",
         "High-materiality models receive enhanced controls; medium + "
         "low receive proportionally-reduced controls. Tier classification "
         "is documented + refreshed at material model changes.",
         "II. Materiality + Tiering"),
    _ctl("II.3", "Aggregate Model Risk View",
         "Senior management + the board receive periodic aggregate "
         "reporting on the model inventory's risk posture.",
         "II. Materiality + Tiering"),
    # --- III. Conceptual Soundness ---
    _ctl("III.A.1", "Theory + Design",
         "Each model's theoretical foundation + design rationale is "
         "documented including: business purpose, key assumptions, "
         "selection of variables, + alternative-approach consideration.",
         "III. Conceptual Soundness"),
    _ctl("III.A.2", "Data Quality + Source Documentation",
         "Model input data sources are documented; data quality is "
         "evaluated for relevance, accuracy, + completeness; data "
         "limitations are documented as model assumptions.",
         "III. Conceptual Soundness"),
    _ctl("III.A.3", "Implementation Documentation",
         "Model implementation (code + computational logic) is "
         "documented to support reproduction + independent review.",
         "III. Conceptual Soundness"),
    _ctl("III.A.4", "Assumptions + Limitations",
         "Model assumptions + limitations are documented; "
         "limitations drive caveats on appropriate model use.",
         "III. Conceptual Soundness"),
    _ctl("III.A.5", "Sensitivity + Stress Testing",
         "Model sensitivity to key inputs + assumptions is documented; "
         "stress scenarios test model behavior under extreme conditions.",
         "III. Conceptual Soundness"),
    # --- III.B Outcomes Analysis ---
    _ctl("III.B.1", "Outcomes Analysis (Backtesting)",
         "Documented backtesting compares model predictions to realized "
         "outcomes; persistent drift triggers model recalibration or retirement.",
         "III. Outcomes Analysis"),
    _ctl("III.B.2", "Benchmarking",
         "Where feasible, model outputs are benchmarked against "
         "alternative models or industry standards.",
         "III. Outcomes Analysis"),
    _ctl("III.B.3", "Override + Adjustment Tracking",
         "Manual overrides + adjustments to model output are tracked + "
         "reviewed; persistent overrides indicate model deficiency.",
         "III. Outcomes Analysis"),
    # --- III.C Ongoing Monitoring ---
    _ctl("III.C.1", "Ongoing Performance Monitoring",
         "Documented monitoring tracks model performance metrics on a "
         "model-appropriate cadence (continuous, daily, monthly, etc.).",
         "III. Ongoing Monitoring"),
    _ctl("III.C.2", "Model Retirement Planning",
         "Each material model has a documented retirement / replacement "
         "plan or rationale for indefinite use.",
         "III. Ongoing Monitoring"),
    _ctl("III.C.3", "Process + Change Controls",
         "Material model changes (re-calibration, re-training, scope "
         "change) follow documented change-management process with "
         "appropriate approval levels.",
         "III. Ongoing Monitoring"),
    # --- III.D Validation ---
    _ctl("III.D.1", "Validation Independence",
         "Validation is performed by parties independent of model "
         "development. For Tier-1 models, validation independence "
         "extends to organizational independence (separate reporting line).",
         "III. Validation"),
    _ctl("III.D.2", "Validation Cadence",
         "Tier-driven validation cadence: Tier 1 typically annual; "
         "Tier 2 biennial; Tier 3 triennial. Material model changes "
         "trigger out-of-cycle validation.",
         "III. Validation"),
    _ctl("III.D.3", "Validation Scope",
         "Validation covers conceptual soundness, ongoing monitoring, + "
         "outcomes analysis dimensions per SR 26-2 §III.D.",
         "III. Validation"),
    _ctl("III.D.4", "Validation Findings + Disposition",
         "Validation findings are classified by severity + tracked to "
         "disposition (remediated, accepted, deferred) with documented rationale.",
         "III. Validation"),
    _ctl("III.D.5", "HIGH Findings Block Production Use",
         "HIGH-severity validation findings block the model from "
         "production use until remediated, unless senior-management "
         "risk-acceptance with documented compensating controls.",
         "III. Validation"),
    _ctl("III.D.6", "Effective Challenge",
         "Validators must apply effective challenge — substantive "
         "questioning of model assumptions, methodology, results — "
         "documented in validation reports.",
         "III. Validation"),
    # --- IV. Vendor Models (§V in source guidance) ---
    _ctl("IV.1", "Vendor Model Inventory",
         "Vendor-supplied models are inventoried with explicit cross-"
         "reference to the institution's TPRM vendor record.",
         "IV. Vendor Models"),
    _ctl("IV.2", "Vendor Model Documentation Sufficiency",
         "Vendor-provided model documentation is reviewed for SR-26-2 "
         "sufficiency; gaps are addressed via institution-side "
         "supplemental documentation.",
         "IV. Vendor Models"),
    _ctl("IV.3", "Vendor Model Validation Approach",
         "Vendor models are validated using the same standards as "
         "internal models; validators may use vendor-provided validation "
         "evidence + supplement with institution-side testing.",
         "IV. Vendor Models"),
    _ctl("IV.4", "Vendor Model Change Notification",
         "Vendor contracts require notification of material model "
         "changes (algorithm change, retraining, scope expansion).",
         "IV. Vendor Models"),
    # --- V. Governance ---
    _ctl("V.1", "Board + Senior Management Oversight",
         "The board (or designated committee) is responsible for "
         "establishing risk-management framework + receives periodic "
         "model risk posture reporting.",
         "V. Governance"),
    _ctl("V.2", "Model Risk Management Policy",
         "Documented model-risk-management policy covers: scope, roles "
         "+ responsibilities, materiality framework, validation requirements, "
         "issue management, + reporting.",
         "V. Governance"),
    _ctl("V.3", "Roles + Responsibilities",
         "Clear roles for: model owner (1st line), model validator (2nd "
         "line), internal audit (3rd line) per Three Lines of Defense.",
         "V. Governance"),
    _ctl("V.4", "Issue + Limitation Tracking System",
         "Validation findings, model limitations, + remediation status "
         "are tracked centrally + reported to appropriate management levels.",
         "V. Governance"),
    _ctl("V.5", "Model Risk Reporting",
         "Aggregate model-risk reporting to board / committee covers: "
         "inventory size + tier distribution, validation status, "
         "open findings by severity, recent material model changes.",
         "V. Governance"),
    _ctl("V.6", "Internal Audit Coverage",
         "Internal audit covers the model-risk-management framework + "
         "individual high-tier model validations as part of its risk-based plan.",
         "V. Governance"),
    # --- VI. AI / ML Specific Considerations ---
    _ctl("VI.1", "ML Model Drift Monitoring",
         "ML models receive enhanced ongoing-monitoring for distributional "
         "drift in inputs + outputs; drift thresholds trigger re-validation.",
         "VI. AI / ML Specific Considerations"),
    _ctl("VI.2", "ML Fairness + Bias Assessment",
         "ML models used in consumer-impact decisions undergo documented "
         "fairness + bias assessment; protected-class disparate-impact "
         "analysis where applicable.",
         "VI. AI / ML Specific Considerations"),
    _ctl("VI.3", "ML Explainability",
         "ML model decisions are explainable to a degree appropriate to "
         "the use case; high-stakes decisions require feature-attribution "
         "or counterfactual explanation capability.",
         "VI. AI / ML Specific Considerations"),
    _ctl("VI.4", "GenAI / LLM Self-Imposed Discipline",
         "Generative AI + agentic AI deployments — outside SR 26-2 "
         "scope — operate under documented self-imposed discipline: "
         "model inventory entries, prompt-hash provenance, run-id audit "
         "correlation, validation + effective-challenge regardless of "
         "regulatory mandate. See Evidentia's GenerationContext + "
         "RiskStatement.model_inventory_ref features.",
         "VI. AI / ML Specific Considerations"),
]


def main() -> None:
    """Emit the OCC 2026-13 / FRB SR 26-2 model-risk catalog."""
    emit_control_catalog(
        framework_id="occ-sr-26-2",
        framework_name=(
            "OCC Bulletin 2026-13 / FRB SR 26-2 — Supervisory "
            "Guidance on Model Risk Management"
        ),
        version="April 17, 2026 (supersedes OCC 2011-12 / SR 11-7)",
        source=OCC_SR_URL,
        families=[
            "I. Scope + Definitions",
            "II. Materiality + Tiering",
            "III. Conceptual Soundness",
            "III. Outcomes Analysis",
            "III. Ongoing Monitoring",
            "III. Validation",
            "IV. Vendor Models",
            "V. Governance",
            "VI. AI / ML Specific Considerations",
        ],
        controls=OCC_SR_26_2_CONTROLS,
        tier="A",
    )


if __name__ == "__main__":
    main()
