"""AI system risk classification — EU AI Act + NIST AI RMF (v0.9.3 P2.3).

Rule-based classifier mapping an :class:`AISystemDescriptor`
(operator-supplied use-case attributes) to:

- :class:`EUAIActTier` — UNACCEPTABLE / HIGH / LIMITED / MINIMAL
  per EU AI Act Article 5 (prohibitions) + Annex III (high-risk)
  + Article 50 (transparency) triggers.
- :class:`NISTAIRMFFunction` — applicable AI RMF 1.0 functions
  (GOVERN / MAP / MEASURE / MANAGE) — all four are universal,
  but the classifier surfaces which are most operationally
  pressing for the supplied descriptor.

Output is :class:`AISystemClassification` carrying both tiers +
rationale (which rule fired). Per the v0.9.3 cycle-open sign-off,
this is "informational starting point, not legal compliance
determination" — the docstrings + AISystemClassification.rationale
field make that explicit.

LLM-augmented classification is reserved for v0.9.4+ once the
rule-based contract has operator feedback.
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from evidentia_core.models.common import EvidentiaModel


class AnnexIIIDomain(str, Enum):
    """Annex III high-risk AI domains per EU AI Act.

    Concrete categories from the published Annex III list. An AI
    system in any of these domains triggers EU AI Act HIGH tier
    classification (subject to Article 6 exemptions).
    """

    BIOMETRICS = "biometrics"
    """1. Biometrics (incl. categorization + emotion recognition)."""

    CRITICAL_INFRASTRUCTURE = "critical_infrastructure"
    """2. Critical infrastructure (digital, road traffic, utilities)."""

    EDUCATION = "education"
    """3. Education + vocational training (admissions, evaluation)."""

    EMPLOYMENT = "employment"
    """4. Employment (recruitment, performance, termination)."""

    ESSENTIAL_SERVICES = "essential_services"
    """5. Essential private + public services (credit scoring, social
    benefits, emergency services dispatch)."""

    LAW_ENFORCEMENT = "law_enforcement"
    """6. Law enforcement (risk assessment, evidence reliability,
    profiling, polygraph alternatives)."""

    MIGRATION = "migration"
    """7. Migration, asylum, border control."""

    JUSTICE = "justice"
    """8. Administration of justice + democratic processes."""

    NONE = "none"
    """Not in any Annex III domain."""


class _DecisionRole(str, Enum):
    """How the AI's output is used in human decision-making."""

    ADVISORY = "advisory"
    """Recommendation that a human must affirm before action."""

    AUTOMATED = "automated"
    """Decision is enacted without human review per case."""

    HYBRID = "hybrid"
    """Some cases auto-decide; others escalate to humans."""


class EUAIActTier(str, Enum):
    """EU AI Act risk tier per Articles 5, 6, 50."""

    UNACCEPTABLE = "unacceptable"
    """Article 5 prohibited practices. Cannot be deployed."""

    HIGH = "high"
    """Annex III high-risk (Article 6). Subject to Articles 9-15
    requirements (risk management, data governance, transparency,
    human oversight, accuracy)."""

    LIMITED = "limited"
    """Article 50 transparency obligations (chatbots, deepfakes,
    emotion recognition). Disclosure required to subjects."""

    MINIMAL = "minimal"
    """No specific EU AI Act obligations beyond general best
    practice. Most AI systems land here."""


class NISTAIRMFFunction(str, Enum):
    """NIST AI RMF 1.0 high-level function."""

    GOVERN = "govern"
    """Cultivate a culture of risk management."""

    MAP = "map"
    """Categorize the AI system + its context."""

    MEASURE = "measure"
    """Assess + analyze risks identified in MAP."""

    MANAGE = "manage"
    """Allocate risk resources, document, respond."""


class AISystemDescriptor(EvidentiaModel):
    """Operator-supplied use-case attributes for classification.

    All fields except ``purpose`` have sensible defaults so quick
    classification of a known-low-risk system is one line. High-risk
    classifications require operators to explicitly specify the
    risk-elevating attributes.
    """

    name: str = Field(
        min_length=1,
        max_length=256,
        description="Human-readable AI system name (free text).",
    )
    purpose: str = Field(
        min_length=1,
        max_length=2048,
        description="Plain-English description of what the system does.",
    )
    annex_iii_domain: AnnexIIIDomain = Field(
        default=AnnexIIIDomain.NONE,
        description=(
            "Annex III high-risk domain (if any). Set to NONE for "
            "systems outside Annex III scope."
        ),
    )
    decision_role: _DecisionRole = Field(
        default=_DecisionRole.ADVISORY,
        description=(
            "Whether the AI output is advisory (human affirms), "
            "automated (no per-case human review), or hybrid."
        ),
    )
    affects_natural_persons: bool = Field(
        default=False,
        description=(
            "Does the system produce outputs that affect EU natural "
            "persons' legal rights or significant interests? "
            "(Materiality test from EU AI Act recital 53.)"
        ),
    )
    interacts_with_natural_persons: bool = Field(
        default=False,
        description=(
            "Does the system directly interact with natural persons "
            "(e.g., chatbot, voice assistant)? Triggers Article 50 "
            "transparency obligation."
        ),
    )
    generates_synthetic_content: bool = Field(
        default=False,
        description=(
            "Does the system generate or significantly alter image, "
            "audio, video, or text content (deepfake / generative)? "
            "Triggers Article 50.4 disclosure."
        ),
    )
    is_prohibited_practice: bool = Field(
        default=False,
        description=(
            "Self-reported flag: does this system fit Article 5 "
            "prohibitions (social scoring by public authorities, "
            "real-time biometric identification in public spaces, "
            "subliminal manipulation, exploitation of vulnerabilities, "
            "untargeted facial scraping, emotion inference in "
            "workplace/education)? Operator MUST self-assess; "
            "classifier defers to this flag for UNACCEPTABLE."
        ),
    )


class AISystemClassification(EvidentiaModel):
    """Result of classifying an :class:`AISystemDescriptor`.

    Per the v0.9.3 sign-off: this is an informational starting
    point, NOT a legal compliance determination. Operators should
    have SME review for any HIGH or UNACCEPTABLE classification.
    """

    descriptor_name: str = Field(
        description="Echo of the input descriptor name for traceability."
    )
    eu_ai_act_tier: EUAIActTier = Field(
        description="EU AI Act risk tier per Articles 5, 6, 50."
    )
    applicable_nist_ai_rmf_functions: list[NISTAIRMFFunction] = Field(
        description=(
            "NIST AI RMF functions most operationally pressing for "
            "this descriptor. Ordered most-pressing first."
        ),
    )
    rationale: list[str] = Field(
        description=(
            "Plain-English explanation of which classifier rules "
            "fired. Ordered as evaluated."
        ),
    )
    disclaimer: str = Field(
        default=(
            "This classification is an informational starting point "
            "produced by a rule-based classifier. It is NOT a legal "
            "compliance determination. Operators should have SME "
            "review for any HIGH or UNACCEPTABLE classification + "
            "before deployment of any AI system that affects natural "
            "persons' legal rights or significant interests."
        ),
        description="Standing disclaimer attached to every classification.",
    )


# ── classifier ────────────────────────────────────────────────────


def classify(descriptor: AISystemDescriptor) -> AISystemClassification:
    """Rule-based classifier mapping a descriptor to AISystemClassification.

    Evaluation order:

    1. Article 5 prohibitions → UNACCEPTABLE (caller self-flagged)
    2. Annex III domain present → HIGH (with limited Article 6
       exemptions: not narrow procedural task, not preparatory,
       not detecting decision patterns — these exemptions are NOT
       auto-applied; operator can downgrade via SME review)
    3. Interacts-with / generates-synthetic → LIMITED (Article 50)
    4. Otherwise → MINIMAL

    NIST AI RMF: all 4 functions apply universally; the classifier
    orders them by operational priority for the descriptor (e.g.,
    high-risk systems prioritize GOVERN + MAP; advisory systems
    prioritize MEASURE).
    """
    rationale: list[str] = []

    # ── EU AI Act tier ──────────────────────────────────────────
    if descriptor.is_prohibited_practice:
        tier = EUAIActTier.UNACCEPTABLE
        rationale.append(
            "Operator self-flagged is_prohibited_practice=True; "
            "Article 5 prohibitions apply (UNACCEPTABLE)."
        )
    elif descriptor.annex_iii_domain != AnnexIIIDomain.NONE:
        tier = EUAIActTier.HIGH
        rationale.append(
            f"Annex III domain '{descriptor.annex_iii_domain}' "
            f"specified; Article 6 high-risk applies (HIGH). Operator "
            f"may downgrade via SME review per Article 6(3) exemptions "
            f"(narrow procedural task, preparatory work, decision-"
            f"pattern detection)."
        )
    elif (
        descriptor.interacts_with_natural_persons
        or descriptor.generates_synthetic_content
    ):
        tier = EUAIActTier.LIMITED
        triggers = []
        if descriptor.interacts_with_natural_persons:
            triggers.append("Article 50.1 (interacts with natural persons)")
        if descriptor.generates_synthetic_content:
            triggers.append(
                "Article 50.4 (generates synthetic content)"
            )
        rationale.append(
            f"Transparency obligations apply: "
            f"{'; '.join(triggers)} (LIMITED)."
        )
    else:
        tier = EUAIActTier.MINIMAL
        rationale.append(
            "No prohibitions, Annex III domain, or transparency "
            "triggers identified (MINIMAL)."
        )

    # ── NIST AI RMF priority ────────────────────────────────────
    # Universal applicability; ordering reflects pressing operational
    # priority given the descriptor's risk profile.
    if tier in (EUAIActTier.UNACCEPTABLE, EUAIActTier.HIGH):
        functions = [
            NISTAIRMFFunction.GOVERN,
            NISTAIRMFFunction.MAP,
            NISTAIRMFFunction.MEASURE,
            NISTAIRMFFunction.MANAGE,
        ]
        rationale.append(
            "High-risk tier; GOVERN + MAP prioritized (organizational "
            "policy + system categorization come before risk measurement)."
        )
    elif descriptor.decision_role == _DecisionRole.AUTOMATED:
        functions = [
            NISTAIRMFFunction.MEASURE,
            NISTAIRMFFunction.MANAGE,
            NISTAIRMFFunction.GOVERN,
            NISTAIRMFFunction.MAP,
        ]
        rationale.append(
            "Automated decision-role; MEASURE + MANAGE prioritized "
            "(per-case human review absent, so risk measurement + "
            "incident response are pressing)."
        )
    else:
        functions = [
            NISTAIRMFFunction.MAP,
            NISTAIRMFFunction.GOVERN,
            NISTAIRMFFunction.MEASURE,
            NISTAIRMFFunction.MANAGE,
        ]
        rationale.append(
            "Advisory/hybrid decision-role; MAP + GOVERN prioritized "
            "(human-in-the-loop reduces measurement urgency)."
        )

    return AISystemClassification(
        descriptor_name=descriptor.name,
        eu_ai_act_tier=tier,
        applicable_nist_ai_rmf_functions=functions,
        rationale=rationale,
    )
