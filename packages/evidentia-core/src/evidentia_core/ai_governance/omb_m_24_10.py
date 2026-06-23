"""OMB M-24-10 AI impact categorization (v0.9.6 P3).

.. deprecated:: 0.10.12
   **OMB M-24-10 was rescinded on 2025-04-03 by
   `M-25-21 <https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-21-Accelerating-Federal-Use-of-AI-through-Innovation-Governance-and-Public-Trust.pdf>`_**,
   which collapses the rights-impacting / safety-impacting split into a
   single "high-impact AI" category. Use
   :mod:`evidentia_core.ai_governance.omb_m_25_21`
   (:class:`~evidentia_core.ai_governance.omb_m_25_21.HighImpactDetermination`
   + :class:`~evidentia_core.ai_governance.omb_m_25_21.OMBHighImpactAssessment`)
   for new work. This module, :class:`OMBImpactCategory`, the
   ``omb_impact`` registry field, and the ``set-omb-impact`` CLI / REST
   verbs are retained (no behaviour change, no runtime warning) so
   persisted M-24-10 inventories keep loading; map a legacy value forward
   with
   :func:`~evidentia_core.ai_governance.omb_m_25_21.crosswalk_from_legacy`.

`OMB Memorandum M-24-10 <https://www.whitehouse.gov/wp-content/uploads/2024/03/M-24-10-Advancing-Governance-Innovation-and-Risk-Management-for-Agency-Use-of-Artificial-Intelligence.pdf>`_
(March 28, 2024) directs federal agencies to inventory AI use cases
and apply minimum risk-management practices to systems that affect
public rights or safety. The memo defines three impact categories
that gate the obligation level:

  - **Rights-Impacting AI** (§5(b)(i)): outputs have legal, material,
    binding, or similarly significant effects on individuals or
    communities. Examples per OMB §5(b): law enforcement, eligibility
    determinations for benefits, hiring / admissions, immigration /
    border adjudications, public health / medical determinations.

  - **Safety-Impacting AI** (§5(b)(ii)): applications that could create
    or exacerbate physical or safety risks. Examples per OMB §5(b):
    safety-critical infrastructure controls, autonomous vehicles,
    medical-device decisions.

  - **Neither**: no rights / safety impact. Subject to baseline
    governance practices but exempt from the §5(c) minimum
    risk-management requirements.

The fourth value, **Rights and Safety-Impacting**, captures systems
hitting BOTH §5(b)(i) and §5(b)(ii) — common in federal AI deployed
to medical / public-health contexts where the same output is both a
medical determination (rights-impacting) AND a safety-relevant signal
(safety-impacting). Evidentia surfaces this as a first-class category
rather than asking operators to pick "the more salient" trigger.

**Threat-model boundary**: this is operator-supplied metadata, not
a control surface. Misclassification is an operator risk; Evidentia
surfaces the category for inventory + reporting but does NOT validate
it against the system's actual use case. Federal agencies have a
legal review path (typically the Chief AI Officer or General Counsel)
that determines the categorization.

**Inventory schema reference**: there is no upstream-published
machine-readable schema for M-24-10 inventory entries. Federal
agencies (Federal Reserve, EXIM, SBA, DOJ, VA, EEOC) publish their
own compliance plans in prose form. Evidentia defines the canonical
JSON / Pydantic representation here so cross-agency tooling has a
shared schema to target.
"""

from __future__ import annotations

from enum import Enum


class OMBImpactCategory(str, Enum):
    """OMB M-24-10 §5(b) AI impact classification.

    .. deprecated:: 0.10.12
       Superseded by
       :class:`~evidentia_core.ai_governance.omb_m_25_21.HighImpactDetermination`
       after M-24-10's 2025-04-03 rescission. Retained for backward
       compatibility (string values + import path are stable); map a
       value forward with
       :func:`~evidentia_core.ai_governance.omb_m_25_21.crosswalk_from_legacy`.

    Operators rate per the published §5 definitions + worked examples
    in agency compliance plans (Federal Reserve / EXIM / SBA / DOJ /
    VA / EEOC each ship their interpretation of the categories).
    String values stable across releases so persisted YAML / JSON
    inventories survive minor / major version bumps.
    """

    RIGHTS_IMPACTING = "rights_impacting"
    """§5(b)(i): outputs have legal, material, binding, or similarly
    significant effects on individuals or communities. Triggers
    OMB §5(c) minimum risk-management practices."""

    SAFETY_IMPACTING = "safety_impacting"
    """§5(b)(ii): applications that could create or exacerbate
    physical or safety risks. Triggers OMB §5(c) minimum risk-
    management practices."""

    RIGHTS_AND_SAFETY_IMPACTING = "rights_and_safety_impacting"
    """Both §5(b)(i) and §5(b)(ii) apply. Common in medical /
    public-health AI. Triggers OMB §5(c); operators MUST address
    BOTH the rights and safety paths in their risk-management
    practices."""

    NEITHER = "neither"
    """Neither §5(b)(i) nor §5(b)(ii) applies. Subject to baseline
    governance practices but exempt from §5(c) minimum practices.
    Examples: internal HR workflow automation, document-routing
    assistance, etc."""


def triggers_minimum_practices(category: OMBImpactCategory) -> bool:
    """Return True iff the category triggers OMB §5(c) minimum practices.

    NEITHER is the only exempt category. The three impacting
    categories all trigger the same §5(c) obligations + the
    operator must perform impact assessments, public-feedback
    mechanisms, ongoing monitoring, and meaningful AI-decision
    notification per §5(c).
    """
    return category != OMBImpactCategory.NEITHER


__all__ = [
    "OMBImpactCategory",
    "triggers_minimum_practices",
]
