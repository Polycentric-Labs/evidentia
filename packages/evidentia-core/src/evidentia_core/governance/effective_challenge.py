"""Effective Challenge primitives (v0.7.10 P1.5 G2).

SR 11-7 §III.D + SR 26-02 / OCC Bulletin 2026-13a explicitly require
"effective challenge" of model assumptions, methodology, and results
by parties independent of model development. Challenge events must
be DOCUMENTED, including who challenged, when, on what grounds, and
what the outcome was.

This module ships the documentation primitive — operators can log
challenge events as structured records via the
:class:`EffectiveChallenge` schema. Each record links back to a
:class:`evidentia_core.models.model_risk.ModelInventory` entry so
the challenge history flows directly from the model inventory.

Companion sibling module ``evidentia_core.governance.lines_of_
defense`` (v0.7.10 P1.5 G1) provides the 3LOD classification
that determines whether a challenger is "independent enough" —
typically a 2nd-line (risk/compliance) or 3rd-line (internal
audit) party challenging a 1st-line (business operations) model
owner.
"""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum

from pydantic import Field

from evidentia_core.models.common import (
    EvidentiaModel,
    current_version,
    new_id,
    utc_now,
)


class ChallengeOutcome(str, Enum):
    """Outcome classification for an effective challenge event.

    Values:

      - ``accepted`` — the challenger's concern was accepted by the
        model owner; subsequent action follows (e.g., recalibrate,
        add limitation, change use)
      - ``rejected`` — the challenger's concern was reviewed and
        rejected with documented rationale
      - ``modify`` — partial acceptance; modification path agreed
      - ``pending`` — challenge logged; resolution still in progress
    """

    ACCEPTED = "accepted"
    REJECTED = "rejected"
    MODIFY = "modify"
    PENDING = "pending"


class EffectiveChallenge(EvidentiaModel):
    """One documented effective-challenge event.

    Each record captures:

      - Subject model — cross-link via ``subject_model_id`` to a
        :class:`ModelInventory.id`
      - Challenger identity + role
      - Challenge date + topic + substance
      - Model-owner response
      - Outcome + rationale
      - Optional resolved_at timestamp

    Records are persisted via
    :mod:`evidentia_core.effective_challenge_store` (JSON-file
    mirroring the vendor + model-risk store patterns).
    """

    id: str = Field(default_factory=new_id)
    subject_model_id: str = Field(
        description=(
            "Cross-link to the ModelInventory record being challenged. "
            "MUST be a UUID matching an entry in the model_risk store."
        )
    )
    challenger_email: str = Field(description="Email identity of the challenger (independent of model dev).")
    challenger_role: str = Field(
        description=(
            "Role label of the challenger (e.g., 'MRM Director', "
            "'Internal Audit Senior'). Used to substantiate "
            "independence + materiality of the challenge."
        )
    )
    challenge_date: date = Field(description="Date the challenge event occurred.")
    challenge_topic: str = Field(
        description=("Short topic label for the challenge (e.g., 'Methodology — feature selection rationale').")
    )
    challenge_substance: str = Field(
        description=("Full substance of the challenge — what was questioned + on what grounds.")
    )
    response: str | None = Field(
        default=None,
        description=("Model owner's documented response to the challenge. None until response is logged."),
    )
    outcome: ChallengeOutcome = Field(
        default=ChallengeOutcome.PENDING,
        description="Outcome classification per SR 11-7 §III.D.",
    )
    outcome_rationale: str | None = Field(
        default=None,
        description="Explanation for the outcome decision.",
    )
    resolved_at: date | None = Field(
        default=None,
        description="Date the challenge was resolved (None while pending).",
    )

    # Auto-populated metadata
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    evidentia_version: str = Field(default_factory=current_version)
