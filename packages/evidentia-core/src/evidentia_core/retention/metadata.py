"""Retention metadata + lifecycle primitives (v0.7.11 P0).

Per-record retention metadata aligned with the major US/EU
regulatory record-retention regimes:

  - **SEC Rule 17a-4 / FINRA 3110** — broker-dealer records, 6
    years (3 years easily accessible)
  - **IRS 1.6001-1** — tax records, 7 years
  - **Sarbanes-Oxley §404** — SOX audit evidence, 7 years
  - **HIPAA Privacy Rule** — protected-health-information records,
    6 years
  - **GLBA / FFIEC IT Handbook** — bank records, 5 years (most
    categories) or per-product
  - **GDPR / CCPA** — personal data, retain only as long as
    necessary for the purpose; right-to-erasure
  - **PCI DSS 10.7** — cardholder logs, 1 year (3 months online)
  - **OCC 2011-12 / SR 11-7 (model risk)** — model documentation
    + validation reports, life of the model + 7 years post-
    retirement
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from enum import Enum

from pydantic import Field, model_validator

from evidentia_core.models.common import (
    EvidentiaModel,
    current_version,
    new_id,
    utc_now,
)


class RetentionClassification(str, Enum):
    """Regulator-aligned record-retention classifications.

    The default-cadence column on each entry is the canonical
    regulator-stated minimum; operators may extend per institution
    policy via the explicit ``retention_period_days`` field.
    """

    SEC_17A_4 = "sec-17a-4"  # 6 years (broker-dealer)
    FINRA_3110 = "finra-3110"  # 6 years
    IRS_TAX = "irs-tax"  # 7 years
    SOX_404 = "sox-404"  # 7 years
    HIPAA = "hipaa"  # 6 years
    GLBA = "glba"  # 5 years
    PCI_DSS = "pci-dss"  # 1 year
    MODEL_RISK = "model-risk"  # life + 7 years
    GDPR = "gdpr"  # purpose-limited (default 0)
    GENERIC = "generic"  # operator-defined


_DEFAULT_RETENTION_DAYS: dict[str, int] = {
    "sec-17a-4": 6 * 365,
    "finra-3110": 6 * 365,
    "irs-tax": 7 * 365,
    "sox-404": 7 * 365,
    "hipaa": 6 * 365,
    "glba": 5 * 365,
    "pci-dss": 365,
    "model-risk": 7 * 365,
    "gdpr": 0,  # purpose-limited; operator must set explicitly
    "generic": 7 * 365,  # safe default
}


def default_retention_days(classification: RetentionClassification | str) -> int:
    """Return the canonical default retention period in days for a class."""
    value = classification.value if isinstance(classification, RetentionClassification) else classification
    return _DEFAULT_RETENTION_DAYS.get(value, 7 * 365)


class RetentionLifecycleStage(str, Enum):
    """Record lifecycle states.

    State machine:
      ACTIVE        → record is in active use; retention countdown
                      hasn't started or hasn't been crossed
      PRESERVED     → record is being explicitly preserved beyond
                      its standard retention (legal hold,
                      regulatory inquiry, ongoing litigation)
      EXPIRED       → standard retention period has elapsed; record
                      is eligible for purge but not yet purged
      PURGED        → record has been securely deleted (terminal
                      state; metadata retained for audit trail)
    """

    ACTIVE = "active"
    PRESERVED = "preserved"
    EXPIRED = "expired"
    PURGED = "purged"


class RetentionPolicy(EvidentiaModel):
    """Reusable retention-policy template.

    Operators define policies once (e.g., 'sox-quarterly-evidence',
    '7-year-model-docs', 'pci-1-year-logs') + reference them by
    name in :class:`RetentionMetadata`.
    """

    name: str = Field(description="Policy name (kebab-case canonical form).")
    description: str = Field(description="What records this policy applies to + why.")
    classification: RetentionClassification = Field(description="Regulator-aligned classification.")
    retention_period_days: int = Field(
        ge=0,
        description=(
            "Minimum retention period in calendar days. Zero is "
            "valid for GDPR purpose-limited records (operator must "
            "explicitly delete when purpose is fulfilled)."
        ),
    )
    lock_enforced: bool = Field(
        default=True,
        description=(
            "Whether records under this policy are protected by a "
            "WORM backend. False = retention is policy-only "
            "(operator-enforced); True = WORM-backend-enforced."
        ),
    )

    # Auto-populated metadata
    created_at: datetime = Field(default_factory=utc_now)


class RetentionMetadata(EvidentiaModel):
    """Per-record retention metadata.

    Attached to a CollectionContext, OSCAL artifact, audit log
    line, or any other record that needs retention tracking.
    """

    id: str = Field(default_factory=new_id)
    classification: RetentionClassification = Field(
        description="Regulator-aligned classification.",
    )
    retention_period_days: int = Field(
        ge=0,
        description=(
            "Retention period in calendar days from `created_at`. Operator may override the per-classification default."
        ),
    )
    lifecycle_stage: RetentionLifecycleStage = Field(
        default=RetentionLifecycleStage.ACTIVE,
        description="Current lifecycle state.",
    )
    legal_hold: bool = Field(
        default=False,
        description=(
            "True = under legal hold; record cannot transition to EXPIRED or PURGED regardless of retention period."
        ),
    )
    lock_until: date | None = Field(
        default=None,
        description=(
            "When set + lifecycle is ACTIVE/PRESERVED, the record "
            "is in its mandatory retention window. Computed from "
            "created_at + retention_period_days at construction; "
            "may be overridden for legacy records imported from "
            "external systems."
        ),
    )
    policy_name: str | None = Field(
        default=None,
        description="Optional cross-reference to a RetentionPolicy.",
    )
    record_pointer: str | None = Field(
        default=None,
        description=(
            "Free-text pointer to the actual record this metadata "
            "covers (file path, S3 ARN, Azure URL, GCS URI, etc.). "
            "The retention metadata itself is operator-owned; this "
            "field links it to the underlying object."
        ),
    )
    notes: str | None = Field(
        default=None,
        description="Free-text operator notes.",
    )

    # Auto-populated metadata
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    evidentia_version: str = Field(default_factory=current_version)

    @model_validator(mode="after")
    def _populate_lock_until(self) -> RetentionMetadata:
        """Compute `lock_until` from `created_at + retention_period_days`
        when not explicitly set by the operator."""
        if self.lock_until is None and self.retention_period_days > 0:
            target = self.created_at.date() + timedelta(days=self.retention_period_days)
            object.__setattr__(self, "lock_until", target)
        return self


def is_locked(metadata: RetentionMetadata, today: date | None = None) -> bool:
    """Return True if the record is currently inside its retention window
    or under legal hold.

    Locked records cannot be transitioned to EXPIRED or PURGED.

    Parameters
    ----------
    metadata
        The record's RetentionMetadata.
    today
        Reference date for the comparison (default = today).
        Mostly useful for testing.
    """
    if metadata.legal_hold:
        return True
    if metadata.lifecycle_stage in (RetentionLifecycleStage.PURGED.value,):
        return False
    today = today or date.today()
    if metadata.lock_until is None:
        return False
    return today < metadata.lock_until


class RetentionTransitionError(ValueError):
    """Raised when an attempted lifecycle transition is illegal."""


def transition_lifecycle(
    metadata: RetentionMetadata,
    new_stage: RetentionLifecycleStage,
    *,
    today: date | None = None,
    force_gdpr_purge: bool = False,
) -> RetentionMetadata:
    """Transition a record's lifecycle stage with validation.

    Rules:

      - PURGED is terminal — cannot transition out
      - EXPIRED → PURGED is allowed (the canonical purge path)
      - ACTIVE → EXPIRED requires the lock window to have passed
        AND no legal hold
      - ACTIVE → PRESERVED is always allowed (legal hold trigger)
      - PRESERVED → ACTIVE is allowed (legal hold released)
      - PRESERVED → EXPIRED requires ``legal_hold=False`` AND the
        lock window to have passed

    GDPR Article 17 (right-to-erasure) override:

      - When ``force_gdpr_purge=True``, ACTIVE → EXPIRED is allowed
        for records whose ``retention_period_days == 0`` (the
        Pydantic invariant for GDPR purpose-limited records). This
        closes the v0.7.11 functional gap where GDPR records had
        ``lock_until=None`` and could not satisfy the standard
        ``can_expire`` precondition.
      - The override is scoped: it does NOT bypass legal_hold
        (which always trumps GDPR per most legal frameworks) and
        it does NOT allow ACTIVE → EXPIRED on records with
        ``retention_period_days > 0`` (those follow the standard
        retention path).
      - Operators MUST audit-log every ``force_gdpr_purge=True``
        call with operator + gdpr_request_ref provenance via
        ``EventAction.RETENTION_GDPR_PURGE``. The
        ``WORMBackend.purge_immediately`` operator workflow is the
        canonical entry point.

    Returns a new RetentionMetadata (input not mutated).
    """
    current = metadata.lifecycle_stage
    new_value = new_stage.value
    if current == RetentionLifecycleStage.PURGED.value:
        raise RetentionTransitionError("PURGED is terminal — cannot transition out of it.")
    if new_value == current:
        return metadata.model_copy(update={"updated_at": utc_now()})

    today = today or date.today()
    # v0.7.12 P1 closure of v0.7.11 GDPR functional gap: GDPR
    # purpose-limited records (retention_period_days=0,
    # lock_until=None) cannot satisfy the standard can_expire
    # precondition because lock_until is None. The
    # force_gdpr_purge override path permits ACTIVE → EXPIRED for
    # these records ONLY (legal_hold still trumps).
    is_gdpr_purpose_limited = metadata.retention_period_days == 0
    can_expire_gdpr = force_gdpr_purge and is_gdpr_purpose_limited and not metadata.legal_hold
    can_expire = (
        not metadata.legal_hold and metadata.lock_until is not None and today >= metadata.lock_until
    ) or can_expire_gdpr

    valid_transitions = {
        RetentionLifecycleStage.ACTIVE.value: {
            RetentionLifecycleStage.PRESERVED.value: True,
            RetentionLifecycleStage.EXPIRED.value: can_expire,
        },
        RetentionLifecycleStage.PRESERVED.value: {
            RetentionLifecycleStage.ACTIVE.value: True,
            RetentionLifecycleStage.EXPIRED.value: can_expire,
        },
        RetentionLifecycleStage.EXPIRED.value: {
            RetentionLifecycleStage.PURGED.value: not metadata.legal_hold,
        },
    }
    allowed_for_current = valid_transitions.get(current, {})
    if new_value not in allowed_for_current:
        raise RetentionTransitionError(
            f"Illegal transition: {current} → {new_value}. Valid from {current}: {sorted(allowed_for_current.keys())}"
        )
    if not allowed_for_current[new_value]:
        # Transition is in the table but pre-conditions fail
        if metadata.legal_hold:
            reason = "legal_hold is True"
        elif metadata.lock_until is not None and today < metadata.lock_until:
            reason = f"still inside retention window (lock_until={metadata.lock_until}; today={today})"
        else:
            reason = "pre-condition not met"
        raise RetentionTransitionError(f"Cannot transition {current} → {new_value}: {reason}")
    return metadata.model_copy(
        update={
            "lifecycle_stage": new_stage.value,
            "updated_at": utc_now(),
        }
    )


def generate_retention_report(
    metadata_list: list[RetentionMetadata],
    today: date | None = None,
) -> str:
    """Generate a Markdown audit report of an evidence inventory's
    retention posture.

    Sections:

      1. Executive summary — counts per lifecycle stage + counts of
         locked records + counts under legal hold
      2. Per-classification distribution table
      3. Records eligible for purge (lifecycle=EXPIRED, no legal
         hold) — operator action items
      4. Records under legal hold — listed with notes
    """
    today = today or date.today()
    if not metadata_list:
        return (
            "# Retention Posture Report\n\n"
            "_No records under retention tracking. Use `evidentia "
            "retention set` to start managing the evidence inventory._\n"
        )

    sections: list[str] = []

    # ── §1 Executive summary ─────────────────────────────────────
    stage_counts: dict[str, int] = {s.value: 0 for s in RetentionLifecycleStage}
    locked_count = 0
    legal_hold_count = 0
    for m in metadata_list:
        stage_counts[m.lifecycle_stage] += 1
        if is_locked(m, today=today):
            locked_count += 1
        if m.legal_hold:
            legal_hold_count += 1

    expired_purgeable = stage_counts[RetentionLifecycleStage.EXPIRED.value]
    callout = ""
    if expired_purgeable > 0:
        callout = (
            f"> ℹ️ **{expired_purgeable} record(s) eligible for "
            "secure purge.** Review §3 below; documented disposal "
            "process applies.\n\n"
        )

    sections.append(
        "# Retention Posture Report\n\n"
        f"_As of {today.isoformat()}, {len(metadata_list)} record(s) "
        "tracked across the audit chain-of-custody._\n\n"
        f"{callout}"
        "| Stage | Count |\n"
        "| --- | --- |\n"
        f"| ACTIVE | {stage_counts['active']} |\n"
        f"| PRESERVED | {stage_counts['preserved']} |\n"
        f"| EXPIRED | {stage_counts['expired']} |\n"
        f"| PURGED | {stage_counts['purged']} |\n"
        f"| **Locked (in retention window)** | **{locked_count}** |\n"
        f"| **Under legal hold** | **{legal_hold_count}** |\n"
        f"| **Total** | **{len(metadata_list)}** |\n"
    )

    # ── §2 Per-classification table ──────────────────────────────
    cls_counts: dict[str, int] = {}
    for m in metadata_list:
        cls_counts[m.classification] = cls_counts.get(m.classification, 0) + 1
    if cls_counts:
        rows = []
        for cls in sorted(cls_counts.keys()):
            rows.append(f"| {cls} | {cls_counts[cls]} |")
        sections.append(
            "## Per-classification distribution\n\n| Classification | Count |\n| --- | --- |\n" + "\n".join(rows) + "\n"
        )

    # ── §3 Records eligible for purge ────────────────────────────
    eligible = [
        m for m in metadata_list if m.lifecycle_stage == RetentionLifecycleStage.EXPIRED.value and not m.legal_hold
    ]
    if eligible:
        rows = []
        for m in sorted(eligible, key=lambda x: x.id):
            pointer = m.record_pointer or "_no pointer_"
            lock_until = m.lock_until.isoformat() if m.lock_until else "—"
            rows.append(f"| `{m.id[:8]}` | {m.classification} | {pointer} | {lock_until} |")
        sections.append(
            "## Records eligible for purge\n\n"
            "| ID | Classification | Pointer | Lock-until |\n"
            "| --- | --- | --- | --- |\n" + "\n".join(rows) + "\n"
        )

    # ── §4 Records under legal hold ──────────────────────────────
    holds = [m for m in metadata_list if m.legal_hold]
    if holds:
        rows = []
        for m in sorted(holds, key=lambda x: x.id):
            note = m.notes or "_no notes_"
            rows.append(f"| `{m.id[:8]}` | {m.classification} | {note} |")
        sections.append(
            "## Records under legal hold\n\n"
            "| ID | Classification | Notes |\n"
            "| --- | --- | --- |\n" + "\n".join(rows) + "\n"
        )

    return "\n".join(sections)
