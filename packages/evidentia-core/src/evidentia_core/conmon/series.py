"""Cadence assertion over the append-only evidence store (v0.13, V13-01).

The conmon state file holds one date per cadence: the last completion an
operator recorded. This module reads the evidence store instead and asks a
different question: does the dated series of artifacts linked to a cadence
show an observation inside every interval of a look-back window?

Two rules from the v0.13 plan are enforced in code, not just prose:

- A gap-free series is evidence of cadence and nothing more. The rendered
  verdict never contains the words "compliant" or "compliance"
  (:meth:`CadenceSeries.describe`, pinned by test).
- Completeness of the record set is a scoping judgement. Counts are reported as
  observed; nothing here asserts that every scan, review or test that happened
  was collected.

Artifacts declare the cadence they satisfy through
``EvidenceArtifact.metadata["cadence_slug"]`` (:data:`CADENCE_SLUG_METADATA_KEY`),
the same convention ``KsiPersistenceCycle.cadence_slug`` uses for KSI evidence.
Pure functions apart from :func:`series_to_finding`'s run-id mint; no I/O. The
`evidentia conmon series` leaf and ``POST /api/conmon/series`` read the store
with :func:`evidentia_core.evidence_store.iter_artifacts` and hand the artifacts
to :func:`assert_series`.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, date, datetime, time, timedelta
from enum import Enum
from itertools import pairwise

from pydantic import Field

from evidentia_core.audit.provenance import CollectionContext, new_run_id
from evidentia_core.conmon.calendar import (
    ConmonCadence,
    get_cadence,
    interval_days_for,
    next_due,
)
from evidentia_core.models.common import (
    EvidentiaModel,
    NonBlankStr,
    Severity,
    current_version,
)
from evidentia_core.models.evidence import EvidenceArtifact
from evidentia_core.models.finding import ComplianceStatus, SecurityFinding

CADENCE_SLUG_METADATA_KEY = "cadence_slug"
"""``EvidenceArtifact.metadata`` key that links an artifact to a cadence slug."""

CADENCE_SOURCE_SYSTEM = "evidentia-cadence"
"""``source_system`` of the findings :func:`series_to_finding` emits."""

DEFAULT_LOOKBACK_DAYS = 365
"""Default look-back window: the twelve months HITECH section 13412 asks for."""

DAY_BASED_TOLERANCE_DAYS = 2
"""Grace added to a day-granular interval before a spacing counts as a gap."""

MONTH_BASED_TOLERANCE_DAYS = 5
"""Grace for month-based cadences, where month-end drift alone moves the
spacing by up to three days (31 January to 28 February to 31 March)."""

_EVIDENCE_NOT_COMPLIANCE = (
    "A gap-free dated series is evidence of cadence and nothing more; the counts "
    "are what the evidence store holds, not what was performed."
)


class SeriesVerdict(str, Enum):
    """What the dated series shows for the window."""

    CONTINUOUS = "continuous"
    """Every interval in the window holds an observation, within tolerance."""

    GAPPED = "gapped"
    """At least one spacing exceeds the cadence interval plus tolerance."""

    INSUFFICIENT = "insufficient"
    """Fewer than two observations in the window; no spacing to assess."""

    UNKNOWN = "unknown"
    """The slug is not a registered cadence."""


class SeriesObservation(EvidentiaModel):
    """One artifact version that counts towards the series."""

    collected_at: datetime
    lineage_id: str
    version: int = Field(ge=1)
    source_system: str


class SeriesGap(EvidentiaModel):
    """A spacing that exceeded the allowed interval."""

    after: datetime = Field(description="Start of the gap: an observation, or the window start.")
    before: datetime = Field(description="End of the gap: the next observation, or the window end.")
    days: int = Field(ge=0, description="Whole days between the two instants.")
    allowed_days: int = Field(ge=0, description="Interval plus tolerance.")
    boundary: bool = Field(
        default=False,
        description="True when one side of the gap is a window edge.",
    )


class CadenceSeries(EvidentiaModel):
    """The dated series for one cadence over a window, with its verdict."""

    slug: NonBlankStr = Field(max_length=128)
    frequency: str | None = Field(default=None)
    interval_days: int | None = Field(default=None)
    window_start: datetime
    window_end: datetime
    tolerance_days: int = Field(ge=0)
    observations: list[SeriesObservation] = Field(default_factory=list)
    gaps: list[SeriesGap] = Field(default_factory=list)
    verdict: SeriesVerdict

    def describe(self) -> str:
        """One paragraph for humans. Never uses the words compliant or compliance."""
        start = self.window_start.date().isoformat()
        end = self.window_end.date().isoformat()
        count = len(self.observations)
        noun = "observation" if count == 1 else "observations"
        head = f"Cadence evidence for {self.slug}: {count} {noun} between {start} and {end}."
        verdict = SeriesVerdict(self.verdict)
        if verdict is SeriesVerdict.UNKNOWN:
            body = " The slug is not a registered cadence, so no interval could be assessed."
        elif verdict is SeriesVerdict.INSUFFICIENT:
            body = " Fewer than two observations, so no spacing could be assessed."
        elif self.gaps:
            worst = max(self.gaps, key=lambda g: g.days)
            plural = "gap" if len(self.gaps) == 1 else "gaps"
            body = (
                f" {len(self.gaps)} {plural}; the widest is {worst.days} days after "
                f"{worst.after.date().isoformat()} against an allowed {worst.allowed_days}."
            )
        else:
            body = " Every interval holds an observation within tolerance."
        return f"{head}{body} Verdict: {verdict.value}. {_EVIDENCE_NOT_COMPLIANCE}"


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def default_window(
    today: date | None = None, *, lookback_days: int = DEFAULT_LOOKBACK_DAYS
) -> tuple[datetime, datetime]:
    """Return ``(start, end)``: ``lookback_days`` ending at the close of ``today`` (UTC)."""
    if lookback_days < 1:
        raise ValueError("lookback_days must be >= 1")
    anchor = today if today is not None else datetime.now(tz=UTC).date()
    end = datetime.combine(anchor, time.max, tzinfo=UTC)
    start = datetime.combine(anchor - timedelta(days=lookback_days), time.min, tzinfo=UTC)
    return start, end


def default_tolerance_days(cadence: ConmonCadence) -> int:
    """Two days for day-granular cadences, five for month-based ones."""
    if interval_days_for(cadence) is not None:
        return DAY_BASED_TOLERANCE_DAYS
    return MONTH_BASED_TOLERANCE_DAYS


def allowed_gap_days(cadence: ConmonCadence, anchor: date, tolerance_days: int) -> int:
    """Longest spacing after ``anchor`` that still counts as on cadence."""
    day_interval = interval_days_for(cadence)
    if day_interval is None:
        day_interval = (next_due(cadence.slug, anchor) - anchor).days
    return day_interval + tolerance_days


def _whole_days(earlier: datetime, later: datetime) -> int:
    return max(0, int((later - earlier).total_seconds() // 86_400))


def assert_series(
    slug: str,
    artifacts: Iterable[EvidenceArtifact],
    *,
    window_start: datetime,
    window_end: datetime,
    tolerance_days: int | None = None,
) -> CadenceSeries:
    """Build the dated series for ``slug`` inside the window and judge it.

    Only artifacts whose ``metadata["cadence_slug"]`` equals ``slug`` and whose
    ``collected_at`` falls inside ``[window_start, window_end]`` are counted, so a
    caller may pass the whole store. ``tolerance_days`` defaults per cadence
    kind (:func:`default_tolerance_days`). Both window edges are assessed: a
    long silence before the first observation or after the last one is a gap
    flagged ``boundary``.
    """
    start = _utc(window_start)
    end = _utc(window_end)
    if end < start:
        raise ValueError("window_end must not precede window_start")
    cadence = get_cadence(slug)
    observations = sorted(
        (
            SeriesObservation(
                collected_at=_utc(artifact.collected_at),
                lineage_id=artifact.effective_lineage_id,
                version=artifact.version,
                source_system=artifact.source_system,
            )
            for artifact in artifacts
            if artifact.metadata.get(CADENCE_SLUG_METADATA_KEY) == slug and start <= _utc(artifact.collected_at) <= end
        ),
        key=lambda o: (o.collected_at, o.lineage_id, o.version),
    )
    if cadence is None:
        return CadenceSeries(
            slug=slug,
            window_start=start,
            window_end=end,
            tolerance_days=tolerance_days or 0,
            observations=observations,
            verdict=SeriesVerdict.UNKNOWN,
        )
    tolerance = tolerance_days if tolerance_days is not None else default_tolerance_days(cadence)
    if tolerance < 0:
        raise ValueError("tolerance_days must be >= 0")
    base = {
        "slug": slug,
        "frequency": str(cadence.frequency),
        "interval_days": interval_days_for(cadence),
        "window_start": start,
        "window_end": end,
        "tolerance_days": tolerance,
        "observations": observations,
    }
    if len(observations) < 2:
        return CadenceSeries(**base, verdict=SeriesVerdict.INSUFFICIENT)

    gaps: list[SeriesGap] = []
    edges: list[tuple[datetime, datetime, bool]] = [
        (start, observations[0].collected_at, True),
        *((previous.collected_at, current.collected_at, False) for previous, current in pairwise(observations)),
        (observations[-1].collected_at, end, True),
    ]
    for after, before, boundary in edges:
        allowed = allowed_gap_days(cadence, after.date(), tolerance)
        days = _whole_days(after, before)
        if days > allowed:
            gaps.append(SeriesGap(after=after, before=before, days=days, allowed_days=allowed, boundary=boundary))
    verdict = SeriesVerdict.GAPPED if gaps else SeriesVerdict.CONTINUOUS
    return CadenceSeries(**base, gaps=gaps, verdict=verdict)


def series_to_finding(series: CadenceSeries, *, run_id: str | None = None) -> SecurityFinding | None:
    """Emit a finding for a gapped or insufficient series; None otherwise.

    The id is deterministic in ``(slug, window)`` so a re-run over the same
    window upserts rather than duplicates. A gapped series is a failed cadence
    check (``compliance_status=FAIL``, medium severity); an insufficient one is
    ``UNKNOWN`` at low severity. The description repeats the evidence-not-
    compliance rule so the finding cannot be read as a compliance verdict.
    """
    verdict = SeriesVerdict(series.verdict)
    if verdict in (SeriesVerdict.CONTINUOUS, SeriesVerdict.UNKNOWN):
        return None
    cadence = get_cadence(series.slug)
    window = f"{series.window_start.date().isoformat()}:{series.window_end.date().isoformat()}"
    if verdict is SeriesVerdict.GAPPED:
        widest = max(series.gaps, key=lambda g: g.days)
        title = (
            f"Cadence gap: {widest.days} days between observations against an allowed "
            f"{widest.allowed_days} ({series.slug})"
        )
        severity, status = Severity.MEDIUM, ComplianceStatus.FAIL
    else:
        title = f"Cadence series too short to assess ({series.slug})"
        severity, status = Severity.LOW, ComplianceStatus.UNKNOWN
    context = CollectionContext(
        collector_id=CADENCE_SOURCE_SYSTEM,
        collector_version=current_version(),
        run_id=run_id or new_run_id(),
        credential_identity="local-evidence-store",
        source_system_id=f"evidence-store:{series.slug}",
    )
    return SecurityFinding(
        title=title,
        description=series.describe(),
        severity=severity,
        compliance_status=status,
        source_system=CADENCE_SOURCE_SYSTEM,
        source_finding_id=f"{series.slug}:{window}",
        resource_type="conmon-cadence",
        resource_id=series.slug,
        collection_context=context,
        raw_data={
            "series": series.model_dump(mode="json"),
            "citation": cadence.citation if cadence is not None else None,
        },
    )


def latest_observations(artifacts: Iterable[EvidenceArtifact]) -> dict[str, date]:
    """Map every cadence slug seen in ``artifacts`` to its latest observation date.

    Only artifacts carrying :data:`CADENCE_SLUG_METADATA_KEY` count. This is the
    evidence-store stand-in for a state-file date: the last time the store saw
    evidence for the cadence, in UTC.
    """
    latest: dict[str, date] = {}
    for artifact in artifacts:
        slug = artifact.metadata.get(CADENCE_SLUG_METADATA_KEY)
        if not isinstance(slug, str) or not slug:
            continue
        observed = _utc(artifact.collected_at).date()
        if slug not in latest or observed > latest[slug]:
            latest[slug] = observed
    return latest


def merge_evidence_anchors(state: dict[str, date], observed: dict[str, date]) -> dict[str, date]:
    """Fill state-file gaps from the evidence store; the state file always wins.

    A slug the operator recorded keeps the recorded date even when the store
    holds a later observation (the record is the operator's statement, the
    store is corroboration). A slug absent from the state file takes the
    store's latest observation. Returns a new mapping.
    """
    merged = dict(observed)
    merged.update(state)
    return merged


def series_verdicts(
    artifacts: Iterable[EvidenceArtifact],
    slugs: Iterable[str],
    *,
    today: date | None = None,
    lookback_days: int = DEFAULT_LOOKBACK_DAYS,
) -> dict[str, SeriesVerdict]:
    """Assert the default-window series for each slug and return its verdict."""
    window_start, window_end = default_window(today, lookback_days=lookback_days)
    pool = list(artifacts)
    return {
        slug: SeriesVerdict(assert_series(slug, pool, window_start=window_start, window_end=window_end).verdict)
        for slug in slugs
    }


__all__: list[str] = [
    "CADENCE_SLUG_METADATA_KEY",
    "CADENCE_SOURCE_SYSTEM",
    "DAY_BASED_TOLERANCE_DAYS",
    "DEFAULT_LOOKBACK_DAYS",
    "MONTH_BASED_TOLERANCE_DAYS",
    "CadenceSeries",
    "SeriesGap",
    "SeriesObservation",
    "SeriesVerdict",
    "allowed_gap_days",
    "assert_series",
    "default_tolerance_days",
    "default_window",
    "latest_observations",
    "merge_evidence_anchors",
    "series_to_finding",
    "series_verdicts",
]
