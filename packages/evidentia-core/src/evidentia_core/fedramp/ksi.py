"""FedRAMP CR26 Security Decision Record (SDR) KSI emitter.

Assembles the operator's :class:`~evidentia_core.models.fedramp_ksi.
KsiStatusDocument` into a schema-valid SDR JSON document with the
``keySecurityIndicators`` block populated, per
``fedramp-security-decision-record-schema-2026-06-24.json`` (vendored
under :mod:`evidentia_core.fedramp.schemas`; upstream pins in
``schemas/UPSTREAM.json`` — byte-identical to upstream since the v0.12
re-vendor retired the interim ``$ref`` local delta).

Design decisions (v0.11 Wave 2 re-based spec, ratified 2026-07-14;
``fedRampRequirements`` revised in v0.12):

- **Full-document emit.** The SDR schema's document-level ``required``
  is ``certificationPackageOverviewUri`` + ``fedRampRequirements``.
  v0.11 emitted the latter as an empty array: schema-valid, but
  ``SDR-CSO-FRR`` (MUST) says the SDR "MUST include at least" an
  explanation, verification, and validation *for each applicable
  FedRAMP rule*, so the document was rule-incomplete. v0.12 emits the
  block from the status file's ``requirements`` map, with IDs checked
  against the bundled ``fedramp-frr-2026`` catalog (provider-facing
  rules only) and coverage reported — the same pattern as the KSI
  block. The statements stay operator-authored; nothing is invented.
  An absent ``requirements`` map still emits ``[]`` so v0.11 files keep
  validating; the coverage report is what surfaces the gap.
- **Top-level ``metadata`` block.** SDR-CSO-MTD (MUST) requires
  version / last-update / source metadata, but the published schema
  models no metadata property. The schema does not set
  ``additionalProperties: false``, so the emitter adds a ``metadata``
  object — rule-required, schema-permitted (asserted by test).
- **Validation is offline.** Draft 2020-12 validation resolves the one
  cross-document ``$ref`` through a local registry of the two vendored
  schemas; no network fetch ever happens.
- **KSI IDs are checked against the bundled ``fedramp-ksi-2026``
  catalog** (generated from the pinned ``FedRAMP/rules`` consolidated
  rules dataset — 10 families / 46 indicators). Unknown IDs are hard
  errors; catalog indicators the operator has not addressed are
  reported as coverage, not errors (FRC-CSX-MAS is a SHOULD).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from evidentia_core.models.fedramp_ksi import (
    FrrRequirementEntry,
    KsiIndicatorEntry,
    KsiStatusDocument,
)

if TYPE_CHECKING:
    from evidentia_core.models.catalog import ControlCatalog

#: The bundled catalogs generated from the pinned FedRAMP/rules dataset.
KSI_CATALOG_ID = "fedramp-ksi-2026"
FRR_CATALOG_ID = "fedramp-frr-2026"

_SCHEMA_DIR = Path(__file__).parent / "schemas"
SDR_SCHEMA_PATH = _SCHEMA_DIR / "fedramp-security-decision-record-schema-2026-06-24.json"
COMMON_SCHEMA_PATH = _SCHEMA_DIR / "fedramp-common-definitions-schema-2026-06-24.json"


@dataclass(frozen=True)
class KsiCoverage:
    """How much of the bundled KSI catalog the status file addresses."""

    total: int
    addressed: int
    missing: tuple[str, ...]

    @property
    def complete(self) -> bool:
        """True when every catalog indicator has an entry."""
        return not self.missing


def load_ksi_catalog() -> ControlCatalog:
    """Load the bundled ``fedramp-ksi-2026`` catalog."""
    from evidentia_core.catalogs.loader import load_catalog

    return load_catalog(KSI_CATALOG_ID)


def load_frr_catalog() -> ControlCatalog:
    """Load the bundled ``fedramp-frr-2026`` catalog (provider-facing rules)."""
    from evidentia_core.catalogs.loader import load_catalog

    return load_catalog(FRR_CATALOG_ID)


@lru_cache(maxsize=1)
def _sdr_validator() -> Draft202012Validator:
    """Build the offline Draft 2020-12 validator for the SDR schema.

    The registry pre-loads both vendored schemas by their ``$id`` so the
    SDR schema's single cross-document ``$ref`` resolves locally.
    """
    sdr = json.loads(SDR_SCHEMA_PATH.read_text(encoding="utf-8"))
    common = json.loads(COMMON_SCHEMA_PATH.read_text(encoding="utf-8"))
    registry = Registry().with_resources(
        [
            (sdr["$id"], Resource.from_contents(sdr)),
            (common["$id"], Resource.from_contents(common)),
        ]
    )
    return Draft202012Validator(sdr, registry=registry)


def validate_sdr_document(document: dict[str, Any]) -> list[str]:
    """Validate an SDR document against the vendored schema.

    Returns a list of human-readable error strings; empty means valid.
    """
    errors = []
    for err in sorted(
        _sdr_validator().iter_errors(document), key=lambda e: list(e.absolute_path)
    ):
        where = "/".join(str(p) for p in err.absolute_path) or "<document root>"
        errors.append(f"{where}: {err.message}")
    return errors


def ksi_coverage(status: KsiStatusDocument) -> KsiCoverage:
    """Report catalog coverage of the operator's status file."""
    catalog = load_ksi_catalog()
    catalog_ids = {control.id for control in catalog.controls}
    addressed = set(status.indicators) & catalog_ids
    missing = tuple(sorted(catalog_ids - set(status.indicators)))
    return KsiCoverage(
        total=len(catalog_ids),
        addressed=len(addressed),
        missing=missing,
    )


def frr_coverage(status: KsiStatusDocument) -> KsiCoverage:
    """Report how much of the provider-facing FRR catalog the file addresses.

    SDR-CSO-FRR is a MUST, so unaddressed rules are the operator's
    to-do list — reported, never errors, mirroring the KSI treatment.
    """
    catalog = load_frr_catalog()
    catalog_ids = {control.id for control in catalog.controls}
    addressed = set(status.requirements) & catalog_ids
    missing = tuple(sorted(catalog_ids - set(status.requirements)))
    return KsiCoverage(
        total=len(catalog_ids),
        addressed=len(addressed),
        missing=missing,
    )


def _validate_requirement_ids(status: KsiStatusDocument) -> None:
    """Reject FRR IDs that are not in the bundled provider-facing catalog."""
    if not status.requirements:
        return
    catalog = load_frr_catalog()
    catalog_ids = {control.id for control in catalog.controls}
    unknown = sorted(set(status.requirements) - catalog_ids)
    if unknown:
        raise ValueError(
            f"unknown FRR requirement ID(s): {', '.join(unknown)}. "
            f"Valid IDs come from the bundled '{FRR_CATALOG_ID}' catalog "
            f"(provider-facing rules only; e.g. "
            f"{', '.join(sorted(catalog_ids)[:3])}, ...); run "
            f"`evidentia catalog show {FRR_CATALOG_ID}` to list them."
        )


def _validate_indicator_ids(status: KsiStatusDocument) -> None:
    """Reject indicator IDs that are not in the bundled KSI catalog."""
    catalog = load_ksi_catalog()
    catalog_ids = {control.id for control in catalog.controls}
    unknown = sorted(set(status.indicators) - catalog_ids)
    if unknown:
        raise ValueError(
            f"unknown KSI indicator ID(s): {', '.join(unknown)}. "
            f"Valid IDs come from the bundled '{KSI_CATALOG_ID}' catalog "
            f"(e.g. {', '.join(sorted(catalog_ids)[:3])}, ...); run "
            f"`evidentia catalog show {KSI_CATALOG_ID}` to list them."
        )


def _render_cycle_statements(
    entry: KsiIndicatorEntry,
    last_completed: dict[str, date] | None,
) -> list[str]:
    """Render SDR-CSX-KSI persistence-cycle statements from CONMON cadences."""
    if not entry.persistence_cycles:
        return []
    from evidentia_core.conmon import get_cadence, next_due

    statements: list[str] = []
    for cycle in entry.persistence_cycles:
        cadence = get_cadence(cycle.cadence_slug)
        if cadence is None:
            raise ValueError(
                f"unknown CONMON cadence slug {cycle.cadence_slug!r} in "
                f"persistence_cycles; run `evidentia conmon list` to see "
                f"available cadences."
            )
        text = (
            f"Persistence cycle: {cadence.activity} — {cadence.frequency} "
            f"(CONMON cadence `{cadence.slug}`)"
        )
        anchor = (last_completed or {}).get(cadence.slug)
        if anchor is not None:
            due = next_due(cadence.slug, anchor)
            text += (
                f"; last completed {anchor.isoformat()}, "
                f"next due {due.isoformat()}"
            )
        text += "."
        if cycle.note:
            text += f" {cycle.note}"
        statements.append(text)
    return statements


def _evidence_to_sdr(entry: KsiIndicatorEntry) -> list[dict[str, Any]]:
    """Map evidence items onto the SDR schema's ``$defs.evidence`` shape."""
    items: list[dict[str, Any]] = []
    for ev in entry.evidence:
        item: dict[str, Any] = {
            "evidenceType": ev.evidence_type,
            "evidenceDescription": ev.description,
        }
        if ev.location is not None:
            item["evidenceLocation"] = ev.location
        if ev.text is not None:
            item["evidenceText"] = ev.text
        if ev.last_updated is not None:
            item["lastUpdated"] = ev.last_updated.isoformat()
        items.append(item)
    return items


def _requirement_to_sdr(frr_id: str, entry: FrrRequirementEntry) -> dict[str, Any]:
    """Map a requirement entry onto the SDR ``fedRampRequirements`` item."""
    item: dict[str, Any] = {
        "frrID": frr_id,
        "frrImplementation": list(entry.implementation),
        "frrValidation": list(entry.validation),
        "frrAssessment": list(entry.assessment),
    }
    if entry.status is not None:
        item["frrImplementationStatus"] = entry.status
    return item


def build_sdr_document(
    status: KsiStatusDocument,
    *,
    last_updated: datetime,
    last_completed: dict[str, date] | None = None,
) -> dict[str, Any]:
    """Assemble a schema-valid SDR document from the operator's status file.

    ``last_completed`` is the CONMON state-file mapping
    (``{cadence_slug: last_completed_date}``); when supplied, rendered
    persistence-cycle statements include last-completed / next-due dates.

    Raises :class:`ValueError` on unknown KSI indicator IDs or unknown
    CONMON cadence slugs — bad references are operator errors, not
    emittable content.
    """
    _validate_indicator_ids(status)
    _validate_requirement_ids(status)

    indicators: list[dict[str, Any]] = []
    for ksi_id in sorted(status.indicators):
        entry = status.indicators[ksi_id]
        implementation = list(entry.implementation)
        implementation.extend(_render_cycle_statements(entry, last_completed))
        item: dict[str, Any] = {
            "ksiId": ksi_id,
            "ksiImplementation": implementation,
            "ksiValidation": list(entry.validation),
            "ksiAssessment": list(entry.assessment),
            "ksiTests": list(entry.tests),
            "ksiEvidence": _evidence_to_sdr(entry),
        }
        if entry.status is not None:
            item["ksiImplementationStatus"] = entry.status
        indicators.append(item)

    return {
        "certificationPackageOverviewUri": (
            status.certification_package_overview_uri
        ),
        "fedRampRequirements": [
            _requirement_to_sdr(frr_id, status.requirements[frr_id])
            for frr_id in sorted(status.requirements)
        ],
        "keySecurityIndicators": indicators,
        "metadata": {
            "version": status.document_version,
            "lastUpdated": last_updated.isoformat(),
            "source": status.source,
        },
    }
