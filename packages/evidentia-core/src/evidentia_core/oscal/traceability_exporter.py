"""Emit a Control↔Threat Traceability Matrix as a Sigstore-signable OSCAL profile.

Per the 2026-06-17 representation decision (multi-model labcoat, primary-source
verified): a static control↔threat matrix is emitted as an OSCAL **profile** —
NOT Assessment Results (a semantic abuse of an assessment-activity model) and
NOT the OSCAL ``mapping`` model (released in 1.2.1, but control↔control only:
its source/target are catalog/profile and items are control/statement, so it
cannot target a threat ID).

The profile imports the control catalog and uses ``modify.alters[]`` to ``add``
a ``link rel="mitigates"`` + Evidentia-namespaced ``prop``s to each control,
pointing at threat resources declared in ``back-matter.resources[]``. Each
threat resource embeds its canonical JSON (base64) + a SHA-256 hash in
``rlinks[].hashes[]`` — the same tamper-evident pattern as the AR exporter's
finding resources — so the emitted profile signs + verifies through the existing
GPG/Sigstore path (``gap analyze --sign-with-*`` / ``oscal verify``) unchanged.

Threat resource UUIDs + per-mapping IDs are derived deterministically (uuid5),
so re-emitting the same matrix on the same inputs reproduces byte-identical
evidence resources + digests.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from evidentia_core.models.common import current_version
from evidentia_core.models.traceability import (
    ControlThreatMapping,
    TraceabilityMatrix,
)
from evidentia_core.oscal._version import OSCAL_SCHEMA_VERSION
from evidentia_core.oscal.digest import digest_bytes

#: Evidentia property namespace for traceability extensions. Tools that don't
#: speak this ns still find the SHA-256 in the standard ``rlinks[].hashes[]``.
EVIDENTIA_NS = "https://evidentia.dev/ns/oscal/traceability"

#: A stable namespace UUID so threat-resource + mapping IDs are deterministic
#: across runs (reproducible evidence). Derived once from the ns string.
_NS_UUID = uuid.uuid5(uuid.NAMESPACE_URL, EVIDENTIA_NS)


def _now_iso() -> str:
    """UTC timestamp in OSCAL ``last-modified`` form (``…Z``)."""
    return (
        datetime.now(UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _threat_key(framework: str, threat_id: str) -> str:
    return f"{framework}:{threat_id}"


def _threat_resource_uuid(framework: str, threat_id: str) -> str:
    """Deterministic UUID for a threat's back-matter resource."""
    return str(uuid.uuid5(_NS_UUID, f"threat/{_threat_key(framework, threat_id)}"))


def _mapping_id(m: ControlThreatMapping) -> str:
    """Stable per-mapping identifier (caller-supplied or deterministically derived)."""
    if m.mapping_id:
        return m.mapping_id
    seed = (
        f"mapping/{m.control_id}/{m.threat_framework}/{m.threat_id}/{m.relationship}"
    )
    return f"urn:uuid:{uuid.uuid5(_NS_UUID, seed)}"


def _threat_canonical_json(m: ControlThreatMapping) -> bytes:
    """Canonical (sorted, whitespace-free) JSON of a threat's identity."""
    payload = {
        "threat-id": m.threat_id,
        "threat-framework": m.threat_framework,
        "threat-name": m.threat_name,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _threat_to_resource(m: ControlThreatMapping) -> dict[str, Any]:
    """Build a tamper-evident OSCAL back-matter resource for a threat.

    Mirrors the AR exporter's finding-resource pattern: canonical JSON in
    ``base64.value`` + SHA-256 in ``rlinks[].hashes[]``.
    """
    res_uuid = _threat_resource_uuid(m.threat_framework, m.threat_id)
    canonical = _threat_canonical_json(m)
    hex_digest = digest_bytes(canonical)
    return {
        "uuid": res_uuid,
        "title": m.threat_name or _threat_key(m.threat_framework, m.threat_id),
        "props": [
            {"name": "threat-id", "ns": EVIDENTIA_NS, "value": m.threat_id},
            {
                "name": "threat-framework",
                "ns": EVIDENTIA_NS,
                "value": m.threat_framework,
            },
        ],
        "rlinks": [
            {
                "href": f"#{res_uuid}",
                "media-type": "application/json",
                "hashes": [{"algorithm": "SHA-256", "value": hex_digest}],
            }
        ],
        "base64": {
            "filename": f"{m.threat_framework}-{m.threat_id}.json",
            "media-type": "application/json",
            "value": base64.b64encode(canonical).decode("ascii"),
        },
    }


def _mapping_to_link(m: ControlThreatMapping, crosswalk_source: str) -> dict[str, Any]:
    """Build the OSCAL ``link`` (control → threat) for one mapping."""
    res_uuid = _threat_resource_uuid(m.threat_framework, m.threat_id)
    return {
        "href": f"#{res_uuid}",
        "rel": m.relationship,
        "text": m.threat_name or _threat_key(m.threat_framework, m.threat_id),
        "props": [
            {"name": "threat-id", "ns": EVIDENTIA_NS, "value": m.threat_id},
            {
                "name": "threat-framework",
                "ns": EVIDENTIA_NS,
                "value": m.threat_framework,
            },
            {"name": "coverage", "ns": EVIDENTIA_NS, "value": m.coverage},
            {"name": "mapping-id", "ns": EVIDENTIA_NS, "value": _mapping_id(m)},
            {
                "name": "crosswalk-source",
                "ns": EVIDENTIA_NS,
                "value": crosswalk_source,
            },
        ],
    }


def traceability_matrix_to_oscal_profile(
    matrix: TraceabilityMatrix,
) -> dict[str, Any]:
    """Render a :class:`TraceabilityMatrix` as an OSCAL profile dict.

    The returned dict is ready to serialize as OSCAL JSON and sign via the
    existing GPG/Sigstore path. Controls are annotated via ``modify.alters[]``;
    threats live in integrity-hashed ``back-matter.resources[]``.
    """
    # Group mappings by control (one alter per control).
    by_control: dict[str, list[ControlThreatMapping]] = {}
    for m in matrix.mappings:
        by_control.setdefault(m.control_id, []).append(m)

    # One back-matter resource per UNIQUE threat (first occurrence wins).
    threats: dict[str, ControlThreatMapping] = {}
    for m in matrix.mappings:
        threats.setdefault(_threat_key(m.threat_framework, m.threat_id), m)
    back_matter_resources = [_threat_to_resource(m) for m in threats.values()]

    alters = [
        {
            "control-id": control_id.lower(),
            "adds": [
                {
                    "position": "ending",
                    "links": [
                        _mapping_to_link(m, matrix.crosswalk_source) for m in ms
                    ],
                }
            ],
        }
        for control_id, ms in by_control.items()
    ]

    return {
        "profile": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": matrix.title,
                "last-modified": _now_iso(),
                "version": current_version(),
                "oscal-version": OSCAL_SCHEMA_VERSION,
                "props": [
                    {
                        "name": "matrix-type",
                        "ns": EVIDENTIA_NS,
                        "value": "control-threat-traceability",
                    },
                    {
                        "name": "crosswalk-source",
                        "ns": EVIDENTIA_NS,
                        "value": matrix.crosswalk_source,
                    },
                ],
            },
            "imports": [
                {
                    "href": matrix.catalog_href,
                    "include-controls": [
                        {"with-ids": [c.lower() for c in matrix.control_ids]}
                    ],
                }
            ],
            "merge": {"as-is": True},
            "modify": {"alters": alters},
            "back-matter": {"resources": back_matter_resources},
        }
    }
