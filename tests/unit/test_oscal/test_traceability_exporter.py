"""Tests for the Control↔Threat Traceability Matrix OSCAL profile emitter.

Per the 2026-06-17 representation decision, the matrix is emitted as an OSCAL
*profile* (imports a control catalog; adds one OSCAL ``add`` per mapping —
props on the addition + a bare ``link rel="mitigates"``; threats in
integrity-hashed back-matter resources). These tests pin the profile shape,
schema-conformance through trestle, and the tamper-evident reproducibility
guarantee.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from evidentia_core.models.traceability import (
    ControlThreatMapping,
    TraceabilityMatrix,
)
from evidentia_core.oscal.traceability_exporter import (
    traceability_matrix_to_oscal_profile,
)
from evidentia_core.oscal.verify import verify_ar_file
from pydantic import ValidationError


def _sample_matrix() -> TraceabilityMatrix:
    return TraceabilityMatrix(
        title="Control-to-Threat Traceability: Demo",
        catalog_href="nist-800-53-rev5-moderate.json",
        framework_id="nist-800-53-rev5-moderate",
        crosswalk_source="self-attested",
        mappings=[
            ControlThreatMapping(
                control_id="AC-2",
                threat_id="T1078",
                threat_framework="mitre-attack",
                threat_name="Valid Accounts",
                relationship="mitigates",
                coverage="partial",
            ),
            ControlThreatMapping(
                control_id="AC-2",
                threat_id="T1098",
                threat_framework="mitre-attack",
                threat_name="Account Manipulation",
            ),
            ControlThreatMapping(
                control_id="SI-2",
                threat_id="CWE-79",
                threat_framework="cwe",
                threat_name="Cross-site Scripting",
                relationship="mitigates",
            ),
        ],
    )


class TestTraceabilityModel:
    def test_control_ids_are_unique_and_order_preserving(self) -> None:
        assert _sample_matrix().control_ids == ["AC-2", "SI-2"]

    def test_conflicting_threat_names_are_rejected(self) -> None:
        # The same (framework, threat_id) with two different names would emit an
        # internally-inconsistent profile (link text vs first-occurrence resource).
        with pytest.raises(ValidationError):
            TraceabilityMatrix(
                title="x",
                catalog_href="cat.json",
                framework_id="f",
                mappings=[
                    ControlThreatMapping(
                        control_id="AC-2",
                        threat_id="T1078",
                        threat_framework="mitre-attack",
                        threat_name="Valid Accounts",
                    ),
                    ControlThreatMapping(
                        control_id="AC-3",
                        threat_id="T1078",
                        threat_framework="mitre-attack",
                        threat_name="A Different Name",
                    ),
                ],
            )


class TestTraceabilityProfileEmitter:
    def test_emits_a_valid_oscal_profile_shape(self) -> None:
        prof = traceability_matrix_to_oscal_profile(_sample_matrix())["profile"]
        assert prof["uuid"]
        assert prof["metadata"]["oscal-version"]
        assert prof["metadata"]["title"] == "Control-to-Threat Traceability: Demo"
        assert prof["imports"][0]["href"] == "nist-800-53-rev5-moderate.json"
        alters = prof["modify"]["alters"]
        assert {a["control-id"] for a in alters} == {"ac-2", "si-2"}

    def test_each_mapping_becomes_an_addition_with_a_bare_link(self) -> None:
        prof = traceability_matrix_to_oscal_profile(_sample_matrix())["profile"]
        ac2 = next(a for a in prof["modify"]["alters"] if a["control-id"] == "ac-2")
        adds = ac2["adds"]
        assert len(adds) == 2  # AC-2 maps two threats -> one addition each
        # OSCAL flag set for `link` (no `props` — that field is schema-invalid
        # on a link; props belong on the addition). Regression guard for C1.
        link_flags = {"href", "rel", "media-type", "resource-fragment", "text"}
        for add in adds:
            link = add["links"][0]
            assert "props" not in link
            assert set(link) <= link_flags
            assert link["rel"] == "mitigates"
            names = {p["name"]: p["value"] for p in add["props"]}
            assert names["threat-id"] in {"T1078", "T1098"}
            assert names["coverage"] in {"partial", "full"}
            assert names["mapping-id"].startswith("urn:uuid:")
            assert names["crosswalk-source"] == "self-attested"

    def test_profile_round_trips_through_trestle(self) -> None:
        """The emitted profile is schema-valid OSCAL per trestle (the OSCAL-Compass
        reference impl, ``Extra.forbid`` on every model). This catches stray fields
        NIST's JSON Schema misses — e.g. props-on-link (F-V1011-C1). Mirrors the AR
        exporter's ``test_ar_round_trips_through_trestle``."""
        trestle_profile = pytest.importorskip("trestle.oscal.profile")
        doc = traceability_matrix_to_oscal_profile(_sample_matrix())
        parsed = trestle_profile.Model.parse_obj(doc)
        assert parsed.profile.uuid == doc["profile"]["uuid"]
        alters = parsed.profile.modify.alters
        assert {a.control_id for a in alters} == {"ac-2", "si-2"}
        # AC-2's two mappings survive as two additions, each with one link.
        ac2 = next(a for a in alters if a.control_id == "ac-2")
        assert len(ac2.adds) == 2
        assert all(len(add.links) == 1 for add in ac2.adds)

    def test_back_matter_threats_are_integrity_hashed(self) -> None:
        prof = traceability_matrix_to_oscal_profile(_sample_matrix())["profile"]
        resources = prof["back-matter"]["resources"]
        assert len(resources) == 3  # three unique threats
        for r in resources:
            h = r["rlinks"][0]["hashes"][0]
            assert h["algorithm"] == "SHA-256"
            decoded = base64.b64decode(r["base64"]["value"])
            assert h["value"] == hashlib.sha256(decoded).hexdigest()

    def test_threat_resources_are_reproducible(self) -> None:
        # Re-emitting the same matrix yields byte-identical back-matter
        # resources (deterministic uuid5 + content hashes) — the tamper-evident
        # reproducibility guarantee. (The profile uuid + last-modified vary.)
        a = traceability_matrix_to_oscal_profile(_sample_matrix())
        b = traceability_matrix_to_oscal_profile(_sample_matrix())
        ka = sorted(a["profile"]["back-matter"]["resources"], key=lambda r: r["uuid"])
        kb = sorted(b["profile"]["back-matter"]["resources"], key=lambda r: r["uuid"])
        assert ka == kb


class TestTraceabilityProfileVerifies:
    """The emitted profile round-trips through the EXISTING `oscal verify`
    (its back-matter digests are checked + tampering is detected) — the reuse
    the labcoat called for, now that verify_digests is model-generic."""

    def test_emitted_profile_digests_verify(self, tmp_path: Path) -> None:
        doc = traceability_matrix_to_oscal_profile(_sample_matrix())
        path = tmp_path / "traceability.profile.json"
        path.write_text(json.dumps(doc), encoding="utf-8")

        report = verify_ar_file(path)
        # The threat resources WERE checked (not skipped as "no back-matter").
        assert report.digest_checks
        assert report.digests_valid
        assert all(c.valid for c in report.digest_checks)

    def test_tampered_back_matter_is_detected(self, tmp_path: Path) -> None:
        doc = traceability_matrix_to_oscal_profile(_sample_matrix())
        # Flip a resource's embedded payload WITHOUT updating its stored hash.
        doc["profile"]["back-matter"]["resources"][0]["base64"]["value"] = (
            base64.b64encode(b'{"tampered":true}').decode("ascii")
        )
        path = tmp_path / "tampered.profile.json"
        path.write_text(json.dumps(doc), encoding="utf-8")

        report = verify_ar_file(path)
        assert not report.digests_valid
