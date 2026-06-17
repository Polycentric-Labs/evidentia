"""Tests for the Control↔Threat Traceability Matrix OSCAL profile emitter.

Per the 2026-06-17 representation decision, the matrix is emitted as an OSCAL
*profile* (imports a control catalog; adds `link rel="mitigates"` + props per
control; threats in integrity-hashed back-matter resources). These tests pin
the profile shape + the tamper-evident reproducibility guarantee.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from evidentia_core.models.traceability import (
    ControlThreatMapping,
    TraceabilityMatrix,
)
from evidentia_core.oscal.traceability_exporter import (
    traceability_matrix_to_oscal_profile,
)
from evidentia_core.oscal.verify import verify_ar_file


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


class TestTraceabilityProfileEmitter:
    def test_emits_a_valid_oscal_profile_shape(self) -> None:
        prof = traceability_matrix_to_oscal_profile(_sample_matrix())["profile"]
        assert prof["uuid"]
        assert prof["metadata"]["oscal-version"]
        assert prof["metadata"]["title"] == "Control-to-Threat Traceability: Demo"
        assert prof["imports"][0]["href"] == "nist-800-53-rev5-moderate.json"
        alters = prof["modify"]["alters"]
        assert {a["control-id"] for a in alters} == {"ac-2", "si-2"}

    def test_each_mapping_becomes_a_relationship_link_with_props(self) -> None:
        prof = traceability_matrix_to_oscal_profile(_sample_matrix())["profile"]
        ac2 = next(a for a in prof["modify"]["alters"] if a["control-id"] == "ac-2")
        links = ac2["adds"][0]["links"]
        assert len(links) == 2  # AC-2 maps two threats
        assert {link["rel"] for link in links} == {"mitigates"}
        names = {p["name"]: p["value"] for p in links[0]["props"]}
        assert names["threat-id"] in {"T1078", "T1098"}
        assert names["coverage"] in {"partial", "full"}
        assert names["mapping-id"].startswith("urn:uuid:")
        assert names["crosswalk-source"] == "self-attested"

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
