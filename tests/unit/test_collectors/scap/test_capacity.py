"""Real-clock complete native capacity with independent synthetic source facts.

The source constructor is test-only and derives expected graphs without a
production parser or factory. All admitted OVAL versions also exercise complete qualified maximum shapes.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from uuid import UUID, uuid5
from xml.sax.saxutils import escape, quoteattr

import pytest
from evidentia_collectors.scap import ScapCompletionAssertion, collect_scap_bytes
from evidentia_collectors.scap._limits import ScapFailure

X = "http://checklists.nist.gov/xccdf/1.2"
FOREIGN = "urn:synthetic:capacity"
STAMP = "2024-03-01T00:00:00Z"
OUTCOMES = ("pass", "fail", "error", "unknown", "notapplicable", "informational", "fixed", "notchecked", "notselected")
N_LIMIT = 5_242_880
A_LIMIT = 2_097_152


def encoded(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def source_strings(document: dict) -> int:
    total = 0
    for node in document["nodes"]:
        if node["kind"] == "element":
            values = list(node["name"].values())
            values += [v for row in node["namespace_declarations"] for v in row.values()]
            values += [v for row in node["attributes"] for v in (*row["name"].values(), row["value"])]
            values += [node["text"], node["tail"]]
        else:
            values = [node["data"], node["tail"]]
        total += sum(len(value.encode("utf-8")) for value in values if value is not None)
    return total


def make_x(
    *,
    leaves: int = 0,
    payloads: list[str] | None = None,
    padding: int = 0,
    rule_count: int = 1,
    timed: bool = False,
    fractions: list[int] | None = None,
    errors: int = 0,
    markers: int = 0,
) -> tuple[bytes, dict, dict]:
    nodes: list[dict] = []
    raw: list[str] = []
    stack: list[int] = []
    outcomes: list[dict] = []
    times: list[dict] = []
    opaque: list[int] = []

    def start(
        local: str,
        *,
        namespace: str = X,
        prefix: str = "",
        attrs: tuple = (),
        namespaces: tuple = (),
        text: str | None = None,
        space: int = 0,
    ) -> int:
        index = len(nodes)
        row = {
            "kind": "element",
            "name": {"namespace_uri": namespace, "local_name": local},
            "namespace_declarations": [{"prefix": p, "namespace_uri": u} for p, u in namespaces],
            "attributes": [{"name": {"namespace_uri": "", "local_name": k}, "value": v} for k, v in attrs],
            "text": text,
            "tail": None,
            "children": [],
        }
        if stack:
            nodes[stack[-1]]["children"].append(index)
        nodes.append(row)
        tag = prefix + local
        raw.append(
            "<"
            + tag
            + "".join(" xmlns" + (":" + p if p else "") + "=" + quoteattr(u) for p, u in namespaces)
            + "".join(" " + k + "=" + quoteattr(v) for k, v in attrs)
            + " " * space
            + ">"
        )
        if text is not None:
            raw.append(escape(text))
        stack.append(index)
        return index

    def end(prefix: str = "") -> None:
        index = stack.pop()
        raw.append("</" + prefix + nodes[index]["name"]["local_name"] + ">")

    def atom(local: str, text: str | None = None, **kwargs) -> int:
        index = start(local, text=text, **kwargs)
        end(kwargs.get("prefix", ""))
        return index

    start(
        "TestResult", attrs=(("id", "xccdf_synthetic_testresult_capacity"), ("end-time", STAMP)), namespaces=(("", X),)
    )
    atom("benchmark", attrs=(("href", "urn:synthetic:benchmark"),))
    atom("target", "Synthetic capacity target")
    if leaves or payloads or padding:
        opaque.append(start("context", namespace=FOREIGN, prefix="z:", namespaces=(("z", FOREIGN), ("", ""))))
        for _ in range(leaves):
            atom("a", namespace="")
        for value in payloads or []:
            atom("p", value, namespace="")
        if padding:
            # A tag is bounded independently; spaces inside markup are not retained text.
            for _ in range(33):
                take = min(padding, 262_140)
                atom("p", namespace="", space=take)
                padding -= take
            assert padding == 0
        end("z:")
    for _ in range(markers):
        index = len(nodes)
        nodes.append({"kind": "comment", "data": "", "tail": None})
        nodes[0]["children"].append(index)
        raw.append("<!---->")
        opaque.append(index)
    times.append(
        {
            "scope_node_index": 0,
            "scope": "selected_assessment",
            "role": "assessment_completion",
            "value_ref": {"node_index": 0, "slot": "attribute_value", "attribute_index": 1},
            "normalization": {"state": "normalized", "utc": STAMP},
        }
    )
    for number in range(rule_count):
        fraction = fractions[number] if fractions else 0
        time_value = STAMP if not fraction else STAMP[:-1] + "." + "1" * fraction + "Z"
        attrs = [("idref", "xccdf_synthetic_rule_capacity")]
        if timed:
            attrs.append(("time", time_value))
        rule = start("rule-result", attrs=tuple(attrs))
        result_value = "error" if number < errors else "pass"
        result = atom("result", result_value)
        end()
        outcomes.append(
            {
                "unit_node_index": 0,
                "node_index": rule,
                "level": "xccdf_rule_result",
                "value_ref": {"node_index": result, "slot": "element_simple_content", "attribute_index": None},
                "native_result": result_value,
            }
        )
        if timed:
            times.append(
                {
                    "scope_node_index": rule,
                    "scope": "selected_assessment",
                    "role": "rule_completion",
                    "value_ref": {"node_index": rule, "slot": "attribute_value", "attribute_index": 1},
                    "normalization": {"state": "normalized", "utc": time_value},
                }
            )
    atom("score", "0")
    end()
    assert not stack
    source = "".join(raw).encode("utf-8")
    graph = {"declaration": None, "text": None, "children": [0], "nodes": nodes}
    unit = {"assessment_index": 0, "unit_kind": "xccdf_test_result", "node_index": 0}
    frame = {
        "schema_version": "scap-finding-identity-v1",
        "source_sha256": digest(source),
        "source_profile": "xccdf-1.2-results",
        "assessment_index": 0,
        "unit_node_index": 0,
        "mapping_rule_id": "scap-assessment-summary-v1",
    }
    key = digest(encoded(frame))
    finding = {
        "node_index": 0,
        "mapping_rule_id": "scap-assessment-summary-v1",
        "source_key_sha256": key,
        "finding_id": str(uuid5(UUID("c81bcb44-9b41-5b18-9f10-72b3b9b4d3d6"), "scap-xccdf\0" + key)),
    }
    opaque_count = leaves + len(payloads or []) + (34 if padding else 0) + (1 if leaves or payloads else 0) + markers
    # Determine each authored opaque subtree's disjoint native span directly from construction.
    if opaque and nodes[opaque[0]]["kind"] == "element":
        opaque_count = 1 + len(nodes[opaque[0]]["children"]) + markers
    coverage = {
        "scope": "selected_assessment_native_projection",
        "selected_node_index": 0,
        "visible_unit_count": 1,
        "selected_unit_count": 1,
        "unselected_unit_count": 0,
        "visible_outcome_count": rule_count,
        "selected_outcome_count": rule_count,
        "top_level_outcome_count": rule_count,
        "countable_top_level_outcome_count": rule_count,
        "outcome_counts": [
            {
                "level": "xccdf_rule_result",
                "native_result": outcome,
                "count": errors if outcome == "error" else rule_count - errors if outcome == "pass" else 0,
            }
            for outcome in OUTCOMES
        ],
        "native_export_detail": "not_applicable",
        "oval_directives": None,
        "collection_flags": [],
        "uninterpreted_node_count": opaque_count,
        "signature_node_indices": [],
        "source_population_complete": "not_established",
        "schema_validation": "bounded_core_profile_rules",
        "complete_schema_validation": "not_performed",
        "platform_validation": "not_performed",
        "signature_verification": "not_performed",
        "producer_interoperability": "not_established",
        "cadence_evidence": "countable" if rule_count else "empty",
        "status_observations": [],
        "core_status_defaults": [],
    }
    assessment = {
        "selection": unit,
        "units": [dict(unit)],
        "outcomes": outcomes,
        "times": times,
        "coverage": coverage,
        "uninterpreted_roots": opaque,
        "finding_refs": [finding],
    }
    return source, graph, assessment


# These constants bind the independently authored constructions, not collector output.
_CASE_FACTS = {
    "small-control": {
        "expected": "success",
        "source_string_bytes": 455,
        "node_count": 6,
        "outcome_count": 1,
        "time_count": 1,
        "files": {
            "assessment.expected.json": {
                "bytes": 2218,
                "sha256": "52894dd5370cfd482b05ff4ff91044e9cbcbcca7c42e7f9c22d4df2c9179d84f",
            },
            "native.expected.json": {
                "bytes": 1641,
                "sha256": "1a0ba6ff0e436638c416b65f0ff04bd1876b10705769c12184cef5e37c99d416",
            },
            "source.xml": {"bytes": 341, "sha256": "26ce697a0398197a0cf45222e1bb58478e1432d748908e9f518e11d08e8ab9b3"},
        },
    },
    "dense-nodes-exact": {
        "expected": "success",
        "source_string_bytes": 33268,
        "node_count": 32768,
        "outcome_count": 1,
        "time_count": 1,
        "files": {
            "assessment.expected.json": {
                "bytes": 2231,
                "sha256": "0f4de82bb03790ecc0780fc79a9dc009ea878018045e40f89a0d843b553985f7",
            },
            "native.expected.json": {
                "bytes": 4970494,
                "sha256": "2642775114016a3daaf0dbf609bf09f3f85f485e109562dd787bc45bf654945f",
            },
            "source.xml": {
                "bytes": 229733,
                "sha256": "fd2cb25d238c6dde03688a81d5033e36824b0a4e69e4ee59be705d20dd30cf25",
            },
        },
    },
    "dense-nodes-plus-one": {
        "expected": "source_limit_exceeded",
        "source_string_bytes": 33269,
        "node_count": 32769,
        "outcome_count": 1,
        "time_count": 1,
        "files": {
            "assessment.expected.json": {
                "bytes": 2231,
                "sha256": "674679391a1ed19387982bdee513c4131f801a6dae9300e9df64e2dd8280cee7",
            },
            "native.expected.json": {
                "bytes": 4970646,
                "sha256": "5b86fc89d57a66a78feff2919d4a74ca89d04b60eba7227916c3e407419c928c",
            },
            "source.xml": {
                "bytes": 229740,
                "sha256": "8c03a0dc2b7906b6657993cc086ab88a221f831996a9e1f1b012c04c8b9a5a45",
            },
        },
    },
    "native-escaped-exact": {
        "expected": "success",
        "source_string_bytes": 1747118,
        "node_count": 15,
        "outcome_count": 1,
        "time_count": 1,
        "files": {
            "assessment.expected.json": {
                "bytes": 2221,
                "sha256": "06f9b0bdeac78c622ece341acf11519b2f06d594768b2f7a3ab0eb377e145693",
            },
            "native.expected.json": {
                "bytes": 5242880,
                "sha256": "176f814774b25ad34972f20b7aed569ae4f7812cdd39a4de34b187db26393f7a",
            },
            "source.xml": {
                "bytes": 1747065,
                "sha256": "e344c5e303239de2ba400cdc3722123bc3a0a7d7521011299195475ce4f1ecb4",
            },
        },
    },
    "native-escaped-plus-one": {
        "expected": "result_limit_exceeded",
        "source_string_bytes": 1747119,
        "node_count": 15,
        "outcome_count": 1,
        "time_count": 1,
        "files": {
            "assessment.expected.json": {
                "bytes": 2221,
                "sha256": "49a856c67bb6ec2304f668b7388363806f7d3300198be9c7b6fbd96ff5e3cd8d",
            },
            "native.expected.json": {
                "bytes": 5242881,
                "sha256": "2d86f33cf37c407be2b64c5ecd6493509f89e258d7f56164e5cc063c9851da2d",
            },
            "source.xml": {
                "bytes": 1747066,
                "sha256": "931e89b7893fbfa1e6a771d7e838833a76ef0da7ea89c33deec6f808fd6021e1",
            },
        },
    },
    "source-text-exact": {
        "expected": "success",
        "source_string_bytes": 4194304,
        "node_count": 24,
        "outcome_count": 1,
        "time_count": 1,
        "files": {
            "assessment.expected.json": {
                "bytes": 2222,
                "sha256": "b49d7665753e75b0bbf1f87563695ea96c193a540029f8e0e6825523a3aaffcd",
            },
            "native.expected.json": {
                "bytes": 4198180,
                "sha256": "13bad8564b8cf183aa83cedfed723d9f415298839168a7d4e576a55e9c43477f",
            },
            "source.xml": {
                "bytes": 4194305,
                "sha256": "5d465f61cc7173be956f71b77ea49b67012a43ce58292c1f03ea00e1265c9e2a",
            },
        },
    },
    "source-text-plus-one": {
        "expected": "source_limit_exceeded",
        "source_string_bytes": 4194305,
        "node_count": 24,
        "outcome_count": 1,
        "time_count": 1,
        "files": {
            "assessment.expected.json": {
                "bytes": 2222,
                "sha256": "9d0031a07c4747326c2d6ef1ad7acffe289953218d630201df2fc48ff7c93bb7",
            },
            "native.expected.json": {
                "bytes": 4198181,
                "sha256": "719f3e2c47e485dc10a899c5feef80ccbd804d87395ffbeb0629a84147aa5641",
            },
            "source.xml": {
                "bytes": 4194306,
                "sha256": "7a7339e5bf24e0312ea1957d82446b6be3a72148443b035a8b7be9d8b5f5a98d",
            },
        },
    },
    "raw-eight-mib": {
        "expected": "success",
        "source_string_bytes": 540,
        "node_count": 40,
        "outcome_count": 1,
        "time_count": 1,
        "files": {
            "assessment.expected.json": {
                "bytes": 2222,
                "sha256": "0a251c9228eb588b43e669abb9b9508dae409578039bd72c850da1cf21674094",
            },
            "native.expected.json": {
                "bytes": 6818,
                "sha256": "678cdfc080de962fdf807042260002ec1b3dd5dabae535a8f75f1373ce32dc2f",
            },
            "source.xml": {
                "bytes": 8388608,
                "sha256": "835dd8d38a94da21a69dcc2d79eb39a04a62ced7d4dcee5fdc579f8518b2a5ba",
            },
        },
    },
    "raw-plus-one": {
        "expected": "source_limit_exceeded",
        "source_string_bytes": 540,
        "node_count": 40,
        "outcome_count": 1,
        "time_count": 1,
        "files": {
            "assessment.expected.json": {
                "bytes": 2222,
                "sha256": "0a251c9228eb588b43e669abb9b9508dae409578039bd72c850da1cf21674094",
            },
            "native.expected.json": {
                "bytes": 6818,
                "sha256": "678cdfc080de962fdf807042260002ec1b3dd5dabae535a8f75f1373ce32dc2f",
            },
            "source.xml": {
                "bytes": 8388609,
                "sha256": "bc0d07936437d734da97072bc809aeaf07093005f17a7f8201f434cc806dc7b6",
            },
        },
    },
    "assessment-exact": {
        "expected": "success",
        "source_string_bytes": 784046,
        "node_count": 10382,
        "outcome_count": 5189,
        "time_count": 5190,
        "files": {
            "assessment.expected.json": {
                "bytes": 2097152,
                "sha256": "6da3bb8cc2024951daa0f1aa932351cdabae66d129d8e27ea8a0ba931caeb0ab",
            },
            "native.expected.json": {
                "bytes": 2911659,
                "sha256": "630325f5493d9284d730b8abb612e5ab538bb3c99125628d44782738c6d6c856",
            },
            "source.xml": {
                "bytes": 591980,
                "sha256": "4a8a7ab994956a3b5374e26fc670af5dfd60880a130f4a99393688bef665c709",
            },
        },
    },
    "assessment-plus-one": {
        "expected": "result_limit_exceeded",
        "source_string_bytes": 784047,
        "node_count": 10382,
        "outcome_count": 5189,
        "time_count": 5190,
        "files": {
            "assessment.expected.json": {
                "bytes": 2097153,
                "sha256": "fad4104a88fc8fa72a8700089595e711e4f7e8c35318c97db6db03f6e764ecf2",
            },
            "native.expected.json": {
                "bytes": 2911660,
                "sha256": "9cb9001cc2029646328ce8d5fe06ba8dea4e43943f9ecf7b56a1dd053c1b97f6",
            },
            "source.xml": {
                "bytes": 591981,
                "sha256": "ccc80b40788b7a27a9ea94e520e81ad4137a3f24f54e5d31ce2c07bb5d85ef2b",
            },
        },
    },
    "combined-native-assessment-exact": {
        "expected": "success",
        "source_string_bytes": 1560652,
        "node_count": 10391,
        "outcome_count": 5189,
        "time_count": 5190,
        "files": {
            "assessment.expected.json": {
                "bytes": 2097152,
                "sha256": "97c7c39013ea6ccd4ac4d4e4b9c4a4f043be6c0c9f5b49d331a0fc157938c469",
            },
            "native.expected.json": {
                "bytes": 5242880,
                "sha256": "d62c5c20dc4e08b0e6f8725840c255bfc937c7f2d8bdf281933c3d42ed59a72d",
            },
            "source.xml": {
                "bytes": 1368647,
                "sha256": "e871dd7e7d1704bbcde4d4af98113cb9d4db877648fe5137343cd9faf5b4988c",
            },
        },
    },
    "outcomes-exact": {
        "expected": "success",
        "source_string_bytes": 1270328,
        "node_count": 20004,
        "outcome_count": 10000,
        "time_count": 1,
        "files": {
            "assessment.expected.json": {
                "bytes": 1790968,
                "sha256": "eb856a7dfab0b4cca10619d02789bf85c5bb578979ac5ab6f218b2715aabd821",
            },
            "native.expected.json": {
                "bytes": 4810073,
                "sha256": "f26162b4b5db67e835ce6cdf5d68a4e710f1c4348873642f8c835a6dc049cce0",
            },
            "source.xml": {
                "bytes": 860255,
                "sha256": "4d125ffda425cd505e8dbfd616c210a63f6ca2f532279dffa23d823d4b7e7d76",
            },
        },
    },
    "outcomes-plus-one": {
        "expected": "source_limit_exceeded",
        "source_string_bytes": 1270455,
        "node_count": 20006,
        "outcome_count": 10001,
        "time_count": 1,
        "files": {
            "assessment.expected.json": {
                "bytes": 1791148,
                "sha256": "db2079946a0f3bc6042d4a441bcdfb6d77a23ab0151d4c077a963806d0b082a3",
            },
            "native.expected.json": {
                "bytes": 4810555,
                "sha256": "035c0ce184aa1540f55b8e7e25bc386930fe64ff6e2eae48fe57aad7feb43ab9",
            },
            "source.xml": {
                "bytes": 860341,
                "sha256": "d43d7e084d249dbdd3c5729dbee7ed74548078f56f9ed1efec396f1f28d9dee7",
            },
        },
    },
}


def _escaped_payloads(cost: int) -> list[str]:
    values = []
    for index in range(8):
        take = min(786_432, cost - (7 - index))
        count, remainder = divmod(take, 12)
        values.append("\U00010000" * count + "A" * remainder)
        assert 0 < len(values[-1].encode("utf-8")) <= 262_144
        cost -= take
    assert cost == 0
    return values


def _case(name: str) -> tuple[bytes, dict, dict]:
    if name == "small-control":
        return make_x()
    if name.startswith("dense-nodes-"):
        return make_x(leaves=32_761 + (name == "dense-nodes-plus-one"))
    if name.startswith("outcomes-"):
        return make_x(rule_count=10_000 + (name == "outcomes-plus-one"))
    if name.startswith("raw-"):
        first = make_x(padding=1)
        specimen = make_x(padding=8_388_608 - len(first[0]) + 1)
        if name == "raw-plus-one":
            return specimen[0] + b" ", specimen[1], specimen[2]
        return specimen
    if name.startswith("source-text-"):
        base = make_x(payloads=["A"] * 17)
        remain = 4_194_304 - source_strings(base[1]) + 17
        values = []
        for index in range(17):
            take = min(262_144, remain - (16 - index))
            values.append("A" * take)
            remain -= take
        assert remain == 0
        if name == "source-text-plus-one":
            values[-1] += "A"
        return make_x(payloads=values)
    if name.startswith("native-escaped-"):
        base = make_x(payloads=["A"] * 8)
        values = _escaped_payloads(N_LIMIT - len(encoded(base[1])) + 8)
        if name == "native-escaped-plus-one":
            values[-1] += "A"
        return make_x(payloads=values)
    if name in ("assessment-exact", "assessment-plus-one", "combined-native-assessment-exact"):
        # The independent source-only search reached 5,189 timed outcomes.
        count = 5_189
        combined = name == "combined-native-assessment-exact"
        payloads = ["A"] * 8 if combined else None
        base = make_x(payloads=payloads, rule_count=count, timed=True)
        remaining = A_LIMIT - len(encoded(base[2]))
        fractions = [0] * count
        for index in range(count):
            if remaining < 2:
                break
            increase = min(7, remaining)
            fractions[index] = increase - 1
            remaining -= increase
        assert remaining in (0, 1)
        if combined:
            base = make_x(payloads=payloads, rule_count=count, timed=True, fractions=fractions, errors=remaining)
            payloads = _escaped_payloads(N_LIMIT - len(encoded(base[1])) + 8)
        return make_x(
            payloads=payloads,
            rule_count=count,
            timed=True,
            fractions=fractions,
            errors=remaining + (name == "assessment-plus-one"),
        )
    raise AssertionError("Unknown declared capacity case")


@pytest.mark.parametrize("name", tuple(_CASE_FACTS))
def test_complete_native_capacity_and_exact_refusal(name: str) -> None:
    source, graph, assessment = _case(name)
    expected = _CASE_FACTS[name]
    n_bytes, a_bytes = encoded(graph), encoded(assessment)
    for leaf, body in (
        ("source.xml", source),
        ("native.expected.json", n_bytes),
        ("assessment.expected.json", a_bytes),
    ):
        assert len(body) == expected["files"][leaf]["bytes"]
        assert digest(body) == expected["files"][leaf]["sha256"]
    assert len(graph["nodes"]) == expected["node_count"]
    assert source_strings(graph) == expected["source_string_bytes"]
    assert len(assessment["outcomes"]) == expected["outcome_count"]
    assert len(assessment["times"]) == expected["time_count"]
    if expected["expected"] != "success":
        with pytest.raises(ScapFailure) as error:
            collect_scap_bytes(
                source, source_profile="xccdf-1.2-results", assessment_index=0, cadence_slug="nist-800-53-rev5-ca7"
            )
        assert error.value.code == expected["expected"]
        return
    started = time.monotonic()
    result = collect_scap_bytes(
        source, source_profile="xccdf-1.2-results", assessment_index=0, cadence_slug="nist-800-53-rev5-ca7"
    )
    assert time.monotonic() - started < 60.0
    native = result.model_dump(mode="json")
    assert native["source"]["sha256"] == digest(source)
    assert native["source"]["bytes"] == len(source)
    assert native["native_document"] == graph
    assert native["assessment"] == assessment
    artifact = native["evidence_artifact"]
    assert artifact is not None
    assert artifact["content"]["native_document"] == graph
    assert artifact["content"]["assessment"] == assessment
    spaced_content = json.dumps(artifact["content"], ensure_ascii=True, sort_keys=True, allow_nan=False).encode("ascii")
    assert artifact["content_hash"] == digest(spaced_content)
    full = len(encoded(native))
    remainder = {
        **native,
        "native_document": None,
        "assessment": None,
        "evidence_artifact": {
            **artifact,
            "content": {**artifact["content"], "native_document": None, "assessment": None},
        },
    }
    rest = len(encoded(remainder))
    assert rest <= 30_997
    assert full == rest + 2 * (len(n_bytes) - 4) + 2 * (len(a_bytes) - 4)
    assert full <= 14_711_045 < 16_777_216


OVAL_R = "http://oval.mitre.org/XMLSchema/oval-results-5"
OVAL_C = "http://oval.mitre.org/XMLSchema/oval-common-5"
OVAL_S = "http://oval.mitre.org/XMLSchema/oval-system-characteristics-5"
OVAL_Z = "urn:synthetic:capacity"
OVAL_CAP_OUTCOMES = ("true", "false", "unknown", "error", "not evaluated", "not applicable")
OVAL_CAP_LEVELS = (
    "oval_definition",
    "oval_criteria",
    "oval_criterion",
    "oval_extend_definition",
    "oval_test",
    "oval_tested_item",
)


class _OvalWriter:
    """Record each authored node when its exact XML syntax is emitted."""

    def __init__(self) -> None:
        self.nodes: list[dict] = []
        self.raw: list[str] = []
        self.stack: list[int] = []
        self.opaque: list[int] = []
        self.depth = 0

    def start(
        self,
        local: str,
        *,
        prefix: str = "",
        namespace: str = OVAL_R,
        attrs: tuple = (),
        namespaces: tuple = (),
        text: str | None = None,
    ) -> int:
        index = len(self.nodes)
        node = {
            "kind": "element",
            "name": {"namespace_uri": namespace, "local_name": local},
            "namespace_declarations": [{"prefix": p, "namespace_uri": uri} for p, uri in namespaces],
            "attributes": [{"name": {"namespace_uri": "", "local_name": key}, "value": value} for key, value in attrs],
            "text": text,
            "tail": None,
            "children": [],
        }
        if self.stack:
            self.nodes[self.stack[-1]]["children"].append(index)
        self.nodes.append(node)
        self.stack.append(index)
        self.depth = max(self.depth, len(self.stack))
        tag = prefix + local
        self.raw.append(
            "<"
            + tag
            + "".join((" xmlns" + (":" + p if p else "") + "=" + quoteattr(uri) for p, uri in namespaces))
            + "".join((" " + key + "=" + quoteattr(value) for key, value in attrs))
            + ">"
        )
        if text is not None:
            self.raw.append(escape(text))
        return index

    def end(self, prefix: str = "") -> None:
        index = self.stack.pop()
        self.raw.append("</" + prefix + self.nodes[index]["name"]["local_name"] + ">")

    def atom(self, local: str, text: str | None = None, **kwargs) -> int:
        index = self.start(local, text=text, **kwargs)
        self.end(kwargs.get("prefix", ""))
        return index

    def split_atom(self, local: str, left: str, right: str, *, prefix: str, namespace: str, kind: str) -> int:
        index = self.start(local, prefix=prefix, namespace=namespace, text=left)
        marker = len(self.nodes)
        if kind == "comment":
            self.nodes.append({"kind": "comment", "data": "split", "tail": right})
            self.raw.append("<!--split-->" + escape(right))
        else:
            self.nodes.append({"kind": "processing_instruction", "target": "split", "data": "value", "tail": right})
            self.raw.append("<?split value?>" + escape(right))
        self.nodes[index]["children"].append(marker)
        self.opaque.append(marker)
        self.end(prefix)
        return index


def _oval_reference(index: int, attribute_index: int | None = None) -> dict:
    return {
        "node_index": index,
        "slot": "element_simple_content" if attribute_index is None else "attribute_value",
        "attribute_index": attribute_index,
    }


def _oval_source_strings(document: dict) -> int:
    total = 0
    for node in document["nodes"]:
        if node["kind"] == "element":
            values = list(node["name"].values())
            values += [value for row in node["namespace_declarations"] for value in row.values()]
            values += [value for row in node["attributes"] for value in (*row["name"].values(), row["value"])]
            values += [node["text"], node["tail"]]
        else:
            values = [node["data"], node["tail"]]
            if node["kind"] == "processing_instruction":
                values.append(node["target"])
        total += sum(len(value.encode("utf-8")) for value in values if value is not None)
    return total


def _make_oval_capacity(
    version: str, *, family: str, statuses: int = 0, fractions: tuple[int, ...] = (), payload_bytes: int = 0
) -> tuple[bytes, dict, dict, dict]:
    assert version in ("5.8", "5.11.2", "5.12.3")
    assert family in ("outcomes", "coverage")
    profile = "oval-" + version + "-core-results"
    writer = _OvalWriter()
    units: list[dict] = []
    rows: list[dict] = []
    times: list[dict] = []
    flags: list[dict] = []
    status_rows: list[dict] = []
    core_status: list[dict] = []
    visible = 0
    system_count = 256 if family == "coverage" else 1
    key_count = 64 if family == "coverage" else 1
    payloads = []
    for _ in range(4):
        take = min(payload_bytes, 600000)
        payloads.append("a" + "\x80" * (take // 6) + "a" * (take % 6))
        payload_bytes -= take
    assert payload_bytes == 0
    writer.start("oval_results", namespaces=(("", OVAL_R), ("oval", OVAL_C), ("sc", OVAL_S), ("z", OVAL_Z)))

    def generator(parent_prefix: str, parent_namespace: str, owner: int, scope: str, ordinal: int) -> None:
        writer.start("generator", prefix=parent_prefix, namespace=parent_namespace)
        if version == "5.8":
            writer.split_atom("schema_version", "+05.", "80", prefix="oval:", namespace=OVAL_C, kind="comment")
        else:
            writer.split_atom(
                "schema_version", version[:-1], version[-1], prefix="oval:", namespace=OVAL_C, kind="comment"
            )
            writer.atom(
                "schema_version",
                version + ":1.0",
                prefix="oval:",
                namespace=OVAL_C,
                attrs=(("platform", "urn:synthetic:platform"),),
            )
        fraction = fractions[ordinal] if fractions else 0
        literal = STAMP if not fraction else STAMP[:-1] + "." + "1" * fraction + "Z"
        stamp = writer.split_atom(
            "timestamp", literal[:-1], literal[-1], prefix="oval:", namespace=OVAL_C, kind="processing_instruction"
        )
        times.append(
            {
                "scope_node_index": owner,
                "scope": scope,
                "role": "document_compilation",
                "value_ref": _oval_reference(stamp),
                "normalization": {"state": "normalized", "utc": literal},
            }
        )
        writer.end(parent_prefix)

    generator("", OVAL_R, 0, "document", 0)
    directives = writer.start("directives", attrs=(("include_source_definitions", "false"),))
    directive_rows = []
    for result in OVAL_CAP_OUTCOMES:
        node = writer.atom("definition_" + result.replace(" ", "_"), attrs=(("reported", "true"),))
        directive_rows.append(
            {
                "node_index": node,
                "outcome": result,
                "reported": {"present": True, "value_ref": _oval_reference(node, 0), "effective_value": True},
                "content": {"present": False, "value_ref": None, "effective_value": "full"},
            }
        )
    writer.end()
    writer.start("results")

    def outcome(unit: int, node: int, level: str, position: int, value: str = "false", *, selected: bool) -> None:
        nonlocal visible
        visible += 1
        if selected:
            rows.append(
                {
                    "unit_node_index": unit,
                    "node_index": node,
                    "level": level,
                    "value_ref": _oval_reference(node, position),
                    "native_result": value,
                }
            )

    for system_number in range(system_count):
        selected = system_number == 0
        count = key_count if selected else 1
        unit = writer.start("system")
        units.append({"assessment_index": system_number, "unit_kind": "oval_system", "node_index": unit})
        writer.start("definitions")
        for number in range(count):
            ident = str(number + 1)
            definition = writer.start(
                "definition",
                attrs=(
                    ("definition_id", "oval:synthetic:def:" + ident),
                    ("version", "00"),
                    ("class", "inventory"),
                    ("result", "false"),
                ),
            )
            outcome(unit, definition, "oval_definition", 3, selected=selected)
            depth = 58 if family == "coverage" and selected and (number == 0) else 1
            for _ in range(depth):
                attributes = (("operator", "AND"), ("result", "false"))
                if version != "5.8":
                    attributes += (("applicability_check", "false"),)
                criteria = writer.start("criteria", attrs=attributes)
                outcome(unit, criteria, "oval_criteria", 1, selected=selected)
            criterion = writer.atom(
                "criterion",
                attrs=(
                    ("test_ref", "oval:synthetic:tst:" + ident),
                    ("version", "0"),
                    ("variable_instance", "01"),
                    ("result", "false"),
                ),
            )
            outcome(unit, criterion, "oval_criterion", 3, selected=selected)
            if family == "coverage" and selected and (number == 1):
                extend = writer.atom(
                    "extend_definition",
                    attrs=(("definition_ref", "oval:synthetic:def:1"), ("version", "000"), ("result", "false")),
                )
                outcome(unit, extend, "oval_extend_definition", 2, selected=True)
            for _ in range(depth):
                writer.end()
            writer.end()
        writer.end()
        writer.start("tests")
        for number in range(count):
            ident = str(number + 1)
            test = writer.start(
                "test",
                attrs=(
                    ("test_id", "oval:synthetic:tst:" + ident),
                    ("version", "0"),
                    ("check", "all"),
                    ("result", "false"),
                ),
            )
            outcome(unit, test, "oval_test", 3, selected=selected)
            repetitions = 9996 if family == "outcomes" else 1 if selected else 0
            for occurrence in range(repetitions):
                result = OVAL_CAP_OUTCOMES[occurrence % len(OVAL_CAP_OUTCOMES)]
                item = writer.atom(
                    "tested_item",
                    attrs=(("item_id", "000" if family == "outcomes" else str(number)), ("result", result)),
                )
                outcome(unit, item, "oval_tested_item", 1, result, selected=selected)
            writer.end()
        writer.end()
        characteristics = writer.start("oval_system_characteristics", prefix="sc:", namespace=OVAL_S)
        generator("sc:", OVAL_S, characteristics, "system_characteristics", system_number + 1)
        writer.start("system_info", prefix="sc:", namespace=OVAL_S)
        for local, text in (
            ("os_name", "SyntheticOS"),
            ("os_version", "0"),
            ("architecture", "synthetic"),
            ("primary_host_name", "synthetic-capacity-system"),
        ):
            writer.atom(local, text, prefix="sc:", namespace=OVAL_S)
        writer.start("interfaces", prefix="sc:", namespace=OVAL_S)
        for _ in range(16 if family == "coverage" and selected else 1):
            writer.start("interface", prefix="sc:", namespace=OVAL_S)
            writer.atom("interface_name", "synthetic0", prefix="sc:", namespace=OVAL_S)
            ip = writer.atom("ip_address", "192.0.2.1", prefix="sc:", namespace=OVAL_S)
            if selected and version == "5.8":
                core_status.append(
                    {
                        "node_index": ip,
                        "present": False,
                        "value_ref": None,
                        "effective_status": "exists",
                        "interpretation": "reviewed_5_8_core_ip_address_status",
                    }
                )
            if version == "5.12.3":
                writer.atom("ip_address", "192.0.2.2", prefix="sc:", namespace=OVAL_S)
                writer.atom("ipv6_address", "2001:db8::1", prefix="sc:", namespace=OVAL_S)
            else:
                writer.atom("mac_address", "02-00-00-00-00-01", prefix="sc:", namespace=OVAL_S)
            writer.end("sc:")
        writer.end("sc:")
        writer.end("sc:")
        if selected:
            writer.start("collected_objects", prefix="sc:", namespace=OVAL_S)
            for number in range(count):
                obj = writer.start(
                    "object",
                    prefix="sc:",
                    namespace=OVAL_S,
                    attrs=(("id", "oval:synthetic:obj:" + str(number + 1)), ("version", "00"), ("flag", "complete")),
                )
                flags.append(
                    {"object_node_index": obj, "value_ref": _oval_reference(obj, 2), "native_flag": "complete"}
                )
                writer.atom("reference", prefix="sc:", namespace=OVAL_S, attrs=(("item_ref", str(number)),))
                writer.end("sc:")
            writer.end("sc:")
            writer.start("system_data", prefix="sc:", namespace=OVAL_S)
            for number in range(count):
                item = writer.start(
                    "item", prefix="z:", namespace=OVAL_Z, attrs=(("id", str(number)), ("status", "exists"))
                )
                writer.opaque.append(item)
                status_rows.append(
                    {
                        "node_index": item,
                        "scope": "direct_system_data_child",
                        "value_ref": _oval_reference(item, 1),
                        "interpretation": "unverified_platform_status",
                        "effective_status": None,
                    }
                )
                if number == 0:
                    for _ in range(statuses):
                        status = writer.atom("v", prefix="z:", namespace=OVAL_Z, attrs=(("status", "exists"),))
                        status_rows.append(
                            {
                                "node_index": status,
                                "scope": "nested_platform_position",
                                "value_ref": _oval_reference(status, 0),
                                "interpretation": "unverified_platform_status",
                                "effective_status": None,
                            }
                        )
                    for payload in payloads:
                        writer.atom("p", payload, prefix="z:", namespace=OVAL_Z)
                writer.end("z:")
            writer.end("sc:")
        writer.end("sc:")
        writer.end()
    writer.end()
    writer.end()
    assert not writer.stack
    source = "".join(writer.raw).encode("utf-8")
    graph = {"declaration": None, "text": None, "children": [0], "nodes": writer.nodes}
    rows.sort(key=lambda row: row["node_index"])
    selected = units[0]["node_index"]
    counts = Counter((row["level"], row["native_result"]) for row in rows)
    selected_top = key_count * 2
    opaque_count = len(writer.opaque) + statuses + 4
    frame = {
        "schema_version": "scap-finding-identity-v1",
        "source_sha256": digest(source),
        "source_profile": profile,
        "assessment_index": 0,
        "unit_node_index": selected,
        "mapping_rule_id": "scap-assessment-summary-v1",
    }
    key = digest(encoded(frame))
    finding = {
        "node_index": selected,
        "mapping_rule_id": "scap-assessment-summary-v1",
        "source_key_sha256": key,
        "finding_id": str(uuid5(UUID("c81bcb44-9b41-5b18-9f10-72b3b9b4d3d6"), "scap-oval\x00" + key)),
    }
    coverage = {
        "scope": "selected_assessment_native_projection",
        "selected_node_index": selected,
        "visible_unit_count": system_count,
        "selected_unit_count": 1,
        "unselected_unit_count": system_count - 1,
        "visible_outcome_count": visible,
        "selected_outcome_count": len(rows),
        "top_level_outcome_count": selected_top,
        "countable_top_level_outcome_count": selected_top,
        "outcome_counts": [
            {"level": level, "native_result": value, "count": counts[level, value]}
            for level in OVAL_CAP_LEVELS
            for value in OVAL_CAP_OUTCOMES
        ],
        "native_export_detail": "full",
        "oval_directives": {
            "node_index": directives,
            "include_source_definitions": {
                "present": True,
                "value_ref": _oval_reference(directives, 0),
                "effective_value": False,
            },
            "embedded_definitions_node_index": None,
            "default_rules": directive_rows,
            "class_rules": [],
        },
        "collection_flags": flags,
        "uninterpreted_node_count": opaque_count,
        "signature_node_indices": [],
        "source_population_complete": "not_established",
        "schema_validation": "bounded_core_profile_rules",
        "complete_schema_validation": "not_performed",
        "platform_validation": "not_performed",
        "signature_verification": "not_performed",
        "producer_interoperability": "not_established",
        "cadence_evidence": "countable",
        "status_observations": status_rows,
        "core_status_defaults": core_status,
    }
    assessment = {
        "selection": units[0],
        "units": units,
        "outcomes": rows,
        "times": times,
        "coverage": coverage,
        "uninterpreted_roots": sorted(writer.opaque),
        "finding_refs": [finding],
    }
    dimensions = {
        "version": version,
        "family": family,
        "systems": system_count,
        "distinct_selected_keys": key_count,
        "nested_statuses": statuses,
        "nodes": len(writer.nodes),
        "maximum_element_depth": writer.depth,
        "source_text_bytes": _oval_source_strings(graph),
        "visible_outcomes": visible,
        "selected_outcomes": len(rows),
        "source_times": len(times),
        "raw_bytes": len(source),
        "N": len(encoded(graph)),
        "A": len(encoded(assessment)),
    }
    return (source, graph, assessment, dimensions)


_OVAL_CASE_FACTS = {
    "oval-5.8-outcomes": {
        "version": "5.8",
        "family": "outcomes",
        "statuses": 0,
        "fraction_prefix": [],
        "payload_bytes": 1793911,
        "files": {
            "assessment.expected.json": {
                "bytes": 1724030,
                "sha256": "8b9614dade35767c5f60414f54a5c184c55ad8f8ff086bb3a50546fd89fe6106",
            },
            "claim.json": {"bytes": 290, "sha256": "b724fcadd2742f93388c329722b3c3c13b5d8403cdc8c26098ea117c8d992faa"},
            "native.expected.json": {
                "bytes": 5242880,
                "sha256": "4b925a3ba854b88e7e869ca06fee53d54e07f3564931139c7c3666ff70817aa0",
            },
            "source.xml": {
                "bytes": 1189898,
                "sha256": "b4e646512fe175e54e6b7275c0880a4c067e52d1100de7708e2c661f45ce325e",
            },
        },
        "dimensions": {
            "A": 1724030,
            "N": 5242880,
            "distinct_selected_keys": 1,
            "family": "outcomes",
            "maximum_element_depth": 8,
            "nested_statuses": 0,
            "nodes": 10042,
            "raw_bytes": 1189898,
            "selected_outcomes": 10000,
            "source_text_bytes": 1410872,
            "source_times": 2,
            "systems": 1,
            "version": "5.8",
            "visible_outcomes": 10000,
        },
        "artifact": {
            "case": "oval-5.8-outcomes",
            "bytes": 6968744,
            "sha256": "56b4a296cdd8ac70791491b243afc3fd863d4b155869f87d76e5f945d6c4d051",
            "content_hash": "75a681c02e901eadb89eed59c55595d2ded3d34893072f9cfe58e261937e7a50",
            "identity_frame_sha256": "bda1cd2d6c75d71f1e06e24cfaa0b25bbc779a87b885d143758ce8a230c1d292",
            "id": "53494b8f-7c23-572d-b026-f881b62a6700",
            "completion_state": "operator_qualified",
            "completion_utc": "2024-03-01T00:00:00Z",
        },
    },
    "oval-5.8-coverage": {
        "version": "5.8",
        "family": "coverage",
        "statuses": 9519,
        "fraction_prefix": [6, 6, 6, 6, 6, 6, 6, 3],
        "payload_bytes": 1237800,
        "files": {
            "assessment.expected.json": {
                "bytes": 2097152,
                "sha256": "5ed47a3d9592e697dfa653f6778758d200818125161f84430edd9c1a59cd98f4",
            },
            "claim.json": {"bytes": 290, "sha256": "c32cc2afa1dea792a88721df7e5512bc16846dd87e1bfadbf78224e93ae13ce2"},
            "native.expected.json": {
                "bytes": 5242880,
                "sha256": "9ab5dd09ac260aeb9a518d715bb2c89cf71703c446633fda38e57e5c0d94a4dc",
            },
            "source.xml": {
                "bytes": 979042,
                "sha256": "fa672a15920df44bf76a048c927e66d5d23aa681998190609306573bcf9e66fc",
            },
        },
        "dimensions": {
            "A": 2097152,
            "N": 5242880,
            "distinct_selected_keys": 64,
            "family": "coverage",
            "maximum_element_depth": 64,
            "nested_statuses": 9519,
            "nodes": 16053,
            "raw_bytes": 979042,
            "selected_outcomes": 378,
            "source_text_bytes": 1237982,
            "source_times": 257,
            "systems": 256,
            "version": "5.8",
            "visible_outcomes": 1398,
        },
        "artifact": {
            "case": "oval-5.8-coverage",
            "bytes": 7341865,
            "sha256": "7b16094dbcd422d4a137f1c14555e15c75ffcef7e7dbb48504a7f06f2bd06392",
            "content_hash": "ca2f462b1ce655f4a438e697caa63f269e00e93d3d72db4c483b55b3b4af8871",
            "identity_frame_sha256": "03b81d25914108d42cd47276d754c1a82d5ae94071dfda69e41af539257a327a",
            "id": "b12c72a6-9270-5aad-8661-af7ca9648344",
            "completion_state": "operator_qualified",
            "completion_utc": "2024-03-01T00:00:00Z",
        },
    },
    "oval-5.11.2-outcomes": {
        "version": "5.11.2",
        "family": "outcomes",
        "statuses": 0,
        "fraction_prefix": [],
        "payload_bytes": 1793222,
        "files": {
            "assessment.expected.json": {
                "bytes": 1723902,
                "sha256": "746232c10bc2c46c8f28876689c720627fc273952e051023e4fd8f451301e463",
            },
            "claim.json": {"bytes": 293, "sha256": "44c5c714d41b2d9f2af9d25aab6d499748fa1b338152a4f387360823d56475de"},
            "native.expected.json": {
                "bytes": 5242880,
                "sha256": "6fbd2b44f36b33b103ea4753ec8cd5e089016a0811ab3d55964a3a09bb1d36cf",
            },
            "source.xml": {
                "bytes": 1189871,
                "sha256": "d66b9a0a2a231d4b9b5552959af1c72bec20daa57ea05a408353835019c6ffc4",
            },
        },
        "dimensions": {
            "A": 1723902,
            "N": 5242880,
            "distinct_selected_keys": 1,
            "family": "outcomes",
            "maximum_element_depth": 8,
            "nested_statuses": 0,
            "nodes": 10044,
            "raw_bytes": 1189871,
            "selected_outcomes": 10000,
            "source_text_bytes": 1410865,
            "source_times": 2,
            "systems": 1,
            "version": "5.11.2",
            "visible_outcomes": 10000,
        },
        "artifact": {
            "case": "oval-5.11.2-outcomes",
            "bytes": 6968625,
            "sha256": "d771739dc5912171d51d8e9cf33abcb289a7f75ad02cf212fb6b3c9eb486f541",
            "content_hash": "28cb7dfebb9c6ca61ee06246735e2e41a53883cb2716e0ba2817b56d0af0d857",
            "identity_frame_sha256": "6a40b2912fa2afcb1f4fdd129570af6f9669e1655cf007f522f4bfed3950bad8",
            "id": "3abbd1b9-2002-5c08-9719-16fac49d103e",
            "completion_state": "operator_qualified",
            "completion_utc": "2024-03-01T00:00:00Z",
        },
    },
    "oval-5.11.2-coverage": {
        "version": "5.11.2",
        "family": "coverage",
        "statuses": 9529,
        "fraction_prefix": [6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 5],
        "payload_bytes": 1126689,
        "files": {
            "assessment.expected.json": {
                "bytes": 2097152,
                "sha256": "deffa6884b8885b91a6c0f934e0788b407c6e798128420a4a49b22f8c389ef01",
            },
            "claim.json": {"bytes": 293, "sha256": "1be4d73a32cbafc32b0e127f46229cdcb5f3bfcf5f7900f1329e773c7c9b57e7"},
            "native.expected.json": {
                "bytes": 5242880,
                "sha256": "d421c388f0f02c82be22dd0a4c00c837d15cb77d61d76780ff4db05b3b82e60e",
            },
            "source.xml": {
                "bytes": 975271,
                "sha256": "03d58626aac47d18693e8543d50c8dcb0519c725d361e1cc85caefe084708c59",
            },
        },
        "dimensions": {
            "A": 2097152,
            "N": 5242880,
            "distinct_selected_keys": 64,
            "family": "coverage",
            "maximum_element_depth": 64,
            "nested_statuses": 9529,
            "nodes": 16320,
            "raw_bytes": 975271,
            "selected_outcomes": 378,
            "source_text_bytes": 1235871,
            "source_times": 257,
            "systems": 256,
            "version": "5.11.2",
            "visible_outcomes": 1398,
        },
        "artifact": {
            "case": "oval-5.11.2-coverage",
            "bytes": 7341874,
            "sha256": "f75ce8507bf6d7ac328b30b567030ae5911e811c51006659d4c39a3c320b4619",
            "content_hash": "1bb64100d296ccd02acd52c6abcabdfc5d9e0b61439d91798b2f0e6857666080",
            "identity_frame_sha256": "1048da82009dfc5227e9dd04b3e4cea6ba93ae31a06885b1c43a476c4de08c03",
            "id": "7c2b144d-e46e-5d3d-aaad-9fb7a4066203",
            "completion_state": "operator_qualified",
            "completion_utc": "2024-03-01T00:00:00Z",
        },
    },
    "oval-5.12.3-outcomes": {
        "version": "5.12.3",
        "family": "outcomes",
        "statuses": 0,
        "fraction_prefix": [],
        "payload_bytes": 1792998,
        "files": {
            "assessment.expected.json": {
                "bytes": 1723902,
                "sha256": "fc5887054ca0177ad07bc168de75f2973c71d4f958a8f506571bc43f84808e22",
            },
            "claim.json": {"bytes": 293, "sha256": "7e0b122922b84f5a9016d8f2d3788f530cd792ec2ce83b7bc11ab50d396590ca"},
            "native.expected.json": {
                "bytes": 5242880,
                "sha256": "0bf7bd3580bbfc539585934dc08bcb3bec0cafcfe3fa37f94cde78f8249679be",
            },
            "source.xml": {
                "bytes": 1189831,
                "sha256": "7fe13317b50f9c149e6f20099d5a4a933f70d22ca4ec6a364b85e83cf001bc46",
            },
        },
        "dimensions": {
            "A": 1723902,
            "N": 5242880,
            "distinct_selected_keys": 1,
            "family": "outcomes",
            "maximum_element_depth": 8,
            "nested_statuses": 0,
            "nodes": 10045,
            "raw_bytes": 1189831,
            "selected_outcomes": 10000,
            "source_text_bytes": 1410864,
            "source_times": 2,
            "systems": 1,
            "version": "5.12.3",
            "visible_outcomes": 10000,
        },
        "artifact": {
            "case": "oval-5.12.3-outcomes",
            "bytes": 6968625,
            "sha256": "6e46ecd220dbae6f6bc30a928297331a02b22caa1212ee0e7c8e5a1dc07a859e",
            "content_hash": "7c7c15bc2a4159110c9589617ae90f8a9bf4dd1ce1dcbea8b4d3da82e1e7d5ba",
            "identity_frame_sha256": "b7b6a428a6d6c9ae64f7f33bc96f93f0aa9373c66d7de4de41999996a233dd60",
            "id": "ccaad353-a636-5c66-9c6a-c943ed11d8ae",
            "completion_state": "operator_qualified",
            "completion_utc": "2024-03-01T00:00:00Z",
        },
    },
    "oval-5.12.3-coverage": {
        "version": "5.12.3",
        "family": "coverage",
        "statuses": 9529,
        "fraction_prefix": [6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 4],
        "payload_bytes": 1066049,
        "files": {
            "assessment.expected.json": {
                "bytes": 2097152,
                "sha256": "426a85c70443528aa01da476ef635e05f3cd2c277fe22e1c1a2aacb3ddc5bbfb",
            },
            "claim.json": {"bytes": 293, "sha256": "02388717824f4703eec4bd5037f0dc4dde9945a53bfd6a5300f1faf97fc4ff9f"},
            "native.expected.json": {
                "bytes": 5242880,
                "sha256": "00fa7644256a22999f4d02b3c604c343b6f03d5f1f917ef10f9ac134559bb6e7",
            },
            "source.xml": {
                "bytes": 964751,
                "sha256": "8849bb14dfc40b4fe7728a5bde463bd8a5d30c809938872b6356538651cab38a",
            },
        },
        "dimensions": {
            "A": 2097152,
            "N": 5242880,
            "distinct_selected_keys": 64,
            "family": "coverage",
            "maximum_element_depth": 64,
            "nested_statuses": 9529,
            "nodes": 16591,
            "raw_bytes": 964751,
            "selected_outcomes": 378,
            "source_text_bytes": 1235920,
            "source_times": 257,
            "systems": 256,
            "version": "5.12.3",
            "visible_outcomes": 1398,
        },
        "artifact": {
            "case": "oval-5.12.3-coverage",
            "bytes": 7341874,
            "sha256": "469723f31715542733dbcaeedbf5a50bd518791ede670e50e20de7b5aafd9ff0",
            "content_hash": "b2f5023b57391f07d7be15dd03cb7a2796e734a6b13e06c5dca6a6f03f1e4060",
            "identity_frame_sha256": "d1fec40ac70be707a9aa73be9e559de44d8c043d13e818ef8f3b8339c1159109",
            "id": "36a84e2b-3e7b-512f-ba9c-fd4162af6303",
            "completion_state": "operator_qualified",
            "completion_utc": "2024-03-01T00:00:00Z",
        },
    },
}


@pytest.mark.parametrize("name", tuple(_OVAL_CASE_FACTS))
def test_oval_complete_qualified_capacity(name: str) -> None:
    expected = _OVAL_CASE_FACTS[name]
    fractions = tuple(expected["fraction_prefix"])
    if expected["family"] == "coverage":
        fractions += (0,) * (257 - len(fractions))
    source, graph, assessment, dimensions = _make_oval_capacity(
        expected["version"],
        family=expected["family"],
        statuses=expected["statuses"],
        fractions=fractions,
        payload_bytes=expected["payload_bytes"],
    )
    assert dimensions == expected["dimensions"]
    n_bytes, a_bytes = encoded(graph), encoded(assessment)
    for leaf, body in (
        ("source.xml", source),
        ("native.expected.json", n_bytes),
        ("assessment.expected.json", a_bytes),
    ):
        assert len(body) == expected["files"][leaf]["bytes"]
        assert digest(body) == expected["files"][leaf]["sha256"]
    claim_data = {
        "schema_version": "scap-completion-assertion-v1",
        "source_sha256": digest(source),
        "source_profile": "oval-" + expected["version"] + "-core-results",
        "assessment_index": 0,
        "completed_at": "2024-03-01T00:00:00.000000Z",
        "reference": "Synthetic local capacity observation",
    }
    claim_bytes = encoded(claim_data)
    assert len(claim_bytes) == expected["files"]["claim.json"]["bytes"]
    assert digest(claim_bytes) == expected["files"]["claim.json"]["sha256"]
    claim = ScapCompletionAssertion.model_validate(claim_data)
    started = time.monotonic()
    result = collect_scap_bytes(
        source,
        source_profile=claim.source_profile,
        assessment_index=0,
        cadence_slug="nist-800-53-rev5-ca7",
        completion_assertion=claim,
        asserted_by="Synthetic capacity operator",
    )
    assert time.monotonic() - started < 60.0
    native = result.model_dump(mode="json")
    assert native["native_document"] == graph
    assert native["assessment"] == assessment
    artifact = native["evidence_artifact"]
    assert artifact is not None
    assert artifact["content"]["native_document"] == graph
    assert artifact["content"]["assessment"] == assessment
    assert digest(encoded(artifact)) == expected["artifact"]["sha256"]
    assert artifact["id"] == expected["artifact"]["id"]
    assert artifact["content_hash"] == expected["artifact"]["content_hash"]
    spaced = json.dumps(artifact["content"], ensure_ascii=True, sort_keys=True, allow_nan=False).encode("ascii")
    assert digest(spaced) == expected["artifact"]["content_hash"]
    full = len(encoded(native))
    remainder = {
        **native,
        "native_document": None,
        "assessment": None,
        "evidence_artifact": {
            **artifact,
            "content": {**artifact["content"], "native_document": None, "assessment": None},
        },
    }
    rest = len(encoded(remainder))
    assert rest <= 30_997
    assert full == rest + 2 * (len(n_bytes) - 4) + 2 * (len(a_bytes) - 4)
    assert full <= 14_711_045 < 16_777_216
