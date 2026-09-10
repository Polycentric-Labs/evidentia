"""Independent expectations for the approved authored observation mappings."""

from __future__ import annotations

import ast
import subprocess
import sys
from dataclasses import FrozenInstanceError, fields, is_dataclass
from pathlib import Path
from typing import cast, get_args

import pytest
from evidentia_collectors.entra_m365 import mapping
from evidentia_collectors.entra_m365.mapping import (
    FRAMEWORK,
    FindingRule,
    RuleSpec,
    control_mappings,
    get_rule,
    rule_specs,
)
from evidentia_core.models.common import ControlMapping, OLIRRelationship

EXPECTED: dict[FindingRule, tuple[str, str, str, tuple[str, ...], str, str]] = {
    "conditional-access-policy": (
        "conditional-access",
        "conditional-access:{source_id}",
        "MicrosoftEntra::ConditionalAccessPolicy",
        ("AC-3", "IA-2"),
        "intersects-with",
        "observed access-policy configuration does not establish effective identity/application coverage.",
    ),
    "authentication-registration-summary": (
        "authentication-registration",
        "authentication-registration:summary",
        "MicrosoftEntra::AuthenticationRegistrationSummary",
        ("IA-2", "IA-5"),
        "intersects-with",
        "observed registration/capability flags cover part of authentication evidence and exclude disabled accounts.",
    ),
    "sign-in-observation": (
        "sign-ins",
        "sign-ins:{source_id}",
        "MicrosoftEntra::SignIn",
        ("AU-6", "SI-4"),
        "intersects-with",
        "the event is monitoring input, not proof of review or complete history.",
    ),
    "directory-role-inventory": (
        "directory-roles",
        "directory-roles:{source_id}",
        "MicrosoftEntra::DirectoryRole",
        ("AC-2", "AC-6"),
        "intersects-with",
        "role inventory does not enumerate assignments or eligibility.",
    ),
    "managed-device-state": (
        "managed-devices",
        "managed-devices:{source_id}",
        "MicrosoftIntune::ManagedDevice",
        ("CM-8", "CA-7"),
        "intersects-with",
        "Intune state is observed device-management evidence with source scope limits.",
    ),
    "retention-label-configuration": (
        "retention-labels",
        "retention-labels:{source_id}",
        "MicrosoftPurview::RetentionLabel",
        ("SI-12",),
        "intersects-with",
        "label configuration does not establish record-set completeness or item application.",
    ),
    "dlp-policy-configuration": (
        "dlp-export",
        "dlp-export:policy:{source_id}",
        "MicrosoftPurview::DlpPolicy",
        ("AC-4", "SI-4"),
        "intersects-with",
        "configuration state does not establish effective content enforcement.",
    ),
    "dlp-unresolved-rule": (
        "dlp-export",
        "dlp-export:unresolved-rule:{source_id}",
        "MicrosoftPurview::DlpRule",
        ("AC-4",),
        "related-to",
        "an unresolved parent prevents interpreting the rule's policy scope.",
    ),
    "defender-alert-observation": (
        "defender-alerts",
        "defender-alerts:{source_id}",
        "MicrosoftDefender::Alert",
        ("SI-4", "IR-5"),
        "intersects-with",
        "observed alert metadata does not establish endpoint-protection deployment or response completion.",
    ),
    "defender-incident-observation": (
        "defender-incidents",
        "defender-incidents:{source_id}",
        "MicrosoftDefender::Incident",
        ("IR-4", "IR-5"),
        "intersects-with",
        "incident state is source-reported operational evidence, not a validated human determination.",
    ),
}


def test_exact_ten_rule_literals_and_immutable_inventory() -> None:
    assert tuple(get_args(FindingRule)) == tuple(EXPECTED)
    actual = rule_specs()
    assert isinstance(actual, tuple)
    assert tuple(item.rule for item in actual) == tuple(EXPECTED)
    assert len({item.rule for item in actual}) == 10
    assert all(isinstance(item, RuleSpec) for item in actual)


@pytest.mark.parametrize("rule", tuple(EXPECTED))
def test_exact_authored_mapping_and_static_scope(rule: FindingRule) -> None:
    capability, suffix, resource_type, controls, relationship, justification = EXPECTED[rule]
    actual = get_rule(rule)
    assert actual.rule == rule
    assert actual.capability == capability
    assert actual.source_suffix == suffix
    assert actual.resource_type == resource_type
    assert actual.control_ids == controls
    assert actual.relationship.value == relationship
    assert actual.justification == justification
    assert actual.title and actual.title == actual.title.strip()
    assert actual.description and actual.description == actual.description.strip()
    assert "{" not in actual.title + actual.description
    assert "}" not in actual.title + actual.description
    actual.title.encode("ascii")
    actual.description.encode("ascii")
    assert FRAMEWORK == "nist-800-53-rev5"
    mappings = control_mappings(rule)
    assert all(type(mapping) is ControlMapping for mapping in mappings)
    assert [mapping.model_dump(mode="json") for mapping in mappings] == [
        {
            "framework": "nist-800-53-rev5",
            "control_id": control,
            "control_title": None,
            "relationship": relationship,
            "justification": justification,
        }
        for control in controls
    ]


def test_related_to_only_for_unresolved_dlp_parent() -> None:
    assert [item.rule for item in rule_specs() if item.relationship is OLIRRelationship.RELATED_TO] == [
        "dlp-unresolved-rule"
    ]
    assert all(
        item.relationship is OLIRRelationship.INTERSECTS_WITH
        for item in rule_specs()
        if item.rule != "dlp-unresolved-rule"
    )
    assert sum(len(control_mappings(rule)) for rule in EXPECTED) == 18


@pytest.mark.parametrize("rule", tuple(EXPECTED))
def test_returned_core_objects_and_lists_are_fresh(rule: FindingRule) -> None:
    first = control_mappings(rule)
    second = control_mappings(rule)
    expected = [mapping.model_dump(mode="json") for mapping in second]
    assert first is not second
    assert all(left is not right for left, right in zip(first, second, strict=True))
    first[0].framework = "synthetic-modified-framework"
    first[0].control_id = "synthetic-modified-control"
    first[0].control_title = "Synthetic changed title"
    first[0].relationship = OLIRRelationship.SUPERSET_OF
    first[0].justification = "Synthetic changed rationale."
    first.clear()
    second.append(ControlMapping(framework="synthetic", control_id="extra"))
    second[0].justification = "Another synthetic change."
    assert [mapping.model_dump(mode="json") for mapping in control_mappings(rule)] == expected
    assert get_rule(rule).control_ids == EXPECTED[rule][3]
    assert get_rule(rule).justification == EXPECTED[rule][5]


@pytest.mark.parametrize("rule", tuple(EXPECTED))
def test_rule_specs_are_frozen_with_only_immutable_fields(rule: FindingRule) -> None:
    spec = get_rule(rule)
    assert is_dataclass(spec)
    assert isinstance(spec.control_ids, tuple)
    assert all(type(control) is str for control in spec.control_ids)
    assert {field.name for field in fields(spec)} == {
        "rule",
        "capability",
        "source_suffix",
        "resource_type",
        "title",
        "description",
        "control_ids",
        "relationship",
        "justification",
    }
    for field in fields(spec):
        with pytest.raises(FrozenInstanceError):
            setattr(spec, field.name, getattr(spec, field.name))
    assert get_rule(rule) == spec


@pytest.mark.parametrize(
    "invalid", ["", "future-rule", " conditional-access-policy", "Conditional-access-policy", None, 3]
)
def test_unrecognized_rule_rejected_without_value_echo(invalid: object) -> None:
    rule = cast(FindingRule, invalid)
    with pytest.raises(ValueError, match=r"^Unknown finding rule$"):
        get_rule(rule)
    with pytest.raises(ValueError, match=r"^Unknown finding rule$"):
        control_mappings(rule)


def test_catalog_package_is_unavailable_in_fresh_mapping_process() -> None:
    code = """
import importlib.abc
import sys

class BlockCatalog(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "evidentia_core.catalogs" or fullname.startswith("evidentia_core.catalogs."):
            raise AssertionError("Runtime catalog dependency")
        return None

sys.meta_path.insert(0, BlockCatalog())
from evidentia_collectors.entra_m365.mapping import control_mappings, rule_specs
assert len(rule_specs()) == 10
assert sum(len(control_mappings(spec.rule)) for spec in rule_specs()) == 18
assert not any(name == "evidentia_core.catalogs" or name.startswith("evidentia_core.catalogs.") for name in sys.modules)
"""
    completed = subprocess.run(
        [sys.executable, "-B", "-c", code],
        cwd=Path(__file__).resolve().parent,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_mapping_imports_only_declarations_and_actual_core_types() -> None:
    source = Path(mapping.__file__).read_text(encoding="ascii")
    tree = ast.parse(source)
    imports = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert set(imports) <= {"__future__", "dataclasses", "typing", "evidentia_core.models.common"}
    assert "evidentia_core.models.common" in imports
    assert not any(isinstance(node, ast.Import) for node in ast.walk(tree))
