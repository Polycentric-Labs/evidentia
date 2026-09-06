"""Tests for the v0.10.1 SecurityFinding -> Finding rename alias.

Both names refer to the same class — see docs/deprecation-calendar.md.
"""

from __future__ import annotations

from evidentia_core.models.common import Severity
from evidentia_core.models.finding import Finding, SecurityFinding


def test_finding_is_same_class_as_security_finding() -> None:
    """`Finding` is `SecurityFinding` — literally the same class object."""
    assert Finding is SecurityFinding


def test_finding_constructor_works_with_canonical_name() -> None:
    """Instances created via `Finding(...)` are valid SecurityFinding instances."""
    f = Finding(
        title="t",
        description="d",
        severity=Severity.LOW,
        source_system="x",
    )
    assert isinstance(f, SecurityFinding)
    assert isinstance(f, Finding)


def test_isinstance_works_against_either_name() -> None:
    """Existing code that uses `isinstance(obj, SecurityFinding)` keeps
    working AND new code that uses `isinstance(obj, Finding)` also works."""
    f = SecurityFinding(
        title="t",
        description="d",
        severity=Severity.LOW,
        source_system="x",
    )
    assert isinstance(f, SecurityFinding)
    assert isinstance(f, Finding)


def test_model_schemas_are_identical_under_both_names() -> None:
    """The JSON schema is the same — the alias is a pure name equivalence,
    not a subclass. Operators / tools generating JSON Schema docs from
    either name see the exact same field set."""
    # `Finding is SecurityFinding` so model_json_schema() returns the
    # same dict — Pydantic computes it once per class object.
    assert Finding.model_json_schema() == SecurityFinding.model_json_schema()


def test_dump_validate_round_trip_works_under_both_names() -> None:
    """A finding serialized under one name re-validates under the other."""
    f1 = SecurityFinding(
        title="t",
        description="d",
        severity=Severity.LOW,
        source_system="x",
    )
    # Dump under SecurityFinding, re-validate under Finding.
    restored = Finding.model_validate(f1.model_dump())
    assert restored == f1
