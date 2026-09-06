"""Tests for OLIR-typed AWS mapping functions (v0.7.0)."""

from __future__ import annotations

import pytest
from evidentia_collectors.aws import (
    map_config_rule_to_control_mappings,
    map_config_rule_to_controls,
    map_security_hub_control_to_control_mappings,
    map_security_hub_control_to_controls,
)
from evidentia_core.models.common import ControlMapping, OLIRRelationship


def test_config_rule_mapping_returns_control_mappings() -> None:
    mappings = map_config_rule_to_control_mappings("s3-bucket-public-read-prohibited")
    assert all(isinstance(m, ControlMapping) for m in mappings)
    assert any(m.control_id == "AC-3" for m in mappings)


def test_config_rule_mapping_unknown_returns_empty() -> None:
    assert map_config_rule_to_control_mappings("totally-bogus-rule") == []


def test_config_rule_s3_public_read_uses_subset_of() -> None:
    mappings = map_config_rule_to_control_mappings("s3-bucket-public-read-prohibited")
    ac3_mapping = next(m for m in mappings if m.control_id == "AC-3")
    assert ac3_mapping.relationship == OLIRRelationship.SUBSET_OF
    assert "FSBP" in ac3_mapping.justification


def test_config_rule_access_keys_rotated_uses_intersects_with_for_ac2() -> None:
    mappings = map_config_rule_to_control_mappings("access-keys-rotated")
    ac2_mapping = next(m for m in mappings if m.control_id == "AC-2")
    assert ac2_mapping.relationship == OLIRRelationship.INTERSECTS_WITH


def test_config_rule_legacy_str_variant_still_works() -> None:
    plain = map_config_rule_to_controls("s3-bucket-public-read-prohibited")
    assert "AC-3" in plain
    assert isinstance(plain, list)
    assert all(isinstance(s, str) for s in plain)


def test_security_hub_mapping_returns_control_mappings() -> None:
    mappings = map_security_hub_control_to_control_mappings("fsbp.s3.1")
    assert all(isinstance(m, ControlMapping) for m in mappings)
    assert any(m.control_id == "AC-3" for m in mappings)


def test_security_hub_mapping_unknown_returns_empty() -> None:
    assert map_security_hub_control_to_control_mappings("bogus.control.0") == []


def test_security_hub_mapping_uses_subset_of_authoritative_claim() -> None:
    mappings = map_security_hub_control_to_control_mappings("fsbp.cloudtrail.1")
    assert all(m.relationship == OLIRRelationship.SUBSET_OF for m in mappings)
    assert all("FSBP" in m.justification or "CIS" in m.justification for m in mappings)


def test_security_hub_mapping_legacy_str_variant_still_works() -> None:
    plain = map_security_hub_control_to_controls("fsbp.s3.1")
    assert "AC-3" in plain
    assert isinstance(plain, list)


@pytest.mark.parametrize(
    "rule_name",
    [
        "access-keys-rotated",
        "iam-password-policy",
        "iam-root-access-key-check",
        "iam-user-mfa-enabled",
        "iam-user-no-policies-check",
        "mfa-enabled-for-iam-console-access",
        "root-account-mfa-enabled",
        "alb-http-to-https-redirection-check",
        "elb-tls-https-listeners-only",
        "encrypted-volumes",
        "rds-storage-encrypted",
        "s3-bucket-server-side-encryption-enabled",
        "s3-bucket-ssl-requests-only",
        "cloudtrail-enabled",
        "cloud-trail-log-file-validation-enabled",
        "multi-region-cloudtrail-enabled",
    ],
)
def test_every_major_config_rule_has_olir_classification(rule_name: str) -> None:
    mappings = map_config_rule_to_control_mappings(rule_name)
    assert mappings, f"No OLIR mapping for {rule_name!r}"
    assert all(m.justification for m in mappings), f"Empty justification on mapping for {rule_name!r}"


@pytest.mark.parametrize(
    "control_id",
    [
        "fsbp.iam.1",
        "fsbp.iam.4",
        "fsbp.iam.6",
        "fsbp.iam.8",
        "fsbp.s3.1",
        "fsbp.s3.2",
        "fsbp.s3.3",
        "fsbp.s3.5",
        "fsbp.cloudtrail.1",
        "cis.1.4",
        "cis.1.5",
    ],
)
def test_every_major_security_hub_control_has_olir_classification(
    control_id: str,
) -> None:
    mappings = map_security_hub_control_to_control_mappings(control_id)
    assert mappings, f"No OLIR mapping for {control_id!r}"
    assert all(m.relationship == OLIRRelationship.SUBSET_OF for m in mappings)
    assert all(m.justification for m in mappings)
