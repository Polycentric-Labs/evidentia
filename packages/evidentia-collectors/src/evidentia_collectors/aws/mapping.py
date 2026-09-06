"""Curated mapping: AWS Config rules + Security Hub controls -> NIST 800-53.

These tables are intentionally conservative. We map what we *know* is
right (the control IDs the AWS Foundational Security Best Practices
standard explicitly references, or that are obvious from the rule's
semantics). Unknown sources fall back to an empty list rather than a
guess — better to under-attribute than to claim false coverage.

Expand this module over time as new rules land; every addition ships
with a code comment naming the primary source (FSBP / CIS / PCI-DSS /
HIPAA). v0.6.0 adds an LLM-assisted mapper for rules not in this
table, gated behind a ``--ai-assist`` flag.
"""

from __future__ import annotations

from typing import Final

from evidentia_core.models.common import ControlMapping, OLIRRelationship

# ── AWS Config rule name -> NIST 800-53 control IDs ───────────────────────

#: Maps normalized AWS Config rule names (lowercase, hyphen-separated)
#: to lists of NIST 800-53 Rev 5 control IDs. Exhaustive for the ~25
#: most-common AWS managed rules as of 2025; external rules or custom
#: rules return an empty list from :func:`map_config_rule_to_controls`.
CONFIG_RULE_TO_CONTROLS: Final[dict[str, list[str]]] = {
    # Access control (AC family)
    "access-keys-rotated": ["AC-2", "IA-5"],
    "iam-password-policy": ["IA-5"],
    "iam-root-access-key-check": ["AC-2", "AC-6"],
    "iam-user-mfa-enabled": ["IA-2"],
    "iam-user-no-policies-check": ["AC-2", "AC-6"],
    "mfa-enabled-for-iam-console-access": ["IA-2"],
    "root-account-mfa-enabled": ["IA-2", "AC-6"],
    # Encryption in transit / at rest (SC family)
    "alb-http-to-https-redirection-check": ["SC-8"],
    "elb-tls-https-listeners-only": ["SC-8"],
    "encrypted-volumes": ["SC-28"],
    "rds-storage-encrypted": ["SC-28"],
    "s3-bucket-server-side-encryption-enabled": ["SC-28"],
    "s3-bucket-ssl-requests-only": ["SC-8"],
    # Public exposure (AC + SC families)
    "ec2-security-group-attached-to-eni": ["AC-4", "SC-7"],
    "rds-instance-public-access-check": ["AC-3", "AC-4", "SC-7"],
    "s3-bucket-public-read-prohibited": ["AC-3", "AC-6"],
    "s3-bucket-public-write-prohibited": ["AC-3", "AC-6"],
    "vpc-default-security-group-closed": ["AC-4", "SC-7"],
    # Logging + audit (AU family)
    "cloudtrail-enabled": ["AU-2", "AU-3", "AU-12"],
    "cloud-trail-log-file-validation-enabled": ["AU-9", "AU-10"],
    "cloudwatch-log-group-encrypted": ["SC-28", "AU-9"],
    "multi-region-cloudtrail-enabled": ["AU-2", "AU-12"],
    "s3-bucket-logging-enabled": ["AU-2", "AU-12"],
    # Backup + availability (CP family)
    "backup-plan-min-frequency-and-min-retention-check": ["CP-9"],
    "rds-automatic-minor-version-upgrade-enabled": ["SI-2"],
    "rds-multi-az-support": ["CP-9", "CP-10"],
    # Patching (SI family)
    "ec2-managedinstance-patch-compliance-status-check": ["SI-2"],
    # Configuration management (CM family)
    "ec2-instance-detailed-monitoring-enabled": ["CM-8", "SI-4"],
    "ec2-instance-managed-by-ssm": ["CM-8"],
}

# ── Security Hub FSBP control id -> NIST 800-53 ──────────────────────────

#: Maps AWS Security Hub (FSBP v1.0.0 + CIS AWS Foundations v1.4.0)
#: control identifiers to NIST 800-53 Rev 5 control IDs. Security Hub
#: itself surfaces NIST SP 800-53 v5 as an enabled standard — when
#: findings carry explicit related-requirements fields, we use those
#: directly and don't consult this table.
SECURITY_HUB_CONTROL_TO_CONTROLS: Final[dict[str, list[str]]] = {
    # CIS AWS Foundations v1.4.0
    "cis.1.4": ["AC-6", "IA-2"],  # Ensure no root user access key
    "cis.1.5": ["IA-2"],  # Root account MFA
    "cis.1.7": ["IA-2"],  # MFA for every user with a password
    "cis.1.8": ["IA-5"],  # Password length >= 14
    "cis.1.10": ["IA-5"],  # Password reuse prevention
    "cis.1.14": ["AC-2"],  # Access keys rotated every 90 days
    "cis.2.1.1": ["SC-28"],  # S3 default encryption
    "cis.3.1": ["AU-2", "AU-12"],  # CloudTrail in all regions
    "cis.3.4": ["AU-9"],  # CloudTrail log file validation
    # AWS Foundational Security Best Practices
    "fsbp.acm.1": ["SC-17"],  # ACM cert renewal
    "fsbp.cloudtrail.1": ["AU-2", "AU-12"],  # CloudTrail enabled
    "fsbp.cloudtrail.4": ["AU-9"],  # CloudTrail validation
    "fsbp.ec2.2": ["AC-4", "SC-7"],  # Security group least-priv
    "fsbp.ec2.6": ["AU-12"],  # VPC flow logs
    "fsbp.iam.1": ["AC-6", "IA-2"],  # Root access key
    "fsbp.iam.4": ["AC-2"],  # Root access key
    "fsbp.iam.6": ["IA-2"],  # Root MFA
    "fsbp.iam.8": ["AC-2"],  # Unused creds 90d
    "fsbp.rds.2": ["AC-3", "SC-7"],  # RDS public access
    "fsbp.rds.3": ["SC-28"],  # RDS encryption at rest
    "fsbp.rds.4": ["SC-8"],  # RDS snapshot encryption
    "fsbp.s3.1": ["AC-3"],  # Block Public Access
    "fsbp.s3.2": ["AC-3"],  # S3 public read
    "fsbp.s3.3": ["AC-3"],  # S3 public write
    "fsbp.s3.5": ["SC-8"],  # S3 SSL-only
    "fsbp.s3.6": ["AU-2"],  # S3 logging
}


def map_config_rule_to_controls(rule_name: str) -> list[str]:
    """Return NIST 800-53 control IDs for an AWS Config rule name.

    Normalizes case + strips common AWS-managed-rule prefixes so both
    hyphenated identifiers (``s3-bucket-public-read-prohibited``) and
    camelCase (``S3BucketPublicReadProhibited``) hit the same mapping.
    Unknown rules return an empty list.
    """
    normalized = _normalize_rule_name(rule_name)
    return list(CONFIG_RULE_TO_CONTROLS.get(normalized, []))


def map_security_hub_control_to_controls(control_id: str) -> list[str]:
    """Return NIST 800-53 control IDs for a Security Hub control identifier.

    ``control_id`` is the ``ControlId`` / ``StandardsControlArn`` suffix
    ("1.4", "IAM.6", "S3.3"). We normalize to lowercase dotted form and
    look up via :data:`SECURITY_HUB_CONTROL_TO_CONTROLS`. Unknown
    controls return an empty list.
    """
    normalized = _normalize_security_hub_id(control_id)
    return list(SECURITY_HUB_CONTROL_TO_CONTROLS.get(normalized, []))


def _normalize_rule_name(raw: str) -> str:
    """Lowercase + hyphen-separate a Config rule name.

    ``S3BucketPublicReadProhibited`` -> ``s3-bucket-public-read-prohibited``
    ``s3-bucket-public-read-prohibited`` -> unchanged.
    """
    if not raw:
        return ""
    out: list[str] = []
    for i, ch in enumerate(raw):
        if ch.isupper() and i > 0 and raw[i - 1] != "-":
            out.append("-")
        out.append(ch.lower())
    return "".join(out).replace("_", "-")


def _normalize_security_hub_id(raw: str) -> str:
    """Normalize a Security Hub control id to lowercase dotted form.

    The AWS Security Hub API returns things like ``"IAM.6"`` (bare FSBP
    id) or ``"1.4"`` (bare CIS id). Our table keys are prefixed
    ``"fsbp.iam.6"`` / ``"cis.1.4"`` to disambiguate across standards.
    This normalizer adds the standard prefix where needed.
    """
    cleaned = raw.strip().lower()
    # If it already has our prefix, leave it.
    if cleaned.startswith(("fsbp.", "cis.")):
        return cleaned
    # CIS controls are dotted numeric ("1.4", "2.1.1", "3.1").
    if cleaned and cleaned[0].isdigit():
        return f"cis.{cleaned}"
    # FSBP controls have a named section prefix ("iam.6", "s3.3").
    return f"fsbp.{cleaned}"


# ═════════════════════════════════════════════════════════════════════════
# v0.7.0: OLIR-typed mapping functions
# ═════════════════════════════════════════════════════════════════════════
#
# Spot-checked against AWS Config Operational Best Practices for NIST
# 800-53 Rev 5 (https://docs.aws.amazon.com/config/latest/developerguide/
# operational-best-practices-for-nist-800-53_rev_5.html), AWS Audit
# Manager 'AWS NIST 800-53 Rev 5' framework, and AWS Security Hub
# controls reference (standards-reference-nist-800-53.html).
#
# Relationship classification convention:
# - SUBSET_OF — Security Hub 'Related requirements' cites the control
#   explicitly (authoritative subset claim per AWS docs).
# - INTERSECTS_WITH — curated inference where the rule addresses one
#   aspect of the NIST control but the control's scope is broader.
# - RELATED_TO — weakest; used only when the connection is indirect.

_CONFIG_RULE_OLIR: Final[dict[str, dict[str, tuple[OLIRRelationship, str]]]] = {
    "access-keys-rotated": {
        "AC-2": (
            OLIRRelationship.INTERSECTS_WITH,
            "AC-2 Account Management encompasses the full credential lifecycle; rule evidences one aspect (key age).",
        ),
        "IA-5": (
            OLIRRelationship.SUBSET_OF,
            "IA-5 Authenticator Management requires periodic authenticator refresh; rule directly evidences rotation.",
        ),
    },
    "iam-password-policy": {
        "IA-5": (
            OLIRRelationship.SUBSET_OF,
            "IA-5 requires complexity/composition policy; rule evidences the policy-existence requirement of IA-5(1).",
        ),
    },
    "iam-root-access-key-check": {
        "AC-2": (
            OLIRRelationship.SUBSET_OF,
            "AC-2 privileged-account management; per Security Hub FSBP/CIS, root access keys violate AC-2 hygiene.",
        ),
        "AC-6": (
            OLIRRelationship.SUBSET_OF,
            "AC-6 Least Privilege — root keys bypass boundaries; Security Hub IAM.4 'Related requirements' cites AC-6.",
        ),
    },
    "iam-user-mfa-enabled": {
        "IA-2": (
            OLIRRelationship.SUBSET_OF,
            "IA-2(1) MFA for privileged accounts; rule evidences MFA presence.",
        ),
    },
    "iam-user-no-policies-check": {
        "AC-2": (
            OLIRRelationship.INTERSECTS_WITH,
            "Group-vs-user policy attachment is one axis of account management structure.",
        ),
        "AC-6": (
            OLIRRelationship.SUBSET_OF,
            "AC-6 Least Privilege prefers group-scoped over user-attached policies.",
        ),
    },
    "mfa-enabled-for-iam-console-access": {
        "IA-2": (
            OLIRRelationship.SUBSET_OF,
            "IA-2(1) Multifactor Authentication to Privileged Accounts; console MFA is the canonical scenario.",
        ),
    },
    "root-account-mfa-enabled": {
        "IA-2": (
            OLIRRelationship.SUBSET_OF,
            "IA-2(1) MFA — root MFA is the highest-privilege auth checkpoint.",
        ),
        "AC-6": (
            OLIRRelationship.SUBSET_OF,
            "AC-6 Least Privilege — root is max-privilege principal; "
            "MFA is defence-in-depth for least-privilege enforcement.",
        ),
    },
    "alb-http-to-https-redirection-check": {
        "SC-8": (
            OLIRRelationship.SUBSET_OF,
            "SC-8 Transmission Confidentiality — HTTPS redirect ensures encryption in transit. FSBP ELB.1 cites SC-8.",
        ),
    },
    "elb-tls-https-listeners-only": {
        "SC-8": (
            OLIRRelationship.SUBSET_OF,
            "SC-8 — TLS-only listeners enforce in-transit encryption per FSBP ELB.2.",
        ),
    },
    "encrypted-volumes": {
        "SC-28": (
            OLIRRelationship.SUBSET_OF,
            "SC-28 Protection of Information at Rest — EBS volume encryption.",
        ),
    },
    "rds-storage-encrypted": {
        "SC-28": (
            OLIRRelationship.SUBSET_OF,
            "SC-28 at-rest encryption; FSBP RDS.3 'Related requirements' cites SC-28.",
        ),
    },
    "s3-bucket-server-side-encryption-enabled": {
        "SC-28": (
            OLIRRelationship.SUBSET_OF,
            "SC-28 at-rest encryption for S3.",
        ),
    },
    "s3-bucket-ssl-requests-only": {
        "SC-8": (
            OLIRRelationship.SUBSET_OF,
            "SC-8 in-transit encryption; enforces TLS on all S3 requests per FSBP S3.5.",
        ),
    },
    "ec2-security-group-attached-to-eni": {
        "AC-4": (
            OLIRRelationship.INTERSECTS_WITH,
            "AC-4 Information Flow Control — SG attachment is one mechanism of flow control.",
        ),
        "SC-7": (
            OLIRRelationship.SUBSET_OF,
            "SC-7 Boundary Protection — SGs are boundary-protection mechanisms; FSBP EC2.2 cites SC-7.",
        ),
    },
    "rds-instance-public-access-check": {
        "AC-3": (
            OLIRRelationship.SUBSET_OF,
            "AC-3 Access Enforcement — blocking public DB access.",
        ),
        "AC-4": (
            OLIRRelationship.INTERSECTS_WITH,
            "AC-4 — information flow restriction across public boundary.",
        ),
        "SC-7": (
            OLIRRelationship.SUBSET_OF,
            "SC-7 Boundary Protection; FSBP RDS.2 cites SC-7.",
        ),
    },
    "s3-bucket-public-read-prohibited": {
        "AC-3": (
            OLIRRelationship.SUBSET_OF,
            "AC-3 Access Enforcement; FSBP S3.2 cites AC-3.",
        ),
        "AC-6": (
            OLIRRelationship.INTERSECTS_WITH,
            "AC-6 Least Privilege — public read grants broad access.",
        ),
    },
    "s3-bucket-public-write-prohibited": {
        "AC-3": (
            OLIRRelationship.SUBSET_OF,
            "AC-3 Access Enforcement; FSBP S3.3 cites AC-3.",
        ),
        "AC-6": (
            OLIRRelationship.INTERSECTS_WITH,
            "AC-6 — public write grants excessive permission.",
        ),
    },
    "vpc-default-security-group-closed": {
        "AC-4": (
            OLIRRelationship.INTERSECTS_WITH,
            "AC-4 Information Flow Control — default SG scope affects flow policy.",
        ),
        "SC-7": (
            OLIRRelationship.SUBSET_OF,
            "SC-7 Boundary Protection — default SG hygiene.",
        ),
    },
    "cloudtrail-enabled": {
        "AU-2": (
            OLIRRelationship.SUBSET_OF,
            "AU-2 Event Logging; FSBP CloudTrail.1 cites AU-2.",
        ),
        "AU-3": (
            OLIRRelationship.SUBSET_OF,
            "AU-3 Content of Audit Records — CloudTrail records AU-3 required fields.",
        ),
        "AU-12": (
            OLIRRelationship.SUBSET_OF,
            "AU-12 Audit Record Generation for AWS control plane.",
        ),
    },
    "cloud-trail-log-file-validation-enabled": {
        "AU-9": (
            OLIRRelationship.SUBSET_OF,
            "AU-9 Protection of Audit Information — log-file validation = tamper detection; FSBP CloudTrail.4.",
        ),
        "AU-10": (
            OLIRRelationship.INTERSECTS_WITH,
            "AU-10 Non-Repudiation — validation supports non-repudiation of logged events.",
        ),
    },
    "cloudwatch-log-group-encrypted": {
        "SC-28": (
            OLIRRelationship.SUBSET_OF,
            "SC-28 — log group KMS encryption protects audit data at rest.",
        ),
        "AU-9": (
            OLIRRelationship.SUBSET_OF,
            "AU-9 — encryption of audit-log storage.",
        ),
    },
    "multi-region-cloudtrail-enabled": {
        "AU-2": (
            OLIRRelationship.SUBSET_OF,
            "AU-2 — multi-region ensures comprehensive audit coverage.",
        ),
        "AU-12": (
            OLIRRelationship.SUBSET_OF,
            "AU-12 Audit Record Generation across all regions.",
        ),
    },
    "s3-bucket-logging-enabled": {
        "AU-2": (
            OLIRRelationship.SUBSET_OF,
            "AU-2 — S3 access logging for data-plane events; FSBP S3.9 cites AU-2.",
        ),
        "AU-12": (
            OLIRRelationship.SUBSET_OF,
            "AU-12 — data-plane audit source.",
        ),
    },
    "backup-plan-min-frequency-and-min-retention-check": {
        "CP-9": (
            OLIRRelationship.SUBSET_OF,
            "CP-9 System Backup — frequency + retention policy evidence.",
        ),
    },
    "rds-automatic-minor-version-upgrade-enabled": {
        "SI-2": (
            OLIRRelationship.SUBSET_OF,
            "SI-2 Flaw Remediation — automated minor upgrades are one mechanism of timely patching.",
        ),
    },
    "rds-multi-az-support": {
        "CP-9": (
            OLIRRelationship.INTERSECTS_WITH,
            "CP-9 — multi-AZ supports availability but is distinct from backup storage.",
        ),
        "CP-10": (
            OLIRRelationship.SUBSET_OF,
            "CP-10 System Recovery — multi-AZ enables automated failover.",
        ),
    },
    "ec2-managedinstance-patch-compliance-status-check": {
        "SI-2": (
            OLIRRelationship.SUBSET_OF,
            "SI-2 Flaw Remediation — patch compliance is primary evidence of timely patching.",
        ),
    },
    "ec2-instance-detailed-monitoring-enabled": {
        "CM-8": (
            OLIRRelationship.INTERSECTS_WITH,
            "CM-8 System Component Inventory — detailed monitoring provides component-level telemetry.",
        ),
        "SI-4": (
            OLIRRelationship.SUBSET_OF,
            "SI-4 System Monitoring — detailed monitoring is fine-grained system monitoring.",
        ),
    },
    "ec2-instance-managed-by-ssm": {
        "CM-8": (
            OLIRRelationship.SUBSET_OF,
            "CM-8 — SSM management implies inventory registration.",
        ),
    },
}


# Security Hub mappings → SUBSET_OF (authoritative per AWS 'Related
# requirements' field).
_SECURITY_HUB_OLIR_JUSTIFICATION: Final[dict[str, str]] = {
    "cis.1.4": "CIS AWS Foundations v1.4 §1.4 — no root access keys.",
    "cis.1.5": "CIS AWS Foundations v1.4 §1.5 — root MFA.",
    "cis.1.7": "CIS AWS Foundations v1.4 §1.7 — MFA for every user.",
    "cis.1.8": "CIS AWS Foundations v1.4 §1.8 — password length ≥14.",
    "cis.1.10": "CIS AWS Foundations v1.4 §1.10 — password reuse prevention.",
    "cis.1.14": "CIS AWS Foundations v1.4 §1.14 — access key rotation ≤90d.",
    "cis.2.1.1": "CIS AWS Foundations v1.4 §2.1.1 — S3 default encryption.",
    "cis.3.1": "CIS AWS Foundations v1.4 §3.1 — CloudTrail in all regions.",
    "cis.3.4": "CIS AWS Foundations v1.4 §3.4 — log file validation.",
    "fsbp.acm.1": "FSBP ACM.1 Related requirements cite SC-17.",
    "fsbp.cloudtrail.1": "FSBP CloudTrail.1 cites AU-2, AU-12.",
    "fsbp.cloudtrail.4": "FSBP CloudTrail.4 cites AU-9.",
    "fsbp.ec2.2": "FSBP EC2.2 cites AC-4, SC-7.",
    "fsbp.ec2.6": "FSBP EC2.6 cites AU-12.",
    "fsbp.iam.1": "FSBP IAM.1 cites AC-6, IA-2.",
    "fsbp.iam.4": "FSBP IAM.4 cites AC-2.",
    "fsbp.iam.6": "FSBP IAM.6 cites IA-2.",
    "fsbp.iam.8": "FSBP IAM.8 cites AC-2.",
    "fsbp.rds.2": "FSBP RDS.2 cites AC-3, SC-7.",
    "fsbp.rds.3": "FSBP RDS.3 cites SC-28.",
    "fsbp.rds.4": "FSBP RDS.4 cites SC-8.",
    "fsbp.s3.1": "FSBP S3.1 cites AC-3.",
    "fsbp.s3.2": "FSBP S3.2 cites AC-3.",
    "fsbp.s3.3": "FSBP S3.3 cites AC-3.",
    "fsbp.s3.5": "FSBP S3.5 cites SC-8.",
    "fsbp.s3.6": "FSBP S3.6 cites AU-2.",
}


def map_config_rule_to_control_mappings(
    rule_name: str,
) -> list[ControlMapping]:
    """Return OLIR-typed :class:`ControlMapping` list for an AWS Config rule.

    v0.7.0 addition. Each returned mapping carries an explicit OLIR
    relationship (``SUBSET_OF`` / ``INTERSECTS_WITH``) plus a
    justification citing the authoritative source. Empty list for
    unknown rules.
    """
    normalized = _normalize_rule_name(rule_name)
    per_rule = _CONFIG_RULE_OLIR.get(normalized)
    if per_rule is None:
        return []
    return [
        ControlMapping(
            framework="nist-800-53-rev5",
            control_id=control_id,
            relationship=relationship,
            justification=justification,
        )
        for control_id, (relationship, justification) in per_rule.items()
    ]


def map_security_hub_control_to_control_mappings(
    control_id: str,
) -> list[ControlMapping]:
    """Return OLIR-typed :class:`ControlMapping` list for a Security Hub control.

    Security Hub's 'Related requirements' field IS the authoritative
    mapping source — every returned ControlMapping uses ``SUBSET_OF``
    with a justification citing the specific FSBP/CIS control reference.
    """
    normalized = _normalize_security_hub_id(control_id)
    raw_ids = SECURITY_HUB_CONTROL_TO_CONTROLS.get(normalized)
    if raw_ids is None:
        return []
    justification = _SECURITY_HUB_OLIR_JUSTIFICATION.get(
        normalized,
        f"AWS Security Hub '{normalized}' Related requirements field.",
    )
    return [
        ControlMapping(
            framework="nist-800-53-rev5",
            control_id=cid,
            relationship=OLIRRelationship.SUBSET_OF,
            justification=justification,
        )
        for cid in raw_ids
    ]
