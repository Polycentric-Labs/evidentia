"""NIST 800-53 Rev 5 control mappings for MySQL / MariaDB findings.

Mirrors the postgres mapping module structure. Per-rule justifications
spot-checked against MySQL 8.0 and MariaDB 10.x security feature
references.
"""

from __future__ import annotations

from evidentia_core.models.common import ControlMapping, OLIRRelationship


def _m(
    control_id: str,
    relationship: OLIRRelationship,
    justification: str,
) -> ControlMapping:
    return ControlMapping(
        framework="nist-800-53-rev5",
        control_id=control_id,
        relationship=relationship,
        justification=justification,
    )


# AC-2 Account Management — mysql.user + role_edges
USER_ROLE_INVENTORY_MAPPINGS = [
    _m(
        "AC-2",
        OLIRRelationship.SUBSET_OF,
        "AC-2 Account Management — mysql.user + mysql.role_edges (8.0+) "
        "enumerate every account on the server; the inventory is a "
        "direct subset of the AC-2 attestation surface.",
    ),
]


# AC-3 Access Enforcement + AC-6 Least Privilege — privilege grants
PRIVILEGE_GRANT_MAPPINGS = [
    _m(
        "AC-3",
        OLIRRelationship.SUBSET_OF,
        "AC-3 Access Enforcement — INFORMATION_SCHEMA.{USER,SCHEMA,TABLE}_PRIVILEGES "
        "ARE the enforcement records.",
    ),
    _m(
        "AC-6",
        OLIRRelationship.INTERSECTS_WITH,
        "AC-6 Least Privilege — privilege grants enumerate who has "
        "what; intersects with AC-6 evidence.",
    ),
]


# AU-2 Event Logging + AU-3 Content of Audit Records
AUDIT_LOG_MAPPINGS = [
    _m(
        "AU-2",
        OLIRRelationship.SUBSET_OF,
        "AU-2 Event Logging — general_log + audit_log_* (Enterprise / "
        "Percona Audit / MariaDB Audit) enumerate which events MySQL "
        "is configured to log.",
    ),
    _m(
        "AU-3",
        OLIRRelationship.INTERSECTS_WITH,
        "AU-3 Content of Audit Records — log file format settings "
        "define the content of each audit record.",
    ),
]


# SC-12 Cryptographic Key Establishment — TLS + require_secure_transport
CRYPTO_CONFIG_MAPPINGS = [
    _m(
        "SC-12",
        OLIRRelationship.SUBSET_OF,
        "SC-12 Cryptographic Key Establishment — have_ssl + ssl_* + "
        "require_secure_transport variables define how TLS keys are "
        "established and enforced.",
    ),
]


# SC-28 Protection of Information at Rest — InnoDB tablespace
# encryption + keyring plugin
ENCRYPTION_AT_REST_MAPPINGS = [
    _m(
        "SC-28",
        OLIRRelationship.SUBSET_OF,
        "SC-28 Protection of Information at Rest — innodb_encrypt_tables "
        "+ keyring_* plugin status describe the in-rest encryption "
        "posture for InnoDB tablespaces.",
    ),
]


# AC-3 Access Enforcement — connection limits
CONNECTION_LIMIT_MAPPINGS = [
    _m(
        "AC-3",
        OLIRRelationship.INTERSECTS_WITH,
        "AC-3 Access Enforcement — max_connections + max_user_connections "
        "rate-limit access at the server boundary.",
    ),
]


# AC-6 Least Privilege — write-privilege probe finding
WRITE_PRIV_DETECTED_MAPPINGS = [
    _m(
        "AC-6",
        OLIRRelationship.SUBSET_OF,
        "AC-6 Least Privilege — the collector's principal should be "
        "read-only. Detected write privilege means a least-privilege "
        "violation that an audit must flag.",
    ),
]
