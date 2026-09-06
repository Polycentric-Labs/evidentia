"""NIST 800-53 Rev 5 control mappings for MS SQL Server findings.

Mirrors the postgres/mysql mapping pattern. SQL Server has the
benefit of built-in TDE (Transparent Data Encryption) so the SC-28
mapping is SUBSET_OF rather than RELATED_TO.
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


# AC-2 Account Management — sys.server_principals + sys.database_principals
USER_ROLE_INVENTORY_MAPPINGS = [
    _m(
        "AC-2",
        OLIRRelationship.SUBSET_OF,
        "AC-2 Account Management — sys.server_principals + "
        "sys.database_principals enumerate every server- and "
        "database-level identity. Inventory is a direct subset of "
        "the AC-2 attestation surface.",
    ),
]


# AC-3 Access Enforcement + AC-6 Least Privilege — privilege grants
PRIVILEGE_GRANT_MAPPINGS = [
    _m(
        "AC-3",
        OLIRRelationship.SUBSET_OF,
        "AC-3 Access Enforcement — sys.server_permissions + sys.database_permissions ARE the enforcement records.",
    ),
    _m(
        "AC-6",
        OLIRRelationship.INTERSECTS_WITH,
        "AC-6 Least Privilege — IS_SRVROLEMEMBER('sysadmin') / "
        "IS_ROLEMEMBER('db_owner') drive the least-privilege "
        "judgement; intersects with broader least-privilege analysis.",
    ),
]


# AU-2 Event Logging + AU-3 Content of Audit Records — sys.server_audits
AUDIT_LOG_MAPPINGS = [
    _m(
        "AU-2",
        OLIRRelationship.SUBSET_OF,
        "AU-2 Event Logging — sys.server_audits enumerates every "
        "configured audit; sys.dm_server_audit_status reports the "
        "running state.",
    ),
    _m(
        "AU-3",
        OLIRRelationship.INTERSECTS_WITH,
        "AU-3 Content of Audit Records — server-audit specifications "
        "(sys.server_audit_specifications) drive what events each "
        "audit captures.",
    ),
]


# SC-12 Cryptographic Key Establishment — TLS / ALPN
CRYPTO_CONFIG_MAPPINGS = [
    _m(
        "SC-12",
        OLIRRelationship.SUBSET_OF,
        "SC-12 Cryptographic Key Establishment — connection_property "
        "ENCRYPT_OPTION + cipher_suite enumerate how the connection "
        "key was established.",
    ),
]


# SC-28 Protection of Information at Rest — Transparent Data Encryption
ENCRYPTION_AT_REST_MAPPINGS = [
    _m(
        "SC-28",
        OLIRRelationship.SUBSET_OF,
        "SC-28 Protection of Information at Rest — "
        "sys.dm_database_encryption_keys.encryption_state directly "
        "reports the TDE state per database (3 = encrypted). Modern "
        "SQL Server has Always Encrypted as a column-level "
        "complement.",
    ),
]


# AC-3 Access Enforcement — connection limits / login restrictions
CONNECTION_LIMIT_MAPPINGS = [
    _m(
        "AC-3",
        OLIRRelationship.INTERSECTS_WITH,
        "AC-3 Access Enforcement — server-level user_connections "
        "limit + login auditing mode are part of access enforcement.",
    ),
]


# AC-6 Least Privilege — write-privilege probe finding
WRITE_PRIV_DETECTED_MAPPINGS = [
    _m(
        "AC-6",
        OLIRRelationship.SUBSET_OF,
        "AC-6 Least Privilege — the collector's principal should be "
        "read-only. sysadmin / db_owner / db_datawriter membership "
        "means a least-privilege violation.",
    ),
]
