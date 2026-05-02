"""NIST 800-53 Rev 5 control mappings for PostgreSQL findings.

Each mapping carries an OLIR relationship + per-rule justification so
the audit trail can defend why a particular DB observation maps to a
particular control. Spot-checked against NIST SP 800-53 Rev 5 control
families and the specific Postgres feature's security role.
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


# AC-2 Account Management — pg_roles + pg_authid + pg_auth_members
USER_ROLE_INVENTORY_MAPPINGS = [
    _m(
        "AC-2",
        OLIRRelationship.SUBSET_OF,
        "AC-2 Account Management — pg_roles + pg_authid enumerate "
        "every account on the database; an inventory is a direct "
        "subset of the AC-2 attestation surface.",
    ),
]


# AC-3 Access Enforcement + AC-6 Least Privilege — privilege grants
PRIVILEGE_GRANT_MAPPINGS = [
    _m(
        "AC-3",
        OLIRRelationship.SUBSET_OF,
        "AC-3 Access Enforcement — INFORMATION_SCHEMA privileges + "
        "pg_class.relacl ARE the enforcement records.",
    ),
    _m(
        "AC-6",
        OLIRRelationship.INTERSECTS_WITH,
        "AC-6 Least Privilege — privilege grants enumerate who has "
        "what; intersects with AC-6 evidence but doesn't subsume the "
        "broader least-privilege analysis.",
    ),
]


# AU-2 Event Logging + AU-3 Content of Audit Records — pg_settings.log_*
AUDIT_LOG_MAPPINGS = [
    _m(
        "AU-2",
        OLIRRelationship.SUBSET_OF,
        "AU-2 Event Logging — pg_settings.log_connections / "
        "log_disconnections / log_statement enumerate which events "
        "Postgres is configured to log.",
    ),
    _m(
        "AU-3",
        OLIRRelationship.INTERSECTS_WITH,
        "AU-3 Content of Audit Records — log_line_prefix + log_* "
        "settings define what each audit record carries.",
    ),
]


# SC-12 Cryptographic Key Establishment — password_encryption + TLS settings
CRYPTO_CONFIG_MAPPINGS = [
    _m(
        "SC-12",
        OLIRRelationship.SUBSET_OF,
        "SC-12 Cryptographic Key Establishment — "
        "pg_settings.password_encryption (must be scram-sha-256 for "
        "modern hash) + ssl/TLS settings define how keys are "
        "established and used.",
    ),
]


# SC-28 Protection of Information at Rest — TLS-on-the-wire AS A PROXY
# (Postgres has no built-in TDE; encryption-at-rest is filesystem-
# level; this mapping is partial — see BLIND_SPOTS in collector.py)
ENCRYPTION_AT_REST_MAPPINGS = [
    _m(
        "SC-28",
        OLIRRelationship.RELATED_TO,
        "SC-28 Protection of Information at Rest — Postgres relies on "
        "filesystem-level encryption (LUKS, dm-crypt, AWS RDS storage "
        "encryption, etc.). This finding reports the SSL/TLS posture "
        "for in-transit protection; in-rest is documented as a "
        "BLIND_SPOT for non-RDS deployments.",
    ),
]


# AC-3 Access Enforcement — connection limits (max_connections,
# pg_hba.conf if readable)
CONNECTION_LIMIT_MAPPINGS = [
    _m(
        "AC-3",
        OLIRRelationship.INTERSECTS_WITH,
        "AC-3 Access Enforcement — max_connections + pg_hba.conf "
        "rule entries are part of access enforcement (rate-limit + "
        "host-based authentication respectively).",
    ),
]


# AC-6 Least Privilege — write-privilege probe finding
# (fired when the read-only probe detects the principal has write
# capability; we still collect read-only evidence but flag the
# violation)
WRITE_PRIV_DETECTED_MAPPINGS = [
    _m(
        "AC-6",
        OLIRRelationship.SUBSET_OF,
        "AC-6 Least Privilege — the collector's principal should be "
        "read-only. Detected write privilege means a least-privilege "
        "violation that an audit must flag.",
    ),
]
