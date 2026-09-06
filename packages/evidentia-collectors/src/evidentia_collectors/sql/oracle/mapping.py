"""NIST 800-53 Rev 5 control mappings for Oracle Database findings.

Oracle's mapping surface is the largest of the SQL-family adapters
because it adds IA-5 (password policy via DBA_PROFILES) on top of
the AC / AU / SC family the other adapters touch.
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


# AC-2 Account Management — DBA_USERS + DBA_ROLES
USER_ROLE_INVENTORY_MAPPINGS = [
    _m(
        "AC-2",
        OLIRRelationship.SUBSET_OF,
        "AC-2 Account Management — DBA_USERS + DBA_ROLES enumerate "
        "every account + role; an inventory is a direct subset of "
        "the AC-2 attestation surface.",
    ),
]


# AC-3 Access Enforcement + AC-6 Least Privilege — DBA_SYS_PRIVS,
# DBA_ROLE_PRIVS, DBA_TAB_PRIVS
PRIVILEGE_GRANT_MAPPINGS = [
    _m(
        "AC-3",
        OLIRRelationship.SUBSET_OF,
        "AC-3 Access Enforcement — DBA_SYS_PRIVS / DBA_TAB_PRIVS / DBA_ROLE_PRIVS ARE the enforcement records.",
    ),
    _m(
        "AC-6",
        OLIRRelationship.INTERSECTS_WITH,
        "AC-6 Least Privilege — DBA role membership + ANY-table "
        "grants enumerate who has elevated privilege; intersects "
        "with broader least-privilege analysis.",
    ),
]


# AU-2 Event Logging + AU-3 Content of Audit Records — Unified Audit
# (12c+) or traditional DBA_AUDIT_TRAIL
AUDIT_LOG_MAPPINGS = [
    _m(
        "AU-2",
        OLIRRelationship.SUBSET_OF,
        "AU-2 Event Logging — AUDIT_UNIFIED_ENABLED_POLICIES (12c+) "
        "or audit_trail parameter + DBA_AUDIT_TRAIL (legacy) "
        "enumerate which events Oracle is configured to log.",
    ),
    _m(
        "AU-3",
        OLIRRelationship.INTERSECTS_WITH,
        "AU-3 Content of Audit Records — Unified Audit policy definitions drive what each record contains.",
    ),
]


# IA-5 Authenticator Management — DBA_PROFILES password resources
PASSWORD_POLICY_MAPPINGS = [
    _m(
        "IA-5",
        OLIRRelationship.SUBSET_OF,
        "IA-5 Authenticator Management — DBA_PROFILES password "
        "resources (PASSWORD_LIFE_TIME, FAILED_LOGIN_ATTEMPTS, "
        "PASSWORD_REUSE_TIME, PASSWORD_VERIFY_FUNCTION) ARE the "
        "configuration record for password policy.",
    ),
]


# SC-12 Cryptographic Key Establishment — sqlnet.encryption_server
CRYPTO_CONFIG_MAPPINGS = [
    _m(
        "SC-12",
        OLIRRelationship.SUBSET_OF,
        "SC-12 Cryptographic Key Establishment — "
        "sqlnet.encryption_server / sqlnet.encryption_types_server "
        "parameters drive how connection-level keys are established.",
    ),
]


# SC-28 Protection of Information at Rest — TDE wallet + tablespace
# encryption (Oracle Advanced Security Option, separately licensed)
ENCRYPTION_AT_REST_MAPPINGS = [
    _m(
        "SC-28",
        OLIRRelationship.SUBSET_OF,
        "SC-28 Protection of Information at Rest — V$ENCRYPTION_WALLET "
        "+ DBA_TABLESPACES.ENCRYPTED report the TDE state. Note: "
        "TDE requires Oracle Advanced Security Option licensing "
        "(documented in BLIND_SPOTS).",
    ),
]


# AC-3 Access Enforcement — connection / session limits
CONNECTION_LIMIT_MAPPINGS = [
    _m(
        "AC-3",
        OLIRRelationship.INTERSECTS_WITH,
        "AC-3 Access Enforcement — sessions / processes parameters "
        "+ DBA_PROFILES SESSIONS_PER_USER provide rate-limit + "
        "concurrent-session evidence.",
    ),
]


# AC-6 Least Privilege — write-privilege probe finding
WRITE_PRIV_DETECTED_MAPPINGS = [
    _m(
        "AC-6",
        OLIRRelationship.SUBSET_OF,
        "AC-6 Least Privilege — DBA role membership / SYSDBA / "
        "ANY-table grants violate the read-only principal contract.",
    ),
]
