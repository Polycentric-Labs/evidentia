"""NIST 800-53 Rev 5 control mappings for Okta findings.

Identity-system evidence maps mostly to AC + IA control families.
Mirrors the OLIR-relationship + per-rule justification pattern
used by the SQL-family adapters.
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


# AC-2 Account Management — user inventory + inactive accounts
USER_INVENTORY_MAPPINGS = [
    _m(
        "AC-2",
        OLIRRelationship.SUBSET_OF,
        "AC-2 Account Management — Okta /api/v1/users enumerates "
        "every user account with status (ACTIVE / SUSPENDED / "
        "DEPROVISIONED / LOCKED_OUT / etc.) + last_login. "
        "Inventory is a direct subset of the AC-2 surface.",
    ),
]


# AC-2 + AC-6 — admin / privileged role membership
PRIVILEGED_ACCOUNT_MAPPINGS = [
    _m(
        "AC-2",
        OLIRRelationship.SUBSET_OF,
        "AC-2 Account Management — admin role assignments (/api/v1/iam/assignees) enumerate elevated accounts.",
    ),
    _m(
        "AC-6",
        OLIRRelationship.INTERSECTS_WITH,
        "AC-6 Least Privilege — admin role count + breakdown "
        "drives the least-privilege judgement; intersects with "
        "broader access-review evidence.",
    ),
]


# AC-2 — inactive accounts (no login in >90 days)
INACTIVE_ACCOUNT_MAPPINGS = [
    _m(
        "AC-2",
        OLIRRelationship.SUBSET_OF,
        "AC-2 Account Management — Okta last_login timestamps "
        "drive the inactive-account review required for "
        "deprovisioning per AC-2(3).",
    ),
]


# IA-2 Identification + Authentication — MFA enforcement
MFA_MAPPINGS = [
    _m(
        "IA-2",
        OLIRRelationship.SUBSET_OF,
        "IA-2 Identification + Authentication — Okta /api/v1/users/"
        "{id}/factors enumerates enrolled MFA factors. The control "
        "requires multi-factor authentication for privileged + "
        "remote access; the collector reports per-user factor "
        "counts and aggregate MFA-enrollment rate.",
    ),
]


# IA-5 Authenticator Management — password policy
PASSWORD_POLICY_MAPPINGS = [
    _m(
        "IA-5",
        OLIRRelationship.SUBSET_OF,
        "IA-5 Authenticator Management — Okta password policies "
        "(/api/v1/policies?type=PASSWORD) enumerate min length, "
        "complexity, history, lockout, age — directly the "
        "configuration surface IA-5 requires evidence of.",
    ),
]


# AC-3 Access Enforcement — sign-on policies (adaptive MFA, IP rules)
SIGN_ON_POLICY_MAPPINGS = [
    _m(
        "AC-3",
        OLIRRelationship.SUBSET_OF,
        "AC-3 Access Enforcement — Okta sign-on policies "
        "(/api/v1/policies?type=OKTA_SIGN_ON) drive context-aware "
        "access enforcement (IP zones, network restrictions, "
        "adaptive MFA challenges).",
    ),
]


# AC-6 Least Privilege — write-priv detected (token holder has
# write capability)
WRITE_PRIV_DETECTED_MAPPINGS = [
    _m(
        "AC-6",
        OLIRRelationship.SUBSET_OF,
        "AC-6 Least Privilege — the collector's API token should "
        "be read-only (READ_ONLY_ADMIN). Detected write-capable "
        "role assignment means a least-privilege violation.",
    ),
]
