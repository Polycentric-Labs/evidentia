"""NIST 800-53 Rev 5 control mappings for Google Workspace findings.

Identity-system evidence maps mostly to AC + IA control families, the
same shape used by the Okta mapping table. Mirrors the OLIR-relationship
+ per-rule justification pattern used across the identity collectors.
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


# AC-2 Account Management: the Directory user inventory.
USER_INVENTORY_MAPPINGS = [
    _m(
        "AC-2",
        OLIRRelationship.SUBSET_OF,
        "AC-2 Account Management: the Directory API's users.list enumerates "
        "every Google Workspace account with its status, admin role and 2SV "
        "fields; the inventory is a direct subset of the AC-2 evidence surface.",
    ),
]

# AC-2 Account Management: inactive-account review.
INACTIVE_ACCOUNT_MAPPINGS = [
    _m(
        "AC-2",
        OLIRRelationship.SUBSET_OF,
        "AC-2 Account Management: lastLoginTime and creationTime drive the "
        "inactive-account review AC-2(3) requires before an account is "
        "disabled or removed.",
    ),
]

# AC-2 + AC-6: admin (super admin / delegated admin) account counts.
ADMIN_ACCOUNT_MAPPINGS = [
    _m(
        "AC-2",
        OLIRRelationship.SUBSET_OF,
        "AC-2 Account Management: isAdmin and isDelegatedAdmin enumerate every elevated Google Workspace account.",
    ),
    _m(
        "AC-6",
        OLIRRelationship.INTERSECTS_WITH,
        "AC-6 Least Privilege: the super admin and delegated admin counts "
        "drive the least-privilege judgement; intersects with broader "
        "access-review evidence.",
    ),
]

# IA-2 + AC-6: super admin 2-Step Verification enrollment.
ADMIN_2SV_MAPPINGS = [
    _m(
        "IA-2",
        OLIRRelationship.SUBSET_OF,
        "IA-2 Identification and Authentication: the 2-Step Verification "
        "enrollment flag (isEnrolledIn2Sv) on every super admin account is "
        "direct evidence for the multi-factor requirement on privileged "
        "accounts.",
    ),
    _m(
        "AC-6",
        OLIRRelationship.INTERSECTS_WITH,
        "AC-6 Least Privilege: a privileged account without 2-Step "
        "Verification compounds a least-privilege exposure; intersects "
        "with the admin-account finding.",
    ),
]

# IA-2: 2-Step Verification enrollment across active accounts.
TWO_SV_ENROLLMENT_MAPPINGS = [
    _m(
        "IA-2",
        OLIRRelationship.SUBSET_OF,
        "2-Step Verification enrollment across active accounts is direct "
        "evidence for the IA-2 multi-factor requirement.",
    ),
]

# AU-6 + AC-7 + SI-4: Reports API login activity.
LOGIN_ACTIVITY_MAPPINGS = [
    _m(
        "AU-6",
        OLIRRelationship.SUBSET_OF,
        "AU-6 Audit Record Review, Analysis, and Reporting: the Reports "
        "API's login activity feed is the reviewed audit trail for sign-in "
        "events.",
    ),
    _m(
        "AC-7",
        OLIRRelationship.INTERSECTS_WITH,
        "AC-7 Unsuccessful Logon Attempts: login_failure and "
        "account-disabled events intersect with the AC-7 lockout "
        "requirement.",
    ),
    _m(
        "SI-4",
        OLIRRelationship.INTERSECTS_WITH,
        "SI-4 System Monitoring: suspicious_login and the related "
        "suspicious-activity events intersect with the SI-4 requirement to "
        "monitor for anomalous activity.",
    ),
]
