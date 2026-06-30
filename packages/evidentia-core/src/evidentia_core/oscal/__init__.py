"""OSCAL (Open Security Controls Assessment Language) integration.

Exporters that convert Evidentia models into NIST OSCAL JSON formats,
plus a profile resolver for turning OSCAL profile + catalog pairs into
resolved baselines.

v0.7.0 adds evidence chain of custody:

- :mod:`.digest` — SHA-256 helpers for finding / file hashing
- :mod:`.signing` — GPG detached-signature support (subprocess-based)
- :mod:`.verify` — orchestrated integrity checks on signed AR documents

v0.9.6 adds :data:`OSCAL_SCHEMA_VERSION` — single source of truth for
the schema version emitted in all OSCAL output (catalog / profile /
assessment-results / plan-of-action-and-milestones / SSP). Bumping
this constant + the assessment-results observation type rename
(handled inline in :mod:`.exporter`) is sufficient to migrate
between adjacent OSCAL minor versions.
"""

from evidentia_core.oscal._version import OSCAL_SCHEMA_VERSION
from evidentia_core.oscal.digest import (
    DIGEST_ALGO,
    digest_bytes,
    digest_file,
    digest_json,
    digest_model,
    format_digest,
    parse_digest,
)
from evidentia_core.oscal.digest import (
    verify_bytes as verify_digest_bytes,
)
from evidentia_core.oscal.digest import (
    verify_file as verify_digest_file,
)
from evidentia_core.oscal.exporter import (
    EVIDENTIA_OSCAL_NS,
    gap_report_to_oscal_ar,
)
from evidentia_core.oscal.keysign import (
    DSSEVerifyResult,
    KeySignError,
    SigningKeyError,
    UnsupportedKeyError,
    VerifyKeyError,
    sign_oscal_file,
    verify_oscal_file,
)
from evidentia_core.oscal.profile import (
    ProfileResolutionError,
    catalog_to_oscal_json,
    resolve_profile,
)
from evidentia_core.oscal.signing import (
    GPGError,
    GPGNotAvailableError,
    GPGSigningError,
    GPGVerifyError,
    VerifyResult,
    gpg_available,
    sign_file,
)
from evidentia_core.oscal.signing import (
    verify_file as gpg_verify_file,
)
from evidentia_core.oscal.sigstore import (
    SigstoreAirGapError,
    SigstoreError,
    SigstoreNotAvailableError,
    SigstoreSigningError,
    SigstoreVerifyError,
    SigstoreVerifyResult,
    sigstore_available,
)
from evidentia_core.oscal.sigstore import (
    sign_file as sigstore_sign_file,
)
from evidentia_core.oscal.sigstore import (
    verify_file as sigstore_verify_file,
)
from evidentia_core.oscal.verify import (
    DigestCheck,
    VerifyReport,
    verify_ar_file,
    verify_digests,
)

__all__ = [
    "DIGEST_ALGO",
    "EVIDENTIA_OSCAL_NS",
    "OSCAL_SCHEMA_VERSION",
    "DSSEVerifyResult",
    "DigestCheck",
    "GPGError",
    "GPGNotAvailableError",
    "GPGSigningError",
    "GPGVerifyError",
    "KeySignError",
    "ProfileResolutionError",
    "SigningKeyError",
    "SigstoreAirGapError",
    "SigstoreError",
    "SigstoreNotAvailableError",
    "SigstoreSigningError",
    "SigstoreVerifyError",
    "SigstoreVerifyResult",
    "UnsupportedKeyError",
    "VerifyKeyError",
    "VerifyReport",
    "VerifyResult",
    "catalog_to_oscal_json",
    "digest_bytes",
    "digest_file",
    "digest_json",
    "digest_model",
    "format_digest",
    "gap_report_to_oscal_ar",
    "gpg_available",
    "gpg_verify_file",
    "parse_digest",
    "resolve_profile",
    "sign_file",
    "sign_oscal_file",
    "sigstore_available",
    "sigstore_sign_file",
    "sigstore_verify_file",
    "verify_ar_file",
    "verify_digest_bytes",
    "verify_digest_file",
    "verify_digests",
    "verify_oscal_file",
]
