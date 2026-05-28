"""GitHub-collector populate helpers for the OSPS Baseline.

This module ships ~15 ``populate_osps_*`` helpers, one per automatable
OSPS Baseline control that GitHub's REST API can observe directly. Each
helper takes a :class:`GitHubClient` plus ``(owner, repo)`` and returns
a single :class:`SecurityFinding` carrying:

- ``compliance_status``: PASS / FAIL / WARNING / NOT_APPLICABLE / UNKNOWN
  per the v0.10.0 OCSF-alignment contract.
- ``control_mappings``: one :class:`ControlMapping` against
  ``framework="osps-baseline"`` plus (where natural) one or more
  cross-walk mappings against NIST SP 800-53 Rev 5 control families.
- ``source_finding_id``: deterministic
  ``osps-<id>:<owner>/<repo>[:<scope>]`` pattern, which lets the
  v0.10.5 P10 :class:`SecurityFinding._derive_deterministic_id`
  validator derive a stable UUID5 ``id`` across re-runs.

Coverage as of v0.10.6 (16 controls):

- **Access Control**: ``OSPS-AC-03.01`` (default-branch protection),
  ``OSPS-AC-03.02`` (deletion guard).
- **Build & Release**: ``OSPS-BR-06.01`` (release signatures /
  attestations on release assets).
- **Documentation**: ``OSPS-DO-02.01`` (defect-reporting mechanism
  via ``has_issues``).
- **Governance**: ``OSPS-GV-03.01`` (CONTRIBUTING guide).
- **Legal**: ``OSPS-LE-02.01`` (OSI/FSF-recognized license),
  ``OSPS-LE-03.01`` (LICENSE in well-known location).
- **Quality**: ``OSPS-QA-01.01`` + ``OSPS-QA-01.02`` (public source +
  public change history), ``OSPS-QA-02.01`` (dependency manifest),
  ``OSPS-QA-03.01`` (required status checks).
- **Vulnerability Management**: ``OSPS-VM-02.01`` (SECURITY.md),
  ``OSPS-VM-03.01`` (private-vulnerability-reporting),
  ``OSPS-VM-04.01`` (security-advisories surface),
  ``OSPS-VM-05.03`` (Dependabot SCA active),
  ``OSPS-VM-06.02`` (code-scanning / SAST active).

**OSPS-VM-05 overlap with dependabot.py.** This module's
``populate_osps_vm_05_03`` emits a **posture finding** (the control
itself is in place, observable via the ``vulnerability-alerts``
endpoint). It is intentionally complementary to the existing
:class:`~evidentia_collectors.github.dependabot.DependabotCollector`,
which emits one finding per CVE alert (the underlying advisories). The
two are emitted at different granularities, both with valid
:class:`ComplianceStatus` against different OSPS bands —
``populate_osps_vm_05_03`` against OSPS-VM-05 (the control), and
``DependabotCollector`` against the per-CVE evidence chain (mapped to
SI-2 / RA-5 / SR-3 etc.). Neither subsumes the other; they are wired
side-by-side in any future composite collector.

**Error handling contract.** Helpers wrap their GitHub calls in
``try/except GitHubApiError`` blocks. A transport or 5xx failure on the
inner call returns a finding with
:class:`ComplianceStatus.UNKNOWN` — operators get a complete run with
the indeterminate items flagged, rather than an aborted run with no
evidence. Endpoint-specific 404s (e.g., branch-not-protected) are
**signal**, not errors, and the underlying ``GitHubClient`` methods
already return ``None`` / empty list in those cases.
"""

from __future__ import annotations

import logging
from typing import Any

from evidentia_core.audit.provenance import CollectionContext
from evidentia_core.models.common import (
    ControlMapping,
    OLIRRelationship,
    Severity,
    current_version,
    new_id,
)
from evidentia_core.models.finding import (
    ComplianceStatus,
    FindingStatus,
    SecurityFinding,
)

from evidentia_collectors.github.client import (
    GitHubApiError,
    GitHubClient,
)

_log = logging.getLogger(__name__)

COLLECTOR_ID = "github-osps"

# ─── OSI / FSF SPDX allow-list (subset of widely recognized) ───────────
#
# Per OSPS-LE-02.01 the license MUST meet the OSI Open Source Definition
# or the FSF Free Software Definition. We use a conservative allow-list
# of SPDX identifiers below — every entry here is on BOTH the OSI
# approved list and the FSF Free/libre list at the v0.10.6 ship date.
# An unknown SPDX id is mapped to ComplianceStatus.WARNING (rather than
# FAIL): the upstream catalog list is large and evolves, so a manual
# review is the honest verdict on the unrecognized case.
_OSI_FSF_RECOGNIZED_SPDX: frozenset[str] = frozenset(
    {
        "Apache-2.0",
        "MIT",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BSD-3-Clause-Clear",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "MPL-2.0",
        "EPL-2.0",
        "ISC",
        "Unlicense",
        "CC0-1.0",
        "Zlib",
        "Artistic-2.0",
        "BSL-1.0",
        # GitHub's `license.spdx_id` for "Apache-2.0" sometimes returns
        # the short "apache-2.0" form; the comparison below is case-
        # insensitive but we also normalize via .upper() in the helper.
    }
)


# ─── Coverage registry ────────────────────────────────────────────────


#: Maps OSPS control id → the populate helper that emits its finding.
#: Tests assert this stays in sync with the actual helpers; consumers
#: can iterate the table to enumerate the v0.10.6 OSPS surface.
OSPS_COVERAGE: dict[str, str] = {
    "OSPS-AC-03.01": "populate_osps_ac_03_01",
    "OSPS-AC-03.02": "populate_osps_ac_03_02",
    "OSPS-BR-06.01": "populate_osps_br_06_01",
    "OSPS-DO-02.01": "populate_osps_do_02_01",
    "OSPS-GV-03.01": "populate_osps_gv_03_01",
    "OSPS-LE-02.01": "populate_osps_le_02_01",
    "OSPS-LE-03.01": "populate_osps_le_03_01",
    "OSPS-QA-01.01": "populate_osps_qa_01_01",
    "OSPS-QA-01.02": "populate_osps_qa_01_02",
    "OSPS-QA-02.01": "populate_osps_qa_02_01",
    "OSPS-QA-03.01": "populate_osps_qa_03_01",
    "OSPS-VM-02.01": "populate_osps_vm_02_01",
    "OSPS-VM-03.01": "populate_osps_vm_03_01",
    "OSPS-VM-04.01": "populate_osps_vm_04_01",
    "OSPS-VM-05.03": "populate_osps_vm_05_03",
    "OSPS-VM-06.02": "populate_osps_vm_06_02",
}


# ─── Common building blocks ───────────────────────────────────────────


def _osps_mapping(
    control_id: str,
    justification: str,
    relationship: OLIRRelationship = OLIRRelationship.SUBSET_OF,
) -> ControlMapping:
    """Build a ControlMapping pointing at the OSPS Baseline catalog."""
    return ControlMapping(
        framework="osps-baseline",
        control_id=control_id,
        relationship=relationship,
        justification=justification,
    )


def _nist_53_mapping(
    control_id: str,
    justification: str,
    relationship: OLIRRelationship = OLIRRelationship.INTERSECTS_WITH,
) -> ControlMapping:
    """Build a NIST SP 800-53 Rev 5 cross-walk mapping."""
    return ControlMapping(
        framework="nist-800-53-rev5",
        control_id=control_id,
        relationship=relationship,
        justification=justification,
    )


def _build_context(owner: str, repo: str) -> CollectionContext:
    """Synthesize a CollectionContext for an OSPS-helper invocation."""
    slug = f"{owner}/{repo}"
    return CollectionContext(
        collector_id=COLLECTOR_ID,
        collector_version=current_version(),
        run_id=new_id(),
        credential_identity=f"github-token:scope:{slug}",
        source_system_id=f"github:{slug}",
        filter_applied={"repo": slug, "framework": "osps-baseline"},
    )


def _severity_for(status: ComplianceStatus) -> Severity:
    """Pick a sensible Severity per compliance status.

    PASS / NOT_APPLICABLE → INFORMATIONAL (the control is satisfied or
    doesn't apply; no operator action). FAIL → MEDIUM (the operator
    needs to act, but OSPS-Baseline-M1 controls are the floor, not the
    ceiling — HIGH is reserved for evidence-of-exposure findings).
    WARNING → LOW. UNKNOWN → LOW (the run is incomplete on this axis;
    the operator should re-attempt with sufficient API permissions).
    """
    if status is ComplianceStatus.PASS:
        return Severity.INFORMATIONAL
    if status is ComplianceStatus.NOT_APPLICABLE:
        return Severity.INFORMATIONAL
    if status is ComplianceStatus.FAIL:
        return Severity.MEDIUM
    return Severity.LOW


def _make_finding(
    *,
    owner: str,
    repo: str,
    control_id: str,
    scope: str | None,
    title: str,
    description: str,
    status: ComplianceStatus,
    mappings: list[ControlMapping],
    raw: Any | None = None,
    remediation: str | None = None,
) -> SecurityFinding:
    """Assemble a SecurityFinding with the OSPS-helper conventions."""
    slug = f"{owner}/{repo}"
    suffix = f":{scope}" if scope else ""
    finding_status = (
        FindingStatus.RESOLVED
        if status is ComplianceStatus.PASS
        or status is ComplianceStatus.NOT_APPLICABLE
        else FindingStatus.ACTIVE
    )
    return SecurityFinding(
        title=title[:200],
        description=description[:2000],
        severity=_severity_for(status),
        status=finding_status,
        compliance_status=status,
        remediation=remediation,
        source_system="github",
        source_finding_id=f"{control_id.lower()}:{slug}{suffix}",
        resource_type="GitHub::Repository",
        resource_id=slug,
        control_mappings=mappings,
        collection_context=_build_context(owner, repo),
        raw_data=raw,
    )


def _unknown_finding(
    *,
    owner: str,
    repo: str,
    control_id: str,
    reason: str,
    error: BaseException,
    justification: str,
    scope: str | None = None,
) -> SecurityFinding:
    """Assemble the ``ComplianceStatus.UNKNOWN`` "indeterminate" finding.

    Centralizes the ~identical UNKNOWN-branch boilerplate that every
    ``populate_osps_*`` helper emits when a GitHub call fails: a transport
    or 5xx error means "we don't know", not PASS and not FAIL (see the
    module-docstring error-handling contract).

    Field derivation matches the prior inline construction exactly:

    - ``title`` → ``"{control_id} indeterminate for {owner}/{repo}"``,
      with an ``"@{scope}"`` suffix appended iff ``scope`` is set (the
      branch-scoped probes carry the default branch; repo-level probes
      pass ``scope=None``).
    - ``description`` → ``"{reason}: {error}"`` — ``reason`` is the
      per-callsite diagnostic prefix (e.g. ``"Branch-protection probe
      failed"``) and ``error`` is the caught exception, whose ``str``
      carries the ``[HTTP <code>] ...`` detail.
    - one OSPS-Baseline :class:`ControlMapping` carrying the per-callsite
      ``justification`` under the ``RELATED_TO`` relationship (the
      indeterminate verdict is a weaker claim than a SUBSET_OF mapping).

    ``reason`` and ``justification`` are passed per callsite rather than
    derived so the distinct diagnostic strings the helpers use are
    preserved verbatim — flattening them would lose operator signal.
    """
    suffix = f"@{scope}" if scope else ""
    return _make_finding(
        owner=owner,
        repo=repo,
        control_id=control_id,
        scope=scope,
        title=f"{control_id} indeterminate for {owner}/{repo}{suffix}",
        description=f"{reason}: {error}",
        status=ComplianceStatus.UNKNOWN,
        mappings=[
            _osps_mapping(
                control_id,
                justification,
                relationship=OLIRRelationship.RELATED_TO,
            ),
        ],
    )


def _file_present_at_any(
    client: GitHubClient,
    owner: str,
    repo: str,
    candidate_paths: tuple[str, ...],
) -> str | None:
    """Return the first ``candidate_paths`` entry the repo contains.

    Tries each path via :meth:`GitHubClient.get_contents`. Any
    :class:`GitHubApiError` from an individual probe is swallowed
    (treat as "not at this path"); callers that want the
    "indeterminate" outcome should call ``get_contents`` directly.
    """
    for path in candidate_paths:
        try:
            result = client.get_contents(owner, repo, path)
        except GitHubApiError:
            continue
        if result is not None:
            return path
    return None


# ─── Helpers ───────────────────────────────────────────────────────────


def populate_osps_ac_03_01(
    client: GitHubClient, owner: str, repo: str
) -> SecurityFinding:
    """OSPS-AC-03.01 — Prevent direct modification of the primary branch.

    PASS iff the default branch has any branch-protection rule in place
    (presence of the protection object is the OSPS-AC-03.01 evidence —
    GitHub's response is non-empty when *any* protection rule exists).
    FAIL iff the protection object is absent (404 → ``None``).
    UNKNOWN if the API call fails.
    """
    try:
        repo_meta = client.get_repo(owner, repo)
    except GitHubApiError as e:
        return _unknown_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-AC-03.01",
            reason="Could not read repo metadata",
            error=e,
            justification=(
                "Default-branch protection cannot be evaluated — "
                "repo metadata read failed."
            ),
        )

    default_branch = str(repo_meta.get("default_branch") or "main")

    try:
        protection = client.get_branch_protection(owner, repo, default_branch)
    except GitHubApiError as e:
        return _unknown_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-AC-03.01",
            scope=default_branch,
            reason="Branch-protection probe failed",
            error=e,
            justification="Branch-protection state could not be read.",
        )

    if protection is None:
        return _make_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-AC-03.01",
            scope=default_branch,
            title=(
                f"OSPS-AC-03.01 FAIL: {default_branch!r} unprotected in "
                f"{owner}/{repo}"
            ),
            description=(
                "OSPS-AC-03.01 requires an enforcement mechanism that "
                "prevents direct modification of the primary branch. "
                "GitHub returned 404 on the branch-protection endpoint, "
                "indicating no protection rules are in place."
            ),
            status=ComplianceStatus.FAIL,
            mappings=[
                _osps_mapping(
                    "OSPS-AC-03.01",
                    "Primary branch lacks any GitHub branch-protection "
                    "rule, violating the OSPS-AC-03.01 evidence requirement.",
                ),
                _nist_53_mapping(
                    "AC-3",
                    "Branch-protection rules ARE the AC-3 Access "
                    "Enforcement mechanism on the source-of-truth.",
                    relationship=OLIRRelationship.SUBSET_OF,
                ),
                _nist_53_mapping(
                    "CM-3",
                    "Unprotected branch bypasses change-control review.",
                    relationship=OLIRRelationship.SUBSET_OF,
                ),
            ],
            remediation=(
                "Enable branch protection on the default branch at "
                "https://github.com/"
                f"{owner}/{repo}/settings/branches"
            ),
        )

    return _make_finding(
        owner=owner,
        repo=repo,
        control_id="OSPS-AC-03.01",
        scope=default_branch,
        title=(
            f"OSPS-AC-03.01 PASS: {default_branch!r} protected in "
            f"{owner}/{repo}"
        ),
        description=(
            f"Branch protection is configured on the default branch "
            f"{default_branch!r}. OSPS-AC-03.01 evidence is satisfied; "
            "review the specific rules separately."
        ),
        status=ComplianceStatus.PASS,
        mappings=[
            _osps_mapping(
                "OSPS-AC-03.01",
                "Branch-protection presence verified on the default "
                "branch via the GitHub REST API.",
            ),
            _nist_53_mapping(
                "AC-3",
                "AC-3 Access Enforcement satisfied via branch-protection.",
                relationship=OLIRRelationship.SUBSET_OF,
            ),
        ],
        raw={"default_branch": default_branch, "protection_keys": sorted(protection.keys())},
    )


def populate_osps_ac_03_02(
    client: GitHubClient, owner: str, repo: str
) -> SecurityFinding:
    """OSPS-AC-03.02 — Branch deletion requires explicit intent.

    PASS iff branch protection exists AND ``allow_deletions.enabled`` is
    falsy (deletion is gated). FAIL if protection is missing or deletion
    is explicitly enabled.
    """
    try:
        repo_meta = client.get_repo(owner, repo)
    except GitHubApiError as e:
        return _unknown_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-AC-03.02",
            reason="Could not read repo metadata",
            error=e,
            justification="Repo metadata read failed.",
        )

    default_branch = str(repo_meta.get("default_branch") or "main")

    try:
        protection = client.get_branch_protection(owner, repo, default_branch)
    except GitHubApiError as e:
        return _unknown_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-AC-03.02",
            scope=default_branch,
            reason="Branch-protection probe failed",
            error=e,
            justification="Branch-protection state could not be read.",
        )

    if protection is None:
        return _make_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-AC-03.02",
            scope=default_branch,
            title=(
                f"OSPS-AC-03.02 FAIL: {default_branch!r} unprotected — "
                f"deletion guard absent in {owner}/{repo}"
            ),
            description=(
                "OSPS-AC-03.02 requires the VCS to treat primary-branch "
                "deletion as a sensitive action. With no branch "
                "protection, the deletion guard is absent."
            ),
            status=ComplianceStatus.FAIL,
            mappings=[
                _osps_mapping(
                    "OSPS-AC-03.02",
                    "Primary branch lacks protection; deletion is not "
                    "guarded.",
                ),
            ],
        )

    allow_deletions = (protection.get("allow_deletions") or {})
    deletion_enabled = bool(allow_deletions.get("enabled", False))
    status = (
        ComplianceStatus.PASS if not deletion_enabled else ComplianceStatus.FAIL
    )
    title_verb = "PASS" if status is ComplianceStatus.PASS else "FAIL"
    return _make_finding(
        owner=owner,
        repo=repo,
        control_id="OSPS-AC-03.02",
        scope=default_branch,
        title=(
            f"OSPS-AC-03.02 {title_verb}: deletion-guard on "
            f"{owner}/{repo}@{default_branch}"
        ),
        description=(
            f"allow_deletions.enabled = {deletion_enabled!r}. "
            f"OSPS-AC-03.02 evidence is {'satisfied' if status is ComplianceStatus.PASS else 'NOT satisfied'}."
        ),
        status=status,
        mappings=[
            _osps_mapping(
                "OSPS-AC-03.02",
                "Branch-protection.allow_deletions inspected.",
            ),
        ],
        raw={"allow_deletions": deletion_enabled},
    )


def populate_osps_br_06_01(
    client: GitHubClient, owner: str, repo: str
) -> SecurityFinding:
    """OSPS-BR-06.01 — Releases signed or attested.

    PASS iff at least one release has an asset whose name carries a
    signature/attestation extension (``.sig``, ``.asc``, ``.intoto``,
    ``.intoto.jsonl``, ``.sigstore``, ``.cdx.json`` with attestation
    suffix, etc.). FAIL if releases exist but none are signed.
    NOT_APPLICABLE if no releases have been cut yet.
    """
    try:
        releases = client.list_releases(owner, repo)
    except GitHubApiError as e:
        return _unknown_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-BR-06.01",
            reason="Releases API call failed",
            error=e,
            justification="Could not enumerate releases.",
        )

    if not releases:
        return _make_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-BR-06.01",
            scope=None,
            title=f"OSPS-BR-06.01 NOT_APPLICABLE: {owner}/{repo} has no releases",
            description=(
                "OSPS-BR-06.01 evaluates the signing posture of official "
                "releases. The repo has zero releases — the control does "
                "not yet apply. Re-evaluate after the first tagged release."
            ),
            status=ComplianceStatus.NOT_APPLICABLE,
            mappings=[
                _osps_mapping(
                    "OSPS-BR-06.01",
                    "No official releases yet — control inapplicable.",
                    relationship=OLIRRelationship.RELATED_TO,
                ),
            ],
        )

    sig_extensions = (
        ".sig",
        ".asc",
        ".sigstore",
        ".intoto",
        ".intoto.jsonl",
        ".pem",
        ".bundle",
        ".attestation",
    )
    signed_tags: list[str] = []
    for release in releases:
        assets = release.get("assets") or []
        if not isinstance(assets, list):
            continue
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            name = str(asset.get("name") or "").lower()
            if any(name.endswith(ext) for ext in sig_extensions):
                signed_tags.append(str(release.get("tag_name") or ""))
                break

    if signed_tags:
        return _make_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-BR-06.01",
            scope=None,
            title=(
                f"OSPS-BR-06.01 PASS: signed/attested release assets in "
                f"{owner}/{repo}"
            ),
            description=(
                f"{len(signed_tags)} of {len(releases)} recent releases "
                "carry signature or attestation assets (.sig / .asc / "
                ".intoto / .sigstore / .bundle). OSPS-BR-06.01 evidence "
                "is satisfied for those releases."
            ),
            status=ComplianceStatus.PASS,
            mappings=[
                _osps_mapping(
                    "OSPS-BR-06.01",
                    "Release assets carry cryptographic signatures or "
                    "attestations.",
                ),
                _nist_53_mapping(
                    "SI-7",
                    "SI-7 Software, Firmware, and Information Integrity "
                    "— signed releases evidence integrity verification.",
                    relationship=OLIRRelationship.INTERSECTS_WITH,
                ),
            ],
            raw={"signed_tags": signed_tags[:10], "release_count": len(releases)},
        )

    return _make_finding(
        owner=owner,
        repo=repo,
        control_id="OSPS-BR-06.01",
        scope=None,
        title=(
            f"OSPS-BR-06.01 FAIL: no signed release assets in {owner}/{repo}"
        ),
        description=(
            f"Inspected {len(releases)} releases; none carry a signature "
            "or attestation asset extension (.sig / .asc / .intoto / "
            ".sigstore). OSPS-BR-06.01 requires releases to be signed "
            "or accounted for in a signed manifest."
        ),
        status=ComplianceStatus.FAIL,
        mappings=[
            _osps_mapping(
                "OSPS-BR-06.01",
                "No signature / attestation assets attached to any "
                "release.",
            ),
        ],
        remediation=(
            "Add Sigstore signatures, GPG signatures, or SLSA "
            "provenance attestations to release assets. See "
            "docs/verification.md (OSPS-DO-03)."
        ),
    )


def populate_osps_do_02_01(
    client: GitHubClient, owner: str, repo: str
) -> SecurityFinding:
    """OSPS-DO-02.01 — Defect-reporting mechanism documented/available.

    PASS iff ``has_issues=true`` on the repo metadata (GitHub Issues is
    the OSPS-recommended default defect tracker). FAIL otherwise.
    A future cycle could refine PASS by also checking for an explicit
    SUPPORT.md / ISSUE_TEMPLATE; this v0.10.6 helper sticks to the
    binary signal.
    """
    try:
        repo_meta = client.get_repo(owner, repo)
    except GitHubApiError as e:
        return _unknown_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-DO-02.01",
            reason="Repo metadata probe failed",
            error=e,
            justification="Could not read repo metadata.",
        )

    has_issues = bool(repo_meta.get("has_issues", False))
    status = ComplianceStatus.PASS if has_issues else ComplianceStatus.FAIL
    verb = "PASS" if has_issues else "FAIL"
    return _make_finding(
        owner=owner,
        repo=repo,
        control_id="OSPS-DO-02.01",
        scope=None,
        title=f"OSPS-DO-02.01 {verb}: defect-reporting in {owner}/{repo}",
        description=(
            f"has_issues = {has_issues}. OSPS-DO-02.01 requires the "
            "project to provide a defect-reporting mechanism; GitHub "
            "Issues is the OSPS-recommended default."
        ),
        status=status,
        mappings=[
            _osps_mapping(
                "OSPS-DO-02.01",
                "GitHub Issues presence is the defect-reporting evidence.",
            ),
        ],
        raw={"has_issues": has_issues},
    )


def populate_osps_gv_03_01(
    client: GitHubClient, owner: str, repo: str
) -> SecurityFinding:
    """OSPS-GV-03.01 — Contribution guide published.

    PASS iff CONTRIBUTING(.md|.rst) is present at one of the well-known
    locations. FAIL otherwise.
    """
    candidate_paths = (
        "CONTRIBUTING.md",
        ".github/CONTRIBUTING.md",
        "docs/CONTRIBUTING.md",
        "CONTRIBUTING.rst",
        "CONTRIBUTING",
    )
    found = _file_present_at_any(client, owner, repo, candidate_paths)
    if found:
        return _make_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-GV-03.01",
            scope=None,
            title=(
                f"OSPS-GV-03.01 PASS: CONTRIBUTING present at "
                f"{found!r} in {owner}/{repo}"
            ),
            description=(
                "Contribution guide located. OSPS-GV-03.01 evidence "
                "satisfied."
            ),
            status=ComplianceStatus.PASS,
            mappings=[
                _osps_mapping(
                    "OSPS-GV-03.01",
                    "CONTRIBUTING file present at a well-known path.",
                ),
            ],
            raw={"path": found},
        )
    return _make_finding(
        owner=owner,
        repo=repo,
        control_id="OSPS-GV-03.01",
        scope=None,
        title=f"OSPS-GV-03.01 FAIL: no CONTRIBUTING in {owner}/{repo}",
        description=(
            "Probed candidate paths "
            + ", ".join(repr(p) for p in candidate_paths)
            + "; none found."
        ),
        status=ComplianceStatus.FAIL,
        mappings=[
            _osps_mapping(
                "OSPS-GV-03.01",
                "Contribution guide missing.",
            ),
        ],
        remediation="Add a CONTRIBUTING.md describing the contribution process.",
    )


def populate_osps_le_02_01(
    client: GitHubClient, owner: str, repo: str
) -> SecurityFinding:
    """OSPS-LE-02.01 — License meets OSI/FSF definition.

    PASS iff the repo's ``license.spdx_id`` (as detected by GitHub's
    licensee-backed scanner) is in the conservative OSI/FSF allow-list.
    WARNING if some SPDX id is present but not on the allow-list (the
    operator should verify manually). FAIL if no license is detected.
    """
    try:
        repo_meta = client.get_repo(owner, repo)
    except GitHubApiError as e:
        return _unknown_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-LE-02.01",
            reason="Repo metadata probe failed",
            error=e,
            justification="Could not read repo metadata.",
        )

    license_obj = repo_meta.get("license") or {}
    spdx_id = license_obj.get("spdx_id") if isinstance(license_obj, dict) else None
    if not spdx_id:
        return _make_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-LE-02.01",
            scope=None,
            title=f"OSPS-LE-02.01 FAIL: no license detected in {owner}/{repo}",
            description=(
                "GitHub's license scanner did not return an SPDX id. "
                "OSPS-LE-02.01 requires an OSI- or FSF-recognized "
                "license."
            ),
            status=ComplianceStatus.FAIL,
            mappings=[
                _osps_mapping(
                    "OSPS-LE-02.01",
                    "No license detected on the repository.",
                ),
            ],
            remediation=(
                "Add a LICENSE file containing an OSI-approved license "
                "(e.g., Apache-2.0, MIT, BSD-3-Clause)."
            ),
        )

    spdx_str = str(spdx_id)
    # Case-insensitive lookup against the allow-list.
    recognized = any(
        spdx_str.lower() == approved.lower()
        for approved in _OSI_FSF_RECOGNIZED_SPDX
    )
    if recognized:
        return _make_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-LE-02.01",
            scope=None,
            title=(
                f"OSPS-LE-02.01 PASS: {spdx_str} on {owner}/{repo} is "
                "OSI/FSF-recognized"
            ),
            description=(
                f"Detected SPDX license {spdx_str!r}. Recognized by both "
                "the OSI Open Source Definition allow-list and the FSF "
                "Free Software Definition."
            ),
            status=ComplianceStatus.PASS,
            mappings=[
                _osps_mapping(
                    "OSPS-LE-02.01",
                    f"SPDX id {spdx_str!r} is on the OSI/FSF allow-list.",
                ),
            ],
            raw={"spdx_id": spdx_str},
        )

    return _make_finding(
        owner=owner,
        repo=repo,
        control_id="OSPS-LE-02.01",
        scope=None,
        title=(
            f"OSPS-LE-02.01 WARNING: {spdx_str} on {owner}/{repo} "
            "needs manual OSI/FSF verification"
        ),
        description=(
            f"Detected SPDX license {spdx_str!r}. Not on the bundled "
            "OSI/FSF allow-list; verify the license is OSI-approved or "
            "FSF-Free, or correct the SPDX identifier in LICENSE."
        ),
        status=ComplianceStatus.WARNING,
        mappings=[
            _osps_mapping(
                "OSPS-LE-02.01",
                f"SPDX id {spdx_str!r} requires manual verification.",
            ),
        ],
        raw={"spdx_id": spdx_str},
    )


def populate_osps_le_03_01(
    client: GitHubClient, owner: str, repo: str
) -> SecurityFinding:
    """OSPS-LE-03.01 — LICENSE in well-known location.

    PASS iff one of (LICENSE, LICENSE.md, LICENSE.txt, COPYING,
    COPYING.md, LICENSES/, LICENSE/) is present at the repository root.
    """
    candidate_paths = (
        "LICENSE",
        "LICENSE.md",
        "LICENSE.txt",
        "COPYING",
        "COPYING.md",
        "LICENSE.rst",
        "LICENSES",
    )
    found = _file_present_at_any(client, owner, repo, candidate_paths)
    if found:
        return _make_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-LE-03.01",
            scope=None,
            title=(
                f"OSPS-LE-03.01 PASS: license file at {found!r} in "
                f"{owner}/{repo}"
            ),
            description=(
                f"LICENSE in the well-known location {found!r}."
            ),
            status=ComplianceStatus.PASS,
            mappings=[
                _osps_mapping(
                    "OSPS-LE-03.01",
                    "License file at a well-known location.",
                ),
            ],
            raw={"path": found},
        )

    return _make_finding(
        owner=owner,
        repo=repo,
        control_id="OSPS-LE-03.01",
        scope=None,
        title=f"OSPS-LE-03.01 FAIL: no license file at any known path in {owner}/{repo}",
        description=(
            "Probed candidate paths "
            + ", ".join(repr(p) for p in candidate_paths)
            + "; none found."
        ),
        status=ComplianceStatus.FAIL,
        mappings=[
            _osps_mapping(
                "OSPS-LE-03.01",
                "No license file at a recognized path.",
            ),
        ],
        remediation="Add a LICENSE file at the repository root.",
    )


def populate_osps_qa_01_01(
    client: GitHubClient, owner: str, repo: str
) -> SecurityFinding:
    """OSPS-QA-01.01 — Source code repository publicly readable.

    PASS iff the repository's ``private`` field is ``false``. FAIL if
    ``true`` (the source is not publicly readable, which OSPS-QA-01.01
    requires for community-of-trust).
    """
    try:
        repo_meta = client.get_repo(owner, repo)
    except GitHubApiError as e:
        return _unknown_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-QA-01.01",
            reason="Repo metadata probe failed",
            error=e,
            justification="Could not read repo metadata.",
        )
    private = bool(repo_meta.get("private", False))
    status = ComplianceStatus.PASS if not private else ComplianceStatus.FAIL
    verb = "PASS" if status is ComplianceStatus.PASS else "FAIL"
    return _make_finding(
        owner=owner,
        repo=repo,
        control_id="OSPS-QA-01.01",
        scope=None,
        title=f"OSPS-QA-01.01 {verb}: {owner}/{repo} publicly readable",
        description=(
            f"private = {private!r}. "
            f"OSPS-QA-01.01 requires the source-code repository to be "
            f"publicly readable at a static URL."
        ),
        status=status,
        mappings=[
            _osps_mapping(
                "OSPS-QA-01.01",
                "Repo visibility inspected via the GitHub API.",
            ),
        ],
        raw={"private": private},
    )


def populate_osps_qa_01_02(
    client: GitHubClient, owner: str, repo: str
) -> SecurityFinding:
    """OSPS-QA-01.02 — Public commit history.

    PASS iff the repo is public (commits are publicly readable in any
    public GitHub repo). FAIL if private. This is intentionally close
    to OSPS-QA-01.01 — both depend on visibility, but the two evidence
    requirements are distinct in the upstream Baseline.
    """
    try:
        repo_meta = client.get_repo(owner, repo)
    except GitHubApiError as e:
        return _unknown_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-QA-01.02",
            reason="Repo metadata probe failed",
            error=e,
            justification="Could not read repo metadata.",
        )
    private = bool(repo_meta.get("private", False))
    status = ComplianceStatus.PASS if not private else ComplianceStatus.FAIL
    verb = "PASS" if status is ComplianceStatus.PASS else "FAIL"
    return _make_finding(
        owner=owner,
        repo=repo,
        control_id="OSPS-QA-01.02",
        scope=None,
        title=f"OSPS-QA-01.02 {verb}: commit history visibility in {owner}/{repo}",
        description=(
            f"private = {private!r}. Public commit history is implicit "
            "for any GitHub repo with private=false."
        ),
        status=status,
        mappings=[
            _osps_mapping(
                "OSPS-QA-01.02",
                "Public commit history follows from repo visibility.",
            ),
        ],
        raw={"private": private},
    )


def populate_osps_qa_02_01(
    client: GitHubClient, owner: str, repo: str
) -> SecurityFinding:
    """OSPS-QA-02.01 — Dependency manifest present.

    PASS iff any common dependency manifest (``pyproject.toml``,
    ``requirements.txt``, ``package.json``, ``Cargo.toml``, ``go.mod``,
    ``pom.xml``, ``Gemfile``, ``composer.json``, ``mix.exs``) is present
    at the repo root. FAIL otherwise.
    """
    candidate_paths = (
        "pyproject.toml",
        "requirements.txt",
        "package.json",
        "Cargo.toml",
        "go.mod",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "Gemfile",
        "composer.json",
        "mix.exs",
        "Pipfile",
        "uv.lock",
    )
    found = _file_present_at_any(client, owner, repo, candidate_paths)
    if found:
        return _make_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-QA-02.01",
            scope=None,
            title=(
                f"OSPS-QA-02.01 PASS: dependency manifest {found!r} in "
                f"{owner}/{repo}"
            ),
            description=(
                f"Detected dependency manifest at {found!r}; OSPS-QA-02.01 "
                "evidence is satisfied for direct dependencies."
            ),
            status=ComplianceStatus.PASS,
            mappings=[
                _osps_mapping(
                    "OSPS-QA-02.01",
                    "Dependency manifest present at repo root.",
                ),
            ],
            raw={"path": found},
        )

    return _make_finding(
        owner=owner,
        repo=repo,
        control_id="OSPS-QA-02.01",
        scope=None,
        title=(
            f"OSPS-QA-02.01 FAIL: no dependency manifest in {owner}/{repo}"
        ),
        description=(
            "Probed common dependency manifest paths; none found. "
            "OSPS-QA-02.01 requires a manifest accounting for direct "
            "language dependencies."
        ),
        status=ComplianceStatus.FAIL,
        mappings=[
            _osps_mapping(
                "OSPS-QA-02.01",
                "No standard dependency manifest detected.",
            ),
        ],
        remediation=(
            "Add the ecosystem-standard manifest (e.g., pyproject.toml, "
            "package.json) at the repo root."
        ),
    )


def populate_osps_qa_03_01(
    client: GitHubClient, owner: str, repo: str
) -> SecurityFinding:
    """OSPS-QA-03.01 — Status checks on primary branch.

    PASS iff branch protection on the default branch lists at least
    one required status-check context. FAIL otherwise.
    """
    try:
        repo_meta = client.get_repo(owner, repo)
    except GitHubApiError as e:
        return _unknown_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-QA-03.01",
            reason="Repo metadata probe failed",
            error=e,
            justification="Could not read repo metadata.",
        )
    default_branch = str(repo_meta.get("default_branch") or "main")

    try:
        protection = client.get_branch_protection(owner, repo, default_branch)
    except GitHubApiError as e:
        return _unknown_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-QA-03.01",
            scope=default_branch,
            reason="Branch-protection probe failed",
            error=e,
            justification="Branch-protection state could not be read.",
        )

    contexts: list[str] = []
    if protection is not None:
        status_checks = (protection.get("required_status_checks") or {})
        raw_contexts = status_checks.get("contexts") or []
        if isinstance(raw_contexts, list):
            contexts = [str(c) for c in raw_contexts]

    if contexts:
        return _make_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-QA-03.01",
            scope=default_branch,
            title=(
                f"OSPS-QA-03.01 PASS: {len(contexts)} required status "
                f"check(s) on {owner}/{repo}@{default_branch}"
            ),
            description=(
                f"Required status-check contexts: "
                f"{', '.join(contexts[:5])}{'...' if len(contexts) > 5 else ''}."
            ),
            status=ComplianceStatus.PASS,
            mappings=[
                _osps_mapping(
                    "OSPS-QA-03.01",
                    "Required status checks enforced on the default branch.",
                ),
                _nist_53_mapping(
                    "SA-11",
                    "SA-11 Developer Security Testing — status checks "
                    "enforce automated test/SAST gates before merge.",
                    relationship=OLIRRelationship.SUBSET_OF,
                ),
            ],
            raw={"contexts": contexts},
        )

    return _make_finding(
        owner=owner,
        repo=repo,
        control_id="OSPS-QA-03.01",
        scope=default_branch,
        title=(
            f"OSPS-QA-03.01 FAIL: no required status checks on "
            f"{owner}/{repo}@{default_branch}"
        ),
        description=(
            "OSPS-QA-03.01 requires that automated status checks pass "
            "or be explicitly bypassed before a commit can land on the "
            "primary branch. No required checks were detected."
        ),
        status=ComplianceStatus.FAIL,
        mappings=[
            _osps_mapping(
                "OSPS-QA-03.01",
                "No required status checks configured on primary branch.",
            ),
        ],
        remediation=(
            "Add at least one required status check to the default "
            "branch's protection rules."
        ),
    )


def populate_osps_vm_02_01(
    client: GitHubClient, owner: str, repo: str
) -> SecurityFinding:
    """OSPS-VM-02.01 — SECURITY.md / security contacts published."""
    candidate_paths = (
        "SECURITY.md",
        ".github/SECURITY.md",
        "docs/SECURITY.md",
        "SECURITY.rst",
        "SECURITY",
    )
    found = _file_present_at_any(client, owner, repo, candidate_paths)
    if found:
        return _make_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-VM-02.01",
            scope=None,
            title=(
                f"OSPS-VM-02.01 PASS: security contacts at {found!r} in "
                f"{owner}/{repo}"
            ),
            description=(
                "Security contacts file located at a well-known path."
            ),
            status=ComplianceStatus.PASS,
            mappings=[
                _osps_mapping(
                    "OSPS-VM-02.01",
                    "SECURITY.md / equivalent file present.",
                ),
                _nist_53_mapping(
                    "IR-6",
                    "IR-6 Incident Reporting — SECURITY.md is the "
                    "external reporting entry point.",
                    relationship=OLIRRelationship.INTERSECTS_WITH,
                ),
            ],
            raw={"path": found},
        )
    return _make_finding(
        owner=owner,
        repo=repo,
        control_id="OSPS-VM-02.01",
        scope=None,
        title=f"OSPS-VM-02.01 FAIL: no SECURITY contacts file in {owner}/{repo}",
        description=(
            "OSPS-VM-02.01 requires the project documentation to contain "
            "security contacts. No SECURITY.md / .github/SECURITY.md / "
            "docs/SECURITY.md detected."
        ),
        status=ComplianceStatus.FAIL,
        mappings=[
            _osps_mapping(
                "OSPS-VM-02.01",
                "Security contacts file missing.",
            ),
        ],
        remediation="Add SECURITY.md with security contacts + disclosure policy.",
    )


def populate_osps_vm_03_01(
    client: GitHubClient, owner: str, repo: str
) -> SecurityFinding:
    """OSPS-VM-03.01 — Private vulnerability reporting enabled."""
    try:
        repo_meta = client.get_repo(owner, repo)
    except GitHubApiError as e:
        return _unknown_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-VM-03.01",
            reason="Repo metadata probe failed",
            error=e,
            justification="Could not read repo metadata.",
        )

    saa = repo_meta.get("security_and_analysis") or {}
    pvr = saa.get("private_vulnerability_reporting") or {}
    pvr_status = str(pvr.get("status") or "").lower()
    enabled = pvr_status == "enabled"
    status = ComplianceStatus.PASS if enabled else ComplianceStatus.FAIL
    verb = "PASS" if enabled else "FAIL"
    return _make_finding(
        owner=owner,
        repo=repo,
        control_id="OSPS-VM-03.01",
        scope=None,
        title=(
            f"OSPS-VM-03.01 {verb}: private vulnerability reporting in "
            f"{owner}/{repo}"
        ),
        description=(
            f"security_and_analysis.private_vulnerability_reporting.status "
            f"= {pvr_status!r}. OSPS-VM-03.01 requires a private "
            "reporting channel directly to project security contacts."
        ),
        status=status,
        mappings=[
            _osps_mapping(
                "OSPS-VM-03.01",
                "Private-vulnerability-reporting flag inspected.",
            ),
            _nist_53_mapping(
                "IR-6",
                "IR-6 Incident Reporting — private vulnerability "
                "reporting is the confidential pre-disclosure channel.",
                relationship=OLIRRelationship.INTERSECTS_WITH,
            ),
        ],
        raw={"private_vulnerability_reporting": pvr_status or "unset"},
        remediation=(
            None
            if enabled
            else "Enable Private Vulnerability Reporting in the repo's "
            "Settings → Security & analysis."
        ),
    )


def populate_osps_vm_04_01(
    client: GitHubClient, owner: str, repo: str
) -> SecurityFinding:
    """OSPS-VM-04.01 — Discovered vulnerabilities publicly published.

    NOT_APPLICABLE if the repo is private (the upstream control
    is about public projects). PASS if the security-advisories endpoint
    is reachable (the mechanism is in place; the advisory log may be
    empty if no vulns have been disclosed yet). FAIL otherwise.
    """
    try:
        repo_meta = client.get_repo(owner, repo)
    except GitHubApiError as e:
        return _unknown_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-VM-04.01",
            reason="Repo metadata probe failed",
            error=e,
            justification="Could not read repo metadata.",
        )

    if bool(repo_meta.get("private", False)):
        return _make_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-VM-04.01",
            scope=None,
            title=(
                f"OSPS-VM-04.01 NOT_APPLICABLE: {owner}/{repo} is private"
            ),
            description=(
                "OSPS-VM-04.01 evaluates the public-disclosure mechanism. "
                "Private repos do not have a public-publish surface; the "
                "control does not apply."
            ),
            status=ComplianceStatus.NOT_APPLICABLE,
            mappings=[
                _osps_mapping(
                    "OSPS-VM-04.01",
                    "Private repo — no public-publish surface required.",
                    relationship=OLIRRelationship.RELATED_TO,
                ),
            ],
        )

    try:
        advisories = client.list_security_advisories(owner, repo)
    except GitHubApiError as e:
        return _unknown_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-VM-04.01",
            reason="security-advisories probe failed",
            error=e,
            justification="Could not enumerate security advisories.",
        )

    # PASS even on empty-list: the surface exists. No advisories yet is
    # an honest state; OSPS-VM-04 evaluates the mechanism, not the count.
    return _make_finding(
        owner=owner,
        repo=repo,
        control_id="OSPS-VM-04.01",
        scope=None,
        title=(
            f"OSPS-VM-04.01 PASS: security-advisories surface reachable "
            f"on {owner}/{repo} ({len(advisories)} advisories)"
        ),
        description=(
            "GitHub Security Advisories endpoint reachable. "
            f"{len(advisories)} advisor{'y' if len(advisories) == 1 else 'ies'} "
            "published. The OSPS-VM-04.01 public-publish mechanism is "
            "in place."
        ),
        status=ComplianceStatus.PASS,
        mappings=[
            _osps_mapping(
                "OSPS-VM-04.01",
                "Public-advisories endpoint reachable.",
            ),
        ],
        raw={"advisory_count": len(advisories)},
    )


def populate_osps_vm_05_03(
    client: GitHubClient, owner: str, repo: str
) -> SecurityFinding:
    """OSPS-VM-05.03 — Dependency SCA active on changes.

    Posture-level finding: is Dependabot's vulnerability-alerts
    surface enabled on the repo? The per-CVE evidence chain (one
    finding per advisory) is emitted by the existing
    :class:`~evidentia_collectors.github.dependabot.DependabotCollector`;
    that collector and this helper are intentionally complementary,
    not duplicative. This helper answers "is the control mechanism in
    place?"; the collector answers "what does the mechanism currently
    report?".
    """
    try:
        enabled = client.are_vulnerability_alerts_enabled(owner, repo)
    except GitHubApiError as e:
        return _unknown_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-VM-05.03",
            reason="vulnerability-alerts probe failed",
            error=e,
            justification="Could not probe Dependabot status.",
        )

    status = ComplianceStatus.PASS if enabled else ComplianceStatus.FAIL
    verb = "PASS" if enabled else "FAIL"
    return _make_finding(
        owner=owner,
        repo=repo,
        control_id="OSPS-VM-05.03",
        scope=None,
        title=(
            f"OSPS-VM-05.03 {verb}: Dependabot SCA on {owner}/{repo} "
            f"({'enabled' if enabled else 'disabled'})"
        ),
        description=(
            "Dependabot vulnerability alerts mechanism = "
            f"{'enabled' if enabled else 'disabled'}. "
            "OSPS-VM-05.03 requires automated evaluation of changes "
            "against a documented dependency-vulnerability policy."
        ),
        status=status,
        mappings=[
            _osps_mapping(
                "OSPS-VM-05.03",
                "Dependabot vulnerability-alerts presence inspected via "
                "the /repos/{o}/{r}/vulnerability-alerts probe.",
            ),
            _nist_53_mapping(
                "RA-5",
                "RA-5 Vulnerability Monitoring and Scanning — Dependabot "
                "provides continuous dependency vulnerability monitoring.",
                relationship=OLIRRelationship.SUBSET_OF,
            ),
            _nist_53_mapping(
                "SI-2",
                "SI-2 Flaw Remediation — Dependabot alerts directly "
                "evidence known flaws in third-party dependencies.",
                relationship=OLIRRelationship.INTERSECTS_WITH,
            ),
        ],
        raw={"vulnerability_alerts_enabled": enabled},
        remediation=(
            None
            if enabled
            else "Enable Dependabot alerts in Settings → Security & "
            "analysis."
        ),
    )


def populate_osps_vm_06_02(
    client: GitHubClient, owner: str, repo: str
) -> SecurityFinding:
    """OSPS-VM-06.02 — Code scanning (SAST) on changes."""
    try:
        enabled = client.is_code_scanning_enabled(owner, repo)
    except GitHubApiError as e:
        return _unknown_finding(
            owner=owner,
            repo=repo,
            control_id="OSPS-VM-06.02",
            reason="code-scanning probe failed",
            error=e,
            justification="Could not probe code-scanning status.",
        )

    status = ComplianceStatus.PASS if enabled else ComplianceStatus.FAIL
    verb = "PASS" if enabled else "FAIL"
    return _make_finding(
        owner=owner,
        repo=repo,
        control_id="OSPS-VM-06.02",
        scope=None,
        title=(
            f"OSPS-VM-06.02 {verb}: code scanning on {owner}/{repo} "
            f"({'enabled' if enabled else 'disabled'})"
        ),
        description=(
            "Code-scanning alerts endpoint = "
            f"{'reachable' if enabled else 'not reachable'}. "
            "OSPS-VM-06.02 requires automated SAST against changes."
        ),
        status=status,
        mappings=[
            _osps_mapping(
                "OSPS-VM-06.02",
                "Code-scanning alerts endpoint reachability inspected.",
            ),
            _nist_53_mapping(
                "SA-11",
                "SA-11 Developer Security Testing — code scanning is the "
                "automated SAST gate enforced before merge.",
                relationship=OLIRRelationship.SUBSET_OF,
            ),
        ],
        raw={"code_scanning_enabled": enabled},
        remediation=(
            None
            if enabled
            else "Enable Code Scanning (CodeQL default setup or a custom "
            "workflow) in Settings → Security & analysis."
        ),
    )


__all__ = [
    "COLLECTOR_ID",
    "OSPS_COVERAGE",
    "populate_osps_ac_03_01",
    "populate_osps_ac_03_02",
    "populate_osps_br_06_01",
    "populate_osps_do_02_01",
    "populate_osps_gv_03_01",
    "populate_osps_le_02_01",
    "populate_osps_le_03_01",
    "populate_osps_qa_01_01",
    "populate_osps_qa_01_02",
    "populate_osps_qa_02_01",
    "populate_osps_qa_03_01",
    "populate_osps_vm_02_01",
    "populate_osps_vm_03_01",
    "populate_osps_vm_04_01",
    "populate_osps_vm_05_03",
    "populate_osps_vm_06_02",
]
