#!/usr/bin/env python3
"""Re-validate every claimed-PASS evidence link in ``OSPS-CONFORMANCE.md``.

Extracted (v0.10.7, D2.3) from the embedded ``python <<'PY'`` heredoc in
``.github/workflows/verify-osps-conformance.yml`` so the URL-translation
logic can be unit-tested directly (the prior heredoc-in-YAML shape blocked
pytest coverage — Issue #2 from the C3 review / the ``TODO(v0.10.7)``
marker in the workflow). Behavior is preserved exactly: same regexes, same
``translate_url`` rules, same hard-fail-on-unmapped-shape semantics, same
404 detection, same exit codes, same ``GH_TOKEN`` usage.

What it does
------------
1. Parse ``OSPS-CONFORMANCE.md`` for table rows of the form
   ``| OSPS-XX-NN | <title> | OK PASS | [text](URL) ... |`` (the PASS
   marker is the U+2705 check-mark glyph).
2. For each cited evidence URL, translate the GitHub HTML-render URL into
   the corresponding REST API endpoint (which returns a clean 404 on a
   missing resource, unlike the HTML renderer which can 200-OK a missing
   path).
3. Call ``gh api`` for each endpoint; collect any HTTP 404.
4. Exit non-zero if any evidence link 404s OR if any URL shape has no
   translation rule (an unmapped shape is a silent-PASS hazard — the
   SF-2 failure mode this gate exists to close).

Threat model: see ``docs/threat-model.md`` ->  "v0.10.6 attack-surface
delta" ->  "Guards: verify-osps-conformance.yml workflow".

Exit codes
----------
- ``0`` — all PASS-claimed evidence links resolved.
- ``1`` — one or more evidence links 404'd, OR one or more URL shapes had
  no translation rule, OR no PASS-claimed controls were parsed at all
  (table-format drift).
- ``2`` — ``OSPS-CONFORMANCE.md`` not found.

Security note: evidence URLs are passed to ``gh api`` only as
``subprocess.run`` positional arguments (an argument list, never a shell
string), blocking workflow-injection from doc content.

Per the publishing-authority protocol (~/.claude/CLAUDE.md), this script
is read-only — it never edits, pushes, tags, or publishes.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# The repo coordinates (owner/repo) for translating html-render URLs into
# API endpoints. Pinned here rather than read from $GITHUB_REPOSITORY so
# the script stays functional if a fork triggers the workflow via PR —
# evidence URLs in this doc always point at the upstream repo.
OWNER_REPO = "Polycentric-Labs/evidentia"

# The conformance doc, resolved relative to the repo root (this file lives
# in scripts/, so the repo root is one parent up).
CONFORMANCE_DOC = Path(__file__).resolve().parent.parent / "docs" / "OSPS-CONFORMANCE.md"

# Table-row matcher. Matches rows of the form:
#   | OSPS-XX-NN | <title> | <check> PASS | [link-text](URL) ... |
# The `(?:\.\d+)?` allows assessment-requirement IDs like OSPS-AC-01.01
# in addition to top-level OSPS-AC-01. "✅" is the green check-mark.
CLAIM_PATTERN = re.compile(
    r"^\|\s*(OSPS-[A-Z]{2}-\d+(?:\.\d+)?)\s*\|"
    r"[^|]+\|"  # title cell
    r"\s*✅\s*PASS\s*\|"
    r"\s*([^|]+)\|",  # evidence cell
    re.MULTILINE,
)

# Markdown link URL extractor (pulls the URL out of `[text](URL)`).
URL_PATTERN = re.compile(r"\[[^\]]*\]\((https?://[^\s\)]+)\)")

# HTML-render URL shape matchers. Each shape has a corresponding REST API
# form that returns a true 404 on a missing resource.
_HTML_BLOB_RE = re.compile(rf"^https?://github\.com/{re.escape(OWNER_REPO)}/blob/main/(.+)$")
_HTML_TREE_RE = re.compile(rf"^https?://github\.com/{re.escape(OWNER_REPO)}/tree/main/(.+)$")
_HTML_RELEASE_TAG_RE = re.compile(
    rf"^https?://github\.com/{re.escape(OWNER_REPO)}/releases/tag/([^/?#]+)$"
)
_HTML_COMMITS_RE = re.compile(rf"^https?://github\.com/{re.escape(OWNER_REPO)}/commits/([^/?#]+)$")
_HTML_SECURITY_ADVISORIES_RE = re.compile(
    rf"^https?://github\.com/{re.escape(OWNER_REPO)}/security/advisories/?$"
)
_HTML_REPO_ROOT_RE = re.compile(rf"^https?://github\.com/{re.escape(OWNER_REPO)}/?$")


def translate_url(url: str) -> tuple[str, str]:
    """Return ``(api_endpoint, shape_label)`` for a doc URL.

    The ``api_endpoint`` is suitable to pass directly as a ``gh api``
    positional argument (no scheme — ``gh api`` prepends api.github.com).
    The ``shape_label`` is for diagnostic annotations.

    WHY each shape maps the way it does: GitHub's HTML renderer can return
    HTTP 200 with a "Page Not Found" body for paths under a public repo
    even when the file does NOT exist on ``main`` HEAD (depending on auth
    state + caching layer behavior). The REST endpoints below are the
    documented "does this resource exist" checks and return a clean 404.

    URL shapes that DON'T match any translation rule return the
    ``"unmapped"`` label — the caller treats that as a HARD FAILURE (not a
    warning), forcing every URL shape used in OSPS-CONFORMANCE.md to have
    an explicit translation entry here. The previous ``::warning::``-and-
    pass fallback re-introduced the SF-2 failure mode (``gh api`` against
    the HTML URL 200-OKs from GitHub's renderer even when the underlying
    resource is missing). New URL shapes MUST be added to ``translate_url``
    before they're cited as evidence.
    """
    m = _HTML_BLOB_RE.match(url)
    if m:
        path = m.group(1)
        return (f"repos/{OWNER_REPO}/contents/{path}?ref=main", "blob")
    m = _HTML_TREE_RE.match(url)
    if m:
        path = m.group(1).rstrip("/")
        return (f"repos/{OWNER_REPO}/contents/{path}?ref=main", "tree")
    m = _HTML_RELEASE_TAG_RE.match(url)
    if m:
        tag = m.group(1)
        return (f"repos/{OWNER_REPO}/releases/tags/{tag}", "release-tag")
    m = _HTML_COMMITS_RE.match(url)
    if m:
        ref = m.group(1)
        # contents/?ref=<ref> on the repo root tests the ref exists. We
        # use the dedicated branches API for branch refs since it returns
        # 404 cleanly on missing branches (vs. the contents API which
        # returns the root tree, which is less specific).
        return (f"repos/{OWNER_REPO}/branches/{ref}", "commits-ref")
    if _HTML_SECURITY_ADVISORIES_RE.match(url):
        # The /security/advisories listing page maps to the REST endpoint
        # that lists published advisories. The endpoint returns a JSON
        # array (possibly empty — that's fine; the evidence is "endpoint
        # exists", not "has advisories"). A missing-repo or missing-
        # feature scenario returns 404 here, which is the gate we want.
        return (f"repos/{OWNER_REPO}/security-advisories", "security-advisories")
    if _HTML_REPO_ROOT_RE.match(url):
        return (f"repos/{OWNER_REPO}", "repo-root")
    # No translation rule matched. Hard-fail signal: log the URL so a
    # contributor can add an explicit translation before the next
    # push/PR. We do NOT fall through to gh-api-on-the-HTML-URL — that
    # path 200-OKs from GitHub's HTML renderer for missing resources (the
    # SF-2 failure mode this gate exists to close).
    return (url, "unmapped")


def _endpoint_returns_404(api_endpoint: str) -> bool:
    """Call ``gh api`` for ``api_endpoint``; return True iff HTTP 404.

    Uses an argument list (no shell). The ``-i`` flag includes response
    headers, which we parse for the status line. ``gh api`` writes headers
    to stderr when the call returns a non-2xx status (the body lands on
    stdout regardless), so we check both streams for the 404 status line
    to be robust to gh's stream routing across versions.
    """
    result = subprocess.run(
        [
            "gh",
            "api",
            "-i",
            "-H",
            "Accept: application/vnd.github+json",
            api_endpoint,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    combined = result.stdout + "\n" + result.stderr
    return (
        "HTTP/2.0 404" in combined
        or "HTTP/1.1 404" in combined
        or "HTTP/2 404" in combined
    )


def parse_claims(markdown: str) -> list[tuple[str, str]]:
    """Return ``(control_id, evidence_cell)`` tuples for each PASS row."""
    return CLAIM_PATTERN.findall(markdown)


def main(argv: list[str] | None = None) -> int:
    doc_path = CONFORMANCE_DOC
    if argv:
        # Optional positional override (used by ad-hoc invocations); the
        # workflow calls with no args and relies on the default path.
        doc_path = Path(argv[0])

    if not doc_path.exists():
        print(f"::error::{doc_path} not found.", file=sys.stderr)
        return 2

    md = doc_path.read_text(encoding="utf-8")
    claims = parse_claims(md)
    if not claims:
        print(
            "::error::No PASS-claimed controls parsed from OSPS-CONFORMANCE.md. "
            "Has the table format drifted from the regex?",
            file=sys.stderr,
        )
        return 1

    print(
        f"::notice::Parsed {len(claims)} PASS-claimed controls; "
        "verifying evidence URLs..."
    )

    failures: list[tuple[str, str]] = []
    unmapped: list[tuple[str, str]] = []
    checked = 0
    for control_id, evidence_cell in claims:
        for url in URL_PATTERN.findall(evidence_cell):
            checked += 1
            api_endpoint, shape = translate_url(url)
            if shape == "unmapped":
                # Hard-fail: an unmapped URL shape means the gh-api-on-
                # HTML-URL fallback would 200-OK from GitHub's renderer
                # even for missing resources (SF-2 regression). Surface as
                # an error + collect; we return non-zero after the loop so
                # all unmapped shapes are visible in one run.
                unmapped.append((control_id, url))
                print(
                    f"::error::Unmapped URL shape for {control_id}: {url}. "
                    "Add an explicit translation rule to translate_url() "
                    "before citing this URL shape as evidence.",
                    file=sys.stderr,
                )
                continue
            if _endpoint_returns_404(api_endpoint):
                failures.append((control_id, url))
                print(
                    f"::error::404 on evidence for {control_id} "
                    f"(shape={shape}, endpoint={api_endpoint}): {url}",
                    file=sys.stderr,
                )

    if failures:
        print(
            f"::error::{len(failures)} of {checked} evidence link(s) returned "
            "HTTP 404. Update OSPS-CONFORMANCE.md before the next release.",
            file=sys.stderr,
        )
        return 1

    if unmapped:
        print(
            f"::error::{len(unmapped)} of {checked} evidence URL(s) had no "
            "translation rule in translate_url(). Each unmapped shape is a "
            "silent-PASS hazard (gh api against the HTML URL 200-OKs from "
            "GitHub's renderer even for missing resources — SF-2). Add "
            "explicit translation entries before the next push/PR.",
            file=sys.stderr,
        )
        return 1

    print(
        f"::notice::Verified {len(claims)} PASS-claimed controls / "
        f"{checked} evidence URLs; all resolved."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
