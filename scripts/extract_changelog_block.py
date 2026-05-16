#!/usr/bin/env python3
"""Extract a single ``[X.Y.Z]`` block from CHANGELOG.md.

v0.7.13 P2.2.1 deliverable. Wired into ``.github/workflows/release.yml``
so every release auto-populates its GitHub Release body with the
substantive CHANGELOG content + canonical PEP 740 verify stanza,
preventing the v0.7.5–v0.7.12 stub-body gap from recurring.

Usage:

    python scripts/extract_changelog_block.py 0.7.13

Reads ``CHANGELOG.md`` from the repo root, locates the
``## [0.7.13] - <date>`` heading, captures every line until the
next ``## [`` heading (or EOF), strips the heading line itself,
and prints the captured block to stdout.

Exit codes:
- 0 — block found + emitted
- 1 — no matching block found (release.yml fails fast; surfaces
  as a CI failure rather than silently shipping a stub body)
- 2 — CLI usage error

Self-test: see ``tests/unit/test_extract_changelog_block.py`` —
the test exercises every shipped release block (v0.7.0 → v0.7.12)
+ the [Unreleased] block + a synthetic edge-case block.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def extract_block(changelog_text: str, version: str) -> str | None:
    """Return the lines between ``## [<version>]`` and the next
    ``## [`` heading, exclusive of both heading lines.

    The function is whitespace-strict on the leading ``## [`` so
    the YAML changelog convention's dash bullets (``- ``) inside
    blocks aren't confused for section starts.
    """
    # Match `## [X.Y.Z]` allowing optional `- YYYY-MM-DD` suffix.
    # Anchor at line-start; VERSION must be exact (literal, escaped).
    start_pattern = re.compile(
        rf"^## \[{re.escape(version)}\][ \-].*$",
        re.MULTILINE,
    )
    next_heading_pattern = re.compile(r"^## \[", re.MULTILINE)

    start_match = start_pattern.search(changelog_text)
    if start_match is None:
        return None

    # Block content starts immediately after the heading's newline.
    block_start = start_match.end()
    # Skip the newline after the heading line itself.
    if block_start < len(changelog_text) and changelog_text[block_start] == "\n":
        block_start += 1

    # Find the next `## [` heading after our block-start position.
    next_match = next_heading_pattern.search(changelog_text, pos=block_start)
    block_end = next_match.start() if next_match else len(changelog_text)

    block = changelog_text[block_start:block_end].rstrip()
    return block if block.strip() else None


def render_release_body(version: str, block: str) -> str:
    """Wrap the CHANGELOG block in a release-body template with
    PEP 740 wheel verification stanza.

    The container-image stanza is appended downstream by
    ``publish-container`` (release.yml line 358) via
    ``softprops/action-gh-release@... append_body: true``, so we
    only emit the wheels half here.
    """
    return f"""## Highlights

{block}

---

### Verify the wheels (PEP 740 publish attestations)

Every wheel uploaded to PyPI from this release carries a
Sigstore-signed PEP 740 publish attestation. Verify locally:

```bash
pip install pypi-attestations
pypi-attestations verify pypi \\
  --repository https://github.com/polycentric-labs/evidentia \\
  "pypi:evidentia=={version}"
```

Verification confirms the wheel was built + published from
``polycentric-labs/evidentia/release.yml@refs/tags/v{version}``
under GitHub Actions OIDC — i.e., a malicious mirror cannot
serve a tampered wheel without the verification failing.

See [docs/sigstore-quickstart.md](https://github.com/polycentric-labs/evidentia/blob/main/docs/sigstore-quickstart.md)
for the full verification narrative + supply-chain framing.

### CHANGELOG

Full changelog (every release): [CHANGELOG.md](https://github.com/polycentric-labs/evidentia/blob/v{version}/CHANGELOG.md)
"""


def main() -> int:
    if len(sys.argv) < 2:
        print(
            "usage: extract_changelog_block.py <version> [--changelog PATH]",
            file=sys.stderr,
        )
        return 2

    version = sys.argv[1]
    changelog_arg = "CHANGELOG.md"
    if len(sys.argv) >= 4 and sys.argv[2] == "--changelog":
        changelog_arg = sys.argv[3]

    changelog_path = Path(changelog_arg).resolve()
    if not changelog_path.is_file():
        print(
            f"error: CHANGELOG file not found at {changelog_path}",
            file=sys.stderr,
        )
        return 1

    text = changelog_path.read_text(encoding="utf-8")
    block = extract_block(text, version)
    if block is None:
        print(
            f"error: no `## [{version}]` block found in {changelog_path}",
            file=sys.stderr,
        )
        return 1

    body = render_release_body(version, block)
    # Force UTF-8 encoding on stdout so Unicode chars (≈, →, etc.)
    # in CHANGELOG entries survive the Windows cp1252 default
    # encoding. release.yml runs on ubuntu-latest where this is a
    # no-op, but local self-tests on Windows benefit from the
    # explicit reconfigure.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
