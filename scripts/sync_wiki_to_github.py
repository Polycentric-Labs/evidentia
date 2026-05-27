#!/usr/bin/env python3
"""Sync docs/wiki/ to the repo's GitHub wiki (separate <repo>.wiki.git).

Runs from CI via .github/workflows/sync-wiki.yml on push to main when
docs/wiki/** changes. Authenticated via $GITHUB_TOKEN (provided by the
workflow's secrets.GITHUB_TOKEN). The token requires contents: write.

Dual-source canonical: docs/wiki/ in main repo is the SOURCE OF TRUTH;
the GitHub wiki is auto-generated downstream. Wiki edits go through
normal PR review against docs/wiki/. Wiki should be restricted to
collaborators-only via Settings -> Features -> Wikis -> Restrict
editing to collaborators only.

Conversion rules:

1. Flatten nested docs/wiki/<section>/<page>.md into wiki-flat names:
   - docs/wiki/index.md                                -> Home.md
   - docs/wiki/1-getting-started/index.md              -> Getting-Started.md
   - docs/wiki/1-getting-started/quickstart.md         -> Quickstart.md
   - docs/wiki/5-compliance/osps-baseline-mapping.md   -> OSPS-Baseline-Mapping.md
   - docs/wiki/3-concepts/architecture.md              -> Architecture.md

2. Rewrite markdown links:
   - In-wiki links resolve to flat names (no .md extension):
       [Architecture](../3-concepts/architecture.md) -> [Architecture](Architecture)
   - Out-of-wiki repo links become absolute GitHub URLs:
       [verify](../../verification.md) -> [verify](https://github.com/<repo>/blob/main/docs/verification.md)
   - Anchor-only + external (http/https/mailto) links unchanged
   - Anchors on in-wiki links preserved: file.md#section -> Flat-Name#section

3. Generate _Sidebar.md from the section structure (alphabetic section
   order matches the 1-/2-/3-... prefix on directories).

Usage:
    python scripts/sync_wiki_to_github.py            # real sync (needs $GITHUB_TOKEN)
    python scripts/sync_wiki_to_github.py --dry-run  # preview to /tmp; no push

Exit codes:
    0 = success (or no changes to commit)
    1 = expected error (wiki repo not initialized; clone failed)
    2 = unexpected error (missing env, bad path, etc.)
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

WIKI_SRC = Path("docs/wiki")
REPO_ROOT = Path.cwd()

# Acronyms preserve uppercase in flat page names. Add as the wiki grows.
ACRONYM_FIXUPS: dict[str, str] = {
    r"\bOsps\b": "OSPS",
    r"\bOcsf\b": "OCSF",
    r"\bOscal\b": "OSCAL",
    r"\bMcp\b": "MCP",
    r"\bCli\b": "CLI",
    r"\bApi\b": "API",
    r"\bFaq\b": "FAQ",
    r"\bRbac\b": "RBAC",
    r"\bEol\b": "EOL",
    r"\bCimd\b": "CIMD",
    r"\bConmon\b": "CONMON",
    r"\bPoam\b": "POAM",
    r"\bSarif\b": "SARIF",
    r"\bVex\b": "VEX",
    r"\bSbom\b": "SBOM",
    r"\bIa\b": "IA",
    r"\bSso\b": "SSO",
    r"\bRest\b": "REST",
}


def to_titlecase(slug: str) -> str:
    """Convert kebab-case slug to TitleCase-With-Hyphens."""
    titled = "-".join(part.capitalize() for part in slug.split("-"))
    for pattern, replacement in ACRONYM_FIXUPS.items():
        titled = re.sub(pattern, replacement, titled)
    return titled


def wiki_flat_name(path: Path) -> str:
    """Map a docs/wiki/-relative .md path to its wiki-flat filename stem.

    Examples (input -> output):
        docs/wiki/index.md                              -> Home
        docs/wiki/1-getting-started/index.md            -> Getting-Started
        docs/wiki/1-getting-started/quickstart.md       -> Quickstart
        docs/wiki/5-compliance/osps-baseline-mapping.md -> OSPS-Baseline-Mapping
    """
    rel = path.relative_to(WIKI_SRC)
    parts = rel.parts

    if len(parts) == 1 and parts[0] == "index.md":
        return "Home"

    if len(parts) == 2 and parts[1] == "index.md":
        section_slug = re.sub(r"^\d+-", "", parts[0])
        return to_titlecase(section_slug)

    if len(parts) == 2:
        return to_titlecase(parts[1].removesuffix(".md"))

    raise ValueError(f"Unexpected wiki path depth: {path}")


def build_link_map() -> dict[Path, str]:
    """Map each docs/wiki/*.md path to its flat wiki name."""
    return {p: wiki_flat_name(p) for p in WIKI_SRC.rglob("*.md")}


def rewrite_links(
    content: str,
    source_path: Path,
    link_map: dict[Path, str],
    repo: str,
) -> str:
    """Rewrite markdown links per the migration rules."""
    blob_url = f"https://github.com/{repo}/blob/main/"

    def replace(match: re.Match[str]) -> str:
        text = match.group(1)
        target = match.group(2)

        if target.startswith(("#", "http://", "https://", "mailto:")):
            return match.group(0)

        if "#" in target:
            path_part, anchor = target.split("#", 1)
            anchor = f"#{anchor}"
        else:
            path_part, anchor = target, ""

        if not path_part:
            return match.group(0)

        # Trailing slash = directory reference (e.g., "1-getting-started/").
        # Treat as the directory's index.md.
        if path_part.endswith("/"):
            path_part = path_part + "index.md"

        try:
            abs_target = (source_path.parent / path_part).resolve()
        except (ValueError, OSError):
            return match.group(0)

        # If resolved path is a directory (no trailing slash but is a dir),
        # try its index.md.
        if abs_target.is_dir():
            candidate = abs_target / "index.md"
            if candidate.exists():
                abs_target = candidate

        try:
            rel_to_repo = abs_target.relative_to(REPO_ROOT.resolve())
        except ValueError:
            return match.group(0)

        try:
            rel_to_wiki = rel_to_repo.relative_to(WIKI_SRC)
        except ValueError:
            rel_to_wiki = None

        if rel_to_wiki is not None:
            key = WIKI_SRC / rel_to_wiki
            if key in link_map:
                return f"[{text}]({link_map[key]}{anchor})"

        return f"[{text}]({blob_url}{rel_to_repo.as_posix()}{anchor})"

    return re.sub(r"\[([^\]]+)\]\(([^)]+)\)", replace, content)


def generate_sidebar(link_map: dict[Path, str]) -> str:
    """Generate _Sidebar.md from the section directory structure."""
    lines = [
        "# Evidentia wiki",
        "",
        "- **[Home](Home)**",
        "",
    ]

    section_dirs = sorted(p for p in WIKI_SRC.iterdir() if p.is_dir())
    for section_dir in section_dirs:
        index = section_dir / "index.md"
        section_name = link_map.get(index)
        if not section_name:
            continue
        lines.append(f"- **[{section_name.replace('-', ' ')}]({section_name})**")
        pages = sorted(
            p for p in section_dir.iterdir()
            if p.is_file() and p.name != "index.md" and p.suffix == ".md"
        )
        for page in pages:
            page_name = link_map.get(page)
            if page_name:
                lines.append(f"  - [{page_name.replace('-', ' ')}]({page_name})")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_wiki_files(link_map: dict[Path, str], output_dir: Path, repo: str) -> None:
    """Write converted wiki files (and _Sidebar.md) into output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)
    for source, flat_name in link_map.items():
        content = source.read_text(encoding="utf-8")
        rewritten = rewrite_links(content, source, link_map, repo)
        (output_dir / f"{flat_name}.md").write_text(rewritten, encoding="utf-8")
        print(f"  {source.as_posix()} -> {flat_name}.md")
    (output_dir / "_Sidebar.md").write_text(generate_sidebar(link_map), encoding="utf-8")
    print("  generated _Sidebar.md")


def main() -> int:
    if not WIKI_SRC.exists():
        print(f"ERROR: {WIKI_SRC} does not exist", file=sys.stderr)
        return 2

    dry_run = "--dry-run" in sys.argv
    repo = os.environ.get("GITHUB_REPOSITORY", "Polycentric-Labs/evidentia")

    print(f"Building link map from {WIKI_SRC}...")
    link_map = build_link_map()
    print(f"  {len(link_map)} markdown files found")

    if dry_run:
        output_dir = Path("/tmp/wiki-sync-dry-run")
        if output_dir.exists():
            shutil.rmtree(output_dir)
        print(f"\nDry-run: converting to {output_dir}")
        write_wiki_files(link_map, output_dir, repo)
        print(f"\nDry-run complete; output at {output_dir}")
        return 0

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("ERROR: GITHUB_TOKEN not set", file=sys.stderr)
        return 2

    wiki_url = f"https://x-access-token:{token}@github.com/{repo}.wiki.git"
    wiki_dir = Path("/tmp/wiki-sync-repo")

    if wiki_dir.exists():
        shutil.rmtree(wiki_dir)

    print("\nCloning wiki repo...")
    clone = subprocess.run(
        ["git", "clone", wiki_url, str(wiki_dir)],
        capture_output=True,
        text=True,
        check=False,
    )
    if clone.returncode != 0:
        print("ERROR: failed to clone wiki repo", file=sys.stderr)
        print(f"  stderr: {clone.stderr.strip()}", file=sys.stderr)
        print(
            "  Has the wiki feature been enabled?\n"
            "  Settings -> Features -> Wikis -> enable + restrict to collaborators.",
            file=sys.stderr,
        )
        return 1

    print("Clearing existing wiki content...")
    for old in wiki_dir.glob("*.md"):
        old.unlink()

    print("Writing converted content...")
    write_wiki_files(link_map, wiki_dir, repo)

    print("\nCommitting...")
    subprocess.run(
        ["git", "-C", str(wiki_dir), "config", "user.name", "evidentia-wiki-sync[bot]"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(wiki_dir), "config", "user.email", "noreply@github.com"],
        check=True,
    )
    subprocess.run(["git", "-C", str(wiki_dir), "add", "."], check=True)

    diff = subprocess.run(
        ["git", "-C", str(wiki_dir), "diff", "--cached", "--quiet"],
        check=False,
    )
    if diff.returncode == 0:
        print("No changes to commit; wiki is up to date.")
        return 0

    commit_sha = os.environ.get("GITHUB_SHA", "unknown")
    subprocess.run(
        [
            "git", "-C", str(wiki_dir), "commit", "-m",
            f"sync from docs/wiki/ @ {commit_sha[:7]} via sync-wiki.yml",
        ],
        check=True,
    )
    subprocess.run(["git", "-C", str(wiki_dir), "push", "origin", "HEAD"], check=True)
    print("Wiki sync complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
