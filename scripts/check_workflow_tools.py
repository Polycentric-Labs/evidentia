#!/usr/bin/env python3
"""G8 tool-availability + G9 extras-validity checker for GitHub workflows.

Mechanizes engineering-practices lessons 8-9 (the v0.10.15 exit-127 ghost tag
and the nonexistent-[ai,api,collectors] silent-skip incident):

G8 — for every job in every TOP-LEVEL workflow, each command invoked in a
``run:`` block must be (i) provided by an earlier ``uses:`` step in the SAME
job (committed ACTION_TOOLS map), (ii) on the committed RUNNER_PREINSTALLED
allowlist, (iii) a shell keyword/builtin, or (iv) waived by an inline
``# tool-check: ok <cmd>`` comment inside that ``run:`` block. Waivers are for
VERIFIED false-positives only (e.g. a tool installed by a prior ``run:`` step);
a genuinely missing setup step is a workflow bug — fix it, never waive it.

G9 — any install-spec ``<pkg>[<extras>]`` in a ``run:`` block whose ``<pkg>``
is a WORKSPACE package must only name extras declared in that package's
pyproject manifest (pip warns and exits 0 on a nonexistent extra — verified
live 2026-07-02 — so nothing downstream catches it). Third-party specs like
``psycopg[binary]`` are ignored: their extras are not in workspace manifests.

SCOPE (v1, honest limits):
- Top-level ``.github/workflows/*.yml`` only; composite actions and reusable
  workflows are OUT of scope.
- RUNNER_PREINSTALLED approximates ubuntu-latest; cross-OS matrix jobs share it.
- Extraction is a QUOTE-AWARE first-token heuristic: quoted-string content is
  masked (with cross-line state, so multi-line ``python -c "..."`` bodies are
  opaque) before operator splitting; heredoc bodies and ``case``…``esac``
  bodies are skipped; ``VAR=value`` prefixes are stripped; line-leading
  ``$(...)`` unwraps one level; backslash continuations fold. Tools invoked
  via variables/paths (``$X``, ``./x``, ``/usr/bin/x``) and commands inside
  mid-line substitutions or case arms are skipped — a disclosed
  false-NEGATIVE surface, accepted for v1. A literal ``<<`` inside a string
  can false-trigger heredoc skipping (disclosed; none in this repo today).

Dependency note: PyYAML (an existing dev dependency, same as the
``audit_workflow_permissions.py`` precedent) + stdlib ``tomllib``. Zero NEW
third-party dependencies.

Exit codes (mirrors the precedent):
    0 — clean, or advisory mode (no ``--strict``)
    2 — findings (including parse errors) under ``--strict``
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

# Committed action -> provided-tools map. Keyed on the action name WITHOUT the
# version ref. Owned like osv-scanner.toml's allowlist: PR-reviewed, commented.
# Unknown actions contribute nothing (never a finding by themselves).
ACTION_TOOLS: dict[str, set[str]] = {
    "astral-sh/setup-uv": {"uv", "uvx"},
    "actions/setup-python": {"python", "python3", "pip", "pip3"},
    "actions/setup-node": {"node", "npm", "npx"},
    "sigstore/cosign-installer": {"cosign"},
    # docker/* setup actions provide no CLI beyond the preinstalled `docker`.
}

# ubuntu-latest preinstalled approximation — the honest 20% that catches the
# 80%. Deliberately conservative; extend only with a comment naming the need.
RUNNER_PREINSTALLED: set[str] = {
    "awk", "basename", "bash", "cat", "chmod", "cp", "curl", "cut", "date",
    "df", "dirname", "docker", "du", "env", "find", "gh", "git", "grep",
    "gunzip", "gzip", "head", "jq", "ls", "mkdir", "mv", "node", "npm",
    "npx", "pip", "pip3", "python", "python3", "rm", "sed", "sh",
    "sha256sum", "sleep", "sort", "tail", "tar", "tee", "touch", "tr",
    "uniq", "unzip", "wc", "wget", "which", "xargs", "zip",
}

# Wrapper tokens: strip and keep parsing the remainder of the statement.
_WRAPPER_TOKENS: set[str] = {
    "sudo", "command", "nohup", "exec", "time", "if", "until", "while",
    "then", "else", "elif", "do", "!",
}

# Terminal keywords/builtins: the statement is satisfied — skip it.
# ``{`` / ``}`` are brace-group compound-command delimiters (``{ cmd; } >> f``),
# not external commands — a first token of ``{`` or ``}`` is shell grouping, never
# a tool invocation (real in base-freshness.yml / stale-branches.yml).
SHELL_BUILTINS: set[str] = {
    ".", ":", "[", "[[", "break", "continue", "cd", "declare", "done",
    "echo", "esac", "eval", "exit", "export", "false", "fi", "for",
    "function", "hash", "in", "let", "local", "popd", "printf", "pushd",
    "read", "readonly", "return", "select", "set", "shift", "source",
    "test", "trap", "true", "type", "ulimit", "umask", "unset", "wait",
    "{", "}",
}

WAIVER_RE = re.compile(r"#\s*tool-check:\s*ok\s+(?P<cmd>[\w.+-]+)")
_STMT_SPLIT_RE = re.compile(r"&&|\|\||\||;")
_HEREDOC_RE = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?")
_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=(?P<rest>.*)$", re.DOTALL)
_REDIRECT_RE = re.compile(r"^\d*[<>]")
_COMMENT_SPLIT_RE = re.compile(r"(?:^|\s)#")


def _mask_line(line: str, state: str) -> tuple[str, str]:
    """Mask quoted-string CONTENT on one line with spaces, threading quote
    state ('' / \"'\" / '\"') across lines so multi-line strings (python -c
    bodies) stay opaque. Quote characters themselves are preserved.
    POSIX-ish: no escapes inside single quotes; backslash escapes inside
    double quotes and in bare context.

    An unquoted ``#`` at a word boundary (line start or after whitespace)
    begins a shell comment: the rest of the line is copied verbatim and does
    NOT mutate quote state. Without this, an apostrophe in a prose comment
    (``can't``, ``package's``) would spuriously open single-quote state that
    leaks across lines and desyncs the masking of every command below it —
    the root cause of the ``%s`` / ``s`` / ``evidentia`` fragment noise."""
    out: list[str] = []
    escaped = False
    prev_ws = True  # line start counts as a word boundary
    for i, ch in enumerate(line):
        if state == "'":
            if ch == "'":
                state = ""
                out.append(ch)
            else:
                out.append(" ")
            prev_ws = False
        elif state == '"':
            if escaped:
                escaped = False
                out.append(" ")
            elif ch == "\\":
                escaped = True
                out.append(" ")
            elif ch == '"':
                state = ""
                out.append(ch)
            else:
                out.append(" ")
            prev_ws = False
        else:
            if escaped:
                escaped = False
                out.append(ch)
                prev_ws = False
            elif ch == "\\":
                escaped = True
                out.append(ch)
                prev_ws = False
            elif ch == "#" and prev_ws:
                # Word-boundary '#' → comment; copy the tail verbatim and stop
                # (a comment cannot open a cross-line string).
                out.append(line[i:])
                break
            elif ch == "'":
                state = "'"
                out.append(ch)
                prev_ws = False
            elif ch == '"':
                state = '"'
                out.append(ch)
                prev_ws = False
            else:
                out.append(ch)
                prev_ws = ch.isspace()
    return "".join(out), state


def extract_commands(script: str) -> list[str]:
    """Quote-aware first-token command candidates from a run: block."""
    tokens: list[str] = []
    pending_heredocs: list[str] = []
    continuation = False
    in_case = False
    quote_state = ""
    for raw in script.splitlines():
        if pending_heredocs:
            if raw.strip() == pending_heredocs[0]:
                pending_heredocs.pop(0)
            continue
        masked, quote_state = _mask_line(raw, quote_state)
        if continuation:
            continuation = masked.rstrip().endswith("\\")
            continue
        line = masked.strip()
        if not line or line.startswith("#"):
            continue
        if in_case:
            if re.search(r"\besac\b", line):
                in_case = False
            continue
        # Heredoc openers are detected on the RAW line — a quoted terminator
        # (<<'STANZA') is masked in `masked` and would be missed there.
        for m in _HEREDOC_RE.finditer(raw):
            pending_heredocs.append(m.group(1))
        continuation = line.endswith("\\")
        # Truncate any trailing comment (safe post-masking: a '#' inside a
        # string has been masked away).
        line = _COMMENT_SPLIT_RE.split(line, maxsplit=1)[0].strip()
        if not line:
            continue
        for stmt in _STMT_SPLIT_RE.split(line):
            stmt = stmt.strip()
            m = _ASSIGN_RE.match(stmt)
            if m:
                rest = m.group("rest").strip()
                if not rest or rest.startswith(("'", '"')) or rest.startswith("$(("):
                    continue
                if rest.startswith("$("):
                    stmt = rest[2:].strip()
                else:
                    parts = rest.split(None, 1)
                    if len(parts) < 2:
                        continue
                    stmt = parts[1].strip()
            if stmt.startswith("$(("):
                continue
            if stmt.startswith("$("):
                stmt = stmt[2:].strip()
            while stmt:
                first = stmt.split()[0].strip("\"'()").rstrip(";")
                if first in _WRAPPER_TOKENS:
                    parts = stmt.split(None, 1)
                    stmt = parts[1].strip() if len(parts) > 1 else ""
                    continue
                break
            if not stmt:
                continue
            first = stmt.split()[0].strip("\"'()").rstrip(";")
            if not first or first.startswith(("$", "-", "&")):
                continue
            if _REDIRECT_RE.match(first):
                continue
            if "/" in first or "=" in first:
                continue
            if first == "case":
                in_case = True
                break
            if first in SHELL_BUILTINS:
                continue
            tokens.append(first)
    return tokens


@dataclass
class Finding:
    workflow: str
    job: str
    step: str
    kind: str  # "missing-tool" | "unknown-extra" | "parse-error"
    detail: str


def _load_workflow(path: Path) -> dict | Finding:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return Finding(path.name, "-", "-", "parse-error", str(exc))
    if not isinstance(data, dict):
        return Finding(path.name, "-", "-", "parse-error", "top-level not a YAML mapping")
    return data


def check_workflow_tools(path: Path) -> list[Finding]:
    """G8: per-job, every run-block command must be provided/allowed/waived."""
    data = _load_workflow(path)
    if isinstance(data, Finding):
        return [data]
    findings: list[Finding] = []
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return findings
    for job_id, job in jobs.items():
        if not isinstance(job, dict) or "steps" not in job:
            # Reusable-workflow call jobs (job-level `uses:`) — out of scope v1.
            continue
        available = set(RUNNER_PREINSTALLED)
        steps = job.get("steps") or []
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if isinstance(uses, str):
                available |= ACTION_TOOLS.get(uses.split("@", 1)[0], set())
                continue
            run = step.get("run")
            if not isinstance(run, str):
                continue
            waived = {m.group("cmd") for m in WAIVER_RE.finditer(run)}
            step_name = str(step.get("name", f"step[{idx}]"))
            for cmd in extract_commands(run):
                if cmd in available or cmd in waived:
                    continue
                findings.append(
                    Finding(
                        path.name,
                        str(job_id),
                        step_name,
                        "missing-tool",
                        f"`{cmd}` is not provided by an earlier `uses:` step in "
                        f"job `{job_id}`, not runner-preinstalled, and not "
                        f"waived (`# tool-check: ok {cmd}`)",
                    )
                )
    return findings


_INSTALL_SPEC_RE = re.compile(
    r"(?P<pkg>[A-Za-z0-9][A-Za-z0-9._-]*)\[(?P<extras>[A-Za-z0-9_,\s-]+)\]"
)


def _normalize(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def workspace_manifests() -> list[Path]:
    """Root pyproject + every packages/*/pyproject.toml that exists."""
    candidates = [REPO_ROOT / "pyproject.toml"]
    candidates += sorted((REPO_ROOT / "packages").glob("*/pyproject.toml"))
    return [p for p in candidates if p.is_file()]


def collect_workspace_extras(manifests: list[Path]) -> dict[str, set[str]]:
    extras_by_pkg: dict[str, set[str]] = {}
    for manifest in manifests:
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        project = data.get("project")
        if not isinstance(project, dict) or "name" not in project:
            continue
        extras = project.get("optional-dependencies", {})
        extras_by_pkg[_normalize(str(project["name"]))] = {
            _normalize(e) for e in extras
        }
    return extras_by_pkg


def check_workflow_extras(
    path: Path, extras_by_pkg: dict[str, set[str]]
) -> list[Finding]:
    """G9: workspace-package install-specs may only name declared extras."""
    data = _load_workflow(path)
    if isinstance(data, Finding):
        return []  # the parse error is already reported by the G8 pass
    findings: list[Finding] = []
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return findings
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for idx, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict) or not isinstance(step.get("run"), str):
                continue
            step_name = str(step.get("name", f"step[{idx}]"))
            for m in _INSTALL_SPEC_RE.finditer(step["run"]):
                pkg = _normalize(m.group("pkg"))
                if pkg not in extras_by_pkg:
                    continue  # third-party spec (or shell noise) — out of scope
                declared = extras_by_pkg[pkg]
                for extra in m.group("extras").split(","):
                    if _normalize(extra) not in declared:
                        findings.append(
                            Finding(
                                path.name,
                                str(job_id),
                                step_name,
                                "unknown-extra",
                                f"`{extra.strip()}` is not a declared extra of "
                                f"workspace package `{pkg}` (declared: "
                                f"{sorted(declared)}); pip silently skips "
                                f"unknown extras (exit 0)",
                            )
                        )
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--strict",
        action="store_true",
        help="exit 2 if any finding (incl. parse errors); default is advisory",
    )
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args(argv)

    extras_by_pkg = collect_workspace_extras(workspace_manifests())
    paths = sorted(WORKFLOWS_DIR.glob("*.yml")) + sorted(WORKFLOWS_DIR.glob("*.yaml"))
    findings: list[Finding] = []
    for path in paths:
        findings.extend(check_workflow_tools(path))
        findings.extend(check_workflow_extras(path, extras_by_pkg))

    if args.as_json:
        print(json.dumps({"findings": [asdict(f) for f in findings]}, indent=2))
    else:
        for f in findings:
            print(f"{f.kind:13} {f.workflow} :: {f.job} :: {f.step} :: {f.detail}")
        print(
            f"check_workflow_tools: {len(findings)} finding(s) across "
            f"{len(paths)} workflow file(s)"
        )
    if findings and args.strict:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
