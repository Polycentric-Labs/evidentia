# IDE setup — Cursor + VS Code

> Version-controlled IDE configuration so Evidentia contributors get
> testing + validation feedback inline, with the same conventions
> across editors. Both Cursor and VS Code read the `.vscode/`
> directory + `.editorconfig`; Cursor additionally reads `.cursorrules`
> for AI guardrails.
>
> Status: shipped in v0.7.2 (per `docs/v0.7.2-plan.md` item DOC6).
> Pre-v0.7.2 contributors used ad-hoc per-developer setups; v0.7.2
> brings the workflow into the repo so onboarding is one-clone.

---

## Quick start

1. **Clone + sync deps**:
   ```bash
   git clone https://github.com/polycentric-labs/evidentia
   cd evidentia
   uv sync --all-extras --all-packages
   ```

2. **Open in your editor**:
   ```bash
   code .       # VS Code
   # or
   cursor .     # Cursor
   ```

3. **Install recommended extensions**: VS Code / Cursor will prompt
   on first open (per `.vscode/extensions.json`). Click
   "Install all recommended" — Python, Pylance, Ruff, Coverage
   Gutters, Markdown, YAML, GitHub Actions, EditorConfig, Prettier,
   ESLint, Tailwind CSS, Vitest, GitLens.

4. **Open the Testing panel** (flask icon in the sidebar). Pytest
   tests should auto-discover under `tests/`. Run any test by
   clicking the arrow next to its node.

5. **Try a debug launch**: pick `Pytest — current file` from the
   Run/Debug dropdown, open any `tests/unit/test_*.py` file, hit F5.

---

## Tooling matrix — what you get inline

| Tool | What it surfaces | How to invoke |
|---|---|---|
| **Pytest** | Test results inline + Test Explorer tree | Auto-run on save (configurable); click ▶ in gutter |
| **Pylance** | Type errors, completions, refactor | Continuous (Pylance is the LSP) |
| **Mypy** | `--strict` errors as squiggles | Continuous via `ms-python.mypy-type-checker` |
| **Ruff** | Lint warnings + auto-fix on save + format | Continuous via `charliermarsh.ruff` |
| **Coverage Gutters** | Per-line coverage from `pytest --cov` | Run "pytest --cov=packages" task → click "Watch" |
| **debugpy** | Step debugger for pytest + `evidentia serve` + CLI | F5 with appropriate launch config |
| **GitLens** | Inline blame, file history, branch comparisons | Continuous |
| **EditorConfig** | Consistent indent / EOL / trailing whitespace | Continuous |
| **Markdown All in One** | TOC generation, link refactor, preview | Continuous |
| **GitHub Actions** | Workflow YAML schema validation | Open `.github/workflows/*.yml` |
| **Vitest Explorer** (UI) | Run UI unit tests inline | Open `packages/evidentia-ui/` |

---

## Defined tasks (Ctrl+Shift+P → "Tasks: Run Task")

Pre-canned tasks live in `.vscode/tasks.json`:

### Python / backend

- **`uv sync (all-extras, all-packages)`** — refresh dependencies
- **`pytest -q (full suite, no coverage)`** — fast test run (~13s)
- **`pytest --cov=packages (full suite + coverage)`** — coverage XML
  for Coverage Gutters + HTML report (`htmlcov/`)
- **`mypy --strict (all 6 packages)`** — strict type-check
- **`ruff check`** / **`ruff check --fix`** / **`ruff format`** —
  lint surface
- **`uv build --all-packages`** — produce 6 wheels + 6 sdists
- **`twine check dist/*`** — distribution validation
- **`Pre-release gate (ruff + mypy + pytest + build + twine)`** — the
  full release-checklist Step 5 gate as a single task
- **`evidentia doctor (smoke check)`** — runtime health check
- **`evidentia serve (FastAPI + UI on :8000)`** — local dev server

### Frontend

- **`Frontend — npm run build (UI dist)`** — produce `packages/evidentia-ui/dist/`
- **`Frontend — npm run dev (Vite HMR)`** — Vite dev server with HMR
- **`Frontend — vitest (UI unit tests)`** — Vitest run
- **`Frontend — typecheck (tsc --noEmit)`** — TypeScript strict check

---

## Defined launch configurations (F5 to debug)

Pre-canned debug configs live in `.vscode/launch.json`:

- **`Pytest — current file`** — debug the test file you have open
- **`Pytest — full suite`** — debug `pytest tests`
- **`Pytest — single test (prompt)`** — prompt for a node id
- **`evidentia serve — FastAPI + UI`** — debug the FastAPI app
- **`evidentia gap analyze — Meridian sample`** — debug a gap analysis
  run end-to-end against the bundled sample inventory
- **`evidentia explain — single control`** — prompt for a control id,
  debug the explain pipeline
- **`evidentia doctor`** — debug the doctor command (incl. `--check-air-gap`)

---

## Cursor-specific guidance

### `.cursorrules` (project-root)

Cursor reads `.cursorrules` for AI guardrails. The Evidentia version
encodes:

- **Quality bar patterns** — typed exception hierarchy, `@with_retry`,
  `BLIND_SPOTS`, audit logger, network_guard, secret scrubber
- **Testing patterns** — pytest mocking, mypy strict, ruff clean, OS
  matrix
- **Frontend patterns** — Radix primitives for WCAG, TanStack Query,
  hand-typed REST surface, Zustand for client state
- **Release/publishing discipline** — Cursor must NEVER suggest
  irreversible commands (`git push`, `git tag && push`, `gh`
  mutations, `twine upload`, etc.)
- **Commit-attribution discipline** — never include `Co-Authored-By:
  Claude` or AI footers in commit metadata

This file is the Cursor-equivalent of `~/.claude/CLAUDE.md` (Allen's
private Claude Code memory) for the parts of that memory that are
project-relevant + safe to commit publicly.

### Cursor Composer / Cursor Tab

- **Composer**: useful for multi-file edits within a single feature
  (e.g., adding a new collector → both the implementation file +
  test file in one prompt). Always sanity-check that imports follow
  the no-shortened-imports rule (no
  `from evidentia_core.models import RiskStatement`).
- **Cursor Tab**: works well for boilerplate completion. Disable
  autocomplete in `tests/` files where you want to write the
  assertions deliberately.

### When to use Cursor vs Claude Code

- **Cursor**: fast local edits, IDE-integrated test feedback, code
  review on a single file, refactor a function, write a short test.
- **Claude Code (CLI)**: ship cycles (release-checklist runs),
  multi-step research (positioning re-sync), cross-doc consistency
  passes, anything that needs the `~/.claude/skills/` skills like
  `pre-release-review`. Per Allen's CLAUDE.md publishing-authority
  protocol, Claude Code is the only tool authorized for irreversible
  actions (push / tag / publish) — and only with explicit per-action
  approval.

---

## Pre-commit hooks (active since v0.7.3)

`.pre-commit-config.yaml` ships at the repo root. Both Cursor and
VS Code run hooks on commit (and on demand via
`pre-commit run --all-files`). One-time setup per clone:

```bash
uv tool install pre-commit
pre-commit install         # installs the .git/hooks/pre-commit shim
pre-commit run --all-files # one-time sweep (optional)
```

Active hooks:

- **ruff (check + format)** — same `[tool.ruff]` config as CI
- **mypy** (strict) — same source roots + flags as the
  `test.yml::typecheck` job
- **markdownlint-cli2** — config at `.markdownlint.yaml`
- **prettier** — applies to `packages/evidentia-ui/{src,public}/`;
  excludes generated TypeScript types at `src/types/api.ts`
- **yamllint** — config at `.yamllint`; scoped to `.github/`,
  `.cursor/`, and `docs/` YAML (the bundled catalog data files under
  `packages/evidentia-core/.../catalogs/data/` are out of scope —
  their upstream sources aren't yamllint-clean by our standards and we
  don't author them)
- **end-of-file-fixer**, **trailing-whitespace**, **check-yaml**,
  **check-toml**, **check-json**, **check-merge-conflict**,
  **check-added-large-files** (max 2 MB to allow CycloneDX SBOM)

Hook config conventions: ruff + mypy + prettier inherit the
project's existing config so editor + CI + hook all behave
identically. yamllint and markdownlint configs ship as
project-root files.

---

## Dev container (active since v0.7.3)

`.devcontainer/devcontainer.json` ships a guaranteed-reproducible
contributor environment. With the
[Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
installed in VS Code or Cursor, click "Reopen in Container" after
cloning and you get:

- Python 3.12 (the primary CI matrix version + `[tool.ruff]` target; CI also
  runs a 3.14 leg since the v0.13 cap lift)
- Node 20 (matches release.yml + test.yml `actions/setup-node` pin)
- `uv` (Astral) — primary Python package + project manager
- `gh` (GitHub CLI) — for the publishing-authority workflow
- `gpg` + `git` + standard build tools (from the base image)
- All recommended VS Code extensions pre-installed (matches
  `.vscode/extensions.json`)
- A `postCreateCommand` that runs `uv sync --all-packages --frozen`
  + installs pre-commit hooks
- Port 8000 forwarded for `evidentia serve`
- A named volume mounted at `/home/vscode/.cache/uv` so dependency
  downloads persist across container rebuilds

Real secrets (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.) are NOT
baked into the container — paste them into a local `.env` per the
secret-handling protocol in your global Claude config.

---

## Troubleshooting

### "Pytest test discovery fails"

- Confirm `python.defaultInterpreterPath` resolves to
  `${workspaceFolder}/.venv/Scripts/python.exe` (Windows) or
  `${workspaceFolder}/.venv/bin/python` (Linux/macOS). On non-Windows,
  edit `.vscode/settings.json` if needed.
- Open the Python output panel: View → Output → Python. Look for
  pytest discovery errors.
- Run from the terminal: `uv run --no-sync python -m pytest --collect-only`.

### "Mypy is slow"

- Mypy runs `--strict` against all 6 packages by default. To narrow
  scope, edit `python.linting.mypyArgs` in `.vscode/settings.json` to
  point at the specific package you're working on.
- Disable continuous mypy by setting `python.linting.mypyEnabled` to
  `false` and run mypy via the Tasks panel instead.

### "Ruff format-on-save modifies too much"

- Ruff applies safe auto-fixes on save (`source.fixAll.ruff`). To
  disable for a session, comment out the `editor.codeActionsOnSave`
  block in `.vscode/settings.json`.
- For one-off cases, prefix the file with `# ruff: noqa: <code>`.

### "Coverage gutters don't update"

- Run the `pytest --cov=packages` task — it writes `coverage.xml` to
  the workspace root.
- Click "Watch" in the Coverage Gutters status-bar widget.
- Reload the window if gutters still don't appear (Ctrl+Shift+P →
  "Developer: Reload Window").

### "Cursor AI suggests bypassing publishing-authority protocol"

- Stop and re-read `.cursorrules`. Cursor must NEVER suggest
  `git push`, `gh issue close`, `twine upload`, etc. Allen runs
  those manually after explicit approval.
- If a Cursor suggestion includes any of those commands, reject it
  and report the suggestion to Allen so the `.cursorrules` rules
  can be hardened.

---

## Related docs

- [`docs/release-checklist.md`](release-checklist.md) — per-release
  runbook (the Pre-release gate task above maps to Step 5)
- [`docs/testing-playbook.md`](testing-playbook.md) — operational
  test loop
- [`docs/enterprise-grade.md`](enterprise-grade.md) — quality bar
  the IDE setup helps enforce
- [`docs/capability-matrix.md`](capability-matrix.md) — what's tested
  + how
