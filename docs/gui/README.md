# Evidentia Web UI

v0.4.0 introduces a local web UI for Evidentia — a React/Vite/shadcn/ui frontend served by a FastAPI backend. This guide covers installation, first-run, page-by-page feature walkthrough, and troubleshooting.

## Install

The web UI ships as an optional extra on the meta-package:

```bash
# with uv
uv tool install "evidentia[gui]"

# with pip
pip install "evidentia[gui]"
```

The extra pulls in `evidentia-api` (FastAPI + bundled SPA) alongside the core CLI. Everything stays installable from a single wheel — no separate frontend download, no Node runtime needed at install time.

## Launch

```bash
evidentia serve
```

By default this:

- Binds uvicorn to `127.0.0.1:8000` (localhost only — the UI is **not** exposed on your network)
- Opens `http://127.0.0.1:8000` in your default browser
- Serves the REST API at `/api/*` and the React SPA at `/`

Ctrl+C to stop.

### Useful flags

| Flag | Default | Purpose |
|---|---|---|
| `--port / -p` | `8000` | TCP port to bind |
| `--host` | `127.0.0.1` | Bind address. `0.0.0.0` emits a security warning (no auth in v0.4.0) |
| `--no-browser` | — | Don't auto-open a browser |
| `--reload` | — | uvicorn auto-reload for backend development |
| `--dev` | — | Permissive CORS for Vite HMR (pairs with `npm run dev` in `packages/evidentia-ui/`) |
| `--offline` | — | Air-gapped mode (see [`../air-gapped.md`](../air-gapped.md)) |

## Feature walkthrough (v0.7.6 — alpha.2 wired)

> Screenshots in `docs/gui/screenshots/` were captured 2026-05-01
> against `evidentia serve --dev` on Windows 11 / Chromium at
> 1440×900. Re-capture with `.local/capture_screenshots.py` after a
> meaningful UI change.

### Home `/`

![Home](screenshots/home.png)

Welcome screen with the three-path onboarding wizard: "Try sample
data" (preloads the bundled Meridian fintech scenario, 48 controls,
3 frameworks), "Upload inventory" (drag-and-drop YAML / CSV / OSCAL
JSON, auto-detects format), or "Start from scratch" (4-question
wizard generates a starter inventory + recommended frameworks).
Sidebar version footer reflects the v0.7.6 alpha.2 state.

### Dashboard `/dashboard`

Lists every saved gap report from the local gap store (`%APPDATA%\Evidentia\gap_store\` on Windows, `~/.local/share/evidentia/gap_store/` on Linux/macOS). Shows:

- Three metric cards: bundled frameworks count, saved reports count, latest coverage %
- Recent-reports list with org name, timestamp, frameworks analyzed, total/critical gap counts, storage key

Click any report in `alpha.2` to drill into a full per-gap view. For now, use `evidentia gap analyze` in the terminal to create reports.

### Frameworks `/frameworks`

![Frameworks browser](screenshots/frameworks.png)

Browses all 89 bundled catalogs with three filters:

- **Tier** — A (public domain), B (free-restricted), C (licensed), D (government regulation)
- **Category** — control, technique, vulnerability, obligation
- **Free-text search** — matches ID and name

Click a framework card to open its detail page.

### Gap Analyze `/gap/analyze` (v0.7.6 alpha.2)

![Gap Analyze](screenshots/gap-analyze.png)

Browser-side equivalent of `evidentia gap analyze`. Two inventory
entry paths (file upload OR server-side path), framework
multi-select, and per-run organization + system-name overrides.
Results render as a `GapTable` below the form with critical / high
/ medium / low badges + coverage % + efficiency-opportunity counts.
Reports save to the local gap store automatically and appear on
the Dashboard.

### Gap Diff `/gap/diff` (v0.7.6 alpha.2)

![Gap Diff](screenshots/gap-diff.png)

Pick two saved gap reports from the gap-store list (or drag-and-drop
external reports). Compare runs the same `evidentia gap diff`
engine that powers the GitHub Action's PR comment. Output:
opened / closed / severity-up / severity-down / unchanged
classification per gap, with download-as-markdown and
download-as-PR-comment buttons.

### Risk Generate `/risk/generate` (v0.7.6 alpha.2)

![Risk Generate](screenshots/risk-generate.png)

Wraps the `/api/risks/generate` SSE endpoint. Pick gaps (or run
batch over a saved report), pick a system context, pick the LLM
provider (OpenAI / Anthropic / Google / Bedrock / Ollama via
LiteLLM), and watch risk statements stream in live with per-gap
progress indicators. Air-gap mode (`--offline`) refuses non-
loopback LLM endpoints; the Settings page shows current
network-egress posture.

### Framework detail `/frameworks/:id`

Metadata header (tier badge, category, version, license notice) plus a full control list. Each control card shows ID (monospace), title, family, and an excerpt of the description (truncated at 300 chars for readability). Placeholder controls (Tier C stubs without authoritative text) are marked distinctly.

### Settings `/settings`

Read-only configuration view (`alpha.1`):

- **Project configuration** — org, system name, framework defaults, LLM model/temperature, from `evidentia.yaml`
- **LLM providers** — per-provider presence badges (OpenAI / Anthropic / Google / Azure OpenAI / Ollama). **The browser never sees key values** — only booleans and source identifiers (`env:OPENAI_API_KEY`, `model:ollama/llama3`, etc.).
- **Air-gap posture** — per-subsystem status matching `evidentia doctor --check-air-gap`

Editing lands in `alpha.2` as a validated form that posts `PUT /api/config`.

## REST API

Every page is powered by the REST API under `/api/*`. FastAPI auto-generates interactive docs:

- **Swagger UI**: http://127.0.0.1:8000/api/docs
- **ReDoc**: http://127.0.0.1:8000/api/redoc
- **OpenAPI JSON**: http://127.0.0.1:8000/api/openapi.json

See [`architecture.md`](architecture.md) for a per-endpoint reference.

## Accessibility

Evidentia's UI uses [shadcn/ui](https://ui.shadcn.com/) components built on top of [Radix UI primitives](https://www.radix-ui.com/). This gives us WCAG 2.1 AA compliance out of the box for:

- Keyboard navigation (Tab / Shift+Tab / Enter / Escape on every interactive element)
- ARIA labels and live regions on status indicators
- Screen-reader announcements for state changes
- Focus management in dialogs and drawers
- Sufficient color contrast in both light and dark themes

Remaining a11y gaps are tracked in `docs/gui/a11y.md` (lands in `alpha.2`).

## Troubleshooting

### "The Evidentia web UI is not bundled in this install"

This JSON response means the SPA static assets are missing from the wheel. Causes:

1. **You're developing locally without having built the frontend.** Run:
   ```bash
   cd packages/evidentia-ui
   npm install
   npm run build
   ```
   Or use `evidentia serve --dev` and run `npm run dev` in a second terminal.

2. **You installed from a source distribution that skipped the frontend build.** Reinstall forcing the frontend build:
   ```bash
   pip uninstall evidentia-api
   pip install --force-reinstall "evidentia[gui]"
   ```

### "Could not reach the backend"

The UI shows a red "disconnected" badge. Causes:

- The server isn't running. Start with `evidentia serve`.
- A firewall / VPN blocks `127.0.0.1:8000`. Try a different port: `evidentia serve --port 8080`.

### The browser didn't open automatically

Use `--no-browser` + open the URL manually, or check your default-browser settings. The auto-open is best-effort and fails silently on some headless / SSH-forwarded environments.

### Port 8000 is in use

Another process owns the port. `evidentia serve --port 8080` picks a different one. The browser auto-open respects `--port`.

### "SECURITY: binding to ..." warning

You passed `--host 0.0.0.0` (or another non-loopback address). Evidentia has no auth in v0.4.0 — anyone who can reach the address can view and modify gap reports. Bind to `127.0.0.1` unless you've placed the service behind an authenticated reverse proxy.

## Developer notes

- Frontend lives in `packages/evidentia-ui/` (Vite + React + TS).
- Backend lives in `packages/evidentia-api/` (FastAPI).
- At wheel-build time, the hatchling build hook (`packages/evidentia-api/hatch_build.py`) runs `npm run build` in the UI dir and copies `dist/*` into the Python package's `static/` directory.
- Set `EVIDENTIA_SKIP_FRONTEND_BUILD=1` to skip the frontend build in CI matrices that only test Python code.
- Set `EVIDENTIA_API_OFFLINE=1` / `EVIDENTIA_API_DEV=1` to control the subprocess-launched server's mode (used internally by `evidentia serve`).
