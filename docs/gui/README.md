# Evidentia web console

Evidentia ships a local browser console — a React / Vite / shadcn/ui single-page
app served by the `evidentia-api` FastAPI backend — that drives the same engine
as the CLI without you leaving the browser. It is a sidebar-driven, multi-console
SPA: every CLI workflow that has a UI surface lives behind a left-rail nav item,
grouped under section headers (Analyze, Govern, Connect, Library, Configure).

This is a reference for the console as a whole — what it is, how to launch it,
and a nav-group-by-nav-group tour of every console with a pointer to the
task-focused guide for each. For a step-by-step walkthrough of the gap-analysis
flow specifically (the most common entry point), see
[Serve the local web UI](../wiki/2-guides/serve-the-web-ui.md).

## Install

The console ships as an optional extra on the meta-package:

```bash
# with uv
uv tool install "evidentia[gui]"

# with pip
pip install "evidentia[gui]"
```

The `[gui]` extra pulls in `evidentia-api` (FastAPI + the bundled SPA) alongside
the core CLI. The `evidentia serve` command itself lives in the base `evidentia`
package, but the server it launches is what the extra provides — without it,
`serve` prints an install hint and exits. Everything stays installable from a
single wheel: no separate frontend download, no Node runtime at install time.

A handful of consoles need a further optional extra to reach their full surface
— the two OCSF export formats require the server's `[ocsf]` extra
(`py-ocsf-models`). When it is absent, the relevant control returns an
actionable error for those formats only; every other format and console works
unchanged.

Confirm the console is available before you start:

```bash
evidentia doctor
```

The `evidentia_api` row should report **`installed (web UI available)`**.

## Launch

```bash
evidentia serve
```

By default this:

- Binds uvicorn to **`127.0.0.1:8000`** (localhost only — the console is **not**
  exposed on your network)
- Serves the REST API at `/api/*` and the React SPA at `/`
- Opens `http://127.0.0.1:8000` in your default browser

It is a **blocking** process — it runs in the foreground until you press
**Ctrl+C**.

### Useful flags

Run `evidentia serve --help` for the authoritative set.

| Flag | Default | Purpose |
| --- | --- | --- |
| `--host` | `127.0.0.1` | Interface to bind. `127.0.0.1` is localhost-only. Binding `0.0.0.0` exposes the console on your network — pair it with `--auth-token-file` (see [Auth posture](#auth-posture)). |
| `--port`, `-p` | `8000` | TCP port to serve on. |
| `--no-browser` | off | Don't auto-open a browser (use for headless / remote / scripted starts). |
| `--auth-token-file` | none | Path to a file holding a bearer token. When set, every `/api/*` route requires `Authorization: Bearer <token>`; the liveness probes (`/api/health`, `/api/version`, `/api/openapi.json`, `/api/docs`, `/api/redoc`) bypass it. |
| `--security-headers` / `--no-security-headers` | auto | Inject defense-in-depth response headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS, Permissions-Policy). **Auto** = on for a non-loopback host, off for localhost. |
| `--dev` | off | Permissive CORS for the Vite dev server (pairs with `npm run dev` in `packages/evidentia-ui/`). Frontend development only. |
| `--reload` | off | uvicorn auto-reload for backend development. |

To start it on a different port without grabbing browser focus:

```bash
evidentia serve --port 8137 --no-browser
```

Confirm it's live from a second terminal:

```bash
curl -s http://127.0.0.1:8000/api/health
```

The health probe returns a small JSON object — `status` `ok` plus the running
version. The SPA itself is served at the root (`http://127.0.0.1:8000/`).

## The console tour

Browse to **`http://127.0.0.1:8000`**. The left navigation rail groups every
console under section headers. The top item (Home) sits above the groups; the
backend-status card (connection dot, version, air-gap posture, configured model)
lives at the foot of the rail. A header breadcrumb names the active console, and
a theme toggle flips light / dark.

Each console mirrors the corresponding CLI verb and calls the same engine over
`/api/*` — there is no UI-only logic path. Routes below are the ones
`AppLayout`'s nav rail and `App.tsx` actually register.

### Home

| Console | Route | Purpose |
| --- | --- | --- |
| **Home** | `/` | Welcome + onboarding — load a sample scenario or upload an inventory to get started. |

The landing screen is the on-ramp: it seeds a starting inventory (or loads a
bundled sample) so the Analyze consoles have something to work against.

### Analyze

| Console | Route | Purpose | Guide |
| --- | --- | --- | --- |
| **Gap Analyze** | `/gap/analyze` | Run a gap analysis in-browser against one or more frameworks; results persist to the local gap store and carry an export control. | [Serve the web UI](../wiki/2-guides/serve-the-web-ui.md) · [Run a gap analysis](../wiki/2-guides/run-gap-analysis.md) |
| **Gap Diff** | `/gap/diff` | Compare two saved gap reports (base vs head) — opened / closed / severity-shifted / unchanged per gap. | [Run a gap analysis](../wiki/2-guides/run-gap-analysis.md) |
| **Risk Generate** | `/risk/generate` | Stream AI-authored risk statements for the top-priority gaps of a saved report (LLM resolved server-side). | [Generate and quantify risk](../wiki/2-guides/generate-and-quantify-risk.md) |
| **Risk Quantify** | `/risk/quantify` | FAIR risk quantification — loss-event frequency / magnitude into an annualized loss range. | [Generate and quantify risk](../wiki/2-guides/generate-and-quantify-risk.md) |
| **Explain Control** | `/explain` | Plain-English help for any control (what it means, why it matters, what to do); LLM-backed with on-disk caching. | [Explain a control](../wiki/2-guides/explain-controls.md) |

### Govern

| Console | Route | Purpose | Guide |
| --- | --- | --- | --- |
| **POA&M** | `/poam` | Plan of Action & Milestones — track remediation items to closure. | [Manage POA&M items](../wiki/2-guides/manage-poam.md) |
| **Continuous Monitoring** | `/conmon` | Continuous-monitoring cadences and check status. | [Deploy continuous monitoring](../wiki/2-guides/conmon-deployment.md) |
| **TPRM** | `/tprm` | Third-party / vendor risk management. | [Manage third-party risk](../wiki/2-guides/manage-third-party-risk.md) |
| **Governance** | `/governance` | Governance challenges, metrics, and workflows. | [Governance metrics and workflows](../wiki/2-guides/governance-metrics-and-workflows.md) |
| **Retention** | `/retention` | Records-retention metadata, the WORM extend-only lock, legal holds, and the active → preserved → expired → purged lifecycle. | [Manage audit retention](../wiki/2-guides/manage-retention.md) |
| **Evidence** | `/evidence` | The append-only, WORM-enforced evidence store — artifact versioning and lineage. | [Track evidence lineage](../wiki/2-guides/track-evidence-lineage.md) |
| **Model Risk** | `/model-risk` | SR 11-7 model inventory and model-risk metadata. | [Manage model risk](../wiki/2-guides/manage-model-risk.md) |
| **AI Governance** | `/ai-gov` | EU AI Act / NIST AI RMF system registry. | [AI governance](../wiki/2-guides/ai-governance.md) |
| **OSCAL Verify** | `/oscal` | Verify a signed OSCAL Assessment Result you upload (read-only — signing stays a CLI / air-gap operation). | [Sign and verify evidence](../wiki/2-guides/sign-and-verify-evidence.md) |
| **Traceability** | `/traceability` | Control ↔ threat traceability matrix (read-only view; the signed OSCAL Profile is emitted from the CLI). | [Emit a traceability matrix](../wiki/2-guides/emit-traceability-matrix.md) |

### Connect

| Console | Route | Purpose | Guide |
| --- | --- | --- | --- |
| **Collect** | `/collect` | Run evidence collectors against AWS, GitHub, Okta, SQL databases, Snowflake, and more. Credentials stay server-side; the URL-mode collector carries the `--block-private-ips` SSRF guard. **Credentialed — auth-gated** (see below). | [Run evidence collectors](../wiki/2-guides/run-collectors.md) |
| **Integrations** | `/integrations` | Push gaps to Jira / ServiceNow and publish to Tableau / Power BI. Credentials stay server-side, with an external-push confirmation step. **Credentialed — auth-gated** (see below). | [Push to integrations](../wiki/2-guides/push-to-integrations.md) |

### Library

| Console | Route | Purpose | Guide |
| --- | --- | --- | --- |
| **Dashboard** | `/dashboard` | Every saved gap report from the local gap store, with coverage and gap-count summaries; click through to a report. | — |
| **Frameworks** | `/frameworks` | Browse the bundled catalogs (filter by tier / category / free-text); drill into a framework's detail page (`/frameworks/:id`) for its full control list. | [Browse and manage catalogs](../wiki/2-guides/manage-catalogs.md) |
| **Catalog mgmt** | `/catalog` | Catalog management — list, inspect, crosswalk, import, and remove catalogs; the bundled-vs-user-imported split and per-catalog license tiers. | [Browse and manage catalogs](../wiki/2-guides/manage-catalogs.md) |

### Configure

| Console | Route | Purpose |
| --- | --- | --- |
| **Settings** | `/settings` | Read-only configuration view — project config, per-provider LLM presence badges (booleans and source identifiers only; **the browser never sees a key value**), and the per-subsystem air-gap posture matching `evidentia doctor --check-air-gap`. |

## Auth posture

Evidentia's API ships **anonymous-by-default and RBAC-permissive**: when no
auth token is configured, anything that can reach the local API can drive the
console — including its mutating and credentialed actions. The console surfaces
this honestly, in two layers, per the v0.10.12 threat model §4(c):

1. **The `SecurityPostureBanner` (soft, always-visible).** When the server
   reports `auth_configured = false`, a persistent strip across the top of the
   workspace reads *"Unsecured deployment"* and explains that the API has no
   authentication, that anyone who can reach it can read and modify local
   compliance data, and that credentialed actions are disabled. It points at
   `EVIDENTIA_API_AUTH_TOKEN_FILE` as the fix. Once an auth token **is**
   configured the banner renders nothing — a secured deployment (and the static
   demo bundle) shows no strip.

2. **Auth-gated credentialed buttons (hard).** The two consoles that make
   **outbound, authenticated** calls — **Collect** and **Integrations** — gate
   their "Run" / "Push" buttons on `auth_configured`. On an unsecured
   (anonymous) deployment those buttons are **disabled**, with an inline
   explanation, until you set `EVIDENTIA_API_AUTH_TOKEN_FILE`. The read-only and
   local-store consoles stay usable either way; only the network-egress,
   credential-bearing actions are held back.

To secure a deployment — required before binding anything beyond `127.0.0.1` —
start the server with a bearer token file:

```bash
evidentia serve --auth-token-file /path/to/token --host 0.0.0.0
```

Every `/api/*` route then requires `Authorization: Bearer <token>` (the liveness
probes stay open), the §4(c) banner clears, and the credentialed Run buttons
unlock. For a non-loopback host, `--security-headers` engages automatically.

> Keep the default `127.0.0.1` bind for single-operator local use. Air-gapped
> operators can keep everything local — see
> [Air-gapped install](../wiki/2-guides/air-gapped-install.md).

## Gap-export control

When a gap analysis finishes on the **Gap Analyze** console, an **Export format**
control sits in the results header next to the gap-count badges — a format
dropdown plus a **Download** button. Pick a format, click **Download**, and the
browser saves the artifact.

Under the hood the control posts the in-memory report to
**`POST /api/gap/export`**, which reuses the CLI's `export_report` emitters (no
second serialization implementation) and streams the bytes back with a
`Content-Disposition: attachment` header. An export from the console is therefore
byte-for-byte what `evidentia gap analyze --format <id>` produces on the same
report. The dropdown offers the same eight formats the CLI honors:

| Format | `--format` id | Notes |
| --- | --- | --- |
| **JSON** | `json` | Full report in Evidentia's native schema. |
| **OSCAL AR** | `oscal-ar` | OSCAL Assessment Results. |
| **SARIF** | `sarif` | SARIF 2.1.0 — load into GitHub code-scanning / CI gates. |
| **OCSF Compliance** | `ocsf` | OCSF Compliance Finding (class 2003). Requires the `[ocsf]` extra. |
| **OCSF Detection** | `ocsf-detection` | OCSF Detection Finding (class 2004, SIEM-oriented). Requires the `[ocsf]` extra. |
| **CycloneDX VEX** | `cyclonedx-vex` | CycloneDX 1.6 VEX. |
| **CSV** | `csv` | One row per gap. |
| **Markdown** | `markdown` | Human-readable report. |

A failed export surfaces the server's error inline — most often the
`[ocsf]`-extra hint for the two OCSF formats.

## REST API

Every console is powered by the REST API under `/api/*`. FastAPI auto-generates
interactive docs:

- **Swagger UI**: http://127.0.0.1:8000/api/docs
- **ReDoc**: http://127.0.0.1:8000/api/redoc
- **OpenAPI JSON**: http://127.0.0.1:8000/api/openapi.json

See [`architecture.md`](architecture.md) for a per-endpoint reference.

## Accessibility

The console uses [shadcn/ui](https://ui.shadcn.com/) components built on
[Radix UI primitives](https://www.radix-ui.com/), which carry WCAG 2.1 AA
behavior out of the box:

- Keyboard navigation (Tab / Shift+Tab / Enter / Escape) on every interactive
  element
- ARIA labels and live regions on status indicators (the connection state is an
  `aria-live` region)
- Screen-reader announcements for state changes
- Focus management in dialogs and drawers
- Sufficient color contrast in both the light and dark themes (toggle in the
  header)

## Troubleshooting

### "The Evidentia web UI is not bundled in this install" / `evidentia-api is not installed`

The SPA static assets or the API package are missing. Either the `[gui]` extra
isn't present, or you're developing locally without having built the frontend.

- Install the extra: `pip install "evidentia[gui]"` (or
  `uv tool install "evidentia[gui]"`), then re-run. Confirm with
  `evidentia doctor` — the `evidentia_api` row should read
  `installed (web UI available)`.
- Developing locally? Build the frontend once:
  ```bash
  cd packages/evidentia-ui
  npm install
  npm run build
  ```
  Or use `evidentia serve --dev` and run `npm run dev` in a second terminal.

### "Could not reach the backend" / a red "disconnected" badge

- The server isn't running. Start it with `evidentia serve`.
- A firewall / VPN is blocking the port. Try another: `evidentia serve --port 8137`.

### "Page not found"

You've hit a path outside the app's routes (a typo or a stale bookmark). Use the
left sidebar — every implemented console is grouped there.

### Export fails for `ocsf` / `ocsf-detection`

Those two formats need the server's `[ocsf]` extra
(`pip install "evidentia-core[ocsf]"`). The other six formats are unaffected.

### `/api/*` returns 401

You started the server with `--auth-token-file`; every `/api/*` route then needs
`Authorization: Bearer <token>` matching the file's contents (the liveness probes
`/api/health` and `/api/version` are the exceptions and stay open).

### Collect / Integrations "Run" buttons are disabled

The deployment is unsecured (anonymous), so the §4(c) auth gate holds the
credentialed buttons back. Set `EVIDENTIA_API_AUTH_TOKEN_FILE` (or start with
`--auth-token-file`) to unlock them — see [Auth posture](#auth-posture).

### "SECURITY: binding to ..." warning

You passed `--host 0.0.0.0` (or another non-loopback address). Bind to
`127.0.0.1` unless you've set `--auth-token-file` and placed the service behind
an authenticated reverse proxy.

## Developer notes

- Frontend lives in `packages/evidentia-ui/` (Vite + React + TS). Routes are
  registered in `src/App.tsx`; the nav rail, group ordering, and per-console
  labels/descriptions live in `src/components/layout/AppLayout.tsx` (one edit
  adds a console).
- Backend lives in `packages/evidentia-api/` (FastAPI).
- At wheel-build time, the hatchling build hook
  (`packages/evidentia-api/hatch_build.py`) runs `npm run build` in the UI dir
  and copies `dist/*` into the Python package's `static/` directory.
- Set `EVIDENTIA_SKIP_FRONTEND_BUILD=1` to skip the frontend build in CI
  matrices that only test Python code.
- Set `EVIDENTIA_API_OFFLINE=1` / `EVIDENTIA_API_DEV=1` to control the
  subprocess-launched server's mode (used internally by `evidentia serve`).
- The console renders its version from the API (`/api/health`) — never hardcode
  a version literal in a `.tsx` file (the frontend guard hard-fails on one).
