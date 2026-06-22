# Serve the local web UI

Evidentia ships a local browser UI — a React single-page app backed by a FastAPI
server — that runs the same gap-analysis engine as the CLI without you leaving
the browser. This guide installs the UI, starts it with `evidentia serve`,
walks the in-browser gap-analysis workflow, and uses the **gap-export control**
to download a report in any of the engine's eight formats. The server binds to
`127.0.0.1` by default, so the whole thing stays on your machine — the same
localhost-only / air-gap posture the CLI reports.

## Prerequisites

- **The `[gui]` extra.** `evidentia serve` lives in the base `evidentia`
  package, but the server it launches (the `evidentia-api` FastAPI app plus the
  bundled `evidentia-ui` frontend) ships in the **`[gui]` optional extra**.
  Without it, `serve` prints an install hint and exits. Install it with:

  ```bash
  pip install "evidentia[gui]"
  # or, for an isolated tool install:
  uv tool install "evidentia[gui]"
  ```

- **(Optional) the `[ocsf]` extra** if you intend to export the two OCSF
  formats. `ocsf` and `ocsf-detection` require the server's `[ocsf]` extra
  (`py-ocsf-models`); the other six formats are always available. Without it the
  export control returns an actionable error for those two formats only — see
  [Got stuck?](#got-stuck).

Confirm the web UI is available before you start:

```bash
evidentia doctor
```

You should see the `evidentia_api` row report **`installed (web UI available)`**.
Add `--check-air-gap` to see the localhost-bind posture spelled out:

```
evidentia doctor --check-air-gap
```

The Air-gap Posture Report lists a **Web UI** row reading
`` `evidentia serve` binds to 127.0.0.1 by default ``.

## Step 1 — Start the server

```bash
evidentia serve
```

By default this binds **`127.0.0.1:8000`** (localhost only), serves the React SPA
at `/` and the REST API at `/api/*`, and auto-opens your browser. It is a
**blocking** process — it runs in the foreground until you press **Ctrl+C**.

Useful flags (run `evidentia serve --help` for the authoritative set):

| Flag | Default | What it does |
| --- | --- | --- |
| `--host` | `127.0.0.1` | Interface to bind. `127.0.0.1` is localhost-only. Binding `0.0.0.0` exposes the UI on your network — Evidentia has no built-in auth by default, so only do this deliberately (and pair it with `--auth-token-file`). |
| `--port`, `-p` | `8000` | Port to serve on. |
| `--no-browser` | off | Don't auto-open a browser on startup (use this for headless / remote / scripted starts). |
| `--security-headers` / `--no-security-headers` | auto | Inject defense-in-depth response headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Strict-Transport-Security, Permissions-Policy). **Auto** = on when `--host` is non-loopback, off for localhost. Force with the explicit flag. |
| `--auth-token-file` | none | Path to a file holding a bearer token. When set, every `/api/*` route requires `Authorization: Bearer <token>`; liveness probes (`/api/health`, `/api/version`, `/api/openapi.json`, `/api/docs`, `/api/redoc`) bypass it. When omitted, no auth gating fires. |
| `--dev` | off | Permissive CORS for the Vite dev server at `:5173`. For frontend development only. |
| `--reload` | off | Enable uvicorn `--reload` for backend development. |

To start it on a different port without grabbing focus:

```bash
evidentia serve --port 8137 --no-browser
```

Once it's up you can confirm it's live from a second terminal:

```bash
curl -s http://127.0.0.1:8000/api/health
```

The health probe returns a small JSON object with `status` `ok` and the running
version, e.g. `{"status":"ok","version":"..."}`. The SPA itself is served at the
root (`http://127.0.0.1:8000/`).

> **Security note.** There is no authentication on `/api/*` unless you pass
> `--auth-token-file`. Keep the default `127.0.0.1` bind for single-operator
> local use. If you must bind a routable interface, set `--auth-token-file` and
> let `--security-headers` engage (it does so automatically for a non-loopback
> host). Air-gapped operators can keep everything local — see
> [Air-gapped install](air-gapped-install.md).

## Step 2 — Open the UI

Browse to **`http://127.0.0.1:8000`** (or whatever `--port` you chose). The app
is a sidebar-driven, multi-console SPA. The left navigation groups every console
under section headers (Analyze, Govern, Connect, Library, Configure); the full
set is below.

| Sidebar item | Route | Purpose |
| --- | --- | --- |
| **Home** | `/` | Welcome + onboarding (upload an inventory or load a sample to get started). |
| _Analyze_ | | |
| **Gap Analyze** | `/gap/analyze` | Run a gap analysis in-browser (the focus of this guide). |
| **Gap Diff** | `/gap/diff` | Compare two saved gap reports (base vs head). |
| **Risk Generate** | `/risk/generate` | Generate AI risk statements. |
| **Risk Quantify** | `/risk/quantify` | FAIR risk quantification. |
| **Explain Control** | `/explain` | Plain-English control help. |
| _Govern_ | | |
| **POA&M** | `/poam` | Plan of Action & Milestones. |
| **Continuous Monitoring** | `/conmon` | Continuous monitoring / cadences. |
| **TPRM** | `/tprm` | Third-party risk management. |
| **Governance** | `/governance` | Challenges, metrics, workflows. |
| **Retention** | `/retention` | Records retention + legal hold. |
| **Evidence** | `/evidence` | WORM evidence store. |
| **Model Risk** | `/model-risk` | SR 11-7 model inventory. |
| **AI Governance** | `/ai-gov` | EU AI Act / NIST AI RMF registry. |
| **OSCAL Verify** | `/oscal` | Verify a signed Assessment Result (read-only; signing stays a CLI / air-gap operation). |
| **Traceability** | `/traceability` | Control ↔ threat matrix. |
| _Connect_ | | |
| **Collect** | `/collect` | Evidence collectors. |
| **Integrations** | `/integrations` | Jira / ServiceNow / BI. |
| _Library_ | | |
| **Dashboard** | `/dashboard` | Saved gap reports from the local gap store. |
| **Frameworks** | `/frameworks` | Browse the bundled catalogs; drill into a framework's detail page (`/frameworks/:id`). |
| **Catalog mgmt** | `/catalog` | Catalog management — import / crosswalk / license. |
| _Configure_ | | |
| **Settings** | `/settings` | Config + LLM + air-gap. |

This guide drives the **Gap Analyze** screen.

## Step 3 — Run a gap analysis in the browser

Open **Gap Analyze** (`/gap/analyze`). The page mirrors the CLI's
`evidentia gap analyze` and saves its result to the local gap store
automatically. Fill the form top to bottom:

1. **1. Inventory** — provide your control inventory one of two ways:
   - **Upload file** — choose a local YAML / JSON / CSV inventory. The browser
     reads the file contents and posts them inline.
   - **Or server path** — type an absolute path the server process can read.
     (Handy for CI / headless / power-user flows. The server restricts this to
     paths inside its working directory for safety; for anything else, upload
     the file instead.)
2. **2. Frameworks** — click one or more framework chips to select them (each
   shows its tier as `(T…)`). At least one is required. Use the **Frameworks**
   browser if you need help picking.
3. **Organization / System name overrides (optional)** — leave blank to inherit
   the values from the inventory.
4. Click **Run analysis**.

The results render in place: total / critical / high gap badges, a **Coverage**
metric, the number of frameworks analyzed, efficiency-opportunity count, and a
full gap table. The report is also persisted to the gap store and shows up on
the **Dashboard**.

> The in-browser run calls `POST /api/gap/analyze`, which invokes the same
> `GapAnalyzer` the CLI uses. The result is the identical
> `GapAnalysisReport` shape — there is no UI-only analysis path.

## Step 4 — Export the report (the gap-export control)

Once results are showing, the **Export format** control sits in the results
header next to the gap-count badges. It is a format dropdown plus a **Download**
button.

Pick a format, click **Download**, and the browser saves the artifact. Under the
hood the control posts the in-memory report to **`POST /api/gap/export`**, which
reuses the CLI's `export_report` emitters (no second serialization
implementation) and streams the bytes back with a
`Content-Disposition: attachment` header so the file downloads directly. The
suggested filename is derived from the report's organization plus a
format-appropriate extension.

The dropdown offers **eight formats** — the exact set the CLI's
`evidentia gap analyze --format` honors:

| Format (dropdown label) | `--format` id | Downloaded as | Notes |
| --- | --- | --- | --- |
| **JSON** | `json` | `.json` | Full report in Evidentia's native schema. |
| **OSCAL AR** | `oscal-ar` | `.oscal.json` | OSCAL Assessment Results. |
| **SARIF** | `sarif` | `.sarif` | SARIF 2.1.0 — load into GitHub code-scanning / CI gates. |
| **OCSF Compliance** | `ocsf` | `.ocsf.json` | OCSF Compliance Finding (class 2003). Requires the `[ocsf]` extra. |
| **OCSF Detection** | `ocsf-detection` | `.ocsf-detection.json` | OCSF Detection Finding (class 2004, SIEM-oriented). Requires the `[ocsf]` extra. |
| **CycloneDX VEX** | `cyclonedx-vex` | `.vex.cdx.json` | CycloneDX 1.6 VEX. |
| **CSV** | `csv` | `.csv` | One row per gap. |
| **Markdown** | `markdown` | `.md` | Human-readable report. |

Selecting a format shows a one-line hint beneath the dropdown describing what it
produces; a failed export surfaces the server's error message inline.

Because every format is the engine's own emitter, an export from the UI is
byte-for-byte what you'd get from the CLI's `evidentia gap analyze --format <id>`
on the same report.

## Step 5 — Stop the server

Press **Ctrl+C** in the terminal running `evidentia serve`. If you started it
headless (`--no-browser`) in another shell, stop it by terminating that process
(for example, `kill` the PID, or close the terminal). The server holds no
external state beyond the gap-store files it already wrote.

## What's next

- **Run the same analysis from the CLI**: [Run a gap analysis](run-gap-analysis.md)
  — same engine, same eight `--format` emitters, scriptable.
- **Keep everything offline**: [Air-gapped install](air-gapped-install.md) — the
  `127.0.0.1` bind plus the air-gap posture report make the UI air-gap friendly.
- **Every `serve` and `gap` flag**: [CLI reference](../4-reference/cli.md).
- **Compare reports over time**: use the **Gap Diff** screen (`/gap/diff`) on two
  saved reports.

## Got stuck?

- **`evidentia-api is not installed`** on `evidentia serve` — the `[gui]` extra
  isn't present. Install it: `pip install "evidentia[gui]"` (or
  `uv tool install "evidentia[gui]"`), then re-run. Confirm with
  `evidentia doctor` (the `evidentia_api` row should read
  `installed (web UI available)`).
- **The browser shows "Page not found"** — you've hit a path outside the app's
  routes (a typo or a stale bookmark). Use the left sidebar to reach a console —
  every implemented route is grouped there and listed in
  [Step 2](#step-2-open-the-ui).
- **Export fails for `ocsf` / `ocsf-detection`** with an "unavailable / install
  the `[ocsf]` extra" message — those two formats need the server's `[ocsf]`
  extra (`pip install "evidentia-core[ocsf]"`). The other six formats are
  unaffected.
- **`POST /api/gap/export` returns 400** — the request must carry exactly one of
  an inline `report` or a `report_key`, and a supported `format`. The in-browser
  control always sends the current in-memory report, so this surfaces only for
  hand-crafted API calls.
- **Port already in use** — pass a different `--port` (for example
  `evidentia serve --port 8137`).
- **`/api/*` returns 401** — you started the server with `--auth-token-file`;
  every `/api/*` route then needs `Authorization: Bearer <token>` matching the
  file's contents (the liveness probes `/api/health` and `/api/version` are the
  exceptions and stay open).
