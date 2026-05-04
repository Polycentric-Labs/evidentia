# Evidentia Web UI — architecture reference

v0.4.0 ships two new pieces alongside the existing CLI + core packages:

- **`evidentia-api`** (Python) — FastAPI REST server that exposes every CLI capability over HTTP. Bundles the React SPA as static assets.
- **`evidentia-ui`** (Node/Vite) — React + TypeScript + shadcn/ui frontend. Not a Python workspace member; built separately and copied into the API package's `static/` directory.

Together they form the localhost web UI served by `evidentia serve`.

## Request flow

```
Browser ─► http://127.0.0.1:8000/           (SPA HTML)
Browser ─► /api/frameworks                  (REST API)
                │
                ▼
        FastAPI router dispatch
                │
                ▼
    evidentia_core.catalogs.FrameworkRegistry
    evidentia_core.gap_analyzer.GapAnalyzer
    evidentia_core.gap_store.{save,load,list}_report
    evidentia_core.gap_diff.compute_gap_diff
    evidentia_ai.{RiskStatementGenerator,ExplanationGenerator}
    evidentia_core.init_wizard.{generate_*,recommend_frameworks}
```

Every API endpoint calls into existing public APIs in `evidentia-core` / `evidentia-ai`. The API layer is a thin rendering layer — no duplicated business logic.

## REST endpoint reference

All endpoints live under `/api/*`. Interactive docs at `/api/docs`.

### Health + version

| Method | Path | Response | Purpose |
|---|---|---|---|
| GET | `/api/health` | `{status, version}` | Liveness probe (used by Playwright wait-on) |
| GET | `/api/version` | `{api_version, core_version, ai_version, python_version}` | Component version report |

### Configuration

| Method | Path | Response | Purpose |
|---|---|---|---|
| GET | `/api/config` | `EvidentiaConfig` | Current `evidentia.yaml` contents (walks CWD → parents) |
| PUT | `/api/config` | `EvidentiaConfig` | Write validated config to the discovered path (or `./evidentia.yaml`) |

### Diagnostics + air-gap

| Method | Path | Response | Purpose |
|---|---|---|---|
| GET | `/api/doctor` | `{subsystems: [...]}` | Per-subsystem health summary (mirrors `evidentia doctor`) |
| POST | `/api/doctor/check-air-gap` | `AirGapCheckResponse` | Audit offline posture without network IO |

### LLM configuration

| Method | Path | Response | Purpose |
|---|---|---|---|
| GET | `/api/llm-status` | `LlmStatusResponse` | Per-provider presence + source identifier. **Never returns key values.** |

### Frameworks

| Method | Path | Response | Purpose |
|---|---|---|---|
| GET | `/api/frameworks?tier=A&category=control` | `{total, frameworks: [...]}` | List all 89 bundled catalogs |
| GET | `/api/frameworks/{id}` | `ControlCatalog` | Framework metadata + full control tree |
| GET | `/api/frameworks/{id}/controls/{control_id}` | `CatalogControl` | Single control detail (normalized ID lookup) |

### Gap analysis

| Method | Path | Response | Purpose |
|---|---|---|---|
| POST | `/api/gap/analyze` | `GapAnalysisReport` | Run `GapAnalyzer.analyze()`, save to gap store |
| GET | `/api/gap/reports` | `{total, reports: [...], store_dir}` | List saved reports, newest first |
| GET | `/api/gap/reports/{key}` | `GapAnalysisReport` | Load a report by SHA-16 hex key |
| POST | `/api/gap/diff` | `GapDiff` | Compute diff between two saved reports |

### LLM-backed endpoints (SSE)

Long-running LLM calls stream progress via Server-Sent Events so the browser can render per-gap status without blocking.

| Method | Path | Stream format | Purpose |
|---|---|---|---|
| POST | `/api/risk/generate` | JSON events: `{phase: start/progress/error/done, ...}` | Generate risk statements for selected gaps, concurrent fan-out via `asyncio.as_completed` |
| POST | `/api/explain/{framework}/{control_id:path}` | JSON events: `{phase: start/done/error, explanation?}` | Plain-English explanation of a control, cached on disk per `(framework, control, model, temperature)` tuple |

### Onboarding wizard

| Method | Path | Response | Purpose |
|---|---|---|---|
| POST | `/api/init/wizard` | `InitWizardResponse` | Generate three starter YAMLs (`evidentia.yaml`, `my-controls.yaml`, `system-context.yaml`) + framework recommendations from lightweight industry / hosting / data-type input |

## React frontend

Routes are declared in `packages/evidentia-ui/src/App.tsx`:

```
/                   HomePage              Welcome + quick-nav cards
/dashboard          DashboardPage         Historical gap reports + metrics
/frameworks         FrameworksPage        82-framework browser with filters
/frameworks/:id     FrameworkDetailPage   Framework metadata + control list
/settings           SettingsPage          Config view + LLM status + air-gap

# v0.4.0-alpha.2
/gap/analyze        GapAnalyzePage        Interactive analysis form
/gap/diff           GapDiffPage           Two-report picker + diff view
/risk/generate      RiskGeneratePage      SSE-streamed risk generation
```

### Component tree

- `src/main.tsx` — StrictMode + QueryClientProvider + BrowserRouter
- `src/App.tsx` — Route table wrapped in `AppLayout`
- `src/components/layout/AppLayout.tsx` — Header (connection + air-gap badges) + sidebar nav + outlet
- `src/components/ui/` — shadcn/ui primitives (Button, Card, Badge, Separator)
- `src/routes/*` — One file per page
- `src/lib/api.ts` — Typed fetch wrapper + `api` object exposing every endpoint
- `src/types/api.ts` + `src/types/catalog.ts` + `src/types/config.ts` — TypeScript mirrors of Pydantic response models

### Data fetching

Every API call flows through TanStack Query. Standard hook pattern:

```tsx
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

export function FrameworksPage() {
  const query = useQuery({
    queryKey: ["frameworks", tier, category],
    queryFn: () => api.listFrameworks({ tier, category }),
  });
  // ... render with query.isPending / query.isError / query.data
}
```

30-second `staleTime` + `retry: 1` + `refetchOnWindowFocus: false` are set as global defaults in `main.tsx`. Override per-hook when needed.

### Styling

- Tailwind CSS 3 with shadcn/ui's New York preset
- Theme CSS vars in `src/index.css` (dark mode toggled via `.dark` class — not exposed in UI yet, planned for alpha.2)
- Evidentia severity palette: `--severity-critical/high/medium/low/informational` — pairs with `<Badge variant="critical">` / `"high"` / etc.

## Bundling + release

1. `uv build --all-packages` in the release workflow.
2. Hatchling build hook (`packages/evidentia-api/hatch_build.py`) fires:
   - If `EVIDENTIA_SKIP_FRONTEND_BUILD` is set, no-op.
   - Else, check `packages/evidentia-ui/dist/`. If empty, run `npm ci && npm run build`.
   - Copy `packages/evidentia-ui/dist/*` → `packages/evidentia-api/src/evidentia_api/static/`.
3. Hatchling packages the wheel with the populated `static/` directory.
4. `twine check dist/*`.
5. The release workflow verifies `evidentia_api/static/index.html` is present in the wheel before PyPI publish.

End users `pip install "evidentia[gui]"` — the wheel ships self-contained. No Node required at install time.

## Accessibility

shadcn/ui is built on Radix UI primitives, which implement the [WAI-ARIA Authoring Practices](https://www.w3.org/WAI/ARIA/apg/) for every interactive widget. Out of the box we get:

- Keyboard navigation (Tab, arrow keys, Home/End, typeahead)
- ARIA labels, `aria-live` regions on connection status
- Focus management in dialogs, menus, comboboxes
- Color-contrast tokens meeting WCAG 2.1 AA in both light and dark themes

Remaining gaps (automated a11y testing in CI, formal audit) are tracked for alpha.2.

## Dev loop

Two-terminal setup:

```bash
# Terminal 1 — FastAPI backend with permissive CORS
evidentia serve --dev

# Terminal 2 — Vite dev server with HMR
cd packages/evidentia-ui
npm install       # first time only
npm run dev       # http://127.0.0.1:5173
```

The Vite dev server proxies `/api/*` to `http://127.0.0.1:8000` so `fetch("/api/health")` just works. Edit TS / TSX, see it reload in the browser.

For production-ish local testing: `npm run build` then `evidentia serve` (without `--dev`) serves the built SPA directly from the FastAPI process.
