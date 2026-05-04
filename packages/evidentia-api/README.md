# evidentia-api

FastAPI REST server and bundled React web UI for **Evidentia**, the open-source GRC tool.

This package is not typically installed directly. The preferred way is via the `[gui]` extra on the meta-package:

```bash
uv tool install "evidentia[gui]"
# or
pip install "evidentia[gui]"
```

Then run:

```bash
evidentia serve
# -> FastAPI + React UI at http://127.0.0.1:8000
```

## What's inside

- **FastAPI app** (`evidentia_api.app:app`) — REST endpoints mirroring every CLI capability.
- **SPA** — React/Vite/shadcn/ui frontend, bundled as static assets inside the wheel under `evidentia_api/static/`.
- **SSE streaming** — long-running LLM calls (`risk generate`, `explain`) stream progress to the browser without blocking.

## REST surface

Every endpoint is typed with Pydantic models reused from `evidentia-core`. All endpoints bind to `127.0.0.1` by default; `--host 0.0.0.0` emits a security warning.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Health probe |
| GET | `/api/version` | Evidentia version info |
| GET | `/api/doctor` | Diagnostic summary |
| POST | `/api/doctor/check-air-gap` | Air-gap validator |
| GET | `/api/config` | Read `evidentia.yaml` |
| PUT | `/api/config` | Write `evidentia.yaml` |
| GET | `/api/frameworks` | List all 89 bundled catalogs |
| GET | `/api/frameworks/{id}` | Framework detail |
| GET | `/api/frameworks/{id}/controls/{control_id}` | Single control |
| POST | `/api/gap/analyze` | Run GapAnalyzer, save to gap store |
| GET | `/api/gap/reports` | List saved reports |
| GET | `/api/gap/reports/{key}` | Load a saved report |
| POST | `/api/gap/diff` | Compute diff between two reports |
| POST | `/api/risk/generate` | SSE: per-gap risk statement generation |
| POST | `/api/explain/{framework}/{control_id}` | Plain-English control explanation |
| POST | `/api/init/wizard` | Generate starter YAML files |
| GET | `/api/llm-status` | LLM provider configuration state |

## Air-gapped mode

Running `evidentia serve --offline` wires the air-gap guard into every `/api/*` call. LLM features gracefully degrade with a pointer to Ollama. See [`docs/air-gapped.md`](../../docs/air-gapped.md).

## Development

```bash
# From the repo root:
uv sync --all-packages
cd packages/evidentia-ui && npm install && npm run dev  # Vite dev server at :5173
# In another terminal:
evidentia serve --dev  # FastAPI at :8000 proxies /api/* to itself, / to Vite :5173
```

## License

Apache-2.0 — see [`LICENSE`](../../LICENSE).
