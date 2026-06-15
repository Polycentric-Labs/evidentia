# Evidentia demo suite — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the in-repo artifacts for Evidentia's three-tier public demo suite (per `docs/demo-suite-design.md`), folded into the v0.10.10 cycle.

**Architecture:** Tier 2 is a `VITE_DEMO` build of the existing React UI that swaps the fetch client for a baked-fixtures module (no backend, no network) and renders SSE routes as canned final states; Tier 0 is a self-hosted asciinema cast of the real Meridian-v2 CLI sequence; Tier 1 is a Python argv-allowlist runner + a demo-profile Dockerfile that enforces the threat-model's five conditions. All deploy steps (Vercel, the hosted Tier-1 runner, the site link) are deferred-to-deploy Tier-4 actions, NOT part of this build.

**Tech Stack:** React 19 + Vite 6 + TypeScript (evidentia-ui), Python 3.12 + Typer (CLI), vitest, pytest, asciicast v2.

**Spec:** `docs/demo-suite-design.md`. **Tier-1 threat register:** the run output referenced there. **Hero data:** `examples/meridian-fintech-v2/snapshots/baseline.json` + `pr-branch.json`.

---

## File structure

**Tier 2 (static demo GUI) — `packages/evidentia-ui/`:**
- Create `src/lib/demo/fixtures.ts` — the baked dataset (gap reports, frameworks, poam, tprm, conmon, config, health) seeded from Meridian v2.
- Create `src/lib/demo/demo-api.ts` — a fixtures-backed implementation of every `api` method + a `simulateSse<T>()` helper.
- Create `src/lib/demo/index.ts` — `export const IS_DEMO = import.meta.env.VITE_DEMO === "true"`.
- Modify `src/lib/api.ts` — at the top of `request<T>()` and `explainControlUrl`/the `api` object, route to `demo-api` when `IS_DEMO`.
- Modify `src/routes/ExplainPage.tsx` + `src/routes/RiskGeneratePage.tsx` — branch the SSE `fetch` on `IS_DEMO` to `simulateSse`.
- Modify `src/main.tsx` — `HashRouter` when `IS_DEMO` (static subpath hosting).
- Create `src/components/DemoBanner.tsx` + mount it in `src/App.tsx`.
- Modify `.env.example` — document `VITE_DEMO`.
- Tests: `src/lib/demo/demo-api.test.ts`, `src/lib/demo/fixtures.test.ts`.

**Tier 0 (cast) — repo root + evidentia-ui:**
- Create `scripts/demo/gen_cast.py` — runs the allowlisted Meridian-v2 sequence, emits an asciicast v2 file.
- Create `packages/evidentia-ui/public/demo.cast` — the generated artifact (committed).
- Modify `README.md` — embed the player after the Quickstart code block.

**Tier 1 (constrained runner) — repo root:**
- Create `packages/evidentia/src/evidentia/demo/__init__.py` + `runner.py` — the argv-allowlist runner.
- Create `packages/evidentia/src/evidentia/demo/allowlist.yaml` — the allowed argv vectors.
- Create `docker/Dockerfile.demo` — demo-profile image (FROM the signed release digest; offline; no creds).
- Tests: `tests/unit/test_demo_runner.py`.

**Deferred-to-deploy (Tier-4, NOT built here):** Vercel static deploy of the `VITE_DEMO` bundle; the hosted ephemeral-container platform for Tier 1; the `polycentriclabs-site` link.

---

## Phase B — Tier 2: static demo-mode GUI

> Built first alongside Tier 0 (both fully self-contained). Tier 2 is the centerpiece.

### Task B1: the demo dataset (`fixtures.ts`)

**Files:**
- Create: `packages/evidentia-ui/src/lib/demo/fixtures.ts`
- Test: `packages/evidentia-ui/src/lib/demo/fixtures.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// src/lib/demo/fixtures.test.ts
import { describe, expect, it } from "vitest";
import { DEMO_GAP_REPORT, DEMO_FRAMEWORKS, DEMO_REPORT_LIST } from "./fixtures";

describe("demo fixtures", () => {
  it("the hero gap report mirrors the Meridian v2 baseline shape", () => {
    expect(DEMO_GAP_REPORT.organization).toBe("Meridian Financial");
    expect(DEMO_GAP_REPORT.total_gaps).toBe(311);
    expect(DEMO_GAP_REPORT.critical_gaps).toBe(297);
    expect(DEMO_GAP_REPORT.coverage_percentage).toBeCloseTo(45.3);
    expect(DEMO_GAP_REPORT.frameworks_analyzed).toEqual([
      "nist-800-53-rev5-moderate",
      "soc2-tsc",
    ]);
    // every gap carries the fields the GapTable renders
    for (const g of DEMO_GAP_REPORT.gaps) {
      expect(g.control_id).toBeTruthy();
      expect(["critical", "high", "medium", "low", "informational"]).toContain(
        g.gap_severity,
      );
    }
  });

  it("the report list summary matches the hero report", () => {
    const meta = DEMO_REPORT_LIST.reports.find(
      (r) => r.key === "meridian-fintech-v2:baseline",
    );
    expect(meta?.total_gaps).toBe(DEMO_GAP_REPORT.total_gaps);
  });

  it("ships the catalog the demo story references", () => {
    const ids = DEMO_FRAMEWORKS.frameworks.map((f) => f.id);
    expect(ids).toContain("nist-800-53-rev5-moderate");
    expect(ids).toContain("soc2-tsc");
  });
});
```

- [ ] **Step 2: Run it, expect FAIL** (`npx vitest run src/lib/demo/fixtures.test.ts` → module not found).

- [ ] **Step 3: Write `fixtures.ts`.** Import the real types and build the dataset. The hero gap report mirrors `examples/meridian-fintech-v2/snapshots/baseline.json` (organization "Meridian Financial", 311 gaps / 297 critical / 13 high / 1 medium, 48-of-1196 controls, 45.3% coverage, frameworks `["nist-800-53-rev5-moderate","soc2-tsc"]`). Include **~12 representative `ControlGap` rows** (the demo doesn't need all 311 — `GapTable` paginates; 12 across the severities tells the story) using real control ids from the baseline: critical `CC7.1`, `CC7.2`, `CC6.1`, `CC6.6`, `CC8.1` (soc2-tsc) + `AU-2`, `SI-4`, `IA-2`, `SC-7` (nist); high `CM-6`, `RA-5`; medium `AT-2`. Each row is a complete `ControlGap` (all fields from the type — `id` a stable string like `"demo-gap-cc7-1"`, `created_at` a fixed ISO string, nullables `null`, `equivalent_controls_in_inventory`/`cross_framework_value` from the baseline). Include 3 `efficiency_opportunities` (AC-2 → 3 frameworks/47 gaps/value 8.9; AU-2 → 2/31/7.4; IA-5 → 2/22/6.8) and a `prioritized_roadmap`. Build `DEMO_REPORT_LIST: GapReportListResponse` with two `GapReportMeta` (`meridian-fintech-v2:baseline` + `:pr-branch`) and `DEMO_FRAMEWORKS: FrameworkListResponse` with ~10 real bundled framework entries. Also export `DEMO_GAP_DIFF: GapDiff` (baseline→pr: a few `closed` entries — IA-2, AU-2 — summary `{closed: 3, opened: 0, ...}`), `DEMO_POAM: PoamListResponse` (the same critical gaps as `items`, with `poam_milestones`), `DEMO_VENDORS: VendorListResponse` (3 vendors: Okta/cloud-platform/critical, Snowflake/data-processor/high, an auditor/low), `DEMO_CONMON: ConmonCadence[]` (~6 cadences), `DEMO_CONFIG: EvidentiaConfig` (Meridian), `DEMO_HEALTH`/`DEMO_VERSION`/`DEMO_LLM_STATUS` (llm `configured: false` — air-gap-honest), `DEMO_EXPLANATION: Explanation` (a baked AC-2 explanation), and `DEMO_AIRGAP: AirGapCheckResponse` (`air_gapped: true`). Match every type from `src/types/api.ts` exactly.

- [ ] **Step 4: Run the test, expect PASS.**

- [ ] **Step 5: Commit** (`git add packages/evidentia-ui/src/lib/demo/fixtures.ts packages/evidentia-ui/src/lib/demo/fixtures.test.ts && git commit -m "Add the demo-mode fixture dataset (Meridian v2 hero data)"`).

### Task B2: the fixtures-backed API + SSE simulator (`demo-api.ts`) + the client swap

**Files:**
- Create: `packages/evidentia-ui/src/lib/demo/demo-api.ts`, `src/lib/demo/index.ts`
- Modify: `src/lib/api.ts`
- Test: `src/lib/demo/demo-api.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// src/lib/demo/demo-api.test.ts
import { describe, expect, it } from "vitest";
import { demoApi, simulateSse } from "./demo-api";

describe("demo-api", () => {
  it("returns the hero report list with no network", async () => {
    const list = await demoApi.listGapReports();
    expect(list.reports[0].organization).toBe("Meridian Financial");
  });
  it("resolves a report by key", async () => {
    const r = await demoApi.getGapReport("meridian-fintech-v2:baseline");
    expect(r.total_gaps).toBe(311);
  });
  it("simulateSse emits a start then a terminal done", async () => {
    const events: Array<{ phase: string }> = [];
    await simulateSse(
      [{ phase: "start", framework: "x", control_id: "AC-2" }, { phase: "done", explanation: {} as never }],
      (e) => events.push(e as { phase: string }),
    );
    expect(events.map((e) => e.phase)).toEqual(["start", "done"]);
  });
});
```

- [ ] **Step 2: Run it, expect FAIL.**

- [ ] **Step 3: Write `demo-api.ts`** — an object with the same method names as `api` (Task A inventory), each returning `Promise.resolve(<fixture>)` from `fixtures.ts`; param-filtered methods (`listPoamItems`, `listVendors`) apply the filters to the fixture arrays so the UI filters work. `exportGapReport` returns a `Blob` of `JSON.stringify(report)` + a filename. `simulateSse<T>(events, onEvent, gapMs = 25)` awaits a short delay between events then calls `onEvent` (so progress bars animate). Write `index.ts`: `export const IS_DEMO = import.meta.env.VITE_DEMO === "true";`.

- [ ] **Step 4: Modify `api.ts`** — at the top of the module: `import { demoApi } from "./demo/demo-api"; import { IS_DEMO } from "./demo";`. Replace the exported `api` with `export const api = IS_DEMO ? demoApi : realApi;` (rename the existing object to `realApi`). `explainControlUrl` stays (it only builds a URL; the SSE branch is in the page).

- [ ] **Step 5: Run the test + `npm run typecheck`, expect PASS/clean.**

- [ ] **Step 6: Commit** (`… "Wire the VITE_DEMO API swap + SSE simulator"`).

### Task B3: SSE demo branches in the streaming pages

**Files:** Modify `src/routes/ExplainPage.tsx`, `src/routes/RiskGeneratePage.tsx`. Test: extend the existing page tests.

- [ ] **Step 1:** In `ExplainPage.tsx`, before `const res = await fetch(url, …)`, add: `if (IS_DEMO) { await simulateSse<ExplainEvent>([{ phase: "start", framework, control_id: controlId }, { phase: "done", explanation: DEMO_EXPLANATION }], onEvent); return; }` (import `IS_DEMO`, `simulateSse`, `DEMO_EXPLANATION`).
- [ ] **Step 2:** In `RiskGeneratePage.tsx`, before its `fetch("/api/risk/generate", …)`, add a demo branch emitting `{ phase: "start", total: 5 }`, five `{ phase: "progress", …, status: "done" }` frames over the hero gaps, then `{ phase: "done", generated: 5, failed: 0 }` via `simulateSse<StreamEvent>`.
- [ ] **Step 3:** Add a vitest case to each page test asserting that, with `VITE_DEMO` stubbed, the page reaches its done state and makes **zero** `fetch` calls (spy on `global.fetch`, assert not called).
- [ ] **Step 4: Run `npx vitest run`, expect PASS.**
- [ ] **Step 5: Commit** (`… "Render the SSE demo routes as baked streams (no backend)"`).

### Task B4: HashRouter + the DEMO banner

**Files:** Modify `src/main.tsx`, `src/App.tsx`. Create `src/components/DemoBanner.tsx`.

- [ ] **Step 1:** `DemoBanner.tsx` — a fixed top strip: "DEMO · synthetic data · no live backend" + a link to the repo. Render nothing when `!IS_DEMO`.
- [ ] **Step 2:** `main.tsx` — import `HashRouter`; render `IS_DEMO ? <HashRouter><App/></HashRouter> : <BrowserRouter><App/></BrowserRouter>`.
- [ ] **Step 3:** `App.tsx` — mount `<DemoBanner />` above the layout.
- [ ] **Step 4:** `.env.example` — add the documented `VITE_DEMO=true` block.
- [ ] **Step 5: Run `npm run typecheck && npm run build` (no flag — prod unaffected) and `VITE_DEMO=true npm run build` (demo), expect both PASS.**
- [ ] **Step 6: Commit** (`… "Add the demo banner + HashRouter for static demo hosting"`).

### Task B5: demo-build verification (no network)

- [ ] **Step 1:** `cd packages/evidentia-ui && VITE_DEMO=true npm run build`.
- [ ] **Step 2:** Serve `dist/` statically (`npx vite preview`) and load it; via the preview tools confirm **zero `/api` network requests** across the Dashboard, Gap, POA&M, TPRM, ConMon, Explain routes, and that the Meridian gap report renders. Capture a screenshot.
- [ ] **Step 3: Commit** any fixups (`… "Verify the demo build issues no backend calls"`).

---

## Phase A — Tier 0: asciinema cast (parallel-safe with Phase B)

### Task A1: the cast generator + artifact

**Files:** Create `scripts/demo/gen_cast.py`, `packages/evidentia-ui/public/demo.cast`.

- [ ] **Step 1:** Write `gen_cast.py` — runs the allowlisted Meridian-v2 sequence (`evidentia doctor`; `evidentia catalog list --tier A`; `evidentia gap analyze --inventory examples/meridian-fintech-v2/my-controls.yaml --frameworks nist-800-53-rev5-moderate,soc2-tsc --output /tmp/report.json`; `evidentia gap analyze … --output /tmp/ar.oscal.json --format oscal-ar`; `evidentia oscal verify /tmp/ar.oscal.json`) under `PYTHONIOENCODING=utf-8` + forced Rich color, capturing each command's bytes. Emit asciicast v2: a header line `{"version": 2, "width": 100, "height": 30, "title": "Evidentia — gap analysis on a fintech inventory"}` then `[t, "o", chunk]` events — animate a typed prompt (`$ <cmd>\n`, ~40ms/char) then the captured output, with a 1s pause between commands. Deterministic timestamps (no wall-clock; accumulate a counter) so the artifact is reproducible.
- [ ] **Step 2:** Run `uv run --no-sync python scripts/demo/gen_cast.py packages/evidentia-ui/public/demo.cast`. Validate the file parses as JSON-lines and the header `version == 2`.
- [ ] **Step 3:** Add a tiny test `tests/unit/test_gen_cast.py` asserting the generator produces a valid v2 header + ≥1 `"o"` event for a stubbed command. (Run the real evidentia sequence only in the manual gen step, not the unit test.)
- [ ] **Step 4: Commit** (`… "Generate the Meridian-v2 asciinema demo cast"`).

### Task A2: embed the player

**Files:** Modify `README.md`; add the player assets under `packages/evidentia-ui/public/` (self-hosted `asciinema-player.min.js` + `.css`, pinned).

- [ ] **Step 1:** Vendor the pinned `asciinema-player` dist into `public/vendor/` (self-hosted — no CDN, air-gap-on-brand).
- [ ] **Step 2:** `README.md` — after the Quickstart code block (~line 79), add a "Watch it run" subsection linking to the demo page / an `<asciinema-player>` snippet referencing `demo.cast` (GitHub README can't run JS, so link to the hosted demo page + show a still; the live player lives on the demo page).
- [ ] **Step 3:** Add a `DemoPage` (or extend `HomePage` under `IS_DEMO`) that mounts the player against `/demo.cast`.
- [ ] **Step 4: Commit** (`… "Self-host the asciinema player + embed the cast on the demo page"`).

---

## Phase C — Tier 1: constrained-runner in-repo artifacts (after A+B)

> The hosted deploy is Tier-4/deferred. This builds the runner + profile that the eventual host will use.

### Task C1: the argv-allowlist runner

**Files:** Create `packages/evidentia/src/evidentia/demo/{__init__.py,runner.py,allowlist.yaml}`. Test: `tests/unit/test_demo_runner.py`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_demo_runner.py
import pytest
from evidentia.demo.runner import is_allowed, scrub_env, run

def test_allowlisted_vector_passes():
    assert is_allowed(["doctor"]) is True
    assert is_allowed(["catalog", "list", "--tier", "A"]) is True

def test_raw_shell_and_arbitrary_verbs_refused():
    assert is_allowed(["collect", "okta"]) is False        # network verb excluded
    assert is_allowed(["mcp", "serve"]) is False
    assert is_allowed(["risk", "generate"]) is False
    assert is_allowed(["-c", "import os"]) is False         # no python -c
    assert is_allowed(["gap", "analyze", "--findings", "x"]) is False  # off-allowlist flag

def test_scrub_env_strips_credentials_and_forces_offline():
    env = scrub_env({"OPENAI_API_KEY": "sk-x", "AWS_SECRET_ACCESS_KEY": "y", "PATH": "/usr/bin"})
    assert "OPENAI_API_KEY" not in env and "AWS_SECRET_ACCESS_KEY" not in env
    assert env.get("EVIDENTIA_API_OFFLINE") == "1"
    assert "PATH" in env  # the allowlisted essentials survive
```

- [ ] **Step 2: Run them, expect FAIL.**

- [ ] **Step 3:** Write `allowlist.yaml` (the network-free, fixture-only argv vectors from the design's Tier-1 condition 1: `doctor`, `doctor --check-air-gap`, `catalog list[/ --tier A/ --category control]`, the two `gap analyze` Meridian invocations + the oscal-ar one, `oscal verify <fixed>`, `conmon list[/ --json/ --framework …]`, `conmon next annual --last-completed …`, `explain --framework … --control-id …`). Write `runner.py`: `is_allowed(argv)` matches the FULL argv against the allowlist as exact token sequences (no free-form flags/args; `--output` targets restricted to a fixed temp name); `scrub_env(env)` returns only an allowlisted key set (`PATH`, `HOME`, `LANG`, `PYTHONIOENCODING`, `TERM`) plus `EVIDENTIA_API_OFFLINE=1`; `run(argv)` refuses (exit 2 + message) if not `is_allowed`, else execs `evidentia <argv>` with the scrubbed env, `--offline` forced. No `/bin/sh`, no shell=True, no `-c`/`-m`.

- [ ] **Step 4: Run the tests + `uv run --no-sync mypy packages/evidentia/src/evidentia/demo --strict-optional`, expect PASS/clean.**

- [ ] **Step 5: Commit** (`… "Add the Tier-1 constrained-runner argv allowlist + env scrub"`).

### Task C2: the demo-profile image

**Files:** Create `docker/Dockerfile.demo`.

- [ ] **Step 1:** `Dockerfile.demo` — `FROM ghcr.io/polycentric-labs/evidentia@<signed-release-digest>` (a build-arg, defaulting to the latest signed v0.10.10 digest — filled at deploy time; NOT `:latest`), drop to a non-root user, copy `allowlist.yaml` + the runner, set the entrypoint to the constrained runner (no shell), set `EVIDENTIA_API_OFFLINE=1`, and document the run contract (the host MUST add `--network none`, resource caps, read-only rootfs, a TTL — threat-model conditions 2/4; documented in a header comment as the host's responsibility).
- [ ] **Step 2:** `docker build -f docker/Dockerfile.demo --build-arg BASE=python:3.13-slim .` as a smoke (BASE overridable so the build is testable before the signed digest exists); confirm the runner refuses a raw `sh` and a `collect` verb.
- [ ] **Step 3: Commit** (`… "Add the Tier-1 demo-profile Dockerfile (constrained runner, offline, no creds)"`).

---

## Integration + CHANGELOG

- [ ] Update the v0.10.10 CHANGELOG: add an **Added** "Public demo suite (Tier 0 cast + Tier 2 static demo-mode GUI + Tier 1 constrained-runner artifacts)" entry; adjust the cycle theme to "supply-chain hardening + the public demo suite."
- [ ] Re-run the full gate (`uv run --all-extras --all-packages python -m pytest tests/ -q`; `npm run typecheck && npm run build && npx vitest run`; mypy/ruff; `check_parity`) on the integrated tree before the tag.

## Deferred-to-deploy (Tier-4 — explicit approval each, NOT this build)

- Deploy the `VITE_DEMO=true` static bundle to `evidentia-demo.vercel.app`.
- Stand up the Tier-1 hosted ephemeral-container runner (platform TBD per the design) with `--network none` + caps + TTL, built from the signed v0.10.10 digest.
- Add the demo link/card to `polycentriclabs-site`.
- Later: map `evidentia-demo.polycentriclabs.com`.
