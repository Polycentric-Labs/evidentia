# Evidentia performance benchmarks

> Reproducible numbers for the operations users care about most:
> gap analysis, catalog loading, AI risk-statement generation,
> collector throughput, FastAPI request latency, and web UI bundle
> size. Numbers come with hardware + dataset baselines so anyone
> can re-run on their own setup and see whether their environment
> is in the expected ballpark.

This is a v0.7.6 first-pass — closes [`docs/enterprise-grade.md`](enterprise-grade.md)
M4 (performance benchmarks). v0.7.7+ runs will add AI generation
TTFT/P95, AWS/GitHub collector concurrency, and FastAPI sustained-
load numbers as those surfaces stabilize.

---

## Hardware + software baseline (v0.7.6 reference run)

The numbers in this doc were captured 2026-05-01 on:

- **OS**: Windows 11 (10.0.26200)
- **CPU**: AMD64 Family 25 Model 97 (Ryzen-class)
- **Python**: 3.14.2
- **Evidentia**: v0.7.5 + the v0.7.6 in-flight commits (post-`d2bb82f`)

For comparison runs on different hardware, expect roughly linear
scaling with single-thread CPU performance for the gap-analysis
path (no I/O bottleneck) and roughly fixed cost for the catalog
load path (filesystem-bound JSON parse).

---

## Gap-analysis throughput

**What's measured**: end-to-end `GapAnalyzer().analyze(inventory,
frameworks)` against the bundled sample inventories. Includes
catalog hydration, crosswalk resolution, severity scoring, and
priority-roadmap generation. Excludes I/O for inventory file load
(amortized in setup).

**Method**: each row reports the median of 5 consecutive runs
after one untimed warm-up call. Same Python interpreter, same
bundled catalog data, no GC tuning. Timer is `time.perf_counter_ns()`
with millisecond rounding.

| Inventory | Controls in inventory | Required controls (frameworks) | Median (ms) |
|---|---|---|---|
| `examples/meridian-fintech/my-controls.yaml` | 20 | 287 (NIST 800-53 Mod) | **7.1** |
| `examples/meridian-fintech/my-controls.yaml` | 20 | 348 (NIST 800-53 Mod + SOC 2 TSC) | **9.1** |
| `examples/meridian-fintech-v2/my-controls.yaml` | 49 | 287 (NIST 800-53 Mod) | **5.6** |
| `examples/dod-contractor/my-controls.yaml` | 31 | 287 (NIST 800-53 Mod) | **12.2** |
| `examples/acme-healthtech/my-controls.yaml` | 40 | 287 (NIST 800-53 Mod) | **13.1** |

**Takeaways**:

- A 20-control inventory cross-walked against a 287-control NIST
  baseline is ~7 ms — well under the 100 ms perceptual threshold
  for "instant" UX response.
- Adding a second framework (SOC 2 TSC, +61 controls of placeholder
  surface) costs ~+2 ms — the bottleneck is per-control crosswalk
  lookup, which is O(N) in required controls per inventory entry.
- `meridian-fintech-v2` is faster than `acme-healthtech` despite
  having more controls because v2's controls are more uniformly
  matched (fewer ambiguity-resolution lookups in the crosswalk
  engine). This points at a v0.7.7+ optimization target if it
  ever shows up as a user-facing pain point.

**Throughput projection**: a typical compliance-program inventory
(50-150 controls) cross-walked against 1-3 frameworks on this
hardware sustains roughly **75-200 reports/second**. Sufficient
headroom for interactive UX, batch CI gates, and SaaS-style
multi-tenant gap analysis without per-tenant sharding.

---

## Catalog load

**What's measured**: `evidentia_core.catalogs.loader.load_catalog(...)`
end-to-end — JSON parse + control normalization + family indexing.
First load only (no in-process cache).

| Catalog | Controls | Median (ms) |
|---|---|---|
| `nist-800-53-rev5` (full) | 324 | **138.8** |

**Takeaways**:

- One-time 140 ms cost to hydrate the largest bundled catalog. CLI
  startup amortizes this; the FastAPI server does it once at
  import time and caches.
- This sets the floor for cold-start performance — `evidentia
  catalog list` from a fresh shell is ~150 ms + interpreter startup.

---

## Web UI bundle size

**What's measured**: production build artifacts under
`packages/evidentia-ui/dist/assets/` after `npm run build`.

| Artifact | Size (uncompressed) | Size (gzip) |
|---|---|---|
| `index-<hash>.js` (main bundle) | **358 KB** | **108 KB** |
| `index-<hash>.css` | **22 KB** | **5 KB** |
| `index-<hash>.js.map` (source map) | 1.4 MB | n/a (not shipped) |
| Total client-bound payload (gzipped) | — | **~113 KB** |

**Takeaways**:

- The 358 KB uncompressed JS is well within the relevant
  performance budget when measured at the gzipped wire payload
  (~108 KB) — modern Lighthouse "Time to Interactive" scoring
  reads gzipped/brotli payload, not raw bytes.
- Pre-v0.7.6 (alpha.1 only routes): 280 KB JS / 85 KB gzip. The
  v0.7.6 P0 work that wires the alpha.2 Gap Analyze + Gap Diff +
  Risk Generate pages adds ~+78 KB raw / ~+23 KB gzip. The
  TanStack Table + Zod schemas + per-route mutation hooks make up
  most of the delta.
- Source maps ship to disk during build but are not served by the
  FastAPI static mount unless explicitly requested — they cost
  zero on the user-facing path.

**Future targets (v0.7.7+)**: capture LCP / INP / TTFB numbers via
Playwright + Lighthouse against `evidentia serve` against a freshly
built image. Currently deferred because the CI runner doesn't have
a headed browser warmed up.

---

## Test suite runtime (developer ergonomics)

**What's measured**: `uv run pytest -q --tb=line` against the full
workspace. Reflects developer-facing iteration speed.

| Run | Wall-clock |
|---|---|
| 977 passed + 9 skipped | **11.1 s** (≤13.3 s incl. uv setup) |

**Takeaways**:

- ~88 tests/second on this hardware — fast enough for a `pytest -k
  <foo>` filter to feel near-instant during iteration.
- Adding ~2-3 s tracks `uv sync` cache validation; the
  `--no-sync` invocation that pre-commit hooks use shaves that
  off.

---

## Deferred to v0.7.7+

These benchmarks need external infrastructure (LLM provider, AWS
account, sustained-load harness) that didn't fit the v0.7.6
window. Methodology captured here so v0.7.7's first runs are
reproducible.

### AI risk-statement generation (TTFT + P95)

- **Method**: run `evidentia risk generate <gap-id>` against a
  fixed corpus of 20 representative gaps from
  `examples/meridian-fintech-v2/`, against each LLM provider with
  a stub system context. Capture: time-to-first-token (streaming
  start), wall-clock to last token, P50/P95/P99 across runs.
- **Providers**: OpenAI gpt-5-class, Anthropic claude-opus-4.5+,
  Google gemini-2.5-pro, Bedrock claude-opus-4-5, Ollama
  llama3.3:70b (local).
- **Comparison metric**: per-gap throughput in tokens/second + per-
  gap end-to-end latency. Both vary 5-10× across providers; the
  doc should publish the spread, not a single best number.

### Collector concurrency (AWS / GitHub)

- **Method**: simulated load against AWS Config + GitHub Audit Log
  mock servers (the existing `responses`-mocked test fixtures
  scaled up). Capture throughput at concurrency = 1, 4, 16, 64
  workers; identify the inflection point where concurrent
  collection saturates.
- **Goal**: support a v0.8.0 G7 claim like "Evidentia's collector
  framework sustains N evidence-resource fetches per minute on a
  single 4-core runner against rate-limited APIs."

### FastAPI server p95 latency under sustained load

- **Method**: `locust` or `wrk` against `evidentia serve` running
  in `--dev` mode, hitting the existing `/api/gaps`, `/api/risks`,
  `/api/health` endpoints. 5-minute sustained run at 50 RPS;
  capture P50/P95/P99 latency + error rate.
- **Goal**: establish a baseline + alerting threshold for
  enterprise deployments.

---

## Reproducibility checklist

To re-run these benchmarks on your own hardware:

```bash
# Install
git clone https://github.com/polycentric-labs/evidentia
cd evidentia
uv sync --all-packages

# Gap analysis throughput (5 inventory permutations × 5 runs each)
uv run python -c "
import time
from pathlib import Path
import sys
sys.path.insert(0, 'packages/evidentia-core/src')
from evidentia_core.gap_analyzer import GapAnalyzer, load_inventory
for name in ['meridian-fintech', 'meridian-fintech-v2', 'dod-contractor', 'acme-healthtech']:
    inv = load_inventory(Path(f'examples/{name}/my-controls.yaml'))
    GapAnalyzer().analyze(inv, ['nist-800-53-rev5-moderate'])  # warm
    runs = []
    for _ in range(5):
        t0 = time.perf_counter_ns()
        rep = GapAnalyzer().analyze(inv, ['nist-800-53-rev5-moderate'])
        runs.append((time.perf_counter_ns() - t0) / 1e6)
    print(f'{name}: median {sorted(runs)[len(runs)//2]:.1f} ms')
"

# Catalog load
uv run python -c "
import time
from evidentia_core.catalogs.loader import load_catalog
runs = []
for _ in range(5):
    t0 = time.perf_counter_ns()
    cat = load_catalog('nist-800-53-rev5')
    runs.append((time.perf_counter_ns() - t0) / 1e6)
print(f'NIST 800-53 Rev 5 ({len(cat.controls)} controls): median {sorted(runs)[len(runs)//2]:.1f} ms')
"

# Web UI bundle size
cd packages/evidentia-ui && npm install && npm run build && du -h dist/assets/*

# Test suite
uv run pytest -q --tb=line
```

If your numbers diverge by more than 3× from the table above on
similar hardware, please open an issue with your `evidentia
doctor` output attached.

---

*Last reviewed: v0.7.6 cycle. Created in v0.7.6 P1 B1 work to
close enterprise-grade.md M4 (performance benchmarks).*
