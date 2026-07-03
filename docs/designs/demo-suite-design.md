# Evidentia public demo suite — design

**Status:** DRAFT for review (2026-06-12). Brainstormed + threat-modeled this session.
**Decision lineage:** amends the 2026-06-02 demo strategy (see `docs/ROADMAP.md` §"Demo &
showcase strategy" + the private `evidentia_demo_strategy_decision` memory).
**Next step after approval:** `writing-plans` → phased build.

## 1. Goal & audience

Three demo surfaces telling **one story** (the `examples/meridian-fintech-v2/` sample —
48 controls across NIST 800-53 Moderate + SOC 2 + GDPR, with pre-baked `gap diff`
snapshots) to **both** evaluator types Evidentia is shown to:

- **Technical** (eng / security / platform) — wants to see the *real* tool run.
- **Risk / audit leadership** (less hands-on) — wants to *click* and see output.

Success = an evaluator reaches "I understand what this does and it's credible" in under
two minutes, on a link, with zero install.

## 2. Decision amendment (recorded)

The 2026-06-02 decision **killed** (a) a public hosted *stateful, credentialed* backend
(collector-abuse surface) and (b) a read-only GUI tour. This design **adds Tier 2** — a
**static, no-backend, no-credential** demo-mode GUI (baked fixtures; no API server, no
collectors). That is materially distinct from both killed options: there is no backend to
abuse and no credentials to exfiltrate. The CLI-first principle is preserved — Tiers 0
and 1 lead with the real CLI; Tier 2 is the click-through for non-technical evaluators.

## 3. Hosting

Deploy the static `VITE_DEMO` bundle to **`demo.evidentiagrc.com`** (decided 2026-06-16;
`evidentiagrc.com` is owned and `evidentia-grc.com` redirects to it). The enhanced FDA
Section 524B showcase ships from the **same in-repo bundle** built with the
`VITE_DEMO_FDA_INDEX` flag (the full-bleed `FdaDemoPage` rendered as the index, outside
`AppLayout`) and serves at **`fdademo.evidentiagrc.com`** — the in-repo route is the single
source of truth, retiring the earlier decoupled prototype fork. `polycentriclabs.com/evidentia`
redirects to `evidentiagrc.com` (gated on both being live). Design hosting-agnostic (static
assets + one optional ephemeral-container link). The main Polycentric Labs site (separate
private repo, static HTML on Vercel) gets a **single link/card** — I supply the snippet; no
deep edits to that repo. Every deploy + domain attach is **Tier-4** (your approval each).

## 4. Tier 0 — asciinema cast (self-hosted)

The no-regret floor. Record the **Meridian v2** sequence (the runbook already exists at
`.local/plans/demo-script-zeev-and-future.md`; CLI verbs are frozen/stable):

```
evidentia doctor
evidentia catalog list --tier A | head
evidentia gap analyze --inventory my-controls.yaml \
  --frameworks nist-800-53-rev5-moderate,soc2-tsc --output report.json
evidentia gap analyze --inventory my-controls.yaml \
  --frameworks nist-800-53-rev5-moderate --output ar.oscal.json --format oscal-ar
evidentia oscal verify ar.oscal.json
```

Ship `asciinema-player` JS + the `.cast` file as **static assets** (no asciinema.org
dependency — air-gap-on-brand). Embed on the demo landing page **and** the README.
**Surface:** none (a recording).

## 5. Tier 1 — real-CLI clickable (threat-model-hardened)

Anonymous users drive the **real** `evidentia` CLI in an ephemeral container. A 22-agent
adversarial threat model (this session; full register in the run output —
`tasks/w19e7upla.output`, 15 threats, skeptic-verified) returned: **a safe public real-CLI
demo IS achievable — but only as a guided/allowlisted runner, NEVER a raw shell.**

**Build gate — five non-negotiable conditions (all must hold before Tier 1 goes live):**

1. **No raw shell.** A constrained PTY whose only executable is a wrapper that validates
   `argv` against an allowlist of **network-free, fixture-only** verbs — `gap analyze`
   (bundled fixtures), `catalog list/show`, `crosswalk`, `risk quantify --method open-fair`
   with a **pinned** `--iterations`, `conmon` read-only, `oscal verify` on a **bundled
   signed fixture** — with a scrubbed environment and forced `--offline`. No `/bin/sh`, no
   `-c`/`-m`, no user-controlled env, no free-form flags.
2. **Default-deny egress** (`--network none`/loopback), on a host with **no cloud IAM
   role** and **IMDS blocked**. This single control neutralizes the entire SSRF/egress
   class.
3. **Verifiably empty credentials** (fail-closed startup assertion) + forced `--offline`
   + `EVIDENTIA_API_OFFLINE=1`, so the unauthenticated API, token-exfil collector paths,
   and LLM-cost paths all fail closed.
4. **Per-session resource caps** (memory/cpu/pids) + **read-only rootfs + tmpfs** +
   **hard TTL** (bounds the Monte-Carlo / disk-fill primitives).
5. **Image built FROM the cosign-verified, attestation-checked signed release digest**
   (never `docker build .` / `:latest`); scheduled rebuild cadence.

**Excluded from the demo profile** (no demo value, high surface): `collect*`,
`integrations*`, `mcp serve`, `eval`, `explain`, `risk generate`, `catalog import`,
`cimd-migrate`.

**Platform:** decided at Tier-1 build time (hosted ephemeral container vs self-hosted
ttyd/xterm), AFTER the platform's isolation model is verified against conditions 2 & 4.
**Surface:** real, fully mitigated by the above; Tier 1 does not start until they're met.

> Note: the threat model also surfaced two **product** findings beyond the demo — the
> collectors-SSRF guard gap (T2) and the container `serve` default posture (T3) — being
> fixed in **v0.10.10** (not part of this demo build).

## 6. Tier 2 — static demo-mode GUI (no backend)

The click-through for non-technical evaluators. Feasibility: **moderate, ~2–4h** (recon-
confirmed).

- **Mechanism:** a `VITE_DEMO` build flag swaps the API client for a fixtures module
  (`src/lib/api-fixtures.ts`) covering the **~21 endpoints** the routes call; the **2 SSE
  routes** (Explain, RiskGenerate) render **baked final states** (no live stream).
- **Router:** `HashRouter` (or `basename`) for static subpath hosting.
- **Data:** fixtures seeded from the **Meridian v2** hero data so the GUI tells the *same*
  story as the cast; a persistent **"DEMO · synthetic data · no live backend"** banner.
- **Build/deploy:** `VITE_DEMO=true npm run build` → static bundle → Vercel.
- **Surface:** ~nil — static files, no backend, no credentials; React auto-escapes by
  default and the UI uses no unsafe HTML-injection escape hatches (verified — no
  raw-innerHTML React props). Fixture rendering gets a light XSS sanity pass.

## 7. Site integration

One link/card from `polycentriclabs-site` → `demo.evidentiagrc.com`. I produce the
markup + assets; the live deploy + the site edit are Tier-4 (your approval each).

## 8. Phasing & verification

| Phase | Tier | Gate before live | Verification |
|---|---|---|---|
| A | 0 cast | — | cast plays; commands shown are current/real |
| B | 2 static GUI | — | clickable end-to-end with **zero `/api` network calls** (proven in-browser); all routes render; story matches the cast |
| C0 | 1 threat model | (done) | the 5 conditions specced |
| C1 | 1 platform | platform isolation verified vs conditions 2 & 4 | — |
| C2 | 1 build | all 5 conditions met | real CLI runs within the locked-down sandbox; allowlist enforced; no egress; no creds |

Sequence **A → B → C** (ascending external-dependency risk). Every public deploy is a
Tier-4 approval gate.

## 9. Open items

- DNS attach of `demo.evidentiagrc.com` + `fdademo.evidentiagrc.com` (CNAME → Vercel) — Tier-4.
- Tier-1 platform selection + its isolation verification (Phase C1).
- Whether the demo subdomain is its own repo or a folder under the site repo.

## 10. References

- Threat-model run: `tasks/w19e7upla.output` (15-threat register, skeptic-verified).
- Recon: README quickstart + `examples/meridian-fintech-v2/` + `.local/plans/demo-script-…md`;
  GUI feasibility (VITE_DEMO + ~21 fixtures).
- Decision lineage: `docs/ROADMAP.md` §Demo & showcase strategy; `evidentia_demo_strategy_decision` memory.
