# Quarterly safeguards re-sweep — 2026 Q3

**Swept**: 2026-08-20, during the v0.12 freeze-prep batch.
**Tracking issue**: #134 (opened by `safeguards-resweep.yml`).
**Baseline**: `main` @ `ac5d801` (v0.11.2 + three Dependabot merges).

**Scope** (per the tracking issue): re-confirm the tag-time release gate,
the CLI↔GUI parity debt-ratchet, and the scheduled safeguards are still
*enforced*; catch any new gap opened since the last sweep; adopt any
ready backlog item.

**Verdict**: all safeguards confirmed enforced. **Two real findings** —
one already resolved by this batch, one requiring a release action.

---

## 1. Enforcement confirmations

| Safeguard | Enforced how | Confirmed |
|---|---|---|
| Tag-time release gate | `release.yml` runs `run_gate_suite.py --scope full` on the exact tagged commit | ✅ `release.yml:129` |
| CLI↔GUI parity ratchet | `parity.yml` propagates `check_parity.py`'s exit code (BLOCKING since v0.10.9 item D) | ✅ `parity.yml:63` |
| OpenSSF Scorecard | weekly cron (`0 6 * * 1`) | ✅ last run success 2026-08-20 |
| CodeQL | every push + PR (not merely scheduled) | ✅ last run success 2026-08-20 |
| OSPS conformance | every push + PR, no `paths:` filter | ✅ last run success 2026-08-20 |
| mutmut | scheduled | ✅ last run success 2026-08-16 |

All 15 scheduled workflows were checked for a recent run; none is dead or
silently disabled. `workflow-liveness` continues to guard against
never-firing triggers.

**New this sweep** — `check_public_surface` (v0.12 freeze-prep) joins the
`consistency` gate scope and the pre-push hook, taking the hook from 16
to 17 blocking checks. It holds `api-stability.md` to the code; see
[`v1.0-freeze-candidates.md`](../../v1.0-freeze-candidates.md).

---

## 2. Findings

### 2.1 `api-stability.md` §5 listed four imports that never resolved — **FIXED in this batch**

The NORMATIVE contract's frozen-import list had never been executed by
any gate. Four of its entries raised `ImportError` /
`ModuleNotFoundError` on every release that shipped them:

- `GapFinding` — no such symbol has ever existed (real name: `GapStatus`)
- `from evidentia_core.poam import POAMState, Milestone` — wrong module
  (the models live in `evidentia_core.models.gap`)
- `evidentia_collectors.vendor_risk` — no such module has ever existed,
  and two of the four collectors it advertised (`RiskReconCollector`,
  `UpGuardCollector`) were **never built**
- `SmtpChannel` / `WebhookChannel` — real names are `SMTPAlertChannel` /
  `WebhookAlertChannel`

Corrected in `api-stability.md` (§5 and §1's `gap.py` row) with a
revision-history entry, and now gated by `check_public_surface.py` so it
cannot recur. Not a breaking change: no operator could have depended on
a path that never resolved.

### 2.2 The published v0.11.2 container carries 7 fixable advisories — **ACTION REQUIRED at the v0.12.0 release**

`post-publish-rescan` has failed three consecutive weekly runs
(2026-08-03, -08-10, -08-17). This is the sentinel working as designed,
not a broken gate — it fails only on **fixable** advisories, exactly the
"a fix is now available, rebuild the image" signal.

The 2026-08-17 run executed at 07:59:09Z, **67 minutes after v0.11.2
published** (06:52:48Z), so it scanned the current published image:

```
osv-scanner rescan policy: 7 fixable / 28 unfixable (no upstream fix)
FIXABLE — util-linux 2.41-5+dhi3:
  [Medium 6.1] DEBIAN-CVE-2025-14104  -> 2.41.3-1
  [Medium 5.3] DEBIAN-CVE-2026-13595  -> 2.41.5-0+deb13u1
  [Medium 4.7] DEBIAN-CVE-2026-27456  -> 2.41.5-0+deb13u1
  [Unknown]    DEBIAN-CVE-2026-53612/-53613/-53614/-53615
```

**A fix is available.** The base-freshness sentinel (2026-08-18, issue
**#248**) reports the pinned DHI digest has drifted:

| | digest |
|---|---|
| pinned (`Dockerfile:65`, what v0.11.2 shipped on) | `sha256:0815063751f2b1909fd76f1efe5e17396a7e9d00bfa494a652708e9603debc6a` |
| current upstream `dhi.io/python:3.13` | `sha256:e512071462b6f002ac3d6f4d31bdf7d20fe6ffce3b5ce4f684b5e50d14dba217` |

**Action taken**: the base pin is bumped to
`sha256:e512071462b6…` in the v0.12 batch-2 branch (maintainer decision,
2026-08-20), rather than deferred to release prep. Rationale: doing it
now gets `container-build.yml` to validate the new base in CI while
there is room to react, instead of discovering a problem during a tag.
DHI digests resolve only in CI, so CI is the verification — if the
digest has drifted again by then, re-bump; it is a one-line change.

**Still a release-prep step**: re-confirm the pinned digest is current
immediately before tagging v0.12.0, and regenerate
`docker/requirements.txt` as the release flow already does. Shipping
v0.12.0 on a stale base would keep the rescan red.

This bears on `SECURITY.md` § Supported versions, which promises the
latest patch is free of disclosed advisories — currently true for the
Python closure (Dependabot alerts: 0) but not for the container's
base-OS layer, and it stays untrue until a release actually rebuilds
the image. Reachability is low (distroless: no shell, no apt, and the
Python process never invokes these binaries), which is why this is not
being treated as an emergency. **If v0.12.0 slips beyond ~2–3 weeks, cut
a v0.11.3 patch to rebuild instead of letting the gap sit.**

### 2.3 `fedramp-schema-watch` failing — expected, tracked

Failing 2026-08-12 and 2026-08-19 with `MAJOR upstream drift — failing
the sentinel run`. This is the designed severity behaviour: it detected
the CR26 advisor/assessor `0.1.1 → 1.0.1` moves, updated issue **#239**,
and failed to force attention. It clears when the v0.12 re-vendor lands
(v0.12 plan item 5a). No action beyond the planned re-vendor.

### 2.4 `docs/pre-push-gate.md` documented 7 checks; the hook ran 16 — **FIXED in this batch**

The doc's table had not been updated since v0.10.7 while the hook grew
every cycle. Table and prose corrected to the full 17 (16 pre-existing +
`check_public_surface`), with the hook's own header comment named as the
authoritative list.

---

## 3. Backlog adoption

No Phase-G backlog item was ready to adopt this sweep. The one candidate
worth naming for next quarter is in
[`v1.0-freeze-candidates.md`](../../v1.0-freeze-candidates.md) §6.4: a
mechanically-checked CLI flag inventory. §3 of `api-stability.md` freezes
CLI flag names, but nothing diffs them against the live Typer app — the
same class of unenforced-contract gap that finding 2.1 turned out to be.

---

## 4. Next sweep

`safeguards-resweep.yml` opens the next tracking issue on its schedule.
Carry forward: confirm the container rescan went green after the v0.12.0
rebuild (finding 2.2), and that `fedramp-schema-watch` cleared after the
re-vendor (finding 2.3).
