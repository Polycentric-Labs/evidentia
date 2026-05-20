# Conference outreach — 2026 (v0.9.8 P1.8 drafts)

> **Status**: DRAFT abstracts for human review. Authored during v0.9.8 P1.8 (2026-05-19) per the v0.9.7 deferral. None of these have been submitted yet; Allen reviews + decides which to send.
>
> **Audience**: each abstract targets a specific venue with a distinct frame on Evidentia. The three together carry the v1.0 positioning narrative across AI-safety, federal-compliance, and broader-industry forums.
>
> **CFP deadlines** (verify before submission):
> - DEF CON 34 AI Village — CFP open; typical close ~6 weeks before Aug 2026 conference
> - GovForward FedRAMP Summit — 2026-07-23 (conference date; abstract deadline likely 2026-06)
> - Billington Cybersecurity Summit — 2026-09-08 to 09-10 (conference); abstract deadline likely 2026-07

---

## Abstract 1 — DEF CON 34 AI Village

**Title** (≤80 chars):
DFAH: a determinism harness for AI-generated compliance evidence

**Track**: AI Village — Trust & Safety / AI evaluation

**Length**: 40-minute talk + 10-minute Q&A (request slot length matches AI Village 2024-2025 pattern)

**Abstract** (≤350 words):

LLM-generated GRC artifacts — risk statements, control-mapping rationales, gap-analysis findings — are now routinely shipped to FedRAMP 3PAOs, SOC 2 auditors, and AI risk officers. Most of them carry no integrity guarantees and no way for the receiver to verify that the same prompts would produce the same output tomorrow. We will show what breaks when reviewers actually try.

This talk introduces the Determinism + Faithfulness AI Harness (DFAH), a methodology for treating LLM-generated compliance artifacts as evidence — verifiable, reproducible, and falsifiable. Live demos cover: (1) replay equivalence (a single prompt run N times against the same model + seed must yield byte-identical canonical JSON), (2) faithfulness scoring (sentence-transformers semantic similarity against the source clauses the LLM was reasoning over, with framework-aware thresholds tuned via inter-rater Cohen's Kappa against a 147-entry calibration corpus), and (3) cryptographic envelope wrapping (Sigstore-keyless OIDC + Rekor transparency-log inclusion on every signed tool output via the open-source `evidentia-mcp` package).

The threat model is concrete: an LLM provider rolls a silent model update, the same prompts that produced a passing risk assessment last month now produce subtly different output, and the change is invisible to anyone who didn't capture the determinism baseline. DFAH catches this at CI gate time. We will demonstrate a full pipeline failure-injection: model rollover → DFAH violation → audit-event emission → CI fails the build before the artifact reaches the auditor.

The framework ships under the Apache-2.0-licensed `evidentia-ai` PyPI package. Calibration corpus is public on Hugging Face under `Polycentric-Labs/evidentia-grc-eval`. The talk closes with the open problems we still don't have good answers to: cross-provider determinism (LiteLLM helps but doesn't solve), human-rater scarcity for κ ≥ 0.80 against high-stakes federal scenarios, and the gap between "deterministic against seed N" and "robust against semantically equivalent prompts."

**Bio (Allen Byrd, ≤100 words)**:
Allen Byrd builds Evidentia, an open-source GRC tool focused on cryptographic evidence integrity and AI-quality verification. Prior work spans federal compliance automation, FedRAMP 20x readiness, and the OSCAL standard. He maintains the calibration corpus + DFAH methodology in the public `Polycentric-Labs/evidentia` repository.

---

## Abstract 2 — GovForward FedRAMP Summit 2026

**Title** (≤80 chars):
Open-source FedRAMP 20x readiness: OSCAL, cryptographic CIMD, and the Sept 2026 mandate

**Track**: FedRAMP 20x track — Tooling & Automation

**Length**: 30-minute talk (request shorter slot — GovForward audience prefers practical demos)

**Abstract** (≤300 words):

The September 2026 FedRAMP 20x mandate transitions CSP submissions from PDF + Excel to machine-readable OSCAL 1.2.1 packages. CSPs preparing for the transition face three concrete tooling gaps: (1) producing OSCAL POA&Ms with byte-stable cryptographic integrity that 3PAOs can verify against Rekor + the published catalog version, (2) maintaining a continuous-monitoring cadence calendar that maps NIST 800-53 CA-7 + the 3 FedRAMP ConMon cycles + CMMC L2 obligations against actual operator activity, and (3) producing System Control Records (SCR forms, per RFC-0007 + NOTICE-0009) on every Significant Change Request without re-keying data already in the SSP.

This talk walks the end-to-end pipeline for one of the open-source tools shipping with all three capabilities. Topics covered:

- POA&M lifecycle (FedRAMP POA&M Template Completion Guide v3.0 + NIST SP 800-53A Rev 5 Appendix F state machine) auto-generated from a gap-analysis run, with SHA-256 back-matter integrity on every milestone.
- CONMON cadence calendar (read-only library + a long-running daemon with SMTP / webhook alerting, file-backed deduplication, and `evidentia conmon health` JSON output suitable for SIEM ingest).
- SCR emit (8 RFC-0007 universal-required fields + per-category extras for Adaptive / Transformative changes) with operator-side validation that catches missing fields before the form ships.
- The cryptographic-CIMD path: every MCP tool call emits a Sigstore-keyless-signed envelope, so a CSP can produce evidence that the same configured Evidentia instance produced this output — verifiable downstream by the 3PAO with no shared-secret coordination.

We demonstrate the full pipeline against a hypothetical CSP's Moderate-baseline ATO scenario. Closes with the deferred-but-known gaps (cross-tenant audit trail nuances, real-vuln-source POA&M integration with Tenable / Qualys, and the operator-runbook polish still pending in the v0.9.x → v1.0.0 path).

**Bio**: [Same as Abstract 1]

---

## Abstract 3 — Billington Cybersecurity Summit 2026

**Title** (≤80 chars):
Lessons from shipping v1.0 of an OSS GRC stack with formal API stability

**Track**: Cybersecurity tooling & open-source (best-fit Billington track)

**Length**: 25-minute talk + 5-minute Q&A

**Abstract** (≤300 words):

Most open-source security tools never formally commit to API stability. The cost of doing so is high — every public surface (CLI flag, Pydantic model field, REST endpoint URI, MCP tool name, plugin contract) becomes a versioning obligation. The benefit is high too: enterprise + federal integrators can build against the surface without one-time spelunking that decays the moment maintainers refactor.

This talk covers the playbook we used to ship v1.0 of Evidentia, an open-source GRC tool, with a NORMATIVE API-stability commitment covering 5 frozen surface categories: 45+ Pydantic model fields, 60+ audit-event vocabulary entries, 18+ CLI command groups, 5 plugin contracts (`AuthProvider`, `StorageBackend[T]`, `MarketplaceProvider`, `BaseSaaSCollector`, `ContinuousEvidenceSource`), and 16 REST API URI prefixes. Each carries a documented deprecation cycle (minimum 1 minor-release warning before removal; removal in v(N+2).0 minor or later).

Practical content:
- How we identified each frozen surface from real-operator workflows (vs. inventing a public/private split top-down). The walk-throughs that revealed which surfaces operators actually depend on.
- The pre-release-review v4 methodology that achieved 22+ consecutive PROCEED-CLEAN ship cycles, with mandatory `/security-review` invocations and conditional `/code-review` auto-fires per release.
- The threat-modeling regression we still see in our deferred items, and the open-core commercial story that ships post-v1.0 (separate PyPI packages for Pro / Federal / Enterprise tiers).
- The OpenSSF Best Practices Gold-tier two-contributor threshold and how it shaped our timing.

Audience walks away with the actual pre-release-review checklist, the deprecation calendar template, and the API-stability surface inventory worksheet — all in the public `Polycentric-Labs/evidentia` repo.

**Bio**: [Same as Abstract 1]

---

## Submission status

| Conference | Submitted? | Deadline | Notes |
|---|---|---|---|
| DEF CON 34 AI Village | NO | ~6 weeks before Aug 2026 | Allen reviews abstract |
| GovForward FedRAMP Summit | NO | ~2026-06 (estimated; verify on CFP page) | Highest fit for federal-positioning + v0.9.0 federal-compliance theme |
| Billington Cybersecurity Summit | NO | ~2026-07 (estimated; verify on CFP page) | Highest fit for v1.0 API-stability narrative |

## Authoring notes

- All three abstracts assume v1.0.0 will ship before the conference dates. If v1.0.0 slips, the Billington abstract needs to soften to "lessons from approaching v1.0".
- The DEF CON abstract leans on the publicly-published HF Hub eval-suite (v0.9.8 P1.9 deliverable, in flight). If the publish slips, swap the eval-suite reference for the in-repo `tests/data/dfah-calibration/corpus*.jsonl` files.
- All three abstracts list Allen as solo author. If the OpenSSF Gold-tier 2nd-contributor materializes via the peer-review pass (per v1.0 master plan §F.2), update the bio + author block before submitting.
- Bio is reused verbatim across all three. Allen may want to tailor per-venue (e.g., the GovForward audience cares more about federal-compliance background than the open-source story).

## Cross-references

- [`docs/v1.0-transition.md`](v1.0-transition.md) — v1.0 narrative; positions all three talks against the federal-compliance + API-stability themes
- [`docs/positioning-and-value.md`](positioning-and-value.md) §11.2.A/B — academic positioning citations
- [`docs/hf-eval-suite-scaffolding.md`](hf-eval-suite-scaffolding.md) — HF Hub eval-suite (referenced in Abstract 1)
- `~/.claude/plans/based-on-current-roadmap-polymorphic-mango.md` Phase C.3.4 — marketing-asset framing for the v1.0 launch
