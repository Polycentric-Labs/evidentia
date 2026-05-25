# Evidentia design-partner program — DRAFT v0

> **Status:** DRAFT for Allen review (2026-05-25). Not for external
> publication until Allen reviews + approves the offer wording, pricing,
> and design-partner expectations. Companion to
> [`v0.10.5-plan.md`](v0.10.5-plan.md) Phase 12. Decoupling commercial
> validation from the v1.0 ship date per the 2026-05-25 research-pass
> finding that the regulatory tailwind window (Q3-Q4 2026 mandates)
> closes BEFORE the v1.0 ship date if Evidentia waits to start selling.
>
> **Origin:** 2026-05-25 full-sweep research pass. GPT-5.5 + Stream H
> + Stream F + Gemini cross-doc audit converged on the same diagnosis:
> v1.0 timing risks missing the entire CMMC Phase 2 / FedRAMP OSCAL /
> EU CRA / MODPA budget cycle. Pre-v1.0 paid services (decoupled from
> the OSS-purity commitment for v1.0) is the path that preserves both
> the OSS-purity narrative and the commercial validation timeline.

---

## 1. The offer (DRAFT — Allen-review required)

**Service name (DRAFT):** Evidentia CMMC L2 / FedRAMP Evidence Pipeline Setup

**One-paragraph description:**

> A 6-8 week fixed-fee engagement in which the Evidentia maintainer
> stands up your CMMC Level 2 (or FedRAMP Moderate) evidence pipeline
> end-to-end. Output: a working `evidentia` CLI configured against
> your AWS / GitHub / Okta / ServiceNow / Databricks / Snowflake / SQL
> environment, your bundled framework catalog selection, a documented
> gap report, an auto-generated OSCAL POA&M, a SARIF + OCSF emit
> wired into your SIEM / GitLab / GitHub Code Scanning surface, and
> a knowledge-transfer session with your security engineering team
> so the pipeline keeps running after the engagement closes. Includes
> the v0.10.x and the next two minor releases of Evidentia + a 90-day
> support window.

**Price band (DRAFT):** $25,000 — $75,000 fixed fee, scoped per the
size and complexity of the in-scope cloud + SaaS surface.

**Pricing dimensions:**

| Tier | Scope | Estimated fee |
|---|---|---|
| Starter | 1 framework (CMMC L2 OR FedRAMP Moderate baseline), single AWS account, single GitHub org, 1 SQL warehouse, ≤50 controls in evidence scope | $25,000 |
| Standard | 2 frameworks (CMMC L2 + NIST 800-171 r3), multi-account AWS, GitHub Enterprise, Okta + ServiceNow, ≤120 controls | $45,000 |
| Comprehensive | 3+ frameworks (e.g., CMMC L2 + FedRAMP Moderate + ISO 27001), multi-cloud, full SaaS surface, ≤250 controls | $75,000 |

**Above $75K**: custom scoping conversation. Anything that crosses into Pro/Enterprise/Federal commercial-tier feature territory (multi-tenant RBAC, SSO/SAML, FedRAMP 20x machine-readable packages, IL4/IL5 deployment guides) is OUT OF SCOPE for the Setup engagement and deferred to the post-v1.0 commercial tier.

## 2. Who this is for (target buyer enumeration)

In order of likely fit-velocity:

1. **CMMC L2-bound DoD subcontractors** facing Nov 10 2026 trigger date who can't afford a Vanta / Drata / Optro $50K+/yr SaaS contract on top of the C3PAO assessment fee.
2. **Federal-systems-integrator (SI) compliance teams** at the prime / sub-tier (Leidos, Booz Allen, GDIT, SAIC, CACI, Accenture Federal, Maximus, GovCIO, Peraton, ManTech) looking for a tooling-augmented compliance-as-code primitive they can resell to agency clients.
3. **Boutique SOC 2 / FedRAMP consultancies** (3PAO / RPO ecosystem) that want to differentiate on speed-to-evidence over their peers using only spreadsheets and AuditBoard.
4. **Regulated-startup CISO offices** (fintech, healthtech, defense-tech) where the founder/CISO is technical, has 1-2 engineers, and can't justify a full GRC SaaS license but needs evidence rigor.
5. **Cloud Service Providers** preparing for FedRAMP 20x machine-readable submissions (Sep 30 2026 deadline) who need OSCAL-native tooling for the package they will eventually submit.

**Explicitly NOT for**: Fortune 500 with 10+ existing GRC tools (they'll evaluate Evidentia as point-tool addition, not paid service); orgs without a technical buyer (compliance leadership only — they'll fall back on familiar SaaS); orgs needing fully managed compliance ("we'll handle it for you").

## 3. What's included

The Setup engagement delivers all of the following:

1. **Environment provisioning**: install Evidentia container or PyPI in your environment. Wire AWS / GitHub / Okta / ServiceNow / SQL / Databricks / Snowflake collectors against your actual accounts using least-privilege credentials.
2. **Framework selection + gap-baseline**: walk through Evidentia's 89 bundled catalogs with your team, select the in-scope frameworks, run the first gap analysis. Document the gap baseline.
3. **OSCAL POA&M generation**: produce `poam_state.json` / OSCAL POA&M document from the gap report. Walk through each gap with stakeholders to set initial remediation milestones.
4. **SIEM / CI integration**: wire `evidentia gap analyze --format sarif` into your CI (GitHub Actions / GitLab / Jenkins) as a blocking PR check OR `--format ocsf-detection` (v0.10.5 — for SIEM ingest) OR `--format cyclonedx-vex` (v0.10.5 — for supply-chain export) — your choice.
5. **MCP-server enablement (optional)**: if your team uses Claude Code / Cursor / Copilot CLI / Windsurf, configure the Evidentia MCP server so your AI agents can run gap analyses and ingest OCSF findings deterministically with signed output envelopes.
6. **AI-evidence workflow (optional)**: configure the LiteLLM provider chain. Pilot the risk-statement generator + control explainer against 5-10 representative gaps. Document the DFAH + PRT outputs for your auditor review.
7. **Knowledge transfer**: 2 working sessions with your security engineering team. Recorded if you want.
8. **Runbook**: written runbook capturing the configuration choices, the credential setup, the CI integration, the rollback plan.
9. **90-day support window**: Slack / email support for any breakage or question. Includes any v0.10.x patch releases shipped within the 90 days at no additional cost.

## 4. What's NOT included

To preserve the OSS-purity-through-v1.0 commitment and the future commercial tier boundaries, the Setup engagement explicitly does NOT include:

- ❌ Hosting Evidentia for you (operator runs Evidentia themselves; no SaaS).
- ❌ Multi-tenant RBAC / SSO / SAML / SCIM — these are Enterprise-tier features post-v1.0.
- ❌ FedRAMP 20x machine-readable authorization package authoring — Federal-tier feature post-v1.0. (We DO emit OSCAL artifacts you or your 3PAO would assemble; we don't author the package end-to-end.)
- ❌ IL4 / IL5 deployment configuration — Federal-tier post-v1.0.
- ❌ CONMON daemon (continuous-monitoring live-trigger) — Pro-tier feature post-v1.0. (We DO ship the read-only CONMON cadence library.)
- ❌ Custom framework authoring (writing a new OSCAL catalog from scratch). We can crosswalk to bundled catalogs; new catalogs are a future Pro-tier feature.
- ❌ Audit-firm partnership / 3PAO assessment representation. We are not auditors. We produce evidence; your auditor or 3PAO consumes it.

## 5. Engagement model

- **Discovery call** (free, 30 min): scope confirmation, candidate framework selection, target deliverables.
- **Statement of Work** (free, ~3 days turnaround): fixed-fee proposal with scope, deliverables, milestones, schedule.
- **Engagement** (6-8 weeks): weekly check-ins, 50% payment at SoW signing, 50% at runbook delivery.
- **Wrap** (90 days): support window. After 90 days, conversion to (eventual) Pro / Enterprise / Federal tier or self-service OSS-only continuation.

## 6. Design-partner status (first 3-5 commits)

The first 3-5 design partners get:

- **20% discounted fee** ($20K Starter / $36K Standard / $60K Comprehensive).
- **Co-development input**: priority feedback channel into the Evidentia roadmap for the v0.10.5 → v1.0 cycle. Specific feature requests get serious consideration in the next minor release.
- **Reference-customer opportunity** (with mutual approval): we both benefit if you're willing to be cited as an Evidentia design partner in the v1.0 launch story. Opt-out at any time.
- **Founders-priced access** to the Pro tier when it launches (post-v1.0): 50% off Year 1 pricing for the first 12 months of Pro availability.

**Design-partner expectations** (what we ask of you):
- Engage in good faith — willing to surface real friction during the engagement.
- 1-2 working sessions / week during the engagement window.
- Provide written reference-customer testimonial (optional, mutual approval).
- Willingness to be cited (optional, mutual approval) in the v1.0 launch announcement, blog post, or conference talk.

## 7. Why this works alongside the pure-OSS v1.0 commitment

The Evidentia repo at [Polycentric-Labs/evidentia](https://github.com/Polycentric-Labs/evidentia) stays Apache-2.0 forever; v1.0 ships as the OSS milestone with the API stability commitment + the federal-compliance primitives + the OSPS Baseline Maturity 2 acceptance. The Setup engagement is a paid services layer that runs on top of the OSS — it doesn't gate any OSS features behind a paywall, doesn't fork the codebase, and doesn't change the v1.0-pure-OSS posture in any way.

The eventual commercial-tier packages (Pro / Enterprise / Federal) ship post-v1.0 as **separate PyPI packages in separate private repos with proprietary licenses**, per the locked 2026-05-15 commercial strategy decision. The Setup engagement bridges the v0.10.x → v1.0 → v1.1+ commercial-tier timeline by giving the project a paid-revenue + reference-customer foundation that doesn't depend on the OSS source code becoming non-OSS.

## 8. Open questions for Allen review

Before this doc goes external (private LinkedIn outreach, federal-SI partner conversation, design-partner kickoff), Allen needs to decide:

1. **Naming**: "Evidentia CMMC L2 / FedRAMP Evidence Pipeline Setup" — accept, or rename? Alternative: "Compliance Pipeline Setup", "Evidence Engine Bootstrap", "OSCAL Native Adoption Engagement". Which lands better?

2. **Price band**: $25K-$75K is research-derived. Is the SMB anchor ($25K) too low to filter out non-buyers / too low to be sustainable? Is $75K too high for a Comprehensive engagement? Should there be a flat-fee Starter / Standard / Comprehensive structure or always custom-scoped?

3. **Reference customer expectations**: should design partners be required to provide a reference testimonial (firmer), or is "optional, mutual approval" the right level? More OSS-y to keep it optional; more commercially-credibility-building to require it.

4. **Reference customer NDA**: do we want the option for "private reference customer" status (Evidentia knows you exist; we don't publish your name publicly)? Or is the first-cohort target "anonymous customer #1, #2, #3" if all decline public reference?

5. **Out-of-scope features**: review the §4 NOT-included list. Anything to move INTO scope (because it's already in v0.10.4 OSS) or OUT of scope (because it's actually a commercial-tier feature)?

6. **Discovery-call funnel**: who handles inbound interest? Solo founder (Allen) for all calls? At what volume does that become unsustainable?

7. **Conflicts with current employment / income / time**: Allen is investing time + money in this project without revenue yet. The Setup engagement could conflict with primary income / employment. Decision needed on how much engagement bandwidth is realistic for the next 90 days — 1 engagement at a time? 2 in parallel? Maximum of N during the v0.10.x → v1.0 cycle?

8. **Partnership / channel layer**: should this be sold direct, or through a federal-SI partner channel (the partner sells; Allen delivers)? Direct gives Allen full margin but slower deal velocity; channel gives faster velocity but ~50% margin to the partner.

9. **First-3-5 design-partner candidates**: who specifically does Allen want to approach? The identified Federal/3PAO partner is one candidate. Others are pending the research-pass output on target-buyer enumeration. Recommended list to draft after the next research pass closes.

## 9. Activation checklist (DRAFT)

Before this offer goes external:

- [ ] Allen reviews + approves the §1 offer wording.
- [ ] Allen confirms price band (§1 Tiers).
- [ ] Allen finalizes the §4 NOT-included list against the locked commercial-tier strategy.
- [ ] Allen drafts the actual outreach content (LinkedIn DM template, email template, federal-SI partner intro language).
- [ ] Allen identifies 5-8 candidate design partners (existing 3PAO contact + 4-7 others).
- [ ] Allen defines the "discovery call" → "SoW signing" funnel in concrete steps + scheduling tools.
- [ ] Allen and Claude jointly draft the SoW template that gets sent post-discovery-call.
- [ ] Allen confirms the legal entity that signs the engagement (Polycentric Labs LLC? Allen Byrd sole proprietor? S-corp?).
- [ ] Allen confirms the payment processing path (Stripe Invoice? Wave? Direct ACH?).
- [ ] Allen confirms the engagement-IP question: who owns the runbook + the customer-specific configurations? Default: customer owns; Evidentia retains right to use anonymized learnings for product improvement.

---

*This DRAFT was prepared 2026-05-25 as Phase 12 of the v0.10.5 cycle.*
*Update + finalize after Allen-review and the next research-pass output.*
