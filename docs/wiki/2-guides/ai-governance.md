# Govern AI systems (EU AI Act + NIST AI RMF)

Evidentia's `evidentia ai-gov` command group helps an operator answer two
auditor-facing questions about every AI system they run: *"what risk tier does
this fall into?"* and *"is it on our inventory with an accountable owner?"* The
group runs a **deterministic, rule-based** EU AI Act tier classifier (Articles 5,
6, and 50), surfaces the most operationally pressing NIST AI RMF 1.0 functions,
maintains a JSON-backed AI-system registry, and lets you attach FIPS 199 and
OMB M-25-21 high-impact determinations to registered systems for federal
cross-referencing. (OMB M-24-10 was rescinded on 2025-04-03 by M-25-21; the
legacy `set-omb-impact` verb is retained so older inventories still load.)
None of these commands need an API key, a model endpoint, or any third-party
credential — the classifier is pure rules, and the registry is a local file
store. This guide walks the whole surface end to end with the bundled fixtures.

> **The classifier is not legal advice.** Every classification carries a standing
> disclaimer: it is an *informational starting point produced by a rule-based
> classifier*, **not** a legal compliance determination. Have a subject-matter
> expert review any `high` or `unacceptable` result before deployment. The
> disclaimer prints on every `classify` / `register` / `show` run and is also
> embedded in the JSON output — see the output blocks below.

## Prerequisites

- Nothing beyond a working Evidentia install. No credentials are required.
- The runnable examples below use the two descriptor fixtures bundled in the
  repository:
  - `tests/data/walkthrough-federal-si/ai-systems.yaml` — a high-risk résumé
    screener (EU AI Act Annex III, employment domain).
  - `tests/data/walkthrough-federal-si/ai-systems-low-risk.yaml` — a minimal-risk
    internal email classifier.
- **`PYTHONIOENCODING=utf-8` is required on Windows** before any `evidentia`
  invocation in this group — the rich output and several disclaimer strings
  contain non-Latin-1 characters that crash the default `cp1252` console codec:

  **Bash / Linux / macOS**

  ```bash
  export PYTHONIOENCODING=utf-8   # set this first, every session
  ```

  **PowerShell (Windows)**

  ```powershell
  $env:PYTHONIOENCODING = "utf-8"   # set this first, every session
  ```

- The registry persists to an OS-specific user-data directory by default.
  Override it with the **`EVIDENTIA_AI_REGISTRY_DIR`** environment variable to
  keep a demo (or a CI run) isolated:

  **Bash / Linux / macOS**

  ```bash
  export EVIDENTIA_AI_REGISTRY_DIR=/tmp/evidentia-demo/ai_registry
  ```

  **PowerShell (Windows)**

  ```powershell
  $env:EVIDENTIA_AI_REGISTRY_DIR = "$env:TEMP\evidentia-demo\ai_registry"
  ```

## The nine verbs and how they relate

| Verb | Persists? | Needs a registered system? | What it does |
| --- | --- | --- | --- |
| `classify` | no | no | One-shot tier classification of a descriptor YAML. |
| `register` | yes | no | Classify **and** persist a system to the registry. |
| `list` | reads | — | List registered systems (optional `--tier` filter). |
| `show` | reads | yes (UUID) | Show one registered system in full. |
| `update` | yes | yes (UUID) | Partial-update owner / provider / status / SSP ref. |
| `retire` | yes | yes (UUID) | Set `deployment_status=retired` (entry preserved). |
| `categorize-fips` | yes | yes (UUID) | Attach a FIPS 199 C/I/A categorization. |
| `set-high-impact` | yes | yes (UUID) | Attach an OMB M-25-21 high-impact AI determination. |
| `set-omb-impact` | yes | yes (UUID) | (legacy M-24-10; rescinded) Attach the legacy OMB M-24-10 §5(b) category. |

The EU AI Act tier is computed by a fixed evaluation order — the first rule that
matches wins:

```
is_prohibited_practice ──> UNACCEPTABLE   (Article 5)
annex_iii_domain != none ──> HIGH         (Article 6 / Annex III)
interacts_with_natural_persons OR
generates_synthetic_content ──> LIMITED   (Article 50 transparency)
otherwise ──> MINIMAL
```

A descriptor is a small YAML file matching the `AISystemDescriptor` model. Only
`name` and `purpose` are required; every risk-elevating attribute defaults to the
safe value, so a known-low-risk system classifies in one line and a high-risk one
must explicitly declare what makes it high-risk:

```yaml
name: my-system
purpose: Plain-English description of what the system does.
annex_iii_domain: employment          # optional; default: none
decision_role: advisory               # optional; advisory / automated / hybrid
affects_natural_persons: false        # optional
interacts_with_natural_persons: false # optional; triggers Article 50.1 -> LIMITED
generates_synthetic_content: false    # optional; triggers Article 50.4 -> LIMITED
is_prohibited_practice: false         # optional; operator self-assesses -> UNACCEPTABLE
```

`annex_iii_domain` is an enum: `biometrics`, `critical_infrastructure`,
`education`, `employment`, `essential_services`, `law_enforcement`, `migration`,
`justice`, or `none`. An out-of-vocabulary value is rejected (see
[Got stuck?](#got-stuck)).

## Step 1 — Classify a high-risk system (the centerpiece)

`classify` runs the rule-based classifier over a descriptor YAML and prints the
result without persisting anything. Point it at the bundled résumé-screener
fixture:

```bash
evidentia ai-gov classify --descriptor tests/data/walkthrough-federal-si/ai-systems.yaml
```

```text
federal-si-resume-screener
  EU AI Act tier:     high
  NIST AI RMF (top):  govern
  Rationale:
    • Annex III domain 'employment' specified; Article 6 high-risk applies
(HIGH). Operator may downgrade via SME review per Article 6(3) exemptions
(narrow procedural task, preparatory work, decision-pattern detection).
    • High-risk tier; GOVERN + MAP prioritized (organizational policy + system
categorization come before risk measurement).

This classification is an informational starting point produced by a rule-based
classifier. It is NOT a legal compliance determination. Operators should have
SME review for any HIGH or UNACCEPTABLE classification + before deployment of
any AI system that affects natural persons' legal rights or significant
interests.
```

The screener declares `annex_iii_domain: employment`, so the **second** rule in
the evaluation order fires and the system lands at tier `high`. Because the tier
is high, the classifier orders the NIST AI RMF functions `govern → map → measure
→ manage` (organizational policy and system categorization come before risk
measurement). The disclaimer is printed on every run.

> The classifier emits an `AI_SYSTEM_CLASSIFIED` audit event to the structured
> log on stderr (the `[INFO] evidentia.cli.ai_gov: …` line). Redirect stderr
> (`2>/dev/null`) if you only want the result on stdout.

## Step 2 — Classify a minimal-risk system, and a limited-risk one

Run the same command against the low-risk fixture — an internal email classifier
with no Annex III domain and no natural-person interaction:

```bash
evidentia ai-gov classify --descriptor tests/data/walkthrough-federal-si/ai-systems-low-risk.yaml
```

```text
federal-si-internal-email-classifier
  EU AI Act tier:     minimal
  NIST AI RMF (top):  map
  Rationale:
    • No prohibitions, Annex III domain, or transparency triggers identified
(MINIMAL).
    • Advisory/hybrid decision-role; MAP + GOVERN prioritized
(human-in-the-loop reduces measurement urgency).

This classification is an informational starting point produced by a rule-based
classifier. It is NOT a legal compliance determination. Operators should have
SME review for any HIGH or UNACCEPTABLE classification + before deployment of
any AI system that affects natural persons' legal rights or significant
interests.
```

To see the **limited** tier, write a descriptor for a customer-facing chatbot
that both talks to people and generates content (Article 50 transparency
triggers):

**Bash / Linux / macOS**

```bash
cat > chatbot.yaml <<'YAML'
name: customer-support-chatbot
purpose: >
  Public-facing conversational assistant that answers product
  questions on the company website. Hands off to a human agent for
  account changes; does not make automated decisions about people.
decision_role: advisory
interacts_with_natural_persons: true
generates_synthetic_content: true
YAML
evidentia ai-gov classify --descriptor chatbot.yaml
```

**PowerShell (Windows)**

```powershell
@"
name: customer-support-chatbot
purpose: >
  Public-facing conversational assistant that answers product
  questions on the company website. Hands off to a human agent for
  account changes; does not make automated decisions about people.
decision_role: advisory
interacts_with_natural_persons: true
generates_synthetic_content: true
"@ | Set-Content -Encoding utf8 chatbot.yaml
evidentia ai-gov classify --descriptor chatbot.yaml
```

```text
customer-support-chatbot
  EU AI Act tier:     limited
  NIST AI RMF (top):  map
  Rationale:
    • Transparency obligations apply: Article 50.1 (interacts with natural
persons); Article 50.4 (generates synthetic content) (LIMITED).
    • Advisory/hybrid decision-role; MAP + GOVERN prioritized
(human-in-the-loop reduces measurement urgency).

  …(disclaimer omitted for brevity; it prints on every run)…
```

> The `unacceptable` tier is reached only when a descriptor sets
> `is_prohibited_practice: true` — an explicit operator self-assessment against
> the EU AI Act Article 5 prohibition list (social scoring by public
> authorities, real-time public-space biometric identification, subliminal
> manipulation, etc.). Evidentia defers to that flag; it does not infer
> prohibited practices from the free-text `purpose`.

## Step 3 — Get machine-readable JSON

Add `--json` to emit the full `AISystemClassification` as JSON instead of the
rich panel. This is the form to capture in CI or to pipe into a downstream tool:

```bash
evidentia ai-gov classify --descriptor tests/data/walkthrough-federal-si/ai-systems.yaml --json
```

```json
{
  "descriptor_name": "federal-si-resume-screener",
  "eu_ai_act_tier": "high",
  "applicable_nist_ai_rmf_functions": [
    "govern",
    "map",
    "measure",
    "manage"
  ],
  "rationale": [
    "Annex III domain 'employment' specified; Article 6 high-risk applies (HIGH). Operator may downgrade via SME review per Article 6(3) exemptions (narrow procedural task, preparatory work, decision-pattern detection).",
    "High-risk tier; GOVERN + MAP prioritized (organizational policy + system categorization come before risk measurement)."
  ],
  "disclaimer": "This classification is an informational starting point produced by a rule-based classifier. It is NOT a legal compliance determination. Operators should have SME review for any HIGH or UNACCEPTABLE classification + before deployment of any AI system that affects natural persons' legal rights or significant interests."
}
```

The `disclaimer` field travels with the JSON so the caveat survives any
automated pipeline that consumes the output.

## Step 4 — Register systems into the inventory

`register` runs the same classifier and **persists** the system to the registry,
returning a stable UUID. Unlike `classify`, it requires `--provider` (who supplies
the system) and `--owner` (the accountable person/team); `--deployment-status` is
optional and defaults to `proposed` (enum: `proposed` / `in_development` /
`pilot` / `production` / `retired`).

**Bash / Linux / macOS**

```bash
evidentia ai-gov register \
  --descriptor tests/data/walkthrough-federal-si/ai-systems.yaml \
  --provider "Acme HR Tech" \
  --owner "talent-ops@agency.gov" \
  --deployment-status pilot
```

**PowerShell (Windows)**

```powershell
evidentia ai-gov register `
  --descriptor tests/data/walkthrough-federal-si/ai-systems.yaml `
  --provider "Acme HR Tech" `
  --owner "talent-ops@agency.gov" `
  --deployment-status pilot
```

```text
Registered AI system: federal-si-resume-screener
  system_id: 804e6d97-644e-4805-9970-fd6eb2bbc90d
  EU AI Act tier: high
```

**Bash / Linux / macOS**

```bash
evidentia ai-gov register \
  --descriptor tests/data/walkthrough-federal-si/ai-systems-low-risk.yaml \
  --provider "in-house platform team" \
  --owner "it-ops@agency.gov"
```

**PowerShell (Windows)**

```powershell
evidentia ai-gov register `
  --descriptor tests/data/walkthrough-federal-si/ai-systems-low-risk.yaml `
  --provider "in-house platform team" `
  --owner "it-ops@agency.gov"
```

```text
Registered AI system: federal-si-internal-email-classifier
  system_id: 9cc21a78-915f-4227-a943-a33914145532
  EU AI Act tier: minimal
```

The `system_id` UUID printed here is what every later verb (`show`, `update`,
`retire`, `categorize-fips`, `set-high-impact`, `set-omb-impact`) takes as its
positional argument.
Copy it. `register` fires an `AI_SYSTEM_REGISTERED` audit event.

> `register` does **not** accept `--json` — only `classify`, `list`, and `show`
> do. To capture a registered system as JSON, register first, then read it back
> with `list --json` or `show <id> --json` (Steps 5 and 7).

## Step 5 — List the inventory

```bash
evidentia ai-gov list
```

```text
                        Registered AI systems (2 total)
┌───────────┬──────────────┬─────────┬──────────┬──────────────┬──────────────┐
│ System ID │ Name         │ Tier    │ Status   │ Provider     │ Owner        │
├───────────┼──────────────┼─────────┼──────────┼──────────────┼──────────────┤
│ 2e87f379… │ federal-si-… │ high    │ pilot    │ Acme HR Tech │ talent-ops@… │
│ 9cc21a78… │ federal-si-… │ minimal │ proposed │ in-house     │ it-ops@agen… │
│           │              │         │          │ platform     │              │
│           │              │         │          │ team         │              │
└───────────┴──────────────┴─────────┴──────────┴──────────────┴──────────────┘
```

Filter by tier with `--tier` (`unacceptable` / `high` / `limited` / `minimal`),
and add `--json` for the full registry entries (descriptor + classification +
provider/owner/status + the optional federal fields):

```bash
evidentia ai-gov list --tier high --json
```

```json
[
  {
    "system_id": "2e87f379-ff04-4abe-b669-45189692df05",
    "descriptor": {
      "name": "federal-si-resume-screener",
      "purpose": "LLM-assisted resume scoring for federal Systems Integrator (SI)\n…",
      "annex_iii_domain": "employment",
      "decision_role": "advisory",
      "affects_natural_persons": true,
      "interacts_with_natural_persons": false,
      "generates_synthetic_content": false,
      "is_prohibited_practice": false
    },
    "classification": { "eu_ai_act_tier": "high", "…": "…" },
    "provider": "Acme HR Tech",
    "owner": "talent-ops@agency.gov",
    "deployment_status": "pilot",
    "linked_controls": [],
    "last_assessed_at": null,
    "created_at": "2026-05-30T06:47:21.537071Z",
    "updated_at": "2026-05-30T06:47:21.538071Z",
    "fips_199_categorization": null,
    "ato_reference": null,
    "ssp_reference": null,
    "omb_impact": null,
    "omb_high_impact": null
  }
]
```

(JSON trimmed with `…` for readability; the live command emits the full
classification block and untruncated `purpose`.)

## Step 6 — Show one system in detail

`show <system-id>` renders a single registered entry, including its provider,
owner, deployment status, classification, and the standing disclaimer:

```bash
evidentia ai-gov show 804e6d97-644e-4805-9970-fd6eb2bbc90d
```

```text
federal-si-resume-screener
  Provider:           Acme HR Tech
  Owner:              talent-ops@agency.gov
  Deployment status:  pilot
  System ID:          804e6d97-644e-4805-9970-fd6eb2bbc90d
  EU AI Act tier:     high
  NIST AI RMF (top):  govern
  Rationale:
    • Annex III domain 'employment' specified; Article 6 high-risk applies
(HIGH). Operator may downgrade via SME review per Article 6(3) exemptions
(narrow procedural task, preparatory work, decision-pattern detection).
    • High-risk tier; GOVERN + MAP prioritized (organizational policy + system
categorization come before risk measurement).

  …(standing disclaimer prints here)…
```

Add `--json` for the same full entry shown in Step 7.

## Step 7 — Attach FIPS 199 and OMB M-25-21 categorizations

For federal systems you can attach a FIPS 199 confidentiality / integrity /
availability categorization to a registered entry. All three ratings are
required (`low` / `moderate` / `high`); Evidentia auto-computes the **overall**
rating using the FIPS 199 §3 high-water-mark rule (`overall = max(C, I, A)`).
`--rationale` is optional free text.

**Bash / Linux / macOS**

```bash
evidentia ai-gov categorize-fips 804e6d97-644e-4805-9970-fd6eb2bbc90d \
  -c moderate -i moderate -a low \
  --rationale "Resume PII => moderate C; scoring integrity affects fair hiring => moderate I; batch tolerates downtime => low A."
```

**PowerShell (Windows)**

```powershell
evidentia ai-gov categorize-fips 804e6d97-644e-4805-9970-fd6eb2bbc90d `
  -c moderate -i moderate -a low `
  --rationale "Resume PII => moderate C; scoring integrity affects fair hiring => moderate I; batch tolerates downtime => low A."
```

```text
FIPS 199 categorized federal-si-resume-screener → overall=moderate (C=moderate,
I=moderate, A=low)
```

Set the OMB M-25-21 high-impact AI determination with `set-high-impact`. OMB
M-25-21 collapses the old rights-impacting / safety-impacting split into a single
**high-impact AI** category — AI whose output is a principal basis for decisions
with a significant effect on civil rights/liberties/privacy, access to essential
services, critical government resources, human health & safety, critical
infrastructure, or strategic assets. Pass a `--determination`
(`high_impact` / `not_high_impact` / `not_assessed`) and, for a `high_impact`
call, one or more `--basis` flags plus an optional `--rationale`. For a
résumé-screener that adjudicates access to employment, the determination is
`high_impact`:

**Bash / Linux / macOS**

```bash
evidentia ai-gov set-high-impact 804e6d97-644e-4805-9970-fd6eb2bbc90d \
  --determination high_impact \
  --basis civil_rights_liberties_privacy \
  --basis essential_services_access \
  --rationale "Resume screening adjudicates access to employment (an essential service)."
```

**PowerShell (Windows)**

```powershell
evidentia ai-gov set-high-impact 804e6d97-644e-4805-9970-fd6eb2bbc90d `
  --determination high_impact `
  --basis civil_rights_liberties_privacy `
  --basis essential_services_access `
  --rationale "Resume screening adjudicates access to employment (an essential service)."
```

```text
OMB M-25-21 high-impact classified federal-si-resume-screener → high_impact (bases: civil_rights_liberties_privacy, essential_services_access)
```

Valid `--determination` values: `high_impact` / `not_high_impact` /
`not_assessed`. Valid `--basis` values (repeatable): `civil_rights_liberties_privacy`,
`essential_services_access`, `critical_government_resources`, `health_and_safety`,
`critical_infrastructure`, `strategic_assets`.

> A `high_impact` determination triggers M-25-21's seven minimum
> risk-management practices (pre-deployment testing; AI impact assessment;
> ongoing monitoring + adverse-impact detection; human training/competency;
> enhanced human oversight/intervention; consistent remedies & appeals;
> end-user/public feedback). Evidentia records the determination for downstream
> OSCAL emit and reporting; per-practice tracking is a planned follow-up.

> **Legacy / rescinded memo.** OMB M-24-10 was rescinded on 2025-04-03 by
> M-25-21. The legacy `set-omb-impact <id> --category <rights_impacting /
> safety_impacting / rights_and_safety_impacting / neither>` verb still works for
> older inventories and continues to persist the `omb_impact` field, but new
> classifications should use `set-high-impact` above.

Both fields now persist on the entry. Read them back with `show --json`:

```bash
evidentia ai-gov show 804e6d97-644e-4805-9970-fd6eb2bbc90d --json
```

```json
{
  "system_id": "804e6d97-644e-4805-9970-fd6eb2bbc90d",
  "…": "…",
  "fips_199_categorization": {
    "confidentiality_impact": "moderate",
    "integrity_impact": "moderate",
    "availability_impact": "low",
    "overall": "moderate",
    "rationale": "Resume PII => moderate C; scoring integrity affects fair hiring => moderate I; batch tolerates downtime => low A."
  },
  "ato_reference": null,
  "ssp_reference": null,
  "omb_impact": null,
  "omb_high_impact": {
    "determination": "high_impact",
    "bases": ["civil_rights_liberties_privacy", "essential_services_access"],
    "rationale": "Resume screening adjudicates access to employment (an essential service)."
  }
}
```

> These ratings are **operator-supplied metadata**, not a control surface.
> Evidentia records them for downstream OSCAL emit and reporting but does not
> validate them against the information types the system actually processes —
> that is the operator's NIST SP 800-60 review.

## Step 8 — Update and retire

`update` applies **partial** updates — fields you omit are left unchanged. Move
the system to `production` and reassign the owner:

**Bash / Linux / macOS**

```bash
evidentia ai-gov update 804e6d97-644e-4805-9970-fd6eb2bbc90d \
  --owner "ai-governance-board@agency.gov" \
  --deployment-status production
```

**PowerShell (Windows)**

```powershell
evidentia ai-gov update 804e6d97-644e-4805-9970-fd6eb2bbc90d `
  --owner "ai-governance-board@agency.gov" `
  --deployment-status production
```

```text
Updated AI system federal-si-resume-screener
federal-si-resume-screener
  Provider:           Acme HR Tech
  Owner:              ai-governance-board@agency.gov
  Deployment status:  production
  System ID:          804e6d97-644e-4805-9970-fd6eb2bbc90d
  EU AI Act tier:     high
  …
```

`update` also takes `--provider`, `--ssp-reference` (a URI/handle for the System
Security Plan), and `--emit-scr <path>`, which writes a FedRAMP-compatible
Significant Change Request form pair (`<path>.json` + `<path>.md`) with the
change category auto-detected from the diff.

When a system leaves service, `retire` sets `deployment_status=retired` but
**preserves the entry** so historical audits can still see its classification and
ownership history:

```bash
evidentia ai-gov retire 804e6d97-644e-4805-9970-fd6eb2bbc90d
```

```text
Retired AI system federal-si-resume-screener (entry preserved for audit)
```

## What's next

- **Track remediation against gaps**: [Manage a POA&M](manage-poam.md) — the
  same lifecycle discipline applied to control gaps.
- **Schedule recurring assessment cadences**: the
  [CONMON deployment](conmon-deployment.md) guide covers continuous-monitoring
  cadences that complement an AI-system inventory.
- **Every flag, every default**: the `evidentia ai-gov` section of the
  [CLI reference](../4-reference/cli.md).
- **How registry entries are modelled and persisted**:
  [Concepts → Data model](../3-concepts/data-model.md).

## Got stuck?

- **`Error: invalid descriptor: … Input should be 'biometrics', … or 'none'`** —
  the `annex_iii_domain` (or another enum field) has an out-of-vocabulary value.
  The classifier validates the descriptor with Pydantic and rejects unknown
  enum values (exit code `1`); use one of the listed values:

  ```text
  Error: invalid descriptor: 1 validation error for AISystemDescriptor
  annex_iii_domain
    Input should be 'biometrics', 'critical_infrastructure', 'education',
  'employment', 'essential_services', 'law_enforcement', 'migration', 'justice'
  or 'none'
  ```

- **`Error: no registered AI system with ID '…'`** — the UUID is well-formed but
  not in the registry. Confirm it with `evidentia ai-gov list` (or check you are
  pointed at the right `EVIDENTIA_AI_REGISTRY_DIR`).

- **`Error: Invalid AI system ID format (expected UUID): '…'`** — the argument
  is not a UUID at all. Copy the full `system_id` from `register` or `list`.

- **`Error: 'severe' is not a valid FIPS199Impact`** — `categorize-fips` ratings
  must be exactly `low`, `moderate`, or `high` for each of `-c` / `-i` / `-a`.

- **An unknown `--determination` or `--basis` on `set-high-impact`** — the value
  is out of vocabulary and the verb exits with code `1`, listing the valid
  values. `--determination` must be exactly `high_impact`, `not_high_impact`, or
  `not_assessed`; each `--basis` must be one of `civil_rights_liberties_privacy`,
  `essential_services_access`, `critical_government_resources`,
  `health_and_safety`, `critical_infrastructure`, or `strategic_assets`.

- **A `UnicodeEncodeError` / `cp1252` traceback on Windows** — you skipped
  `export PYTHONIOENCODING=utf-8`. Set it and re-run; the rich output and
  disclaimer strings contain characters the default Windows console codec cannot
  encode.
