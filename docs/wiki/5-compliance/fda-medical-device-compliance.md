# FDA medical-device cybersecurity (Section 524B)

Evidentia ships generic, public support for **FDA Section 524B premarket
device cybersecurity**: the eight security control categories as a real
bundled catalog, license-respecting stubs + crosswalks for the adjacent
risk-management standards, and a demo-only showcase route.

!!! note "Illustrative — feedback welcome"
    This page and the bundled 524B artifacts are an **illustrative** orientation
    aid, not regulatory advice and not an FDA-, ISO-, or AAMI-endorsed mapping.
    They paraphrase public U.S.-Government works in Evidentia's own words and
    point you at the authoritative sources. If something here is wrong or could
    be clearer, please [open an issue](https://github.com/Polycentric-Labs/evidentia/issues).

## What Section 524B is

**FD&C Act Section 524B** (*21 U.S.C. 360n-2*), captioned *"Ensuring
cybersecurity of devices,"* was added by **§3305 of the Food and Drug Omnibus
Reform Act of 2022 (FDORA)** (Pub. L. 117-328) and took effect **March 29,
2023**. It requires a "cyber device" premarket submission to include:

- a plan to monitor, identify, and address postmarket cybersecurity
  vulnerabilities (a **vulnerability-management plan**);
- **secure-by-design** processes that provide a reasonable assurance the device
  and related systems are cybersecure, including making available
  **updates and patches**; and
- a **software bill of materials (SBOM)** covering commercial, open-source, and
  off-the-shelf software components.

FDA's how-to detail lives in the final guidance **"Cybersecurity in Medical
Devices: Quality Management System Considerations and Content of Premarket
Submissions"** (**Feb 3, 2026 edition** — which supersedes the June 27, 2025 and
Sept 27, 2023 editions). Its **Section V.B.1** enumerates the eight security
control categories below; Appendix 1 gives the per-category recommendations.

## The eight security control categories

These category **names are reproduced verbatim** from the guidance's
§V.B.1 (a U.S.-Government work, not subject to copyright — *17 U.S.C. 105*); the
characterizations are written in Evidentia's own words.

| # | Category | What it covers |
|---|----------|----------------|
| 1 | **Authentication** | Verifies the claimed identity of a user, process, or device before granting access. |
| 2 | **Authorization** | Enforces what an authenticated entity is permitted to do, per its privileges. |
| 3 | **Cryptography** | Cryptographic methods + key management protecting data confidentiality, integrity, and authenticity at rest and in transit. |
| 4 | **Code, Data, and Execution Integrity** | Keeps device code, stored data, and the execution environment unaltered and trustworthy. |
| 5 | **Confidentiality** | Protects sensitive data the device handles from disclosure to unauthorized parties. |
| 6 | **Event Detection and Logging** | Detects security-relevant events and records them for monitoring and forensic review. |
| 7 | **Resiliency and Recovery** | Lets the device withstand cybersecurity events and restore safe, essential operation. |
| 8 | **Updatability and Patchability** | Securely update and patch the device over its lifecycle so vulnerabilities can be remediated. |

!!! info "A naming nuance on category #8"
    The guidance is internally inconsistent: §V.B.1 names the eighth category
    **"Updatability and Patchability,"** while **Appendix 1's** subsection header
    for the same category reads **"Firmware and Software Updates."** Evidentia
    uses the §V.B.1 name and notes the Appendix-1 variant in the control
    description, rather than mislabel one against the other.

## Safety risk vs. security risk — the key distinction

Medical-device work runs **two** risk-management processes against a **shared
patient-harm severity axis**:

- **Safety** risk management — **ISO 14971:2019** characterizes risk as a
  *combination of the probability of occurrence of harm and the severity of that
  harm* (commonly operationalized as **probability × severity**).
- **Security** risk management — **ANSI/AAMI SW96:2023** (building on
  **AAMI TIR57:2016 (R2023)**) characterizes security risk in terms of
  **exploitability** rather than probability of occurrence: a security exploit is
  assessed by *how readily it can be carried out* (exploitability) combined with
  the **severity of the resulting patient harm**.

The Section 524B premarket security controls feed the device's **security** risk
management, which in turn informs the **ISO 14971 safety** risk file through the
shared severity axis. (This framing paraphrases the ISO 14971 and AAMI
SW96/TIR57 methodologies; it is not a quotation from the FDA guidance or the
standards.)

## What Evidentia bundles

- **A real catalog** — `fda-524b-appendix1` (Tier A, eight controls). It is a
  fully bundled framework, so it is reachable the same three ways every other
  Evidentia framework is: the **CLI** (`evidentia catalog list`,
  `evidentia gap analyze --frameworks fda-524b-appendix1`), the **API**
  (`GET /api/frameworks`), and the web console's **Gap Analyze** framework
  picker.
- **License-respecting stubs** — `iso-14971` and `aami-sw96` ship as
  **placeholder stubs that cite the standard and link to its publisher** but
  reproduce **no** normative text. ISO 14971 and the AAMI standards are
  copyrighted; only their designations and clause *titles* (paraphrased) appear.
- **Two illustrative crosswalks** — `fda-524b-appendix1 → iso-14971` and
  `fda-524b-appendix1 → aami-sw96`, each carrying the safety-vs-security
  **risk-model note** above. These are **hand-authored, self-attested,
  conceptual** links to orient a reader — not control-equivalence assertions and
  not independently audited. Verify any reliance against the licensed standards.

### Run it

```bash
# List the bundled framework
evidentia catalog list | grep fda-524b-appendix1

# Run a 524B gap analysis against your device control inventory
evidentia gap analyze --inventory my-controls.yaml \
  --frameworks fda-524b-appendix1 --output report.json

# Or emit a SIGNED OSCAL Assessment Results document directly from the analysis:
# --sign-with-gpg takes your GPG key ID (writes a detached <output>.asc), or use
# --sign-with-sigstore for keyless Sigstore signing.
evidentia gap analyze --inventory my-controls.yaml \
  --frameworks fda-524b-appendix1 \
  --format oscal-ar --output report.oscal.json --sign-with-gpg <your-gpg-key-id>

# Verify the signed artifact (digests + GPG and/or Sigstore signatures):
evidentia oscal verify report.oscal.json
```

A synthetic, banner-labeled example Assessment Results document lives at
[`examples/fda-524b-DEMO-example-assessment.oscal.json`](https://github.com/Polycentric-Labs/evidentia/blob/main/examples/fda-524b-DEMO-example-assessment.oscal.json).
Its `_illustrative_signature` block is a **display fixture** — it verifies
nothing, and **no signing key ships in this repository**.

## The demo showcase

The static demo build of the web console (`VITE_DEMO=true`) registers a
demo-only route, **`#/demo/fda`**, that runs a synthetic 524B gap analysis with
**zero backend**: one click reveals the gaps, traces every STRIDE-categorized
device threat to the 524B control that mitigates it and the test that proves it,
and ends on an illustrative signed-evidence artifact. The organization, device,
and findings are invented for illustration; the route is not registered in the
normal API-backed build.

## Authoritative sources

- **FDA** — medical-device cybersecurity hub: <https://www.fda.gov/medical-devices/digital-health-center-excellence/cybersecurity>; guidance documents: <https://www.fda.gov/regulatory-information/search-fda-guidance-documents>
- **Statute** — FD&C Act §524B / 21 U.S.C. § 360n-2: <https://www.law.cornell.edu/uscode/text/21/360n-2>
- **ISO 14971:2019** — *Medical devices — Application of risk management to medical devices* (purchase/preview at <https://www.iso.org/>)
- **ANSI/AAMI SW96:2023** + **AAMI TIR57:2016 (R2023)** — medical-device security risk management (<https://www.aami.org/>)

*Copyright note: the FDA guidance and the statute are U.S.-Government works
(17 U.S.C. 105) and are paraphrasable. ISO 14971 and the AAMI standards are
copyrighted — Evidentia stubs and cites them but never reproduces their text.*
