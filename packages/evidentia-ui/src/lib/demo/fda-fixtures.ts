/**
 * FDA medical-device demo dataset — a synthetic Section 524B premarket
 * cybersecurity gap analysis rendered with zero backend.
 *
 * Domain-tailored, NOT customer-specific: the organization, device, and findings
 * are invented for illustration. The eight control categories are FDA's own
 * Appendix 1 "Security Control Categories" from the premarket cybersecurity
 * guidance (public; described here in our own words). Types are pinned to the
 * same sources the production client uses so the fixtures can never drift from
 * the rendered components.
 */

import type { FrameworkListResponse } from "@/lib/api";
import type {
  ControlGap,
  EfficiencyOpportunity,
  GapAnalysisReport,
} from "@/types/api";

const ANALYZED_AT = "2026-06-16T15:04:11.220115Z";
const CREATED_AT = "2026-06-16T15:04:11.210115Z";
const EVIDENTIA_VERSION = "0.10.10";

/** The synthetic device-maker the story analyzes. Clearly invented. */
export const FDA_ORG = "Northwind MedTech (illustrative)";
export const FDA_SYSTEM = "Connected Therapy Platform — device software (SaMD)";

const FRAMEWORK_ID = "fda-524b-appendix1";

/**
 * Build a schema-complete ControlGap for a 524B Appendix-1 category.
 * `control_id` uses a stable 524B.* scheme; descriptions paraphrase the public
 * FDA guidance category intent (no copyrighted text reproduced).
 */
function gap(
  num: number,
  category: string,
  severity: ControlGap["gap_severity"],
  status: ControlGap["implementation_status"],
  gapDescription: string,
  remediation: string,
  effort: ControlGap["implementation_effort"],
  priority: number,
): ControlGap {
  return {
    id: `fda-524b-a${num}`,
    framework: FRAMEWORK_ID,
    control_id: `524B.A${num}`,
    control_title: category,
    control_description:
      "FDA premarket cybersecurity guidance, Appendix 1 security control category. See the FDA guidance for the authoritative recommendations.",
    control_family: "Appendix 1 — Security Control Categories",
    gap_severity: severity,
    implementation_status: status,
    gap_description: gapDescription,
    status: "open",
    equivalent_controls_in_inventory: [],
    cross_framework_value: [],
    remediation_guidance: remediation,
    implementation_effort: effort,
    priority_score: priority,
    jira_issue_key: null,
    servicenow_ticket_id: null,
    created_at: CREATED_AT,
    remediated_at: null,
    assigned_to: null,
    tags: ["medical-device", "524b", "premarket"],
  };
}

/**
 * Five open gaps across the eight Appendix-1 categories (the other three —
 * Authorization, Confidentiality — are treated as satisfied in the inventory,
 * so coverage reads 37.5%). 2 critical / 2 high / 1 medium.
 */
export const FDA_524B_GAPS: ControlGap[] = [
  gap(
    1,
    "Authentication",
    "critical",
    "missing",
    "The device exposes an unauthenticated maintenance/debug interface, and the device-to-cloud channel does not perform mutual authentication. Either weakness lets an attacker impersonate the device or the gateway.",
    "Establish a cryptographic device identity (per-device certificate via PKI) and require mutual TLS on every external interface. Disable or authenticate the maintenance interface. Document the authentication architecture and map it to the threat model.",
    "high",
    9.2,
  ),
  gap(
    3,
    "Cryptography",
    "critical",
    "missing",
    "A symmetric key is hard-coded in firmware and shared across all units, with no rotation, and a non-NIST-approved cipher is used on one link. A single extracted key compromises the fleet.",
    "Move to NIST-approved algorithms (AES-256, ECC), per-device keys generated and stored in hardware (TPM/HSM where available), and a defined rotation and revocation process. Provide a cryptographic inventory and a path to crypto-agility for the post-quantum transition.",
    "high",
    9.0,
  ),
  gap(
    4,
    "Code, Data, and Execution Integrity",
    "high",
    "missing",
    "Firmware images are not cryptographically signed and the device has no secure-boot chain, so modified or rolled-back firmware can run undetected.",
    "Sign all firmware/software with a managed key, verify signatures in a secure-boot chain, and reject unsigned or downgraded images. Capture the signing and verification evidence as part of the design history file.",
    "high",
    8.1,
  ),
  gap(
    8,
    "Updatability and Patchability",
    "high",
    "partial",
    "There is no validated mechanism to deliver authenticated out-of-cycle patches to fielded devices, which undercuts the postmarket vulnerability-management plan.",
    "Implement authenticated, integrity-protected over-the-air updates with rollback protection, on a reasonably justified cycle plus an out-of-cycle path for critical vulnerabilities. Tie the mechanism to the postmarket plan and coordinated vulnerability disclosure.",
    "medium",
    7.3,
  ),
  gap(
    6,
    "Event Detection and Logging",
    "medium",
    "partial",
    "Security-relevant events are recorded inconsistently and cannot be exported for monitoring, so incidents on fielded devices may go undetected and unprovable.",
    "Log security-relevant events to a tamper-evident store and provide an export path for the operator's monitoring. Define which events are captured and how they support postmarket surveillance.",
    "medium",
    5.6,
  ),
];

/** Cross-framework efficiency wins — controls that also satisfy adjacent standards. */
export const FDA_524B_EFFICIENCY: EfficiencyOpportunity[] = [
  {
    control_id: "524B.A1",
    control_title: "Authentication",
    frameworks_satisfied: ["fda-524b-appendix1", "iec-62443-4-2", "aami-sw96"],
    framework_count: 3,
    total_gaps_closed: 6,
    implementation_effort: "high",
    value_score: 9.1,
  },
  {
    control_id: "524B.A3",
    control_title: "Cryptography",
    frameworks_satisfied: ["fda-524b-appendix1", "iec-62443-4-2"],
    framework_count: 2,
    total_gaps_closed: 4,
    implementation_effort: "high",
    value_score: 8.4,
  },
];

/** The hero report: 8 categories required, 3 satisfied, 5 gaps, 37.5% coverage. */
export const FDA_524B_REPORT: GapAnalysisReport = {
  id: "fda-524b-demo-baseline",
  organization: FDA_ORG,
  frameworks_analyzed: [FRAMEWORK_ID],
  analyzed_at: ANALYZED_AT,
  total_controls_required: 8,
  total_controls_in_inventory: 3,
  total_gaps: 5,
  critical_gaps: 2,
  high_gaps: 2,
  medium_gaps: 1,
  low_gaps: 0,
  informational_gaps: 0,
  coverage_percentage: 37.5,
  gaps: FDA_524B_GAPS,
  efficiency_opportunities: FDA_524B_EFFICIENCY,
  prioritized_roadmap: FDA_524B_GAPS.map((g) => g.id),
  inventory_source: "device-controls.yaml",
  evidentia_version: EVIDENTIA_VERSION,
  notes:
    "Synthetic illustration of a Section 524B premarket cybersecurity gap analysis for connected-device software.",
};

/** The framework entry the picker / catalog routes render. */
export const FDA_524B_FRAMEWORK: FrameworkListResponse = {
  total: 1,
  frameworks: [
    {
      id: FRAMEWORK_ID,
      name: "FDA Premarket Cybersecurity (Section 524B) — Appendix 1",
      version: "2023 final guidance",
      tier: "A",
      category: "control",
      placeholder: "false",
      license_required: "false",
    },
  ],
};

// ── Threat → control → evidence traceability (the differentiated view) ───────

export type TraceStatus = "gap" | "partial" | "satisfied";

export interface TraceRow {
  /** STRIDE category. */
  stride: string;
  /** A concrete device threat event in that category. */
  threat: string;
  /** The Appendix-1 control that mitigates it. */
  controlId: string;
  controlName: string;
  /** The verification evidence / test that proves the control. */
  evidence: string;
  status: TraceStatus;
}

/**
 * Eight rows mapping a STRIDE-categorized device threat to the 524B control that
 * mitigates it and the test/evidence that proves it — the threat → control →
 * test traceability an FDA premarket package rests on.
 */
export const FDA_TRACEABILITY: TraceRow[] = [
  {
    stride: "Spoofing",
    threat: "An attacker impersonates the device to the cloud gateway.",
    controlId: "524B.A1",
    controlName: "Authentication",
    evidence: "Mutual-TLS handshake test; device-identity certificate review.",
    status: "gap",
  },
  {
    stride: "Tampering",
    threat: "Malicious or rolled-back firmware is loaded onto the device.",
    controlId: "524B.A4",
    controlName: "Code, Data, and Execution Integrity",
    evidence: "Secure-boot + signature-verification test; downgrade-rejection test.",
    status: "gap",
  },
  {
    stride: "Information disclosure",
    threat: "Traffic on the device-to-cloud link is intercepted and decrypted.",
    controlId: "524B.A3",
    controlName: "Cryptography",
    evidence: "Cipher-suite scan; key-management and key-storage review.",
    status: "gap",
  },
  {
    stride: "Repudiation",
    threat: "A security event on a fielded device leaves no provable record.",
    controlId: "524B.A6",
    controlName: "Event Detection and Logging",
    evidence: "Tamper-evident log review; event-export validation.",
    status: "partial",
  },
  {
    stride: "Denial of service",
    threat: "Loss of connectivity drives the device into an unsafe state.",
    controlId: "524B.A7",
    controlName: "Resiliency and Recovery",
    evidence: "Fail-safe / return-to-safe-state test on comms loss.",
    status: "satisfied",
  },
  {
    stride: "Elevation of privilege",
    threat: "A maintenance interface is used to gain privileged access.",
    controlId: "524B.A2",
    controlName: "Authorization",
    evidence: "Privilege-boundary and least-privilege test.",
    status: "satisfied",
  },
  {
    stride: "Information disclosure",
    threat: "Patient data at rest on the device is exposed.",
    controlId: "524B.A5",
    controlName: "Confidentiality",
    evidence: "Encryption-at-rest configuration review.",
    status: "satisfied",
  },
  {
    stride: "Tampering",
    threat: "A critical vulnerability cannot be patched on fielded devices.",
    controlId: "524B.A8",
    controlName: "Updatability and Patchability",
    evidence: "Authenticated OTA-update + rollback-protection test.",
    status: "partial",
  },
];

// ── The signed evidence artifact (the wow finish) ────────────────────────────

export interface SignedArtifact {
  filename: string;
  framework: string;
  /** SHA-256 over the assessment payload (synthetic, illustrative). */
  sha256: string;
  /** ULID run identifier. */
  runId: string;
  signedAt: string;
  signer: string;
  /** Sigstore Rekor transparency-log index (synthetic). */
  rekorLogIndex: string;
  verified: boolean;
}

/**
 * A representative signed OSCAL Assessment Results envelope. Real deployments
 * produce these via Sigstore keyless signing (Fulcio cert + Rekor log) from the
 * CLI; this is a pre-computed illustration signed with a test identity.
 */
export const FDA_SIGNED_ARTIFACT: SignedArtifact = {
  filename: "fda-524b-assessment-results.oscal.json",
  framework: "fda-524b-appendix1",
  sha256:
    "9f2c41e8a7b30d6c5e1f8a92b4d07c3e6a1b9d8f2c4e70a5b3d6f1c8e9a2b7d40",
  runId: "01JZ8K6T7QF3WYB9N2C4D5E6F7",
  signedAt: ANALYZED_AT,
  signer: "demo-signing-identity (test key)",
  rekorLogIndex: "148203394",
  verified: true,
};

/** The ~2-second "watch it run" step sequence for the analysis animation. */
export interface RunStep {
  label: string;
  detail: string;
}

export const FDA_RUN_STEPS: RunStep[] = [
  { label: "Loading catalog", detail: "FDA 524B Appendix 1 — 8 control categories" },
  { label: "Parsing device inventory", detail: "device-controls.yaml" },
  { label: "Analyzing gaps", detail: "mapping controls to implemented evidence" },
  { label: "Tracing threats", detail: "STRIDE threat → control → test" },
  { label: "Emitting OSCAL", detail: "Assessment Results + POA&M" },
  { label: "Signing evidence", detail: "Sigstore keyless · Rekor transparency log" },
];
