import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { api } from "@/lib/api";
import { INCIDENT_FIXTURES } from "@/lib/demo/incident-clock-fixtures";
import {
  parseIncidentResponse,
  type IncidentClockRequest,
} from "@/lib/incident-clock";
import { IncidentClockCollectAction } from "./IncidentClockCollectAction";
vi.mock("@/lib/demo", () => ({ IS_DEMO: false }));
vi.mock("@/lib/api", () => ({ api: { collectIncidentClock: vi.fn() } }));
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});
// Issued output from 21 authored synthetic Jira histories through the installed adapter.
// Source literals include a long HTML-shaped value and exact nanosecond timestamps.
// SHA-256: 61d9119d187785223b73c4d93622be51b6b9b347b90c2501a378c3305719e105
const RAW =
  '{"clock":{"elapsed_seconds":"20.000000001","end":{"candidate_event_ids":["event-1b6cbe50f67fc941c74b149b998f60bf1e839ccec1f5ee848b80b62f5b9ece91"],"explicit_occurrence":null,"selected_event_id":"event-1b6cbe50f67fc941c74b149b998f60bf1e839ccec1f5ee848b80b62f5b9ece91","source_literal":"2024-01-01T00:00:20.000000002Z","state":"selected","utc_seconds":"1704067220.000000002"},"start":{"candidate_event_ids":["event-ed47bf9b38185d4ae8084a1439e82491f9f820d9f908fdf7e9fd3b1d40242c8e"],"explicit_occurrence":null,"selected_event_id":"event-ed47bf9b38185d4ae8084a1439e82491f9f820d9f908fdf7e9fd3b1d40242c8e","source_literal":"2024-01-01T00:00:00.000000001Z","state":"selected","utc_seconds":"1704067200.000000001"},"state":"computed"},"credential_validity":"expiry_checked","definition":{"clock_alias":"workflow","declared_workflow_meaning":"Two operational events","definition_sha256":"5ddad947fd9b54b2323b57f110bd2604369a0d60991bc3cc3d718d44a7dee5d8","end":{"field_id":"status","from":{"state":"value","value":"100"},"label":"End","meaning":"Configured workflow end","to":{"state":"value","value":"200"}},"label":"Workflow","mapping_reference":"Synthetic runbook","start":{"field_id":"status","from":{"state":"null","value":null},"label":"Start","meaning":"Configured workflow start","to":{"state":"value","value":"100"}}},"diagnostics":[],"events":[{"event_id":"event-ed47bf9b38185d4ae8084a1439e82491f9f820d9f908fdf7e9fd3b1d40242c8e","matches":["start"],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:00.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"null","value":null},"to":{"state":"value","value":"100"}},"occurrence":{"history_id":"H1","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:00.000000001Z"}},{"event_id":"event-d2b7a5acf6346517045301886c545d6584a09b4086ed3e80c5cb990c990084d8","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:01.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"<img src=x onerror=alert(1)> 🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎🌎"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H2","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:01.000000001Z"}},{"event_id":"event-060f5e12454b437e5c95c00945fff1d28999399be86c485d2906435090249a51","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:02.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"300"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H3","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:02.000000001Z"}},{"event_id":"event-a3ffd2fd0bbe506a686e6bb36b811cb8c7f8ddaf50c2409f6aa2c18407f5024f","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:03.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"300"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H4","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:03.000000001Z"}},{"event_id":"event-63a04062e3ee90477e48ad6b8faefebfebcfff1af4b855a06d06b9bb5edfd9d8","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:04.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"300"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H5","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:04.000000001Z"}},{"event_id":"event-f7b8820c6ce42bb655a45fe4c6be31ecf4f43d1d86a8d45ff1875b6af9d685bd","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:05.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"300"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H6","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:05.000000001Z"}},{"event_id":"event-3a0e994d2037b33f86d208fecd9561b08660b0f9708584d553fb6fd8bb0c335c","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:06.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"300"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H7","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:06.000000001Z"}},{"event_id":"event-bbf7c0ede1009bc8d124edd34e49b429ddba7fad7f0b31da37d309d8062b127f","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:07.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"300"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H8","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:07.000000001Z"}},{"event_id":"event-1c69cc323cbb19a26ce51c72a2ae7ac7222c263c19c3788b892a3a51173943f9","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:08.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"300"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H9","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:08.000000001Z"}},{"event_id":"event-3ff8c802fb9ae0f85d35b0fe845b68428675adc0778f1e3bc7cfaa35577428af","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:09.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"300"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H10","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:09.000000001Z"}},{"event_id":"event-5d88af6c30748bb49c706e59ff19c4e326b87d763d047285e0b28e9ff2d2e7d3","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:10.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"300"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H11","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:10.000000001Z"}},{"event_id":"event-7b9e7f5961de06fa0fcdc16c0dec43707127104511928f85bfb3213cbe71435e","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:11.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"300"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H12","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:11.000000001Z"}},{"event_id":"event-769c1826f94718e5f973e4fc51bb520825ede2a877f44328e64fe5003af583ef","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:12.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"300"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H13","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:12.000000001Z"}},{"event_id":"event-9ecc7f6f02d88dbdb70ea8eaa4e7bfe16d9c83fcc0da778bf563cdc2aba23954","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:13.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"300"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H14","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:13.000000001Z"}},{"event_id":"event-6db93a59e6627e1cd19d9eaca714cbe95bfbd08fd1d5ea339214d548b3b36834","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:14.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"300"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H15","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:14.000000001Z"}},{"event_id":"event-58a53920a6f0d0b8b419ae4d15b5281ee399eb72cf2d98df8b253c1b983e124f","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:15.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"300"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H16","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:15.000000001Z"}},{"event_id":"event-b44cccf247cfdd0ac2d3bd8a603e4e7901c570a37d3fe717819b4b7ee6b67f1a","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:16.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"300"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H17","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:16.000000001Z"}},{"event_id":"event-1ccb9ca0e4765f978ed818812729fe0303b25cfbc8691dff40e63c37e1504359","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:17.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"300"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H18","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:17.000000001Z"}},{"event_id":"event-5f5e9376eca39b79173fa6eadf3986b6fc9851b76f05efe48c3573cdc2abd8dc","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:18.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"300"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H19","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:18.000000001Z"}},{"event_id":"event-3f308e2582950ee9a93620d1626f77d708b29eae98491b490d9b6a4b8da13fd9","matches":[],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:19.000000001Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"300"},"to":{"state":"value","value":"400"}},"occurrence":{"history_id":"H20","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:19.000000001Z"}},{"event_id":"event-1b6cbe50f67fc941c74b149b998f60bf1e839ccec1f5ee848b80b62f5b9ece91","matches":["end"],"native_fields":{"created":{"state":"value","value":"2024-01-01T00:00:20.000000002Z"},"fieldId":{"state":"value","value":"status"},"from":{"state":"value","value":"100"},"to":{"state":"value","value":"200"}},"occurrence":{"history_id":"H21","item_index":0},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","record_id":"10001","timestamp":{"state":"value","value":"2024-01-01T00:00:20.000000002Z"}}],"findings":[{"collection_context":{"collected_at":"2026-09-13T04:13:09.097373Z","collector_id":"incident-clock","collector_version":"0.12.1","credential_identity":"not-established","evidentia_version":"0.12.1","filter_applied":{"definition_sha256":"5ddad947fd9b54b2323b57f110bd2604369a0d60991bc3cc3d718d44a7dee5d8","observation_scope":"selected_incident_clock","profile_binding_sha256":"60caea591f970914c8a88e81ed15850ac62167a6283871f63fbfff805c1a74f0","request":{"clock_alias":"workflow","end_occurrence":null,"profile_alias":"session-test","provider":"jira","record_id":"10001","start_occurrence":null}},"pagination_context":null,"run_id":"01M2CFG436332FVWB16T5G80RK","source_system_id":"incident-clock:jira:60caea591f970914c8a88e81ed15850ac62167a6283871f63fbfff805c1a74f0"},"compliance_status":"unknown","control_mappings":[],"description":"Visible source is complete; configured clock is computed.","first_observed":"2026-09-13T04:13:09.097373Z","id":"e3cd30fd-0835-5e49-bceb-7fc8be8b83c4","last_observed":"2026-09-13T04:13:09.097373Z","raw_data":{"clock_state":"computed","definition_sha256":"5ddad947fd9b54b2323b57f110bd2604369a0d60991bc3cc3d718d44a7dee5d8","elapsed_seconds":"20.000000001","end_event_id":"event-1b6cbe50f67fc941c74b149b998f60bf1e839ccec1f5ee848b80b62f5b9ece91","end_occurrence":{"history_id":"H21","item_index":0},"observation_scope":"selected_incident_clock","profile_binding_sha256":"60caea591f970914c8a88e81ed15850ac62167a6283871f63fbfff805c1a74f0","source_state":"complete","start_event_id":"event-ed47bf9b38185d4ae8084a1439e82491f9f820d9f908fdf7e9fd3b1d40242c8e","start_occurrence":{"history_id":"H1","item_index":0}},"remediation":null,"resolved_at":null,"resource_account":null,"resource_id":"10001","resource_region":null,"resource_type":"selected_incident_clock","severity":"informational","source_finding_id":null,"source_system":"incident-clock","status":"active","title":"Incident clock observation"}],"manifest":{"collection_finished_at":"2026-09-13T04:13:09.147377Z","collection_started_at":"2026-09-13T04:13:09.091372Z","collector_id":"incident-clock","collector_version":"0.12.1","coverage_counts":[{"collected":1,"matched_filter":1,"resource_type":"selected_incident_clock","scanned":1}],"empty_categories":[],"errors":[],"evidentia_version":"0.12.1","filters_applied":{"definition_sha256":"5ddad947fd9b54b2323b57f110bd2604369a0d60991bc3cc3d718d44a7dee5d8","observation_scope":"selected_incident_clock","profile_binding_sha256":"60caea591f970914c8a88e81ed15850ac62167a6283871f63fbfff805c1a74f0","request":{"clock_alias":"workflow","end_occurrence":null,"profile_alias":"session-test","provider":"jira","record_id":"10001","start_occurrence":null}},"incomplete_reason":null,"is_complete":true,"run_id":"01M2CFG436332FVWB16T5G80RK","source_system_ids":["incident-clock:jira:60caea591f970914c8a88e81ed15850ac62167a6283871f63fbfff805c1a74f0"],"total_findings":1,"warnings":["selected_scope_only","workflow_mapping_only"]},"observation_scope":"selected_incident_clock","profile_binding_sha256":"60caea591f970914c8a88e81ed15850ac62167a6283871f63fbfff805c1a74f0","provider":"jira","record":{"fields":{"fields.created":{"state":"value","value":"2023-12-01T00:00:00Z"},"id":{"state":"value","value":"10001"}},"provider":"jira","read_id":"read-76121a139f2234c3f0ced0c7a9312184da6e8db4e6ff535f00342f1ac6f67e8b","record_id":"10001"},"request":{"clock_alias":"workflow","end_occurrence":null,"profile_alias":"session-test","provider":"jira","record_id":"10001","start_occurrence":null},"run_id":"01M2CFG436332FVWB16T5G80RK","schema_version":"1","source_reads":[{"accepted":true,"admitted_events":0,"body_bytes":290,"body_complete":true,"body_sha256":"b9b9ff0e6325331f16b4b971798be644bc5a8d672885355f0fbaf6248c58b427","diagnostic_codes":[],"http_status":200,"kind":"jira_access","ordinal":0,"pagination":null,"read_id":"read-77e7fb6301e410341a59b968842997153a26a31c08433f885f2bbf2e090f06c7","received_records":2,"retrieved_at":"2026-09-13T04:13:09.096373Z","state":"admitted","template":"jira_accessible_resources","wire_bytes":418},{"accepted":true,"admitted_events":0,"body_bytes":77,"body_complete":true,"body_sha256":"4e16bb223bb6d09724d809db16b0c0e17cf19cf9d4f4b22f6e815dda0cc87670","diagnostic_codes":[],"http_status":200,"kind":"record","ordinal":1,"pagination":null,"read_id":"read-76121a139f2234c3f0ced0c7a9312184da6e8db4e6ff535f00342f1ac6f67e8b","received_records":1,"retrieved_at":"2026-09-13T04:13:09.097373Z","state":"admitted","template":"jira_issue","wire_bytes":205},{"accepted":true,"admitted_events":21,"body_bytes":8252,"body_complete":true,"body_sha256":"7edc4ca379c4e2f03434d1eb4d643d352f76140145381e09fa52d70b6e386547","diagnostic_codes":[],"http_status":200,"kind":"history","ordinal":2,"pagination":{"limit":100,"returned":21,"start":0,"terminal":true,"total":21},"read_id":"read-397e91da7fe7430771fef89b795baf82acf372094451a5f4d49eea80ed86cbc6","received_records":21,"retrieved_at":"2026-09-13T04:13:09.099373Z","state":"admitted","template":"jira_changelog","wire_bytes":8380}],"source_state":"complete"}';
function fill(request: IncidentClockRequest) {
  fireEvent.change(screen.getByLabelText("Incident provider"), {
    target: { value: request.provider },
  });
  const recordLabel =
    request.provider === "jira"
      ? "Jira issue ID"
      : request.provider === "servicenow"
        ? "ServiceNow record sys_id"
        : "PagerDuty incident ID";
  for (const [label, value] of [
    ["Authorized profile alias", request.profile_alias],
    ["Workflow clock alias", request.clock_alias],
    [recordLabel, request.record_id],
  ])
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
  if (request.provider === "pagerduty") {
    fireEvent.change(screen.getByLabelText("Log interval since"), {
      target: { value: request.since },
    });
    fireEvent.change(screen.getByLabelText("Log interval until"), {
      target: { value: request.until },
    });
  }
}
test("pages 21 admitted events, bounds literal previews and downloads every original byte", async () => {
  const request = JSON.parse(RAW).request;
  const response = parseIncidentResponse(RAW, request);
  let downloaded: Blob | null = null;
  vi.stubGlobal(
    "URL",
    class extends URL {
      static createObjectURL(value: Blob) {
        downloaded = value;
        return "blob:synthetic-incident-boundary";
      }
      static revokeObjectURL = vi.fn();
    },
  );
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  vi.mocked(api.collectIncidentClock).mockResolvedValue(response);
  render(
    <IncidentClockCollectAction freshAuth verifyAuth={async () => true} />,
  );
  fill(request);
  fireEvent.click(
    screen.getByRole("button", { name: "Collect incident clock" }),
  );
  await screen.findByRole("region", { name: "Incident clock result" });
  expect(screen.getByText("20.000000001")).toBeInTheDocument();
  const events = screen.getByLabelText("Admitted incident events");
  expect(within(events).getAllByText(/^Event [0-9]+; matches:/)).toHaveLength(
    20,
  );
  expect(
    screen.getByText("Showing 1 to 20 of 21 admitted events."),
  ).toBeInTheDocument();
  const literal = [...events.querySelectorAll("pre")].find((item) =>
    item.textContent?.includes("<img src=x onerror=alert(1)>"),
  );
  expect(literal).toBeDefined();
  expect(events.querySelector("img")).toBeNull();
  expect(
    new TextEncoder().encode(literal!.textContent!).length,
  ).toBeLessThanOrEqual(4096);
  expect(literal!.textContent).not.toContain(String.fromCharCode(0xfffd));
  expect(
    screen.getByText(/This preview is limited to 4 KiB/),
  ).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Previous events" }),
  ).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Next events" }));
  expect(within(events).getAllByText(/^Event [0-9]+; matches:/)).toHaveLength(
    1,
  );
  expect(
    screen.getByText("Showing 21 to 21 of 21 admitted events."),
  ).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Next events" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Previous events" }));
  expect(within(events).getAllByText(/^Event [0-9]+; matches:/)).toHaveLength(
    20,
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Download full incident clock JSON" }),
  );
  expect(await (downloaded as unknown as Blob).text()).toBe(RAW);
});
test.each(INCIDENT_FIXTURES)(
  "displays separate source and clock states for $name",
  async (sample) => {
    const request = JSON.parse(sample.raw).request;
    const response = parseIncidentResponse(sample.raw, request);
    vi.mocked(api.collectIncidentClock).mockResolvedValue(response);
    render(
      <IncidentClockCollectAction freshAuth verifyAuth={async () => true} />,
    );
    fill(request);
    fireEvent.click(
      screen.getByRole("button", { name: "Collect incident clock" }),
    );
    const region = await screen.findByRole("region", {
      name: "Incident clock result",
    });
    expect(
      within(region).getByText(response.result.source_state),
    ).toBeInTheDocument();
    expect(
      within(region).getByText(response.result.clock.state),
    ).toBeInTheDocument();
    expect(
      within(region).getByRole("button", {
        name: "Download full incident clock JSON",
      }),
    ).toBeEnabled();
  },
);
