// @vitest-environment node
import { expect, test } from "vitest";
import openapi from "../../../openapi.json";
import { REGISTRY_NAMES, RESULT_SCHEMA } from "@/lib/registry";
import { registryDemoCases, registryDemoResponse } from "./registry-fixtures";

type Node = Record<string, unknown>;
const object = (value: unknown): value is Node =>
  value !== null && typeof value === "object" && !Array.isArray(value);

test("the browser validator matches the generated authoritative response schema", () => {
  const leftDefs = RESULT_SCHEMA.$defs as Record<string, unknown>;
  const rightDefs = openapi.components.schemas as Record<string, unknown>;
  const seen = new Set<string>();
  const compare = (left: unknown, right: unknown): void => {
    if (object(left) && object(right)) {
      if (typeof left.$ref === "string" || typeof right.$ref === "string") {
        const key = String(left.$ref) + ":" + String(right.$ref);
        if (seen.has(key)) return;
        seen.add(key);
        return compare(
          typeof left.$ref === "string"
            ? leftDefs[left.$ref.split("/").at(-1)!]
            : left,
          typeof right.$ref === "string"
            ? rightDefs[right.$ref.split("/").at(-1)!]
            : right,
        );
      }
      const metadata = new Set([
        "$defs",
        "title",
        "description",
        "default",
        "discriminator",
      ]);
      const keys = (value: Node) =>
        Object.keys(value)
          .filter((key) => !metadata.has(key))
          .sort();
      expect(keys(left)).toEqual(keys(right));
      for (const key of keys(left)) {
        if (key === "properties") {
          const one = left[key] as Node;
          const two = right[key] as Node;
          expect(Object.keys(one).sort()).toEqual(Object.keys(two).sort());
          for (const name of Object.keys(one)) compare(one[name], two[name]);
        } else compare(left[key], right[key]);
      }
    } else if (Array.isArray(left) && Array.isArray(right)) {
      expect(left.length).toBe(right.length);
      left.forEach((item, index) => compare(item, right[index]));
    } else expect(left).toEqual(right);
  };
  compare(RESULT_SCHEMA, rightDefs.RegistryLookupResult);
});

test("every selector has real generated examples with its permitted limitations", () => {
  const all = REGISTRY_NAMES.flatMap((registry) => registryDemoCases(registry));
  expect(all).toHaveLength(43);
  for (const registry of REGISTRY_NAMES)
    expect(registryDemoCases(registry).length).toBeGreaterThan(0);
  for (const sample of all) {
    const { result } = registryDemoResponse(sample.request, sample.name);
    if (result.registry === "sam-entity")
      expect(["partial", "unavailable"]).toContain(result.collection_status);
    if (result.registry === "ssl-labs") {
      expect(result.diagnostics.map((item) => item.code)).toEqual([
        "live_disabled",
      ]);
      expect(
        result.source_reads.every((read) => read.network_attempts === 0),
      ).toBe(true);
    }
    if (result.registry === "incommon")
      expect(
        result.observations.every(
          (item) => item.trust.source_signature === "verified",
        ),
      ).toBe(true);
  }
});
