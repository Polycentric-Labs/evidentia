// @vitest-environment node
import { expect, test } from "vitest";
import openapi from "../../../openapi.json";
import { REQUEST_SCHEMA, RESULT_SCHEMA } from "@/lib/incident-clock";
import {
  INCIDENT_FIXTURES,
  incidentDemoCases,
  incidentDemoResponse,
} from "./incident-clock-fixtures";

test.each(INCIDENT_FIXTURES)(
  "keeps the issued synthetic bytes and hash for $name",
  async (item) => {
    const bytes = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(item.raw),
    );
    expect(
      Array.from(new Uint8Array(bytes), (byte) =>
        byte.toString(16).padStart(2, "0"),
      ).join(""),
    ).toBe(item.sha256);
    const request = JSON.parse(item.raw).request;
    expect(incidentDemoResponse(request, item.name).rawJson).toBe(item.raw);
  },
);

test("covers three providers and all published source outcomes", () => {
  expect(
    ["servicenow", "jira", "pagerduty"].map((provider) =>
      INCIDENT_FIXTURES.some(
        (item) => JSON.parse(item.raw).provider === provider,
      ),
    ),
  ).toEqual([true, true, true]);
  expect(
    new Set(INCIDENT_FIXTURES.map((item) => JSON.parse(item.raw).clock.state)),
  ).toEqual(
    new Set([
      "computed",
      "unresolved_events",
      "reversed_order",
      "incomplete_source",
    ]),
  );
  const sample = incidentDemoCases("jira")[0];
  expect(() =>
    incidentDemoResponse(
      { ...sample.request, profile_alias: "other" },
      sample.name,
    ),
  ).toThrow();
  expect(() =>
    incidentDemoResponse(sample.request, "unavailable-name"),
  ).toThrow();
});

type SchemaNode = Record<string, unknown>;
const schemaObject = (value: unknown): value is SchemaNode =>
  value !== null && typeof value === "object" && !Array.isArray(value);
test.each(["request", "result"] as const)(
  "browser %s schema matches generated API constraints",
  (kind) => {
    const source = kind === "request" ? REQUEST_SCHEMA : RESULT_SCHEMA;
    const target =
      kind === "request"
        ? openapi.paths["/api/collectors/incident-clock"].post.requestBody
            .content["application/json"].schema
        : openapi.components.schemas.IncidentClockResult;
    const leftDefs = source.$defs as Record<string, unknown>;
    const rightDefs = openapi.components.schemas as Record<string, unknown>;
    const seen = new Set<string>();
    const compare = (left: unknown, right: unknown): void => {
      if (schemaObject(left) && schemaObject(right)) {
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
          "examples",
        ]);
        const keys = (value: SchemaNode) =>
          Object.keys(value)
            .filter((key) => !metadata.has(key))
            .sort();
        expect(keys(left)).toEqual(keys(right));
        for (const key of keys(left)) {
          if (key === "properties") {
            const one = left[key] as SchemaNode,
              two = right[key] as SchemaNode;
            expect(Object.keys(one).sort()).toEqual(Object.keys(two).sort());
            for (const name of Object.keys(one)) compare(one[name], two[name]);
          } else compare(left[key], right[key]);
        }
      } else if (Array.isArray(left) && Array.isArray(right)) {
        expect(left.length).toBe(right.length);
        left.forEach((item, index) => compare(item, right[index]));
      } else expect(left).toEqual(right);
    };
    compare(source, target);
  },
);
