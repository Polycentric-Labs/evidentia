// @vitest-environment node

import path from "node:path";
import { beforeAll, expect, test } from "vitest";
import openapiTS, { astToString, COMMENT_HEADER } from "openapi-typescript";
import ts from "typescript";
import openapiSchema from "../openapi.json";
import { generateTypes } from "./generate-types.mjs";

let stock;
let generated;
const KNOWN_JSON_NAMES = [
    "JsonValue",
    "StorageRetentionJsonValue",
    "EnterpriseRetentionJsonValue",
    "RegistryJsonValue",
    "evidentia_collectors__entra_m365___contracts__JsonValue",
];
const JSON_NAMES = KNOWN_JSON_NAMES.filter((name) =>
    Object.hasOwn(openapiSchema.components.schemas, name),
);

beforeAll(async () => {
    stock =
        COMMENT_HEADER +
        astToString(
            await openapiTS(structuredClone(openapiSchema), { silent: true }),
        );
    generated = await generateTypes(structuredClone(openapiSchema));
});

function diagnostics(source) {
    const filename = path
        .resolve("generated-openapi-regression.ts")
        .replaceAll("\\", "/");
    const options = {
        noEmit: true,
        strict: true,
        skipLibCheck: false,
        types: [],
        target: ts.ScriptTarget.ES2022,
        module: ts.ModuleKind.ESNext,
    };
    const host = ts.createCompilerHost(options);
    const originalSourceFile = host.getSourceFile.bind(host);
    const originalFileExists = host.fileExists.bind(host);
    const originalReadFile = host.readFile.bind(host);
    const matches = (name) =>
        path.resolve(name).replaceAll("\\", "/") === filename;
    host.getSourceFile = (name, languageVersion, ...rest) =>
        matches(name)
            ? ts.createSourceFile(filename, source, languageVersion, true)
            : originalSourceFile(name, languageVersion, ...rest);
    host.fileExists = (name) => matches(name) || originalFileExists(name);
    host.readFile = (name) => (matches(name) ? source : originalReadFile(name));
    const program = ts.createProgram([filename], options, host);
    return ts.getPreEmitDiagnostics(program).map((item) => ({
        code: item.code,
        message: ts.flattenDiagnosticMessageText(item.messageText, "\n"),
    }));
}

function definitions(text) {
    const file = ts.createSourceFile(
        "generated.ts",
        text,
        ts.ScriptTarget.Latest,
        true,
    );
    const components = file.statements.find(
        (node) =>
            ts.isInterfaceDeclaration(node) && node.name.text === "components",
    );
    const schemas = components.members.find(
        (node) => node.name.getText(file) === "schemas",
    );
    return {
        schemas: new Map(
            schemas.type.members.map((node) => [
                node.name.getText(file),
                node.getFullText(file),
            ]),
        ),
        topLevel: new Map(
            file.statements
                .filter((node) => node.name)
                .map((node) => [node.name.text, node.getText(file)]),
        ),
    };
}

test("the full generated schema passes strict TypeScript checking", () => {
    expect(diagnostics(generated)).toEqual([]);
});

test.each(JSON_NAMES)(
    "%s accepts recursive JSON and rejects values outside JSON",
    (name) => {
        const controls = `
type J = components["schemas"]["${name}"];
type Assert<T extends true> = T;
type Accept<T> = [T] extends [J] ? true : false;
type Reject<T> = [T] extends [J] ? false : true;
export type JsonTypeContract = [
  Assert<Accept<null>>, Assert<Accept<boolean>>, Assert<Accept<number>>, Assert<Accept<string>>,
  Assert<Accept<[]>>, Assert<Accept<{}>>,
  Assert<Accept<{ nested: [true, 0, null, { values: string[] }] }>>,
  Assert<Reject<undefined>>, Assert<Reject<bigint>>, Assert<Reject<symbol>>,
  Assert<Reject<() => void>>, Assert<Reject<Date>>,
  Assert<Reject<{ value: undefined }>>, Assert<Reject<undefined[]>>
];
`;
        expect(diagnostics(generated + controls)).toEqual([]);
    },
);

test("other schema members and existing top-level definitions stay unchanged", () => {
    const before = definitions(stock);
    const after = definitions(generated);
    expect([...after.schemas.keys()]).toEqual([...before.schemas.keys()]);
    for (const [name, value] of before.schemas) {
        if (!JSON_NAMES.includes(name))
            expect(after.schemas.get(name)).toBe(value);
    }
    for (const [name, value] of before.topLevel) {
        if (name !== "components") expect(after.topLevel.get(name)).toBe(value);
    }
    expect(
        [...after.topLevel.keys()].filter((name) => !before.topLevel.has(name)),
    ).toEqual(JSON_NAMES);
});

const invalidShapes = [
    [
        "unrestricted object",
        () => ({ type: "object", additionalProperties: true }),
    ],
    [
        "alternate reference",
        () => ({ $ref: "#/components/schemas/JsonObject" }),
    ],
    ["null schema", () => null],
    ["boolean schema", () => false],
    ["empty union", () => ({ anyOf: [] })],
    [
        "unreviewed metadata",
        (schema) => ({ ...schema, description: "Changed shape" }),
    ],
    [
        "unrestricted array items",
        (schema) => {
            schema.anyOf.find((branch) => branch.type === "array").items = {};
            return schema;
        },
    ],
    [
        "unrestricted object values",
        (schema) => {
            schema.anyOf.find(
                (branch) => branch.type === "object",
            ).additionalProperties = true;
            return schema;
        },
    ],
    [
        "restricted string values",
        (schema) => {
            schema.anyOf.find((branch) => branch.type === "string").enum = [
                "restricted",
            ];
            return schema;
        },
    ],
];

test.each(
    JSON_NAMES.flatMap((name) =>
        invalidShapes.map(([label, alter]) => [name, label, alter]),
    ),
)("refuses unexpected %s shape: %s", async (name, _label, alter) => {
    const changed = structuredClone(openapiSchema);
    changed.components.schemas[name] = alter(changed.components.schemas[name]);
    await expect(generateTypes(changed)).rejects.toThrow(
        new RegExp(`^Unexpected ${name} schema$`),
    );
});

test("a schema without JsonValue keeps the stock generator output", async () => {
    const schema = {
        openapi: "3.1.0",
        info: {
            title: "Synthetic schema without the optional JSON component",
            version: "1",
        },
        paths: {},
        components: { schemas: { Example: { type: "string" } } },
    };
    const expected =
        COMMENT_HEADER + astToString(await openapiTS(schema, { silent: true }));
    expect(await generateTypes(schema)).toBe(expected);
});

test("repeated generation is deterministic", async () => {
    expect(await generateTypes(structuredClone(openapiSchema))).toBe(generated);
});

test("the short JsonValue name remains supported when the schema uses it", async () => {
    const name = "JsonValue";
    const schema = {
        openapi: "3.1.0",
        info: { title: "Synthetic recursive JSON", version: "1" },
        paths: {},
        components: {
            schemas: {
                [name]: {
                    anyOf: [
                        { type: "boolean" },
                        { type: "integer" },
                        { type: "number" },
                        { type: "string" },
                        {
                            type: "array",
                            items: { $ref: "#/components/schemas/JsonValue" },
                        },
                        {
                            type: "object",
                            additionalProperties: {
                                $ref: "#/components/schemas/JsonValue",
                            },
                        },
                        { type: "null" },
                    ],
                },
            },
        },
    };
    const output = await generateTypes(schema);
    expect(output).toContain("export type JsonValue =");
    expect(diagnostics(output)).toEqual([]);
    schema.components.schemas.JsonValue.anyOf[4].items = {};
    await expect(generateTypes(schema)).rejects.toThrow(
        /^Unexpected JsonValue schema$/,
    );
});
