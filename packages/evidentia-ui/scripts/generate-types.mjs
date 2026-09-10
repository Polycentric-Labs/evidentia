import fs from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";
import openapiTS, { astToString, COMMENT_HEADER } from "openapi-typescript";
import ts from "typescript";

const JSON_REF = "#/components/schemas/JsonValue";
const EXPECTED_JSON_SCHEMA = {
    anyOf: [
        { type: "boolean" },
        { type: "integer" },
        { type: "number" },
        { type: "string" },
        { type: "array", items: { $ref: JSON_REF } },
        { type: "object", additionalProperties: { $ref: JSON_REF } },
        { type: "null" },
    ],
};

function isLiteral(node, value) {
    return (
        ts.isLiteralTypeNode(node) &&
        ts.isStringLiteral(node.literal) &&
        node.literal.text === value
    );
}

function isJsonReference(node) {
    return (
        ts.isIndexedAccessTypeNode(node) &&
        isLiteral(node.indexType, "JsonValue") &&
        ts.isIndexedAccessTypeNode(node.objectType) &&
        isLiteral(node.objectType.indexType, "schemas") &&
        ts.isTypeReferenceNode(node.objectType.objectType) &&
        ts.isIdentifier(node.objectType.objectType.typeName) &&
        node.objectType.objectType.typeName.text === "components"
    );
}

export async function generateTypes(schema) {
    const jsonSchema = schema?.components?.schemas?.JsonValue;
    if (jsonSchema === undefined) {
        return (
            COMMENT_HEADER +
            astToString(await openapiTS(schema, { silent: true }))
        );
    }
    if (!isDeepStrictEqual(jsonSchema, EXPECTED_JSON_SCHEMA)) {
        throw new Error("Unexpected JsonValue schema");
    }

    let alias;
    const nodes = await openapiTS(schema, {
        silent: true,
        postTransform(type, { path }) {
            if (path !== JSON_REF) return undefined;
            if (alias !== undefined)
                throw new Error("Repeated JsonValue transformation");
            let references = 0;
            const transformed = ts.transform(type, [
                (context) => {
                    const visit = (node) => {
                        if (isJsonReference(node)) {
                            references += 1;
                            return ts.factory.createTypeReferenceNode(
                                "JsonValue",
                            );
                        }
                        return ts.visitEachChild(node, visit, context);
                    };
                    return (node) => ts.visitNode(node, visit);
                },
            ]);
            const rewritten = transformed.transformed[0];
            if (!ts.isTypeNode(rewritten) || references !== 2) {
                transformed.dispose();
                throw new Error("Unexpected JsonValue type structure");
            }
            alias = ts.factory.createTypeAliasDeclaration(
                [ts.factory.createModifier(ts.SyntaxKind.ExportKeyword)],
                "JsonValue",
                undefined,
                rewritten,
            );
            transformed.dispose();
            return ts.factory.createTypeReferenceNode("JsonValue");
        },
    });
    if (alias === undefined)
        throw new Error("Missing JsonValue transformation");
    return COMMENT_HEADER + astToString([alias, ...nodes]);
}

export async function main() {
    const schema = JSON.parse(await fs.readFile("openapi.json", "utf8"));
    const output = await generateTypes(schema);
    await fs.writeFile("src/types/openapi.ts", output, "utf8");
}

if (
    process.argv[1] &&
    import.meta.url === pathToFileURL(process.argv[1]).href
) {
    await main();
}
