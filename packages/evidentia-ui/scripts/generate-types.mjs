import fs from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";
import openapiTS, { astToString, COMMENT_HEADER } from "openapi-typescript";
import ts from "typescript";

const JSON_NAMES = ["JsonValue", "StorageRetentionJsonValue"];
const jsonRef = (name) => `#/components/schemas/${name}`;
const expectedJsonSchema = (name) => ({
    anyOf: [
        { type: "boolean" },
        { type: "integer" },
        { type: "number" },
        { type: "string" },
        { type: "array", items: { $ref: jsonRef(name) } },
        { type: "object", additionalProperties: { $ref: jsonRef(name) } },
        { type: "null" },
    ],
});

function isLiteral(node, value) {
    return (
        ts.isLiteralTypeNode(node) &&
        ts.isStringLiteral(node.literal) &&
        node.literal.text === value
    );
}

function isJsonReference(node, name) {
    return (
        ts.isIndexedAccessTypeNode(node) &&
        isLiteral(node.indexType, name) &&
        ts.isIndexedAccessTypeNode(node.objectType) &&
        isLiteral(node.objectType.indexType, "schemas") &&
        ts.isTypeReferenceNode(node.objectType.objectType) &&
        ts.isIdentifier(node.objectType.objectType.typeName) &&
        node.objectType.objectType.typeName.text === "components"
    );
}

export async function generateTypes(schema) {
    const names = JSON_NAMES.filter(
        (name) => schema?.components?.schemas?.[name] !== undefined,
    );
    if (names.length === 0) {
        return (
            COMMENT_HEADER +
            astToString(await openapiTS(schema, { silent: true }))
        );
    }
    for (const name of names) {
        if (
            !isDeepStrictEqual(
                schema.components.schemas[name],
                expectedJsonSchema(name),
            )
        ) {
            throw new Error(`Unexpected ${name} schema`);
        }
    }

    const aliases = new Map();
    const nodes = await openapiTS(schema, {
        silent: true,
        postTransform(type, { path }) {
            const name = names.find((candidate) => path === jsonRef(candidate));
            if (name === undefined) return undefined;
            if (aliases.has(name))
                throw new Error(`Repeated ${name} transformation`);
            let references = 0;
            const transformed = ts.transform(type, [
                (context) => {
                    const visit = (node) => {
                        if (isJsonReference(node, name)) {
                            references += 1;
                            return ts.factory.createTypeReferenceNode(name);
                        }
                        return ts.visitEachChild(node, visit, context);
                    };
                    return (node) => ts.visitNode(node, visit);
                },
            ]);
            const rewritten = transformed.transformed[0];
            if (!ts.isTypeNode(rewritten) || references !== 2) {
                transformed.dispose();
                throw new Error(`Unexpected ${name} type structure`);
            }
            aliases.set(
                name,
                ts.factory.createTypeAliasDeclaration(
                    [ts.factory.createModifier(ts.SyntaxKind.ExportKeyword)],
                    name,
                    undefined,
                    rewritten,
                ),
            );
            transformed.dispose();
            return ts.factory.createTypeReferenceNode(name);
        },
    });
    if (aliases.size !== names.length)
        throw new Error("Missing recursive JSON transformation");
    return (
        COMMENT_HEADER +
        astToString([...names.map((name) => aliases.get(name)), ...nodes])
    );
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
