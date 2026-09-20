/// <reference types="node" />
import { createHash } from "node:crypto";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, expect, it, vi } from "vitest";
import { api, ApiError } from "@/lib/api";
import { NativeSourcePanel } from "@/routes/FrameworkDetailPage";
import { NativeImportSection } from "@/routes/CatalogPage";
import { decodeNativeBundle, decodeNativeCatalog } from "@/lib/catalog-native";
import type {
  NativeBundle,
  NativeCatalog,
  NativeRequest,
  CatalogNativeNativeData,
  ValueRef,
  CatalogNativeImportResult,
} from "@/lib/catalog-native";

const demoMode = vi.hoisted(() => ({ enabled: false }));
vi.mock("@/lib/demo", () => ({
  get IS_DEMO() {
    return demoMode.enabled;
  },
}));
afterEach(() => {
  cleanup();
  demoMode.enabled = false;
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
function provider(ui: ReactElement) {
  return (
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      {ui}
    </QueryClientProvider>
  );
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

// The following fixture preserves the independently authored F3 source and byte offsets.
const hash = (value: string | Uint8Array) =>
  createHash("sha256").update(value).digest("hex");
const compact = (value: unknown): string =>
  JSON.stringify(value).replace(
    /[\u007f-\uffff]/g,
    (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
const source =
  '{"id":"G","controls":[{"id":"C","n":9007199254740993,"x":null,"u":"é"}]}';
const bytes = (value: string) => new TextEncoder().encode(value);
function ref(start: number, end: number, kind: ValueRef["kind"]): ValueRef {
  return {
    document_index: 0,
    byte_start: start,
    byte_end: end,
    kind,
    sha256: hash(bytes(source).slice(start, end)),
  };
}
// These offsets count the authored UTF-8 source, including the two-byte é.
function example(): NativeBundle {
  const group = ref(0, 73, "json_object");
  const control = ref(22, 71, "json_object");
  const data: CatalogNativeNativeData = {
    schema_version: "catalog-native-v1",
    profile: "au-ism-2026.09.4",
    catalog_id: "au-ism",
    converter_id: "evidentia-open-corpora-v1",
    converter_sha256: "a".repeat(64),
    documents: [
      {
        binding: {
          source_key: "synthetic",
          role: "authoritative",
          media_type: "application/json",
          repository: "Synthetic/source",
          commit: "b".repeat(40),
          upstream_path: "synthetic.json",
          raw_bytes: 73,
          raw_sha256: hash(source),
        },
        raw_utf8: source,
      },
    ],
    occurrences: [
      {
        index: 0,
        kind: "group",
        parent_index: null,
        sibling_ordinal: 0,
        source: group,
        fields: [
          {
            name: "id",
            key: ref(1, 5, "json_string"),
            value: ref(6, 9, "json_string"),
          },
          {
            name: "controls",
            key: ref(10, 20, "json_string"),
            value: ref(21, 72, "json_array"),
          },
        ],
        selections: [],
      },
      {
        index: 1,
        kind: "control",
        parent_index: 0,
        sibling_ordinal: 0,
        source: control,
        fields: [
          {
            name: "id",
            key: ref(23, 27, "json_string"),
            value: ref(28, 31, "json_string"),
          },
          {
            name: "n",
            key: ref(32, 35, "json_string"),
            value: ref(36, 52, "json_number"),
          },
          {
            name: "x",
            key: ref(53, 56, "json_string"),
            value: ref(57, 61, "json_null"),
          },
          {
            name: "u",
            key: ref(62, 65, "json_string"),
            value: ref(66, 70, "json_string"),
          },
        ],
        selections: [
          {
            role: "native_id",
            value: { state: "present", refs: [ref(28, 31, "json_string")] },
          },
          {
            role: "parameter",
            value: { state: "native_null", refs: [ref(57, 61, "json_null")] },
          },
          { role: "statement", value: { state: "absent" } },
        ],
      },
    ],
    control_bindings: [
      {
        control_id: "C",
        occurrence_index: 1,
        family_occurrence_index: 0,
        parent_control_id: null,
        admitted_criticality: null,
      },
    ],
    context_indices: [0],
    diagnostics: [],
  };
  return seal(data);
}
function seal(data: CatalogNativeNativeData): NativeBundle {
  return {
    bundle_sha256: hash("evidentia.catalog-native.v1\0" + compact(data)),
    data,
  };
}
const expected = (bundle: NativeBundle): NativeRequest => ({
  framework_id: "au-ism",
  bundle_sha256: bundle.bundle_sha256,
});
function ordinary(bundle: NativeBundle): NativeCatalog {
  return {
    framework_id: "au-ism",
    framework_name: "Synthetic",
    version: "1",
    source: "Synthetic/source",
    controls: [
      {
        id: "C",
        title: "Synthetic control",
        description: "Server-projected prose",
        family: "native-group:0",
        class: null,
        control_class: null,
        priority: null,
        baseline_impact: [],
        enhancements: [],
        related_controls: [],
        assessment_objectives: [],
        objective: null,
        risk_tier: null,
        applies_to_annex_iii: null,
        guidance: null,
        examples: [],
        parameters: {},
        ordering: 0,
        tier: null,
        license_required: false,
        license_url: null,
        placeholder: false,
        withdrawn: false,
        properties: {},
        source_rows: [],
        native_source_ref: {
          bundle_sha256: bundle.bundle_sha256,
          occurrence_index: 1,
        },
      },
    ],
    families: ["native-group:0"],
    family_hierarchy: null,
    category: "control",
    tier: null,
    v0_9_3_note: null,
    annex_iii_risk_categories: null,
    license_required: false,
    license_terms: null,
    license_url: null,
    placeholder: false,
    status: null,
    notes: null,
    verified_on: null,
    superseded_by: null,
    audit_contexts: {},
    publication_notices: [],
    native_source: bundle,
  };
}

it("connects full-catalog and native requests to strict source verification", async () => {
  const b = example();
  const fetcher = vi
    .fn()
    .mockResolvedValueOnce(wireResponse(JSON.stringify(ordinary(b))))
    .mockResolvedValueOnce(wireResponse(JSON.stringify(b)));
  vi.stubGlobal("fetch", fetcher);
  const catalog = await api.getFramework("au-ism");
  expect(catalog.native_source?.data.documents[0].raw_utf8).toBe(source);
  const native = await api.getCatalogNative(expected(b));
  expect(native.bundle_sha256).toBe(b.bundle_sha256);
  expect(fetcher.mock.calls[1][0]).toBe(
    "/api/frameworks/au-ism/native-source?bundle_sha256=" + b.bundle_sha256,
  );
});

it.each(["control", "family", "bundle", "duplicate", "source"])(
  "refuses a %s mismatch through the actual transport",
  async (kind) => {
    const b = example();
    const catalog = ordinary(b);
    if (kind === "control") catalog.controls[0].id = "other";
    if (kind === "family") catalog.families = [];
    if (kind === "bundle") b.bundle_sha256 = "0".repeat(64);
    if (kind === "source") b.data.documents[0].raw_utf8 += " ";
    let wire = JSON.stringify(catalog);
    if (kind === "duplicate") wire = '{"framework_id":"other",' + wire.slice(1);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(wireResponse(wire)));
    await expect(api.getFramework("au-ism")).rejects.toThrow();
  },
);

it("counts actual streamed bytes and cancels overflow before parsing", async () => {
  const cancel = vi.fn();
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(16_777_217));
    },
    cancel,
  });
  vi.stubGlobal(
    "fetch",
    vi
      .fn()
      .mockResolvedValue(
        new Response(body, { headers: { "Content-Length": "1" } }),
      ),
  );
  await expect(api.getCatalogNative(expected(example()))).rejects.toThrow();
  expect(cancel).toHaveBeenCalledOnce();
});

it("retains the refusal channel and rejects malformed publication claims", async () => {
  const fetcher = vi
    .fn()
    .mockResolvedValueOnce(
      wireResponse(JSON.stringify({ code: "catalog_generation_changed" }), 409),
    )
    .mockResolvedValueOnce(
      wireResponse(
        JSON.stringify({ code: "catalog_storage_failed", publication: {} }),
        503,
      ),
    );
  vi.stubGlobal("fetch", fetcher);
  await expect(api.getCatalogNative(expected(example()))).rejects.toMatchObject(
    { status: 409, payload: { code: "catalog_generation_changed" } },
  );
  await expect(
    api.getCatalogNative(expected(example())),
  ).rejects.not.toBeInstanceOf(ApiError);
});

it("does not start a native request with an already canceled signal", async () => {
  const controller = new AbortController();
  controller.abort();
  const fetcher = vi.fn();
  vi.stubGlobal("fetch", fetcher);
  await expect(
    api.getCatalogNative(expected(example()), controller.signal),
  ).rejects.toThrow();
  expect(fetcher).not.toHaveBeenCalled();
});

it("renders exact source values and downloads only captured validated bytes", async () => {
  const b = example();
  const native = await decodeNativeBundle(JSON.stringify(b), expected(b));
  const catalog = await decodeNativeCatalog(
    JSON.stringify(ordinary(b)),
    expected(b),
  );
  vi.spyOn(api, "getCatalogNative").mockResolvedValue(native);
  const blobs: Blob[] = [];
  vi.stubGlobal(
    "URL",
    class extends URL {
      static createObjectURL(blob: Blob) {
        blobs.push(blob);
        return "blob:synthetic-native";
      }
      static revokeObjectURL = vi.fn();
    },
  );
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(
    () => undefined,
  );
  render(<NativeSourcePanel catalog={catalog} authGeneration="one" />);
  fireEvent.click(screen.getByRole("button", { name: "Load native source" }));
  await screen.findByText(/Last verified source:/);
  expect(screen.getAllByText("9007199254740993").length).toBeGreaterThan(0);
  expect(screen.getAllByText("Native null").length).toBeGreaterThan(0);
  expect(screen.getAllByText("Absent").length).toBeGreaterThan(0);
  fireEvent.click(
    screen.getByRole("button", { name: "Download native bundle" }),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Download source document 1" }),
  );
  expect(blobs).toHaveLength(2);
  expect(await blobText(blobs[0])).toBe(compact(b));
  expect(await blobText(blobs[1])).toBe(source);
});

it.each(["auth", "cancel", "unmount"])(
  "rejects a late native result after %s",
  async (reason) => {
    const b = example();
    const catalog = await decodeNativeCatalog(
      JSON.stringify(ordinary(b)),
      expected(b),
    );
    const native = await decodeNativeBundle(JSON.stringify(b), expected(b));
    const late = deferred<NativeBundle>();
    const request = vi
      .spyOn(api, "getCatalogNative")
      .mockReturnValue(late.promise);
    const view = render(
      <NativeSourcePanel catalog={catalog} authGeneration="one" />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Load native source" }));
    if (reason === "auth")
      view.rerender(
        <NativeSourcePanel catalog={catalog} authGeneration="two" />,
      );
    if (reason === "cancel")
      fireEvent.click(
        screen.getByRole("button", { name: "Cancel source request" }),
      );
    if (reason === "unmount") view.unmount();
    expect(request.mock.calls[0][1]?.aborted).toBe(true);
    await act(async () => {
      late.resolve(native);
      await late.promise;
    });
    expect(screen.queryByText(/Last verified source:/)).not.toBeInTheDocument();
  },
);

it("keeps prior verified source when a later response fails", async () => {
  const b = example();
  const catalog = await decodeNativeCatalog(
    JSON.stringify(ordinary(b)),
    expected(b),
  );
  const native = await decodeNativeBundle(JSON.stringify(b), expected(b));
  vi.spyOn(api, "getCatalogNative")
    .mockResolvedValueOnce(native)
    .mockRejectedValueOnce(new Error("untrusted message"));
  render(<NativeSourcePanel catalog={catalog} authGeneration="one" />);
  fireEvent.click(screen.getByRole("button", { name: "Load native source" }));
  await screen.findByText(/Last verified source:/);
  fireEvent.click(screen.getByRole("button", { name: "Load native source" }));
  await screen.findByRole("alert");
  expect(screen.getByText(/Last verified source:/)).toBeInTheDocument();
  expect(screen.queryByText("untrusted message")).not.toBeInTheDocument();
});

const importResult: CatalogNativeImportResult = {
  schema_version: "catalog-native-import-result-v1",
  catalog_id: "bsi-grundschutz-plus-plus",
  bundle_sha256: "a".repeat(64),
  projection_sha256: "b".repeat(64),
  status: "imported",
  control_count: 1000,
  storage: "external",
  source_hashes: ["c".repeat(64), "d".repeat(64), "e".repeat(64)],
};
function selectSyntheticFiles() {
  for (const name of [
    "Grundschutz++-resolved_catalog.json",
    "LICENSE",
    "README.md",
  ]) {
    const text =
      name === "Grundschutz++-resolved_catalog.json"
        ? '{"synthetic":true}'
        : "Synthetic test text";
    const file = new File([text], name);
    Object.defineProperty(file, "arrayBuffer", {
      value: async () => bytes(text).buffer,
    });
    fireEvent.change(screen.getByLabelText(name), {
      target: { files: [file] },
    });
  }
  fireEvent.click(screen.getByRole("checkbox"));
}
it.each(["auth", "cancel", "unmount", "selection"])(
  "never posts after %s during the access check",
  async (reason) => {
    const checked = deferred<{
      status: string;
      version: string;
      auth_configured: boolean;
    }>();
    vi.spyOn(api, "health").mockReturnValue(checked.promise);
    const post = vi.spyOn(api, "importNativeCatalog");
    const view = render(
      provider(
        <NativeImportSection
          authGeneration="one"
          accessReady
          authConfigured={false}
        />,
      ),
    );
    selectSyntheticFiles();
    fireEvent.click(
      screen.getByRole("button", { name: "Import native BSI source" }),
    );
    if (reason === "auth")
      view.rerender(
        provider(
          <NativeImportSection
            authGeneration="two"
            accessReady
            authConfigured={false}
          />,
        ),
      );
    if (reason === "cancel")
      fireEvent.click(
        screen.getByRole("button", { name: "Cancel native import" }),
      );
    if (reason === "unmount") view.unmount();
    if (reason === "selection")
      fireEvent.change(screen.getByLabelText("README.md"), {
        target: { files: [] },
      });
    await act(async () => {
      checked.resolve({
        status: "ok",
        version: "test",
        auth_configured: false,
      });
      await checked.promise;
    });
    expect(post).not.toHaveBeenCalled();
  },
);
it("reports only a validated server result and retains it when a later request fails", async () => {
  vi.spyOn(api, "health").mockResolvedValue({
    status: "ok",
    version: "test",
    auth_configured: false,
  });
  const post = vi
    .spyOn(api, "importNativeCatalog")
    .mockResolvedValueOnce(importResult)
    .mockRejectedValueOnce(new Error("untrusted message"));
  render(
    provider(
      <NativeImportSection
        authGeneration="one"
        accessReady
        authConfigured={false}
      />,
    ),
  );
  selectSyntheticFiles();
  fireEvent.click(
    screen.getByRole("button", { name: "Import native BSI source" }),
  );
  await screen.findByText(/Last confirmed import: imported/);
  expect(
    post.mock.calls[0][0].documents.map((document) => document.source_key),
  ).toEqual(["bsi-catalog", "bsi-license", "bsi-readme"]);
  fireEvent.click(
    screen.getByRole("button", { name: "Import native BSI source" }),
  );
  await screen.findByText("Import not confirmed");
  expect(
    screen.getByText(/Last confirmed import: imported/),
  ).toBeInTheDocument();
  expect(screen.queryByText("untrusted message")).not.toBeInTheDocument();
});
it("does not apply a canceled POST result or promise a rollback", async () => {
  vi.spyOn(api, "health").mockResolvedValue({
    status: "ok",
    version: "test",
    auth_configured: false,
  });
  const late = deferred<CatalogNativeImportResult>();
  const post = vi
    .spyOn(api, "importNativeCatalog")
    .mockReturnValue(late.promise);
  render(
    provider(
      <NativeImportSection
        authGeneration="one"
        accessReady
        authConfigured={false}
      />,
    ),
  );
  selectSyntheticFiles();
  fireEvent.click(
    screen.getByRole("button", { name: "Import native BSI source" }),
  );
  await waitFor(() => expect(post).toHaveBeenCalledOnce());
  fireEvent.click(screen.getByRole("button", { name: "Cancel native import" }));
  expect(post.mock.calls[0][1]?.aborted).toBe(true);
  expect(screen.getByText(/server may have committed/)).toBeInTheDocument();
  await act(async () => {
    late.resolve(importResult);
    await late.promise;
  });
  expect(screen.queryByText(/Last confirmed import:/)).not.toBeInTheDocument();
});

function wireResponse(text: string, status = 200) {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(bytes(text)));
      controller.close();
    },
  });
  return new Response(body, { status });
}
function blobText(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () =>
      resolve(new TextDecoder().decode(reader.result as ArrayBuffer));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(blob);
  });
}

it("does not invoke accessors or serializers before native request admission", async () => {
  const callback = vi.fn();
  const fetcher = vi.fn();
  vi.stubGlobal("fetch", fetcher);
  const getter = {
    framework_id: "au-ism",
    get bundle_sha256() {
      callback();
      return "a".repeat(64);
    },
  };
  await expect(api.getCatalogNative(getter as NativeRequest)).rejects.toThrow();
  await expect(
    api.getCatalogNative({
      ...expected(example()),
      toJSON: callback,
    } as NativeRequest),
  ).rejects.toThrow();
  expect(callback).not.toHaveBeenCalled();
  expect(fetcher).not.toHaveBeenCalled();
});

it.each(["auth", "selection", "focus"])(
  "rejects a late POST after %s without confirming publication",
  async (reason) => {
    vi.spyOn(api, "health").mockResolvedValue({
      status: "ok",
      version: "test",
      auth_configured: false,
    });
    const late = deferred<CatalogNativeImportResult>();
    const post = vi
      .spyOn(api, "importNativeCatalog")
      .mockReturnValue(late.promise);
    const view = render(
      provider(
        <NativeImportSection
          authGeneration="one"
          accessReady
          authConfigured={false}
        />,
      ),
    );
    selectSyntheticFiles();
    fireEvent.click(
      screen.getByRole("button", { name: "Import native BSI source" }),
    );
    await waitFor(() => expect(post).toHaveBeenCalledOnce());
    if (reason === "auth")
      view.rerender(
        provider(
          <NativeImportSection
            authGeneration="two"
            accessReady
            authConfigured={false}
          />,
        ),
      );
    if (reason === "selection")
      fireEvent.change(screen.getByLabelText("README.md"), {
        target: { files: [] },
      });
    if (reason === "focus") fireEvent.focus(window);
    expect(post.mock.calls[0][1]?.aborted).toBe(true);
    await act(async () => {
      late.resolve(importResult);
      await late.promise;
    });
    expect(
      screen.queryByText(/Last confirmed import:/),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/Cancellation after submission does not undo/),
    ).toBeInTheDocument();
  },
);
it("does not post after cancellation during a file read", async () => {
  vi.spyOn(api, "health").mockResolvedValue({
    status: "ok",
    version: "test",
    auth_configured: false,
  });
  const post = vi.spyOn(api, "importNativeCatalog");
  render(
    provider(
      <NativeImportSection
        authGeneration="one"
        accessReady
        authConfigured={false}
      />,
    ),
  );
  selectSyntheticFiles();
  const late = deferred<ArrayBuffer>();
  const text = '{"synthetic":true}';
  const file = new File([text], "Grundschutz++-resolved_catalog.json");
  const read = vi.fn().mockReturnValue(late.promise);
  Object.defineProperty(file, "arrayBuffer", { value: read });
  fireEvent.change(screen.getByLabelText(file.name), {
    target: { files: [file] },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Import native BSI source" }),
  );
  await waitFor(() => expect(read).toHaveBeenCalledOnce());
  fireEvent.click(screen.getByRole("button", { name: "Cancel native import" }));
  await act(async () => {
    late.resolve(new Uint8Array(bytes(text)).buffer);
    await late.promise;
  });
  expect(post).not.toHaveBeenCalled();
});
it.each([401, 403])(
  "does not read selected files when the access check returns %s",
  async (status) => {
    vi.spyOn(api, "health").mockRejectedValue(
      new ApiError("denied", status, {}),
    );
    const post = vi.spyOn(api, "importNativeCatalog");
    render(
      provider(
        <NativeImportSection
          authGeneration="one"
          accessReady
          authConfigured={false}
        />,
      ),
    );
    selectSyntheticFiles();
    const file = new File(["synthetic"], "README.md");
    const read = vi.fn();
    Object.defineProperty(file, "arrayBuffer", { value: read });
    fireEvent.change(screen.getByLabelText(file.name), {
      target: { files: [file] },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Import native BSI source" }),
    );
    await screen.findByText("Import not confirmed");
    expect(read).not.toHaveBeenCalled();
    expect(post).not.toHaveBeenCalled();
  },
);
it("refuses an unvalidated bundle even when its public fields match", async () => {
  const b = example();
  const catalog = await decodeNativeCatalog(
    JSON.stringify(ordinary(b)),
    expected(b),
  );
  vi.spyOn(api, "getCatalogNative").mockResolvedValue(b);
  render(<NativeSourcePanel catalog={catalog} authGeneration="one" />);
  fireEvent.click(screen.getByRole("button", { name: "Load native source" }));
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Load native source" }),
    ).toBeEnabled(),
  );
  expect(screen.queryByText(/Last verified source:/)).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Download native bundle" }),
  ).not.toBeInTheDocument();
});
it("invalidates an earlier download on focus or observed access changes", async () => {
  const b = example();
  const catalog = await decodeNativeCatalog(
    JSON.stringify(ordinary(b)),
    expected(b),
  );
  const native = await decodeNativeBundle(JSON.stringify(b), expected(b));
  vi.spyOn(api, "getCatalogNative").mockResolvedValue(native);
  const view = render(
    <NativeSourcePanel catalog={catalog} authGeneration="one" />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Load native source" }));
  await screen.findByText(/Last verified source:/);
  fireEvent.focus(window);
  expect(
    screen.getByRole("button", { name: "Download native bundle" }),
  ).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Load native source" }));
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Download native bundle" }),
    ).toBeEnabled(),
  );
  view.rerender(<NativeSourcePanel catalog={catalog} authGeneration="two" />);
  expect(
    screen.getByRole("button", { name: "Download native bundle" }),
  ).toBeDisabled();
});

// Authored source strings define this oracle; no product converter supplies its offsets.
function pagedExample(): NativeBundle {
  const b = example();
  const texts = Array.from({ length: 21 }, (_, i) =>
    JSON.stringify({
      id: "C" + i,
      text:
        i === 20
          ? '<img src="https://example.invalid/never" onerror="alert(1)">é'.repeat(
              70,
            )
          : "literal",
    }),
  );
  const raw = '{"id":"G","controls":[' + texts.join(",") + "]}";
  const at = (
    start: number,
    end: number,
    kind: ValueRef["kind"],
  ): ValueRef => ({
    document_index: 0,
    byte_start: bytes(raw.slice(0, start)).length,
    byte_end: bytes(raw.slice(0, end)).length,
    kind,
    sha256: hash(raw.slice(start, end)),
  });
  const rootOccurrence = {
    ...b.data.occurrences[0],
    source: at(0, raw.length, "json_object"),
    fields: [
      {
        name: "id",
        key: at(1, 5, "json_string"),
        value: at(6, 9, "json_string"),
      },
      {
        name: "controls",
        key: at(10, 20, "json_string"),
        value: at(21, raw.length - 1, "json_array"),
      },
    ],
  };
  b.data.occurrences = [rootOccurrence];
  b.data.control_bindings = [];
  let offset = 22;
  texts.forEach((text, i) => {
    const idEnd = offset + 6 + JSON.stringify("C" + i).length;
    const textKeyStart = idEnd + 1;
    const textStart = textKeyStart + 7;
    const id = at(offset + 6, idEnd, "json_string");
    b.data.occurrences.push({
      index: i + 1,
      kind: "control",
      parent_index: 0,
      sibling_ordinal: i,
      source: at(offset, offset + text.length, "json_object"),
      fields: [
        {
          name: "id",
          key: at(offset + 1, offset + 5, "json_string"),
          value: id,
        },
        {
          name: "text",
          key: at(textKeyStart, textKeyStart + 6, "json_string"),
          value: at(textStart, offset + text.length - 1, "json_string"),
        },
      ],
      selections: [
        { role: "native_id", value: { state: "present", refs: [id] } },
      ],
    });
    b.data.control_bindings.push({
      control_id: "C" + i,
      occurrence_index: i + 1,
      family_occurrence_index: 0,
      parent_control_id: null,
      admitted_criticality: null,
    });
    offset += text.length + 1;
  });
  b.data.documents[0].raw_utf8 = raw;
  b.data.documents[0].binding.raw_bytes = bytes(raw).length;
  b.data.documents[0].binding.raw_sha256 = hash(raw);
  return seal(b.data);
}
it("paginates literal occurrences and expands bounded UTF-8 previews without active markup", async () => {
  const b = pagedExample();
  const native = await decodeNativeBundle(JSON.stringify(b), expected(b));
  const c = ordinary(b);
  const base = c.controls[0];
  c.controls = b.data.control_bindings.map((row) => ({
    ...base,
    id: row.control_id,
    native_source_ref: {
      bundle_sha256: b.bundle_sha256,
      occurrence_index: row.occurrence_index,
    },
  }));
  const catalog = await decodeNativeCatalog(JSON.stringify(c), expected(b));
  const fetcher = vi.fn();
  vi.stubGlobal("fetch", fetcher);
  vi.spyOn(api, "getCatalogNative").mockResolvedValue(native);
  const view = render(
    <NativeSourcePanel catalog={catalog} authGeneration="one" />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Load native source" }));
  await screen.findByText(/page 1 of 2/);
  expect(
    screen.queryByRole("article", { name: "Native occurrence 21" }),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Next occurrences" }));
  const item = screen.getByRole("article", { name: "Native occurrence 21" });
  expect(
    [...item.querySelectorAll("pre")].every(
      (p) => bytes(p.textContent ?? "").length <= 4096,
    ),
  ).toBe(true);
  fireEvent.click(
    within(item).getAllByRole("button", { name: "Expand source text" })[0],
  );
  expect(
    [...item.querySelectorAll("pre")].some(
      (p) => bytes(p.textContent ?? "").length > 4096,
    ),
  ).toBe(true);
  expect(view.container.querySelectorAll("img,script,iframe,a")).toHaveLength(
    0,
  );
  expect(fetcher).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Previous occurrences" }));
  expect(
    screen.queryByRole("article", { name: "Native occurrence 21" }),
  ).not.toBeInTheDocument();
});
it("disables native import and retrieval in demo components", async () => {
  const b = example();
  const catalog = await decodeNativeCatalog(
    JSON.stringify(ordinary(b)),
    expected(b),
  );
  const fetcher = vi.fn();
  vi.stubGlobal("fetch", fetcher);
  demoMode.enabled = true;
  render(
    provider(
      <>
        <NativeSourcePanel catalog={catalog} authGeneration="demo" />
        <NativeImportSection
          authGeneration="demo"
          accessReady
          authConfigured={false}
        />
      </>,
    ),
  );
  expect(
    screen.getByRole("button", { name: "Load native source" }),
  ).toBeDisabled();
  expect(
    screen.getByRole("button", { name: "Import native BSI source" }),
  ).toBeDisabled();
  for (const file of [
    "Grundschutz++-resolved_catalog.json",
    "LICENSE",
    "README.md",
  ])
    expect(screen.getByLabelText(file)).toBeDisabled();
  expect(fetcher).not.toHaveBeenCalled();
});

it("accepts exactly 16 MiB through the native transport", async () => {
  const b = example();
  const body = JSON.stringify(b);
  const padding = 16_777_216 - bytes(body).length;
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(wireResponse(body + " ".repeat(padding))),
  );
  expect((await api.getCatalogNative(expected(b))).bundle_sha256).toBe(
    b.bundle_sha256,
  );
});
it("refuses native operations through the actual demo API without reading request properties or fetching", async () => {
  demoMode.enabled = true;
  vi.resetModules();
  const demoClient = (await import("@/lib/api")).api;
  const fetcher = vi.fn();
  const getter = vi.fn();
  vi.stubGlobal("fetch", fetcher);
  const request = {
    get framework_id() {
      getter();
      return "au-ism";
    },
    bundle_sha256: "a".repeat(64),
  } as NativeRequest;
  await expect(demoClient.getCatalogNative(request)).rejects.toThrow();
  await expect(
    demoClient.importNativeCatalog({
      profile: "bsi-grundschutz-plus-plus-367d7750",
      documents: [],
    }),
  ).rejects.toThrow();
  expect(getter).not.toHaveBeenCalled();
  expect(fetcher).not.toHaveBeenCalled();
});
