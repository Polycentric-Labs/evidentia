import { describe, expect, it } from "vitest";

import { readSse } from "@/lib/sse";

/** Build a ReadableStream<Uint8Array> that emits each chunk then closes. */
function streamOf(...chunks: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
}

/** Drain a stream through readSse, collecting every dispatched event. */
async function collect<T>(body: ReadableStream<Uint8Array>): Promise<T[]> {
  const events: T[] = [];
  await readSse<T>(body, (evt) => events.push(evt));
  return events;
}

describe("readSse", () => {
  it("parses a single data: frame", async () => {
    const events = await collect(streamOf('data: {"phase":"start"}\n\n'));
    expect(events).toEqual([{ phase: "start" }]);
  });

  it("dispatches multiple events arriving in one chunk", async () => {
    const events = await collect(
      streamOf('data: {"n":1}\n\ndata: {"n":2}\n\n'),
    );
    expect(events).toEqual([{ n: 1 }, { n: 2 }]);
  });

  it("buffers a frame split across chunks", async () => {
    const events = await collect(
      streamOf('data: {"phase":"do', 'ne","total":3}\n\n'),
    );
    expect(events).toEqual([{ phase: "done", total: 3 }]);
  });

  it("joins multiple data: lines in one record before parsing", async () => {
    // Per the SSE spec, consecutive `data:` lines in one record concatenate
    // with "\n" — the joined text must parse as a single JSON payload.
    const events = await collect(streamOf("data: [1,\ndata: 2]\n\n"));
    expect(events).toEqual([[1, 2]]);
  });

  it("silently skips keep-alive comments and malformed frames", async () => {
    const events = await collect(
      streamOf(
        ": keep-alive\n\n",
        "data: not-json\n\n",
        'data: {"ok":true}\n\n',
      ),
    );
    expect(events).toEqual([{ ok: true }]);
  });

  it("discards a trailing partial record at stream close", async () => {
    // Matches the page behavior this was extracted from: an unterminated
    // record (no "\n\n" before close) is never dispatched.
    const events = await collect(
      streamOf('data: {"n":1}\n\ndata: {"n":', "2}"),
    );
    expect(events).toEqual([{ n: 1 }]);
  });

  it("propagates an onEvent throw and releases the reader lock", async () => {
    const body = streamOf('data: {"n":1}\n\n');
    await expect(
      readSse(body, () => {
        throw new Error("handler boom");
      }),
    ).rejects.toThrow("handler boom");
    // The finally released the lock — acquiring a fresh reader succeeds
    // (it would throw a TypeError on a still-locked stream).
    expect(() => body.getReader()).not.toThrow();
  });
});
