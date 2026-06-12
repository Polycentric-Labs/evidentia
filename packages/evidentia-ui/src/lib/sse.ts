/**
 * Minimal SSE reader for a POST-initiated `text/event-stream` response.
 *
 * The standard `EventSource` API can't POST, so streaming screens fetch
 * the endpoint themselves and hand the response body here. Extracted from
 * the (identical) per-page readers in ExplainPage / RiskGeneratePage.
 */

/**
 * Read an SSE body to completion, dispatching each parsed event to `onEvent`.
 *
 * Splits on the SSE record separator (`\n\n`), joins each record's `data:`
 * lines with a newline (per the SSE spec), and dispatches parsed JSON to
 * `onEvent`. Malformed payloads are skipped silently — sse-starlette emits
 * keep-alive comment pings that aren't JSON `data:` payloads. The caller's
 * event union binds `T`; no validation is performed beyond `JSON.parse`.
 */
export async function readSse<T>(
  body: ReadableStream<Uint8Array>,
  onEvent: (evt: T) => void,
): Promise<void> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      const parts = buffer.split("\n\n");
      buffer = parts.pop() ?? "";
      for (const part of parts) {
        const dataLines = part
          .split("\n")
          .filter((l) => l.startsWith("data:"))
          .map((l) => l.slice(5).trimStart());
        if (dataLines.length === 0) continue;
        let parsed: T;
        try {
          parsed = JSON.parse(dataLines.join("\n")) as T;
        } catch {
          // Ignore malformed / keep-alive frames (sse-starlette emits comment
          // pings that aren't JSON `data:` payloads).
          continue;
        }
        // Dispatch OUTSIDE the parse guard: an onEvent throw is the
        // caller's error and must propagate (the finally below still
        // releases the reader lock), not be swallowed as a bad frame.
        onEvent(parsed);
      }
    }
  } finally {
    // Release the lock even when onEvent (or a read) throws, so the
    // caller can still acquire a new reader / cancel the body.
    reader.releaseLock();
  }
}
