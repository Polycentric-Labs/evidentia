import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * The plain-English explanation payload the `done` SSE event carries. Mirrors
 * `evidentia_ai.explain.models.PlainEnglishExplanation` (model_dump(mode="json")).
 */
interface Explanation {
  framework_id: string;
  control_id: string;
  control_title: string;
  plain_english: string;
  why_it_matters: string;
  what_to_do: string[];
  effort_estimate: string;
  common_misconceptions?: string | null;
  generation_context?: { model?: string | null } | null;
}

/**
 * SSE frames emitted by `POST /api/explain/{framework}/{control_id}`.
 *
 * The endpoint is NOT token-level streaming (yet): it emits a `start` frame
 * immediately to keep the browser responsive, then a single terminal frame —
 * `done` (with the whole explanation) or `error`. See
 * `packages/evidentia-api/.../routers/explain.py`.
 */
type ExplainEvent =
  | { phase: "start"; framework: string; control_id: string }
  | { phase: "done"; explanation: Explanation }
  | { phase: "error"; detail: string; type?: string };

/**
 * Explain Control — pick a framework + control id, then stream a plain-English
 * explanation from the LLM.
 *
 * The endpoint streams `text/event-stream`, so (like RiskGeneratePage) we POST
 * with `fetch` + read `res.body.getReader()` ourselves — `EventSource` can't
 * POST. The explanation is cached server-side per (framework, control, model,
 * temperature); the "Bypass cache" toggle forces a fresh generation.
 */
export function ExplainPage() {
  const [framework, setFramework] = useState<string | null>(null);
  const [controlId, setControlId] = useState("");
  const [refresh, setRefresh] = useState(false);

  const [isStreaming, setIsStreaming] = useState(false);
  const [explanation, setExplanation] = useState<Explanation | null>(null);
  const [streamError, setStreamError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const fwQuery = useQuery({
    queryKey: ["frameworks-picker"],
    queryFn: () => api.listFrameworks(),
  });

  // LLM status — explanations are LLM-backed, so warn up front if no provider
  // is configured (the same `providers` shape the Settings screen renders).
  const llmQuery = useQuery({
    queryKey: ["llm-status"],
    queryFn: () => api.llmStatus(),
    staleTime: 60_000,
  });
  const llmConfigured = llmQuery.data
    ? Object.values(llmQuery.data.providers).some((p) => p.configured)
    : undefined;

  const start = async () => {
    if (!framework || !controlId.trim()) return;
    setExplanation(null);
    setStreamError(null);
    setIsStreaming(true);
    abortRef.current = new AbortController();

    // The endpoint emits a single terminal frame (`done` or `error`) after an
    // immediate `start`. Track whether we saw one so a clean stream close with
    // no terminal frame surfaces an error instead of spinning forever.
    let sawTerminal = false;
    const onEvent = (evt: ExplainEvent) => {
      if (evt.phase === "done") {
        sawTerminal = true;
        setExplanation(evt.explanation);
        setIsStreaming(false);
      } else if (evt.phase === "error") {
        sawTerminal = true;
        setStreamError(evt.detail);
        setIsStreaming(false);
      }
      // `start` just confirms the stream opened; the "Explaining…" state is
      // already shown from the moment we set isStreaming on submit.
    };

    try {
      const url = api.explainControlUrl(framework, controlId.trim(), {
        refresh,
      });
      const res = await fetch(url, {
        method: "POST",
        headers: { Accept: "text/event-stream" },
        signal: abortRef.current.signal,
      });

      if (!res.ok || !res.body) {
        // The router raises 404 (framework/control not found) and 500
        // (evidentia-ai unavailable) as JSON before the stream opens.
        let detail = "";
        try {
          const body = (await res.json()) as { detail?: unknown };
          if (typeof body.detail === "string") detail = body.detail;
        } catch {
          detail = (await res.text().catch(() => "")) || `HTTP ${res.status}`;
        }
        setStreamError(detail || `Request failed (HTTP ${res.status})`);
        setIsStreaming(false);
        return;
      }

      await readSse(res.body, onEvent);

      if (!sawTerminal) {
        setStreamError("Stream ended without a result.");
        setIsStreaming(false);
      }
    } catch (e) {
      if ((e as { name?: string }).name !== "AbortError") {
        setStreamError(e instanceof Error ? e.message : String(e));
      }
      setIsStreaming(false);
    }
  };

  const cancel = () => {
    abortRef.current?.abort();
    setIsStreaming(false);
  };

  useEffect(() => () => abortRef.current?.abort(), []);

  const canSubmit = Boolean(framework) && controlId.trim().length > 0;

  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">Explain Control</h1>
        <p className="page-sub">
          Pick a framework and a control id to stream a plain-English
          explanation — what it requires, why it matters, and concrete steps to
          implement it. Explanations are LLM-backed and cached on the server.
        </p>
      </header>

      {llmConfigured === false && (
        <Alert variant="destructive">
          <AlertTitle>No LLM provider configured</AlertTitle>
          <AlertDescription>
            Explanations need a configured LLM provider. Set a provider API key
            (for example <code className="kbd">ANTHROPIC_API_KEY</code>) in the
            server's environment — see the{" "}
            <a href="/settings" className="primary underline">
              Settings
            </a>{" "}
            page for the current provider status.
          </AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="base">Control</CardTitle>
          <CardDescription>
            Choose one framework, then enter a control id exactly as it appears
            in that catalog (for example <code className="kbd">AC-2</code> or{" "}
            <code className="kbd">CC6.1</code>).
          </CardDescription>
        </CardHeader>
        <CardContent className="stack-4">
          <form
            className="stack-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (canSubmit && !isStreaming) start();
            }}
          >
            <div className="stack-2">
              <Label>Framework</Label>
              <div className="box scroll-60">
                {fwQuery.isPending && <p className="text-sm">Loading...</p>}
                {fwQuery.isError && (
                  <p className="text-sm text-destructive">
                    Could not load frameworks.
                  </p>
                )}
                <div className="row wrap gap-2">
                  {fwQuery.data?.frameworks.map((fw) => {
                    const checked = framework === fw.id;
                    return (
                      <button
                        key={fw.id}
                        type="button"
                        role="radio"
                        aria-checked={checked}
                        onClick={() => setFramework(fw.id)}
                        className={cn("pill", checked && "on")}
                      >
                        {fw.id} <span className="dim">(T{fw.tier})</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>

            <div className="stack-2">
              <Label htmlFor="explain-control-id">Control id</Label>
              <Input
                id="explain-control-id"
                placeholder="AC-2"
                value={controlId}
                onChange={(e) => setControlId(e.target.value)}
                autoComplete="off"
              />
              <p className="text-xs muted">
                Not sure of the id? Browse a framework in the{" "}
                <a href="/frameworks" className="primary-link">
                  Frameworks browser
                </a>
                .
              </p>
            </div>

            <div className="row-between">
              <div className="row gap-3">
                <Switch
                  id="explain-refresh"
                  checked={refresh}
                  onCheckedChange={setRefresh}
                />
                <Label htmlFor="explain-refresh" className="cursor-pointer">
                  Bypass cache (re-generate)
                </Label>
              </div>
              {isStreaming ? (
                <Button type="button" variant="outline" onClick={cancel}>
                  Cancel
                </Button>
              ) : (
                <Button type="submit" disabled={!canSubmit}>
                  Explain
                </Button>
              )}
            </div>
          </form>
        </CardContent>
      </Card>

      {isStreaming && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="base">Explaining…</CardTitle>
            <CardDescription>
              Asking the model to translate{" "}
              <code className="kbd">
                {framework}:{controlId.trim()}
              </code>
              . A cold-cache control can take several seconds.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm muted" role="status" aria-live="polite">
              Streaming the explanation from the server…
            </p>
          </CardContent>
        </Card>
      )}

      {streamError && (
        <Alert variant="destructive">
          <AlertTitle>Explanation failed</AlertTitle>
          <AlertDescription>{streamError}</AlertDescription>
        </Alert>
      )}

      {explanation && <ExplanationCard explanation={explanation} />}
    </div>
  );
}

function ExplanationCard({ explanation }: { explanation: Explanation }) {
  const model = explanation.generation_context?.model ?? undefined;
  return (
    <section className="stack-4" aria-labelledby="explanation-heading">
      <Card>
        <CardHeader>
          <div className="row-between wrap gap-2">
            <div className="stack-2">
              <CardTitle id="explanation-heading" className="base">
                {explanation.control_title}
              </CardTitle>
              <CardDescription>
                <code className="kbd">
                  {explanation.framework_id}:{explanation.control_id}
                </code>
              </CardDescription>
            </div>
            {model && (
              <Badge variant="outline" className="shrink-0">
                {model}
              </Badge>
            )}
          </div>
        </CardHeader>
        <CardContent className="stack-5">
          <div className="stack-2">
            <h3 className="text-xs font-semibold uppercase tracking-wide muted">
              In plain English
            </h3>
            <p className="text-sm">{explanation.plain_english}</p>
          </div>

          <div className="stack-2">
            <h3 className="text-xs font-semibold uppercase tracking-wide muted">
              Why it matters
            </h3>
            <p className="text-sm">{explanation.why_it_matters}</p>
          </div>

          <div className="stack-2">
            <h3 className="text-xs font-semibold uppercase tracking-wide muted">
              What to do
            </h3>
            <ul className="list-disc space-y-1 pl-5 text-sm">
              {explanation.what_to_do.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ul>
          </div>

          <div className="stack-2">
            <h3 className="text-xs font-semibold uppercase tracking-wide muted">
              Effort estimate
            </h3>
            <p className="text-sm">{explanation.effort_estimate}</p>
          </div>

          {explanation.common_misconceptions && (
            <div className="stack-2">
              <h3 className="text-xs font-semibold uppercase tracking-wide muted">
                Common misconceptions
              </h3>
              <p className="text-sm">{explanation.common_misconceptions}</p>
            </div>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

/**
 * Minimal SSE reader for a POST-initiated `text/event-stream` response.
 * Splits on the SSE record separator (`\n\n`), parses `data:` lines, and
 * dispatches parsed JSON to `onEvent`. Mirrors RiskGeneratePage's `readSse`.
 */
async function readSse(
  body: ReadableStream<Uint8Array>,
  onEvent: (evt: ExplainEvent) => void,
): Promise<void> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

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
      try {
        const parsed = JSON.parse(dataLines.join("\n")) as ExplainEvent;
        onEvent(parsed);
      } catch {
        // Ignore malformed / keep-alive frames (sse-starlette emits comment
        // pings that aren't JSON `data:` payloads).
      }
    }
  }
}
