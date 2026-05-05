import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

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
import { api } from "@/lib/api";
import type { EvidentiaConfig } from "@/types/config";

/**
 * Settings page — editable for v0.4.1.
 *
 * Reads /api/config into a form; on Save, PUT /api/config with the
 * validated payload. Immutable sections (LLM providers, air-gap
 * posture) stay read-only since they're derived from server process
 * state (env vars) rather than the yaml file.
 *
 * v0.7.15 P0.2: split the form into <SettingsForm/> sub-component
 * keyed on the loaded config's source_path (or "loading" sentinel).
 * The previous pattern (useEffect → setState to seed form fields
 * from configQuery.data) tripped the react-hooks/set-state-in-effect
 * rule introduced in plugin-react-hooks v7. The key-based remount
 * pattern is React's canonical idiom for "initialize state from
 * async data": when the query resolves, the sub-component's `key`
 * changes, React unmounts + remounts it, and useState's lazy
 * initializer seeds with the fresh data on first render. No effect
 * + no setState-in-effect.
 */
export function SettingsPage() {
  const configQuery = useQuery({
    queryKey: ["config"],
    queryFn: () => api.getConfig(),
  });
  const llm = useQuery({
    queryKey: ["llm-status"],
    queryFn: () => api.llmStatus(),
  });
  const airGap = useQuery({
    queryKey: ["air-gap"],
    queryFn: () => api.doctorCheckAirGap(),
  });

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-3xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-1 text-muted-foreground">
          Edit{" "}
          <code className="rounded bg-muted px-1 py-0.5">
            evidentia.yaml
          </code>{" "}
          here. The server writes the file after validation; your CLI
          + GUI both pick up the new values immediately.
        </p>
      </header>

      {configQuery.data ? (
        <SettingsForm
          // Key change on source-path swap (or initial load) remounts the
          // form with fresh initial state seeded by useState's lazy
          // initializer. Replaces the v0.4.1 useEffect+setState seed
          // pattern that tripped react-hooks/set-state-in-effect (v7).
          key={configQuery.data.source_path ?? "default"}
          config={configQuery.data}
        />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Project configuration</CardTitle>
            <CardDescription>Loading…</CardDescription>
          </CardHeader>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>LLM providers (read-only)</CardTitle>
          <CardDescription>
            Keys are sourced from environment variables; the browser
            never sees key values.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          {llm.data ? (
            Object.entries(llm.data.providers).map(([name, state]) => (
              <div key={name} className="flex items-center justify-between">
                <span className="capitalize">{name.replace(/_/g, " ")}</span>
                {state.configured ? (
                  <Badge>configured via {state.source}</Badge>
                ) : (
                  <Badge variant="outline">not configured</Badge>
                )}
              </div>
            ))
          ) : (
            <span className="text-muted-foreground">Loading...</span>
          )}
          <p className="pt-2 text-xs text-muted-foreground">
            Active model:{" "}
            <code className="rounded bg-muted px-1 py-0.5">
              {llm.data?.configured_model ?? "—"}
            </code>
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            Air-gap posture
            {airGap.data?.air_gapped ? (
              <Badge>air-gap ready</Badge>
            ) : (
              <Badge variant="destructive">would leak</Badge>
            )}
          </CardTitle>
          <CardDescription>
            Audits configured endpoints without issuing network IO.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          {airGap.data?.checks.map((check) => (
            <div
              key={check.subsystem}
              className="flex items-start justify-between gap-4"
            >
              <div>
                <div className="font-mono text-xs uppercase tracking-wide text-muted-foreground">
                  {check.subsystem}
                </div>
                <div>{check.detail}</div>
              </div>
              {check.status === "ok" && <Badge>ok</Badge>}
              {check.status === "would_leak" && (
                <Badge variant="destructive">would leak</Badge>
              )}
              {check.status === "skipped" && (
                <Badge variant="outline">skipped</Badge>
              )}
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

interface SettingsFormProps {
  config: EvidentiaConfig;
}

/**
 * Inner form component — owns the editable form state. Mounted with
 * `key={config.source_path}` so each new config-load triggers a
 * remount with fresh initial state seeded via useState's lazy
 * initializer. This avoids useEffect+setState (v0.7.15 P0.2 pattern).
 */
function SettingsForm({ config }: SettingsFormProps) {
  const queryClient = useQueryClient();

  const [organization, setOrganization] = useState(
    () => config.organization ?? "",
  );
  const [systemName, setSystemName] = useState(
    () => config.system_name ?? "",
  );
  const [frameworks, setFrameworks] = useState(() =>
    config.frameworks.join(", "),
  );
  const [llmModel, setLlmModel] = useState(() => config.llm.model ?? "");
  const [llmTemperature, setLlmTemperature] = useState<string>(() =>
    config.llm.temperature != null ? String(config.llm.temperature) : "",
  );

  const saveMutation = useMutation({
    mutationFn: () => {
      const fw = frameworks
        .split(",")
        .map((f) => f.trim())
        .filter(Boolean);
      return api.putConfig({
        organization: organization.trim() || null,
        system_name: systemName.trim() || null,
        frameworks: fw,
        llm: {
          model: llmModel.trim() || null,
          temperature:
            llmTemperature.trim() === ""
              ? null
              : Number.parseFloat(llmTemperature),
        },
      });
    },
    onSuccess: (saved) => {
      queryClient.setQueryData(["config"], saved);
    },
  });

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Project configuration</CardTitle>
          <CardDescription>
            {config.source_path ? (
              <>
                File:{" "}
                <code className="rounded bg-muted px-1 py-0.5">
                  {config.source_path}
                </code>
              </>
            ) : (
              "No evidentia.yaml yet; save will create one in your CWD."
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <Label htmlFor="org">Organization</Label>
              <Input
                id="org"
                value={organization}
                onChange={(e) => setOrganization(e.target.value)}
                className="mt-1"
              />
            </div>
            <div>
              <Label htmlFor="system">System name</Label>
              <Input
                id="system"
                value={systemName}
                onChange={(e) => setSystemName(e.target.value)}
                className="mt-1"
              />
            </div>
          </div>
          <div>
            <Label htmlFor="frameworks">Default frameworks (comma-separated)</Label>
            <Input
              id="frameworks"
              value={frameworks}
              onChange={(e) => setFrameworks(e.target.value)}
              placeholder="nist-800-53-rev5-moderate, soc2-tsc"
              className="mt-1"
            />
            <p className="mt-1 text-xs text-muted-foreground">
              CLI <code>--frameworks</code> overrides this list entirely.
              Warning fires at load time if more than 5 are listed.
            </p>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <Label htmlFor="model">LLM model</Label>
              <Input
                id="model"
                value={llmModel}
                onChange={(e) => setLlmModel(e.target.value)}
                placeholder="gpt-4o (or ollama/llama3 for offline)"
                className="mt-1"
              />
            </div>
            <div>
              <Label htmlFor="temp">LLM temperature</Label>
              <Input
                id="temp"
                type="number"
                step="0.1"
                min="0"
                max="2"
                value={llmTemperature}
                onChange={(e) => setLlmTemperature(e.target.value)}
                placeholder="0.1"
                className="mt-1"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {saveMutation.isError && (
        <Alert variant="destructive">
          <AlertTitle>Save failed</AlertTitle>
          <AlertDescription>
            {saveMutation.error instanceof Error
              ? saveMutation.error.message
              : "Unknown error."}
          </AlertDescription>
        </Alert>
      )}
      {saveMutation.isSuccess && (
        <Alert variant="success">
          <AlertTitle>Saved</AlertTitle>
          <AlertDescription>
            {config.source_path
              ? `Wrote ${config.source_path}.`
              : "Wrote evidentia.yaml."}
          </AlertDescription>
        </Alert>
      )}

      <div className="flex items-center justify-end">
        <Button
          onClick={() => saveMutation.mutate()}
          disabled={saveMutation.isPending}
        >
          {saveMutation.isPending ? "Saving..." : "Save"}
        </Button>
      </div>
    </>
  );
}
