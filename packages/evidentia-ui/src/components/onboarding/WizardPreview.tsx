import { useMutation } from "@tanstack/react-query";
import { Check, Copy, Save } from "lucide-react";
import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import { useWizardStore } from "@/lib/wizard-store";

/**
 * Renders the three generated YAML files + recommended framework list
 * returned by /api/init/wizard. Each file has a Copy button so users
 * can paste into their editor of choice.
 *
 * The "Write files to disk" button (v0.10.12) posts to /api/init/commit,
 * which regenerates the same files server-side and writes them to the
 * server's working directory. Existing files are SKIPPED unless the user
 * explicitly chooses to overwrite — never a silent clobber.
 */
export function WizardPreview() {
  const { preview, form, reset, setStep } = useWizardStore();

  const commit = useMutation({
    mutationFn: (overwrite: boolean) => api.initCommit({ ...form, overwrite }),
  });
  const result = commit.data;

  if (!preview) {
    return null;
  }

  return (
    <section aria-labelledby="preview-heading" className="stack-6">
      <header className="row-between gap-4">
        <div>
          <h2 id="preview-heading" className="h2-lg">
            Your starter files
          </h2>
          <p className="page-sub">
            Three YAML files tailored to your answers. Copy them into your
            project directory or let the wizard write them on disk.
          </p>
        </div>
        <Button variant="ghost" onClick={() => setStep("wizard-form")}>
          Edit answers
        </Button>
      </header>

      <Card>
        <CardHeader>
          <CardTitle className="lg">Recommended frameworks</CardTitle>
          <CardDescription>
            Based on your industry, hosting, data types, and regulatory scope.
            These are suggestions — add or remove any you don't need.
          </CardDescription>
        </CardHeader>
        <CardContent className="row wrap gap-2">
          {preview.recommended_frameworks.map((fw) => (
            <Badge key={fw} variant="secondary">
              {fw}
            </Badge>
          ))}
        </CardContent>
      </Card>

      <Tabs defaultValue="evidentia" className="w-full">
        <TabsList>
          <TabsTrigger value="evidentia">evidentia.yaml</TabsTrigger>
          <TabsTrigger value="controls">my-controls.yaml</TabsTrigger>
          <TabsTrigger value="context">system-context.yaml</TabsTrigger>
        </TabsList>
        <TabsContent value="evidentia">
          <YamlCard filename="evidentia.yaml" content={preview.evidentia_yaml} />
        </TabsContent>
        <TabsContent value="controls">
          <YamlCard
            filename="my-controls.yaml"
            content={preview.my_controls_yaml}
          />
        </TabsContent>
        <TabsContent value="context">
          <YamlCard
            filename="system-context.yaml"
            content={preview.system_context_yaml}
          />
        </TabsContent>
      </Tabs>

      {commit.isError && (
        <p role="alert" className="text-sm text-destructive">
          Couldn't write the files: {(commit.error as Error).message}
        </p>
      )}
      {result && (
        <div
          role="status"
          className="rounded-md border border-border bg-card px-4 py-3 text-sm"
        >
          {result.created.length > 0 && (
            <p>
              Wrote{" "}
              <span className="font-mono">{result.created.join(", ")}</span> to{" "}
              <span className="font-mono">{result.directory}</span>.
            </p>
          )}
          {result.skipped.length > 0 && (
            <p className="mt-1 text-muted-foreground">
              Left existing file{result.skipped.length > 1 ? "s" : ""} untouched:{" "}
              <span className="font-mono">{result.skipped.join(", ")}</span>.{" "}
              <button
                type="button"
                className="font-medium text-primary underline-offset-2 hover:underline disabled:opacity-50"
                onClick={() => commit.mutate(true)}
                disabled={commit.isPending}
              >
                Overwrite
              </button>
            </p>
          )}
        </div>
      )}

      <footer className="row-end gap-3 pt-4">
        <Button variant="outline" onClick={reset}>
          Start over
        </Button>
        <Button
          variant="outline"
          onClick={() => commit.mutate(false)}
          disabled={commit.isPending}
        >
          <Save className="h-3.5 w-3.5" />
          {commit.isPending ? "Writing…" : "Write files to disk"}
        </Button>
        <Button onClick={() => setStep("done")}>Done</Button>
      </footer>
    </section>
  );
}

function YamlCard({ filename, content }: { filename: string; content: string }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    await navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };
  return (
    <Card>
      <CardHeader className="row-between pb-3">
        <CardTitle className="base mono">{filename}</CardTitle>
        <Button
          size="sm"
          variant="outline"
          onClick={onCopy}
          aria-label={`Copy ${filename}`}
        >
          {copied ? (
            <>
              <Check className="h-3.5 w-3.5" /> Copied
            </>
          ) : (
            <>
              <Copy className="h-3.5 w-3.5" /> Copy
            </>
          )}
        </Button>
      </CardHeader>
      <CardContent>
        <pre className="block scroll-72">
          <code>{content}</code>
        </pre>
      </CardContent>
    </Card>
  );
}
