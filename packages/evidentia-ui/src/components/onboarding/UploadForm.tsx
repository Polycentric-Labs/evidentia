import { FileUp } from "lucide-react";
import { useRef, useState } from "react";
import { Link } from "react-router-dom";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { useWizardStore } from "@/lib/wizard-store";

/**
 * "Upload inventory" path. v0.4.1 guides the user to the Gap Analyze
 * page — which handles the actual upload + analysis in one step. This
 * screen is a signpost + format-support documentation.
 */
export function UploadForm() {
  const reset = useWizardStore((s) => s.reset);
  const setUploadFile = useWizardStore((s) => s.setUploadFile);
  const fileInput = useRef<HTMLInputElement | null>(null);
  const [droppedName, setDroppedName] = useState<string | null>(null);

  const handleFiles = (files: FileList | null) => {
    if (!files || files.length === 0) return;
    const f = files[0];
    setUploadFile(f);
    setDroppedName(f.name);
  };

  return (
    <section aria-labelledby="upload-heading" className="stack-4">
      <div className="row-between gap-4">
        <div>
          <h2 id="upload-heading" className="h2-lg">
            Upload an inventory
          </h2>
          <p className="page-sub">
            We auto-detect the format based on the file extension.
          </p>
        </div>
        <Button variant="ghost" size="sm" onClick={reset}>
          Cancel
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="base">Supported formats</CardTitle>
          <CardDescription>
            YAML / JSON / CSV. OSCAL component definitions and CISO Assistant
            exports are parsed automatically. CSV expects columns{" "}
            <code className="kbd">id</code>, <code className="kbd">title</code>,
            and <code className="kbd">status</code>.
          </CardDescription>
        </CardHeader>
      </Card>

      <label
        htmlFor="inventory-upload"
        className={cn(
          "box dashed stack-2",
          "block cursor-pointer text-center",
          droppedName && "border-primary bg-primary/5",
        )}
        style={{ padding: "2.5rem" }}
        onDragOver={(e) => {
          e.preventDefault();
        }}
        onDrop={(e) => {
          e.preventDefault();
          handleFiles(e.dataTransfer.files);
        }}
      >
        <FileUp className="icon-card mx-auto h-7 w-7" aria-hidden />
        <div className="text-sm font-medium">
          {droppedName ?? "Drop a file here, or click to browse"}
        </div>
        <div className="text-xs muted">
          CSV, YAML, or OSCAL JSON — auto-detected
        </div>
        <input
          ref={fileInput}
          type="file"
          accept=".yaml,.yml,.json,.csv"
          className="sr-only"
          id="inventory-upload"
          onChange={(e) => handleFiles(e.target.files)}
        />
      </label>

      {droppedName && (
        <Alert variant="success">
          <AlertTitle>File ready for analysis</AlertTitle>
          <AlertDescription>
            Head to <strong>Gap Analyze</strong> to pick frameworks and run
            the analysis.
          </AlertDescription>
        </Alert>
      )}

      <div className="row-end gap-2">
        <Button variant="outline" onClick={reset}>
          Start over
        </Button>
        <Button
          asChild
          disabled={!droppedName}
          variant={droppedName ? "default" : "secondary"}
        >
          <Link to="/gap/analyze">Continue to Gap Analyze</Link>
        </Button>
      </div>
    </section>
  );
}
