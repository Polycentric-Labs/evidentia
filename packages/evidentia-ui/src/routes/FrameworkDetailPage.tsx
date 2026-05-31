import { useQuery } from "@tanstack/react-query";
import { useParams, Link } from "react-router-dom";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { api } from "@/lib/api";

export function FrameworkDetailPage() {
  const { id } = useParams<{ id: string }>();
  const query = useQuery({
    queryKey: ["framework", id],
    queryFn: () => api.getFramework(id ?? ""),
    enabled: Boolean(id),
  });

  if (!id) {
    return (
      <div className="stack-4">
        <Card className="border-dest">
          <CardHeader>
            <CardTitle className="base">No framework ID</CardTitle>
            <CardDescription>No framework ID in URL.</CardDescription>
          </CardHeader>
        </Card>
        <Button asChild variant="outline">
          <Link to="/frameworks">Back to frameworks</Link>
        </Button>
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="stack-4">
        <Card className="border-dest">
          <CardHeader>
            <CardTitle className="base">Framework not found</CardTitle>
            <CardDescription>
              Could not load framework <code className="kbd">{id}</code>.
            </CardDescription>
          </CardHeader>
        </Card>
        <Button asChild variant="outline">
          <Link to="/frameworks">Back to frameworks</Link>
        </Button>
      </div>
    );
  }

  if (!query.data) {
    return (
      <div className="stack-6">
        <header className="stack-2">
          <div className="skel" style={{ height: "1.5rem", width: "14rem" }} />
          <div className="skel" style={{ height: "2.25rem", width: "20rem" }} />
          <div className="skel" style={{ height: "1.25rem", width: "16rem" }} />
        </header>
        <section className="stack-3">
          <div className="skel" style={{ height: "1.5rem", width: "8rem" }} />
          <ul className="reset stack-2">
            {[0, 1, 2].map((i) => (
              <li key={i} className="reset">
                <Card>
                  <CardHeader className="pb-3 stack-2">
                    <div
                      className="skel"
                      style={{ height: "1.25rem", width: "6rem" }}
                    />
                    <div
                      className="skel"
                      style={{ height: "1rem", width: "18rem" }}
                    />
                  </CardHeader>
                </Card>
              </li>
            ))}
          </ul>
        </section>
      </div>
    );
  }

  const catalog = query.data;

  return (
    <div className="stack-6">
      <header className="stack-2">
        <div className="row gap-2 wrap">
          <Badge variant="outline">Tier {catalog.tier ?? "?"}</Badge>
          <Badge variant="secondary">{catalog.category}</Badge>
          {catalog.placeholder && <Badge variant="destructive">placeholder</Badge>}
          {catalog.license_required && <Badge>license required</Badge>}
        </div>
        <h1 className="page-title">{catalog.framework_name}</h1>
        <p className="page-sub">
          <code className="kbd">{catalog.framework_id}</code> &middot; version{" "}
          {catalog.version} &middot; {catalog.controls.length} top-level controls
          ({catalog.families.length} families)
        </p>
      </header>

      {catalog.license_terms && (
        <Card>
          <CardHeader>
            <CardTitle className="base">License</CardTitle>
            <CardDescription>{catalog.license_terms}</CardDescription>
          </CardHeader>
        </Card>
      )}

      <section aria-labelledby="controls-list" className="stack-3">
        <h2 id="controls-list" className="h2">
          Controls
        </h2>
        <ul className="reset stack-2">
          {catalog.controls.map((ctrl) => (
            <li key={ctrl.id} className="reset">
              <Card>
                <CardHeader className="pb-3 stack-2">
                  <div
                    className="row-between gap-4"
                    style={{ alignItems: "flex-start" }}
                  >
                    <CardTitle className="base mono">{ctrl.id}</CardTitle>
                    {ctrl.family && (
                      <Badge variant="outline">{ctrl.family}</Badge>
                    )}
                  </div>
                  <CardDescription>{ctrl.title}</CardDescription>
                </CardHeader>
                {ctrl.description && !ctrl.placeholder && (
                  <CardContent className="pt-0 text-sm muted">
                    {ctrl.description.length > 300
                      ? `${ctrl.description.slice(0, 300)}...`
                      : ctrl.description}
                  </CardContent>
                )}
                {ctrl.placeholder && (
                  <CardContent className="pt-0 text-sm muted">
                    <span style={{ fontStyle: "italic" }}>
                      Placeholder control. Supply your licensed copy via{" "}
                      <code className="kbd">evidentia catalog import</code>.
                    </span>
                  </CardContent>
                )}
              </Card>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
