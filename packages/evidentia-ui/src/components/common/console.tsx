import type { LucideIcon } from "lucide-react";
import { useMemo, type ReactNode } from "react";

import { cn } from "@/lib/utils";
import type { GapSeverity } from "@/types/api";

/**
 * Shared presentational pieces for the GUI v2 console (design-system classes
 * live in index.css @layer components). Presentation only — no data fetching.
 */

/** Stat / metric tile. Pass `bar` (0-100) for the coverage-style variant. */
export function MetricCard({
  icon: Icon,
  label,
  value,
  description,
  big = false,
  bar,
}: {
  icon?: LucideIcon;
  label: string;
  value: ReactNode;
  description?: ReactNode;
  big?: boolean;
  bar?: number;
}) {
  return (
    <div className="card">
      <div className="card-body" style={{ padding: "var(--card-pad)" }}>
        <div className="row-between" style={{ alignItems: "flex-start" }}>
          <p className="metric-label">{label}</p>
          {Icon ? <Icon className="metric-ic" aria-hidden /> : null}
        </div>
        <div className={cn("metric-value", !big && "sm")}>{value}</div>
        {bar !== undefined && (
          <div className="progress" style={{ margin: "0.6rem 0 0.1rem" }}>
            <div
              className="progress-bar"
              style={{ width: `${Math.max(0, Math.min(100, bar))}%` }}
            />
          </div>
        )}
        {description != null && (
          <p className={cn("metric-detail", bar !== undefined && "line-1")}>{description}</p>
        )}
      </div>
    </div>
  );
}

const SEV_ORDER: GapSeverity[] = ["critical", "high", "medium", "low", "informational"];
const SEV_LABEL: Record<GapSeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Info",
};

/** Severity-distribution bar + legend, computed from a list of gaps. */
export function SeverityBar({ gaps }: { gaps: { gap_severity: GapSeverity }[] }) {
  const counts = useMemo(() => {
    const c: Record<GapSeverity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
    };
    for (const g of gaps) c[g.gap_severity] = (c[g.gap_severity] ?? 0) + 1;
    return c;
  }, [gaps]);
  const total = gaps.length || 1;

  return (
    <div className="sevbar-wrap">
      <div className="sevbar" role="img" aria-label="Severity distribution">
        {SEV_ORDER.map((s) =>
          counts[s] > 0 ? (
            <span
              key={s}
              className={`s-${s}`}
              style={{ width: `${(counts[s] / total) * 100}%` }}
              title={`${SEV_LABEL[s]}: ${counts[s]}`}
            />
          ) : null,
        )}
      </div>
      <div className="sevlegend">
        {SEV_ORDER.map((s) => (
          <span key={s} className="sl">
            <span className="sw" style={{ background: `hsl(var(--severity-${s}))` }} />
            {SEV_LABEL[s]} <b>{counts[s]}</b>
          </span>
        ))}
      </div>
    </div>
  );
}
