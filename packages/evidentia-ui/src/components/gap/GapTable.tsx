import {
  columnFilteringFeature,
  columnVisibilityFeature,
  createFilteredRowModel,
  createSortedRowModel,
  flexRender,
  globalFilteringFeature,
  rowSortingFeature,
  sortFn_alphanumeric,
  sortFn_basic,
  sortFn_datetime,
  sortFn_text,
  tableFeatures,
  useTable,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import { useMemo, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { SEVERITY_RANK, severityBadge } from "@/lib/severity";
import type { ControlGap } from "@/types/api";

/**
 * Sortable + filterable gap table powered by TanStack Table.
 *
 * Renders all rows (no row virtualization); comfortable to ~1000 rows.
 * Virtualization for larger reports is a backlog item, not shipped.
 */
type Density = "compact" | "default" | "comfortable";

const DENSITY_OPTIONS: readonly [Density, string][] = [
  ["compact", "Compact"],
  ["default", "Default"],
  ["comfortable", "Comfy"],
];

// Table V9 requires features to be declared up front rather than bundled
// into the hook. columnFilteringFeature is not used for its own sake (no
// per-column filters render); it is required here because both
// globalFilteringFeature and the filteredRowModel factory depend on it at
// the type level. columnVisibilityFeature is likewise never toggled, but it
// is what puts `row.getVisibleCells()` on the Row prototype. Sort functions
// are registered individually rather than through the deprecated
// whole-registry `sortFns` export, so `sortFn: "auto"` (the default for
// every column but Severity) can resolve whichever built-in the
// auto-detector picks from a column's sampled values.
const features = tableFeatures({
  rowSortingFeature,
  columnFilteringFeature,
  columnVisibilityFeature,
  globalFilteringFeature,
  sortedRowModel: createSortedRowModel(),
  filteredRowModel: createFilteredRowModel(),
  sortFns: {
    alphanumeric: sortFn_alphanumeric,
    basic: sortFn_basic,
    datetime: sortFn_datetime,
    text: sortFn_text,
  },
});

export function GapTable({ gaps }: { gaps: ControlGap[] }) {
  const [filter, setFilter] = useState("");
  const [sorting, setSorting] = useState<SortingState>([
    { id: "priority_score", desc: true },
  ]);
  // Local presentation-only density control (CSS keys off data-density).
  const [density, setDensity] = useState<Density>("compact");

  const columns = useMemo<ColumnDef<typeof features, ControlGap>[]>(
    () => [
      {
        accessorKey: "framework",
        header: "Framework",
        cell: ({ row }) => (
          <code className="kbd">{String(row.original.framework)}</code>
        ),
      },
      {
        accessorKey: "control_id",
        header: "Control",
        cell: ({ row }) => (
          <span className="mono text-xs">
            {String(row.original.control_id)}
          </span>
        ),
      },
      {
        accessorKey: "control_title",
        header: "Title",
        cell: ({ row }) => (
          <span className="line-1 text-sm">
            {String(row.original.control_title)}
          </span>
        ),
      },
      {
        accessorKey: "gap_severity",
        header: "Severity",
        sortFn: (a, b, id) =>
          SEVERITY_RANK[a.getValue(id) as keyof typeof SEVERITY_RANK] -
          SEVERITY_RANK[b.getValue(id) as keyof typeof SEVERITY_RANK],
        cell: ({ row }) => (
          <Badge variant={severityBadge(row.original.gap_severity)}>
            {row.original.gap_severity}
          </Badge>
        ),
      },
      {
        accessorKey: "implementation_effort",
        header: "Effort",
        cell: ({ row }) => (
          <Badge variant="outline" className="cap">
            {row.original.implementation_effort.replace(/_/g, " ")}
          </Badge>
        ),
      },
      {
        accessorKey: "priority_score",
        header: "Priority",
        cell: ({ row }) => (
          <span className="mono text-xs tnum">
            {row.original.priority_score.toFixed(2)}
          </span>
        ),
      },
      {
        accessorKey: "status",
        header: "Status",
        cell: ({ row }) => (
          <span
            className={cn(
              "capitalize text-xs",
              row.original.status === "open"
                ? "text-destructive"
                : "text-muted-foreground",
            )}
          >
            {row.original.status.replace(/_/g, " ")}
          </span>
        ),
      },
    ],
    [],
  );

  const table = useTable({
    features,
    data: gaps,
    columns,
    state: { sorting, globalFilter: filter },
    onSortingChange: setSorting,
    onGlobalFilterChange: setFilter,
    globalFilterFn: (row, _columnId, value) => {
      const q = String(value).toLowerCase();
      return (
        row.original.control_id.toLowerCase().includes(q) ||
        row.original.control_title.toLowerCase().includes(q) ||
        row.original.framework.toLowerCase().includes(q)
      );
    },
  });

  const filteredRows = table.getFilteredRowModel().rows;

  return (
    <div className="stack-3">
      <div className="row-between gap-4 wrap">
        <Input
          type="search"
          placeholder="Filter by control ID, title, or framework..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="max-sm"
          aria-label="Filter gaps"
        />
        <div className="row gap-3">
          <div className="row gap-2" role="radiogroup" aria-label="Row density">
            <span className="text-xs faint">Density</span>
            {DENSITY_OPTIONS.map(([value, label]) => (
              <button
                key={value}
                type="button"
                role="radio"
                aria-checked={density === value}
                className={cn("seg", density === value && "on")}
                onClick={() => setDensity(value)}
              >
                {label}
              </button>
            ))}
          </div>
          <span className="text-xs muted tnum">
            {filteredRows.length} of {gaps.length} rows
          </span>
        </div>
      </div>
      <div className="table-wrap" data-density={density}>
        <table className="tbl">
          <thead>
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((header) => {
                  const sorted = header.column.getIsSorted();
                  return (
                    <th
                      key={header.id}
                      scope="col"
                      className={cn(header.column.getCanSort() && "sortable")}
                      onClick={header.column.getToggleSortingHandler()}
                    >
                      {flexRender(
                        header.column.columnDef.header,
                        header.getContext(),
                      )}
                      {sorted ? (
                        <span className="sortarrow">
                          {sorted === "desc" ? " ▼" : " ▲"}
                        </span>
                      ) : null}
                    </th>
                  );
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map((row) => (
              <tr key={row.id} data-severity={row.original.gap_severity}>
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id}>
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
            {table.getRowModel().rows.length === 0 && (
              <tr>
                <td
                  colSpan={columns.length}
                  className="text-sm muted"
                  style={{ textAlign: "center", padding: "2rem" }}
                >
                  No gaps match the current filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
