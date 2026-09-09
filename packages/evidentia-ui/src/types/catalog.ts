/** TypeScript mirrors of CatalogControl + ControlCatalog from
 *  evidentia_core.models.catalog. */

import type { components } from "@/types/openapi";

export type CatalogSourceRow = components["schemas"]["CatalogSourceRow"];

export interface CatalogControl {
  id: string;
  title: string;
  description: string;
  family: string | null;
  class?: string | null;
  control_class?: string | null;
  priority?: string | null;
  properties?: Record<string, string>;
  source_rows?: CatalogSourceRow[];
  withdrawn?: boolean;
  baseline_impact: string[];
  enhancements: CatalogControl[];
  related_controls: string[];
  assessment_objectives: string[];
  objective?: string | null;
  guidance?: string | null;
  examples: string[];
  parameters: Record<string, string>;
  ordering?: number | null;
  tier?: string | null;
  license_required: boolean;
  license_url?: string | null;
  placeholder: boolean;
}

export type CatalogStatus = "current" | "superseded" | "retired" | "historical";

export interface CatalogAuditContext {
  authority: string;
  version: string;
  source_url: string;
  verified_on: string;
  valid_through?: string | null;
  notes?: string | null;
}

export interface CatalogPublicationNotice {
  id: string;
  title: string;
  status: "approved-future" | "approved-superseded" | "pending";
  source_url: string;
  approved_on?: string | null;
  published_on?: string | null;
  order_effective_on?: string | null;
  effective_on?: string | null;
  inactive_on?: string | null;
  superseded_by?: string | null;
  notes?: string | null;
}

export interface ControlCatalog {
  framework_id: string;
  framework_name: string;
  version: string;
  source: string;
  controls: CatalogControl[];
  families: string[];
  family_hierarchy?: Record<string, string[]> | null;
  category: "control" | "technique" | "vulnerability" | "obligation";
  tier?: string | null;
  license_required: boolean;
  license_terms?: string | null;
  license_url?: string | null;
  placeholder: boolean;
  status?: CatalogStatus | null;
  notes?: string | null;
  verified_on?: string | null;
  superseded_by?: string | null;
  audit_contexts?: Record<string, CatalogAuditContext>;
  publication_notices?: CatalogPublicationNotice[];
}
