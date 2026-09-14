import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";

import { cn } from "@/lib/utils";

/**
 * Badge — re-skinned to the GUI v2 design-system classes (see index.css
 * @layer components). The variant union is unchanged so existing call sites
 * (incl. `severityBadge()` -> "critical" | "high" | …) keep working; severity
 * variants render the soft-tint + leading-dot treatment that mirrors the CLI.
 */
const badgeVariants = cva("badge", {
  variants: {
    variant: {
      default: "default",
      secondary: "secondary",
      destructive: "destructive",
      outline: "outline",
      // Severity variants — `.sev` adds the leading dot; hue from --sev-*.
      critical: "sev critical",
      high: "sev high",
      medium: "sev medium",
      low: "sev low",
      informational: "sev informational",
    },
  },
  defaultVariants: {
    variant: "default",
  },
});

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge };
