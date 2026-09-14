import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";

import { cn } from "@/lib/utils";

/**
 * Button — re-skinned to the GUI v2 design-system classes (see index.css
 * @layer components). Prop API (variant / size / asChild) is unchanged. The
 * `[&_svg]` rules keep lucide icons sized even without the prototype's `.ic`
 * class. `destructive` / `link` reuse the base `.btn` layout with token-driven
 * color utilities (the prototype CSS defines no such variants).
 */
const buttonVariants = cva(
  "btn [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default: "default",
        destructive:
          "border-transparent bg-destructive text-destructive-foreground hover:bg-destructive/90",
        outline: "outline",
        secondary: "secondary",
        ghost: "ghost",
        link: "border-transparent bg-transparent !h-auto !px-0 text-primary underline-offset-4 hover:underline",
      },
      size: {
        default: "",
        sm: "sm",
        lg: "lg",
        icon: "!px-0 w-10",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    );
  },
);
Button.displayName = "Button";

export { Button };
