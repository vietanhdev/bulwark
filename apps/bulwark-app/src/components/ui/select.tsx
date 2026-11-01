import * as React from "react";
import { ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * A native `<select>` dressed exactly like `Input`: same height, radius, border, card background,
 * shadow and focus ring. Native rather than a custom listbox so keyboard, screen-reader and
 * type-to-select behaviour come for free — but with `appearance-none`, because WebKitGTK (the
 * engine the desktop app actually runs on) otherwise draws a grey GTK combo box with its own
 * border and arrow that matches nothing around it. The chevron is ours and follows the theme.
 *
 * `className` styles the wrapper (width, max-width); everything else goes to the `<select>`.
 */
function Select({ className, children, ...props }: React.ComponentProps<"select">) {
  return (
    <div className={cn("relative w-full min-w-0", className)}>
      <select
        data-slot="select"
        className={cn(
          "flex h-9 w-full min-w-0 cursor-pointer appearance-none rounded-md border border-input bg-card py-1 pr-9 pl-3 text-sm text-foreground shadow-xs transition-[color,box-shadow] outline-none",
          "focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/40",
          "disabled:cursor-not-allowed disabled:opacity-50",
        )}
        {...props}
      >
        {children}
      </select>
      <ChevronDown
        aria-hidden
        className="pointer-events-none absolute top-1/2 right-3 h-4 w-4 -translate-y-1/2 text-muted-foreground"
      />
    </div>
  );
}

export { Select };
