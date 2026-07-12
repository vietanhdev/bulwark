import type { CSSProperties } from "react";
import { cn } from "@/lib/utils";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Worst first. The single source of truth for severity ordering across sorting and counting. */
export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/**
 * Paints a row's severity rail — the 3px bar in its left gutter. Pair with the `rail` class
 * (and usually `rail-dim`, which keeps a long list calm by holding rails at 45% until hover).
 * See styles.css for why the rail exists rather than a badge.
 */
export function railStyle(severity: Severity | "resolved"): CSSProperties {
  return { "--rail-color": `var(--sev-${severity})` } as CSSProperties;
}

/**
 * The severity word itself. Text-on-tint, not the old white-on-solid-fill chip — that chip
 * failed WCAG AA on 8 of 10 severity/theme combinations (down to 2.03:1 for medium in dark
 * mode) because 10px white text was being set on mid-lightness fills. Every tint/foreground
 * pair here is solved to at least 4.5:1; see the severity triads in styles.css.
 */
export function SeverityLabel({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center rounded-sm px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider",
        className,
      )}
      style={{
        background: `var(--sev-${severity}-tint)`,
        color: `var(--sev-${severity}-fg)`,
      }}
    >
      {LABEL[severity]}
    </span>
  );
}

/** A bare severity dot, for places too tight for the word (legends, dense table cells). */
export function SeverityDot({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cn("inline-block h-2 w-2 shrink-0 rounded-full", className)}
      style={{ background: `var(--sev-${severity})` }}
      aria-hidden
    />
  );
}
