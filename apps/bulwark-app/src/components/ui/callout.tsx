import type { ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Info, ShieldAlert, type LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

export type CalloutTone = "critical" | "warning" | "success" | "info";

/* Each tone borrows a severity triad rather than defining its own colours, so a "warning"
   callout is exactly the amber a `medium` finding is — the app never speaks in two different
   ambers. `info` is the one that doesn't map to a severity; it takes the muted surface. */
const TONE: Record<CalloutTone, { sev: string | null; icon: LucideIcon }> = {
  critical: { sev: "critical", icon: ShieldAlert },
  warning: { sev: "medium", icon: AlertTriangle },
  success: { sev: "resolved", icon: CheckCircle2 },
  info: { sev: null, icon: Info },
};

interface CalloutProps {
  tone: CalloutTone;
  children: ReactNode;
  /** Right-aligned slot for the action that resolves the callout (e.g. "Run privileged checks"). */
  action?: ReactNode;
  className?: string;
}

/**
 * The app's one banner. Replaces six separately hand-rolled variants of
 * `rounded-lg border border-[var(--sev-x)]/30 bg-[var(--sev-x)]/10 px-3 py-2 …` that had
 * drifted apart across the Overview and Antivirus views — differing padding, differing border
 * opacity, and in one case a raw `text-amber-500` that bypassed the severity tokens entirely.
 */
export function Callout({ tone, children, action, className }: CalloutProps) {
  const { sev, icon: Icon } = TONE[tone];
  // A soft, fully-outlined tinted panel rather than a hard 3px left bar — the border is the severity
  // colour dialled back so it reads as a gentle tint edge, matching the rounded, elevated surfaces
  // around it instead of the old left-accent stripe.
  const style = sev
    ? {
        background: `var(--sev-${sev}-tint)`,
        color: `var(--sev-${sev}-fg)`,
        borderColor: `color-mix(in oklch, var(--sev-${sev}) 38%, transparent)`,
      }
    : undefined;

  return (
    <div
      className={cn(
        "flex items-start gap-2.5 rounded-lg border px-3 py-2.5 text-sm",
        // `info` has no severity hue to borrow, so it falls back to the neutral surface.
        !sev && "border-border bg-muted text-muted-foreground",
        className,
      )}
      style={style}
    >
      <Icon className="mt-px h-4 w-4 shrink-0" strokeWidth={2} />
      <div className="min-w-0 flex-1 [&_code]:font-mono [&_code]:text-[0.9em]">{children}</div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}
