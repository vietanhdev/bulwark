import { hardeningTone, type HardeningIndex } from "@/lib/hardening";
import { cn } from "@/lib/utils";

const R = 15.5;
const CIRCUMFERENCE = 2 * Math.PI * R;

/**
 * Bulwark's headline number, and the closest thing it has to a gauge.
 *
 * Lynis leads its report with a single hardening index rather than a pass/fail list, and that
 * is the right call: it's the one figure that answers "is this host in decent shape?" without
 * reading anything else. It used to be buried on the Compliance page; it belongs on the
 * Overview, next to the verdict it quantifies.
 */
export function HardeningRing({
  index,
  size = "md",
  className,
}: {
  index: HardeningIndex;
  size?: "md" | "lg";
  className?: string;
}) {
  const tone = hardeningTone(index.score);
  const dash = (index.score / 100) * CIRCUMFERENCE;

  return (
    <div className={cn("flex items-center gap-3.5", className)}>
      <div
        className={cn(
          "relative flex shrink-0 items-center justify-center",
          size === "lg" ? "h-20 w-20" : "h-16 w-16",
        )}
      >
        <svg viewBox="0 0 36 36" className="h-full w-full -rotate-90">
          <circle cx="18" cy="18" r={R} fill="none" className="stroke-border" strokeWidth="2.5" />
          <circle
            cx="18"
            cy="18"
            r={R}
            fill="none"
            strokeWidth="2.5"
            strokeLinecap="round"
            stroke={`var(--sev-${tone})`}
            strokeDasharray={`${dash} ${CIRCUMFERENCE}`}
          />
        </svg>
        <span
          className={cn(
            "absolute font-mono font-semibold tabular-nums",
            size === "lg" ? "text-2xl" : "text-lg",
          )}
        >
          {index.score}
        </span>
      </div>
      <div className="min-w-0">
        <div className="font-mono text-[11px] font-semibold uppercase tracking-widest text-muted-foreground">
          Hardening index
        </div>
        <div className="mt-1 text-sm font-medium">
          {index.passing}/{index.evaluated} checks passing
        </div>
        {index.skipped > 0 && (
          <div className="mt-0.5 text-xs text-muted-foreground">
            {index.skipped} not evaluated — excluded from the score, not counted as passing
          </div>
        )}
      </div>
    </div>
  );
}
