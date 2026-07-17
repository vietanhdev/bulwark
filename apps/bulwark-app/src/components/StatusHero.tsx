import { AlertTriangle, Check, Clock, HelpCircle, X, type LucideIcon } from "lucide-react";
import { ShieldMark } from "@/components/ShieldMark";
import { SeverityDot, severityLabel, type Severity } from "@/components/Severity";
import { cn } from "@/lib/utils";

export type ProtectionStatus = "idle" | "clean" | "warning" | "critical" | "scanning";

/* The verdict is written as a sentence a person would actually say, not a status enum. "This
   host is in good shape" tells you where you stand; "CLEAN" makes you decode a label. */
const CONFIG: Record<
  Exclude<ProtectionStatus, "scanning">,
  { icon: LucideIcon; headline: string; shieldColor: string }
> = {
  idle: {
    icon: HelpCircle,
    headline: "Let's check this computer",
    shieldColor: "var(--muted-foreground)",
  },
  clean: {
    icon: Check,
    headline: "Your computer looks safe",
    shieldColor: "var(--sev-resolved)",
  },
  warning: {
    icon: AlertTriangle,
    headline: "Your computer needs a little attention",
    shieldColor: "var(--sev-medium)",
  },
  critical: {
    icon: X,
    headline: "Your computer needs attention",
    shieldColor: "var(--sev-critical)",
  },
};

interface StatusHeroProps {
  status: ProtectionStatus;
  counts: { sev: Severity; count: number }[];
  /** Host fingerprint of the most recent scan, or null if nothing has run. */
  host: string | null;
  /** When false, the inline severity-dot breakdown is suppressed — used where a fuller breakdown
   *  (e.g. the Overview's posture bar) already owns that job, so the two don't duplicate. */
  showBreakdown?: boolean;
}

/**
 * The Overview's thesis: the shield, coloured by the verdict, and the verdict in plain words.
 *
 * The severity breakdown underneath lists only the severities that actually occur. The old
 * version rendered all five as fixed-width cells whatever the result, so a perfectly clean
 * host still displayed a row of five zeros — five reminders of things that aren't wrong, which
 * is precisely the opposite of what a clean scan should feel like.
 */
export function StatusHero({ status, counts, host, showBreakdown = true }: StatusHeroProps) {
  const scanning = status === "scanning";
  const { icon: Icon, headline, shieldColor } = CONFIG[scanning ? "idle" : status];
  const present = counts.filter((c) => c.count > 0);

  return (
    <div className="flex items-center gap-4">
      <div className="relative flex h-14 w-14 shrink-0 items-center justify-center">
        {scanning && (
          <>
            <span className="status-ring absolute inset-0 rounded-full bg-primary/25" />
            <span className="status-ring-delayed absolute inset-0 rounded-full bg-primary/25" />
          </>
        )}
        <ShieldMark
          className={cn("relative h-14 w-14 transition-colors duration-500", scanning && "animate-pulse")}
          style={{ color: scanning ? "var(--primary)" : shieldColor }}
        />
        {!scanning && (
          <Icon
            className="absolute h-5 w-5"
            style={{ color: "var(--card)", marginTop: "-3px" }}
            strokeWidth={3}
          />
        )}
      </div>

      <div className="min-w-0">
        <h2 className="font-heading text-lg font-semibold tracking-tight">
          {scanning ? "Checking your computer…" : headline}
        </h2>

        {showBreakdown && !scanning && present.length > 0 && (
          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1">
            {present.map(({ sev, count }) => (
              <span key={sev} className="flex items-center gap-1.5 text-sm">
                <SeverityDot severity={sev} />
                <span className="font-mono font-semibold tabular-nums">{count}</span>
                <span className="text-muted-foreground">{severityLabel(sev)}</span>
              </span>
            ))}
          </div>
        )}

        {!scanning && host && (
          <div className="mt-1.5 flex items-center gap-1.5 font-mono text-[11px] text-muted-foreground">
            <Clock className="h-3 w-3 shrink-0" />
            <span className="truncate">Last checked {host}</span>
          </div>
        )}
      </div>
    </div>
  );
}
