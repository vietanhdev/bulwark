import { Check, AlertTriangle, X, HelpCircle, Clock } from "lucide-react";
import { ShieldMark } from "@/components/ShieldMark";
import { cn } from "@/lib/utils";

export type ProtectionStatus = "idle" | "clean" | "warning" | "critical" | "scanning";

const CONFIG: Record<
  Exclude<ProtectionStatus, "scanning">,
  { icon: typeof Check; label: string; shieldClass: string }
> = {
  idle: {
    icon: HelpCircle,
    label: "Not scanned yet",
    shieldClass: "text-muted-foreground/50",
  },
  clean: {
    icon: Check,
    label: "Protected — no issues found",
    shieldClass: "text-[var(--sev-resolved)]",
  },
  warning: {
    icon: AlertTriangle,
    label: "Issues need attention",
    shieldClass: "text-[var(--sev-medium)]",
  },
  critical: {
    icon: X,
    label: "Critical issues found",
    shieldClass: "text-[var(--sev-critical)]",
  },
};

/// Horizontal, not the vertical centered block this used to be — a security dashboard's
/// status is something you glance at once and then want out of the way of the actually
/// useful content (protection modules, findings) below it. This is Bulwark's persistent
/// header, not a splash screen; it shouldn't compete with the scrollable content for space
/// every time the window opens.
export function StatusHero({
  status,
  lastScanLabel,
}: {
  status: ProtectionStatus;
  lastScanLabel: string | null;
}) {
  const scanning = status === "scanning";
  const resolved = scanning ? "idle" : status;
  const { icon: Icon, label, shieldClass } = CONFIG[resolved];

  return (
    <div className="flex items-center gap-3">
      <div className="relative flex h-11 w-11 shrink-0 items-center justify-center">
        {scanning && (
          <>
            <span className="status-ring absolute inset-0 rounded-full bg-primary/30" />
            <span className="status-ring-delayed absolute inset-0 rounded-full bg-primary/30" />
          </>
        )}
        <ShieldMark
          className={cn(
            "relative h-11 w-11 transition-colors duration-300",
            scanning ? "animate-pulse text-primary" : shieldClass,
          )}
        />
        {!scanning && (
          <Icon className="absolute h-4 w-4 text-background" strokeWidth={3} style={{ marginTop: "-2px" }} />
        )}
      </div>
      <div className="min-w-0">
        <div className="text-sm font-semibold leading-tight">{scanning ? "Scanning…" : label}</div>
        {lastScanLabel && !scanning && (
          <div className="mt-0.5 flex items-center gap-1 font-mono text-[11px] text-muted-foreground">
            <Clock className="h-3 w-3 shrink-0" />
            <span className="truncate">{lastScanLabel}</span>
          </div>
        )}
      </div>
    </div>
  );
}
