import { AlertOctagon, AlertTriangle, AlertCircle, Info, CircleDot } from "lucide-react";
import { cn } from "@/lib/utils";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

const LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const CLASS: Record<Severity, string> = {
  critical: "bg-[var(--sev-critical)] text-white",
  high: "bg-[var(--sev-high)] text-white",
  medium: "bg-[var(--sev-medium)] text-white",
  low: "bg-[var(--sev-low)] text-white",
  info: "bg-[var(--sev-info)] text-white",
};

const ICON: Record<Severity, typeof AlertOctagon> = {
  critical: AlertOctagon,
  high: AlertTriangle,
  medium: AlertCircle,
  low: Info,
  info: CircleDot,
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const Icon = ICON[severity];
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
        CLASS[severity],
      )}
    >
      <Icon className="h-2.5 w-2.5" strokeWidth={2.5} />
      {LABEL[severity]}
    </span>
  );
}
