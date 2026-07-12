import { LayoutDashboard, ListChecks, ShieldCheck, Radar, BadgeCheck, History, Info } from "lucide-react";
import { cn } from "@/lib/utils";

export type View = "dashboard" | "threats" | "compliance" | "rules" | "monitoring" | "history" | "about";

interface SidebarProps {
  view: View;
  onChange: (view: View) => void;
  historyCount: number | null;
  monitoringEnabled: boolean | null;
}

// Grouped logically rather than in build order: what you look at day-to-day (protection
// status, threats found) first, reference material (what gets checked, compliance mapping)
// second, background configuration (monitoring cadence) last — closest to the live status
// chip it controls.
const PROTECTION_ITEMS: { id: View; label: string; icon: typeof LayoutDashboard }[] = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "threats", label: "Antivirus", icon: ShieldCheck },
];
const REFERENCE_ITEMS: { id: View; label: string; icon: typeof LayoutDashboard }[] = [
  { id: "rules", label: "Rules", icon: ListChecks },
  { id: "compliance", label: "Compliance", icon: BadgeCheck },
  { id: "history", label: "History", icon: History },
];
const CONFIG_ITEMS: { id: View; label: string; icon: typeof LayoutDashboard }[] = [
  { id: "monitoring", label: "Monitoring", icon: Radar },
  { id: "about", label: "About", icon: Info },
];

function NavGroup({
  items,
  view,
  onChange,
}: {
  items: typeof PROTECTION_ITEMS;
  view: View;
  onChange: (view: View) => void;
}) {
  return (
    <div className="flex flex-col gap-1">
      {items.map(({ id, label, icon: Icon }) => (
        <button
          key={id}
          onClick={() => onChange(id)}
          className={cn(
            "flex items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-sm font-medium transition-colors",
            view === id
              ? "bg-sidebar-primary text-sidebar-primary-foreground"
              : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
          )}
        >
          <Icon className="h-4 w-4" />
          {label}
        </button>
      ))}
    </div>
  );
}

export function Sidebar({ view, onChange, historyCount, monitoringEnabled }: SidebarProps) {
  return (
    <nav className="flex w-48 shrink-0 flex-col justify-between border-r border-sidebar-border bg-sidebar p-2">
      <div className="flex flex-col gap-4">
        <NavGroup items={PROTECTION_ITEMS} view={view} onChange={onChange} />
        <NavGroup items={REFERENCE_ITEMS} view={view} onChange={onChange} />
        <NavGroup items={CONFIG_ITEMS} view={view} onChange={onChange} />
      </div>

      <button
        onClick={() => onChange("monitoring")}
        className="flex flex-col gap-1 rounded-md px-2.5 py-2 text-left transition-colors hover:bg-sidebar-accent"
      >
        <div className="flex items-center gap-1.5">
          <span
            className={cn(
              "h-1.5 w-1.5 rounded-full",
              monitoringEnabled === null
                ? "bg-muted-foreground/40"
                : monitoringEnabled
                  ? "animate-pulse bg-primary"
                  : "bg-muted-foreground/40",
            )}
          />
          <span className="text-xs font-medium text-sidebar-foreground">
            {monitoringEnabled === null ? "Checking status…" : monitoringEnabled ? "Monitoring active" : "Monitoring paused"}
          </span>
        </div>
        <span className="font-mono text-[11px] text-muted-foreground">
          {historyCount === null ? "—" : `${historyCount} scan${historyCount === 1 ? "" : "s"} recorded`}
        </span>
      </button>
    </nav>
  );
}
