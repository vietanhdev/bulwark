import {
  BadgeCheck,
  FileCheck2,
  History,
  LayoutDashboard,
  ListChecks,
  Settings,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";

export type View = "overview" | "antivirus" | "integrity" | "rules" | "compliance" | "history" | "settings";

interface SidebarProps {
  view: View;
  onChange: (view: View) => void;
  historyCount: number | null;
  monitoringEnabled: boolean | null;
}

interface NavItem {
  id: View;
  label: string;
  icon: LucideIcon;
}

/* Three groups, cut by the question each answers rather than by build order.
   `Overview` is ungrouped and alone at the top because it is the answer — everything else is
   a way of getting to it or of explaining it.

   What moved, and why (the old nav had seven items too, but two of them were doing someone
   else's job):
     - File integrity was a right-hand column inside a page called "Antivirus", despite being
       an independent pillar of the product with its own threat model. It gets its own page.
     - "Monitoring" was a cadence setting dressed as a destination, and "About" was a footer.
       Both are Settings.
     - The Overview's three quick-nav cards duplicated sidebar entries exactly. Deleted: the
       sidebar is right there. */
const GROUPS: { label: string | null; items: NavItem[] }[] = [
  {
    label: null,
    items: [{ id: "overview", label: "Overview", icon: LayoutDashboard }],
  },
  {
    label: "Protection",
    items: [
      { id: "antivirus", label: "Antivirus", icon: ShieldCheck },
      { id: "integrity", label: "File integrity", icon: FileCheck2 },
    ],
  },
  {
    label: "Reference",
    items: [
      { id: "rules", label: "Rules", icon: ListChecks },
      { id: "compliance", label: "Compliance", icon: BadgeCheck },
      { id: "history", label: "History", icon: History },
    ],
  },
];

function NavButton({
  item,
  active,
  onChange,
}: {
  item: NavItem;
  active: boolean;
  onChange: (view: View) => void;
}) {
  const { id, label, icon: Icon } = item;
  return (
    <button
      onClick={() => onChange(id)}
      aria-current={active ? "page" : undefined}
      className={cn(
        // The severity rail again, doing navigational work: the active page is the one with a
        // bar in its gutter, exactly like the finding you're reading. One structural idea,
        // used consistently, rather than a second highlight vocabulary just for the chrome.
        "rail relative flex items-center gap-2.5 rounded-md py-2 pr-2.5 pl-3 text-left text-sm transition-colors",
        "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary",
        active
          ? "bg-ink-raised font-medium text-ink-fg"
          : "font-normal text-ink-muted hover:bg-ink-raised/50 hover:text-ink-fg",
      )}
      style={{ "--rail-color": active ? "var(--primary)" : "transparent" } as React.CSSProperties}
    >
      <Icon className="h-4 w-4 shrink-0" strokeWidth={active ? 2.25 : 1.75} />
      {label}
    </button>
  );
}

export function Sidebar({ view, onChange, historyCount, monitoringEnabled }: SidebarProps) {
  return (
    <nav className="flex w-52 shrink-0 flex-col justify-between border-r border-ink-border bg-ink p-2.5">
      <div className="flex flex-col gap-5">
        {GROUPS.map((group, i) => (
          <div key={group.label ?? i} className="flex flex-col gap-1">
            {group.label && (
              <div className="mb-1 px-3 font-mono text-[10px] font-semibold uppercase tracking-widest text-ink-muted/70">
                {group.label}
              </div>
            )}
            {group.items.map((item) => (
              <NavButton key={item.id} item={item} active={view === item.id} onChange={onChange} />
            ))}
          </div>
        ))}
      </div>

      <div className="flex flex-col gap-1">
        {/* The live status chip doubles as the way into the setting that governs it — clicking
            "Monitoring paused" should take you to the thing that un-pauses it. */}
        <button
          onClick={() => onChange("settings")}
          className="flex flex-col gap-1 rounded-md px-3 py-2 text-left transition-colors hover:bg-ink-raised/50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
        >
          <span className="flex items-center gap-1.5">
            <span className="relative flex h-1.5 w-1.5 shrink-0">
              {monitoringEnabled && (
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-75" />
              )}
              <span
                className={cn(
                  "relative inline-flex h-1.5 w-1.5 rounded-full",
                  monitoringEnabled ? "bg-primary" : "bg-ink-muted/50",
                )}
              />
            </span>
            <span className="text-xs font-medium text-ink-fg">
              {monitoringEnabled === null
                ? "Checking status…"
                : monitoringEnabled
                  ? "Monitoring active"
                  : "Monitoring paused"}
            </span>
          </span>
          <span className="pl-3 font-mono text-[11px] text-ink-muted">
            {historyCount === null ? "—" : `${historyCount} scan${historyCount === 1 ? "" : "s"} recorded`}
          </span>
        </button>

        <NavButton
          item={{ id: "settings", label: "Settings", icon: Settings }}
          active={view === "settings"}
          onChange={onChange}
        />
      </div>
    </nav>
  );
}
