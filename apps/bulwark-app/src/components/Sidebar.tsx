import {
  BadgeCheck,
  Bot,
  FileCheck2,
  History,
  LayoutDashboard,
  LineChart,
  ListChecks,
  Settings,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";

export type View =
  | "overview"
  | "agent-security"
  | "antivirus"
  | "integrity"
  | "rules"
  | "compliance"
  | "analytics"
  | "history"
  | "settings";

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
  /** Marks the item as new, with a small "New" badge.
   *
   *  Deliberately NOT a colour treatment. The first cut of this gave the promoted item a
   *  standing primary rail and a primary background wash — which is precisely the vocabulary
   *  this sidebar uses for *the page you are currently on*. The result was that sitting on
   *  Overview, Agent Security still looked selected, and the Overview's own findings read as
   *  though they belonged to Agent Security. Selection state owns the rail and the wash; nothing
   *  else may borrow them, or the nav stops being able to answer "where am I". */
  badge?: string;
}

/* The nav mirrors the product's actual shape: one scanner per tab, and one page that adds them
   up.

   `Overview` is ungrouped and alone at the top because it is *the answer* — it aggregates every
   scanner's findings into a single "what is wrong with this machine" list, and its scan button
   drives all of them.

   "Scans" is the four engines, ordered oldest-and-most-load-bearing first: Compliance (the
   configuration rule pack's scan results — the issues found and how to fix them), Antivirus
   (ClamAV), Agent Security (AI assistant artifacts), File integrity. Each page is where you go to
   run that engine on its own and read its results in detail.

   "Reference" is what explains the results rather than producing them: the rule pack itself —
   every rule plus how it maps to CIS/MITRE and this host's hardening index (folded in from what
   used to be a separate Compliance tab) — and the scan timeline.

   What moved, and why:
     - File integrity was a right-hand column inside a page called "Antivirus", despite being
       an independent pillar with its own threat model. It gets its own page.
     - "Monitoring" was a cadence setting dressed as a destination, and "About" was a footer.
       Both are Settings.
     - Compliance sat under "Reference" as though it were documentation, but it reports the
       results of a scan — it belongs with the scanners.
     - The group was called "Protection", which described a *property* rather than what the
       items are. They are scanners; the label now says so. */
const GROUPS: { label: string | null; items: NavItem[] }[] = [
  {
    label: null,
    items: [{ id: "overview", label: "Overview", icon: LayoutDashboard }],
  },
  {
    label: "Scans",
    items: [
      { id: "compliance", label: "Compliance", icon: BadgeCheck },
      { id: "antivirus", label: "Antivirus", icon: ShieldCheck },
      // The newest pillar, and the one most users won't know to look for — so it carries a "new"
      // badge. A badge, not a colour: see NavItem.badge for why it must not borrow the rail.
      { id: "agent-security", label: "Agent Security", icon: Bot, badge: "New" },
      { id: "integrity", label: "File integrity", icon: FileCheck2 },
    ],
  },
  {
    label: "Reference",
    items: [
      { id: "rules", label: "Rules", icon: ListChecks },
      { id: "analytics", label: "Analytics", icon: LineChart },
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
  const { id, label, icon: Icon, badge } = item;
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
      // The rail is painted only for the active page — see NavItem.badge for why a "new" item
      // must not borrow it.
      style={{ "--rail-color": active ? "var(--primary)" : "transparent" } as React.CSSProperties}
    >
      <Icon className="h-4 w-4 shrink-0" strokeWidth={active ? 2.25 : 1.75} />
      <span className="min-w-0 flex-1 truncate">{label}</span>
      {badge && (
        <span className="shrink-0 rounded-full border border-ink-border px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-wider text-ink-muted">
          {badge}
        </span>
      )}
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
