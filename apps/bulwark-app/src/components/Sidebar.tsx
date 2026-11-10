import { ArrowLeft, Settings } from "lucide-react";
import { WorkbenchIcon } from "./WorkbenchIcon";

export type View =
  | "access"
  | "overview"
  | "machines"
  | "antivirus"
  | "integrity"
  | "rules"
  | "compliance"
  | "analytics"
  | "settings"
  | "tools";
const PRIMARY = [
  { id: "overview", label: "Scan", icon: "scan" },
  { id: "access", label: "Secrets", icon: "sessions" },
  { id: "tools", label: "Tools", icon: "tools" },
] as const;
const SECONDARY: View[] = ["compliance", "machines", "antivirus", "integrity", "rules", "analytics"];

/** Compact task navigation. Secondary tools stay reachable without dominating the workspace. */
export function WorkbenchNav({
  view,
  onChange,
  monitoringEnabled,
}: {
  view: View;
  onChange: (view: View) => void;
  monitoringEnabled: boolean | null;
}) {
  return (
    <>
      <nav
        aria-label="Workbench"
        className="workbench-tabs flex shrink-0 items-center gap-1 border-b border-border px-3"
      >
        {PRIMARY.map(({ id, label, icon }) => {
          const selected = view === id || (id === "tools" && SECONDARY.includes(view));
          return (
            <button
              key={id}
              onClick={() => onChange(id)}
              aria-current={selected ? "page" : undefined}
              className="workbench-tab"
            >
              <WorkbenchIcon kind={icon} className="tab-icon" />
              {label}
            </button>
          );
        })}
        <button
          onClick={() => onChange("settings")}
          aria-current={view === "settings" ? "page" : undefined}
          title={
            monitoringEnabled === null
              ? "Settings — schedule unavailable"
              : `Settings — scheduled checks ${monitoringEnabled ? "on" : "off"}`
          }
          className="workbench-tab ml-auto"
        >
          <Settings className="tab-icon" strokeWidth={1.6} aria-hidden="true" />
          Settings
        </button>
      </nav>
      {SECONDARY.includes(view) && (
        <div className="shrink-0 px-6 pt-3">
          <button
            onClick={() => onChange("tools")}
            className="flex items-center gap-1.5 rounded text-xs text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-primary"
          >
            <ArrowLeft className="size-3" aria-hidden="true" />
            Back to tools
          </button>
        </div>
      )}
    </>
  );
}
