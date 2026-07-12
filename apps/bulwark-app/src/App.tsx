import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { TooltipProvider } from "@/components/ui/tooltip";
import { TitleBar } from "@/components/TitleBar";
import { Sidebar, type View } from "@/components/Sidebar";
import { OverviewView } from "@/components/OverviewView";
import { AgentSecurityView } from "@/components/AgentSecurityView";
import { AntivirusView } from "@/components/AntivirusView";
import { IntegrityView } from "@/components/IntegrityView";
import { RulesView } from "@/components/RulesView";
import { ComplianceView } from "@/components/ComplianceView";
import { HistoryView } from "@/components/HistoryView";
import { SettingsView, type MonitoringStatus } from "@/components/SettingsView";
import { RevisionProvider, useRevision } from "@/lib/revision";
import { cn } from "@/lib/utils";

const VIEWS: { id: View; render: (active: boolean, navigate: (v: View) => void) => React.ReactNode }[] = [
  { id: "overview", render: (_active, navigate) => <OverviewView onNavigate={navigate} /> },
  { id: "agent-security", render: (active) => <AgentSecurityView active={active} /> },
  { id: "antivirus", render: (active) => <AntivirusView active={active} /> },
  { id: "integrity", render: () => <IntegrityView /> },
  { id: "rules", render: () => <RulesView /> },
  { id: "compliance", render: () => <ComplianceView /> },
  { id: "history", render: () => <HistoryView /> },
  { id: "settings", render: () => <SettingsView /> },
];

function Shell() {
  const [view, setViewRaw] = useState<View>("overview");
  const [historyCount, setHistoryCount] = useState<number | null>(null);
  const [monitoringEnabled, setMonitoringEnabled] = useState<boolean | null>(null);
  const { revision, bump } = useRevision();

  // Every view a user has opened at least once stays mounted forever after (hidden via CSS,
  // not unmounted). Real bug report: switching tabs mid-scan lost all progress, because
  // `{view === "x" && <X/>}` unmounts the component and destroys its local state the moment
  // you navigate away — even though the scan keeps running on the Rust side the whole time,
  // the frontend just loses its connection to it. This fixes it uniformly for every view,
  // current and future, without each one needing its own state-lifting workaround.
  //
  // The cost is that a mounted-forever view will happily show data it fetched once and never
  // refreshed; `useRevision` (see lib/revision.tsx) is what pays it.
  const [visited, setVisited] = useState<Set<View>>(() => new Set(["overview"]));

  // Mark the view visited in the same update that changes it, rather than reactively in a
  // useEffect watching `view` — setting state from state inside an effect costs an extra
  // cascading render on every navigation; doing both in the handler that causes the change
  // does not.
  const setView = useCallback((v: View) => {
    setViewRaw(v);
    setVisited((prev) => (prev.has(v) ? prev : new Set(prev).add(v)));
  }, []);

  const refreshChrome = useCallback(() => {
    invoke<number>("history_count")
      .then(setHistoryCount)
      .catch(() => setHistoryCount(null));
    invoke<MonitoringStatus>("monitoring_get_status")
      .then((s) => setMonitoringEnabled(s.enabled))
      .catch(() => setMonitoringEnabled(null));
  }, []);

  useEffect(() => {
    refreshChrome();
  }, [refreshChrome, revision]);

  useEffect(() => {
    // A background tick is the one event that can change stored state without the user having
    // done anything, so it both refreshes the sidebar's own chip and bumps the revision that
    // tells every mounted view to re-read what's on disk.
    const unlistenPromise = listen("monitoring:tick", bump);
    // Monitoring can also be toggled from the CLI or a second window, so the chip polls in
    // addition to listening. Cheap, and it keeps the sidebar honest.
    const poll = setInterval(refreshChrome, 5000);
    return () => {
      clearInterval(poll);
      unlistenPromise.then((unlisten) => unlisten());
    };
  }, [bump, refreshChrome]);

  return (
    <div className="app-shell flex h-screen flex-col bg-background text-foreground">
      <TitleBar />
      <div className="flex min-h-0 flex-1">
        <Sidebar
          view={view}
          onChange={setView}
          historyCount={historyCount}
          monitoringEnabled={monitoringEnabled}
        />
        <main className="min-h-0 min-w-0 flex-1 overflow-hidden">
          {/* Mounted once first visited, then kept alive and merely hidden on every later
              switch away — see the `visited` state above for why this isn't the more obvious
              `{view === "x" && <X/>}`. */}
          {VIEWS.filter(({ id }) => visited.has(id)).map(({ id, render }) => (
            <div key={id} className={cn("h-full", view !== id && "hidden")}>
              {render(view === id, setView)}
            </div>
          ))}
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <RevisionProvider>
      <TooltipProvider>
        <Shell />
      </TooltipProvider>
    </RevisionProvider>
  );
}
