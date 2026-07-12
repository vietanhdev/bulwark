import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { TooltipProvider } from "@/components/ui/tooltip";
import { TitleBar } from "@/components/TitleBar";
import { Sidebar, type View } from "@/components/Sidebar";
import { Dashboard } from "@/components/Dashboard";
import { RulesView } from "@/components/RulesView";
import { ThreatsView } from "@/components/ThreatsView";
import { ComplianceView } from "@/components/ComplianceView";
import { HistoryView } from "@/components/HistoryView";
import { MonitoringView, type MonitoringStatus } from "@/components/MonitoringView";
import { AboutView } from "@/components/AboutView";
import { cn } from "@/lib/utils";

export default function App() {
  const [view, setViewRaw] = useState<View>("dashboard");
  const [historyCount, setHistoryCount] = useState<number | null>(null);
  const [monitoringEnabled, setMonitoringEnabled] = useState<boolean | null>(null);
  // Every view a user has opened at least once stays mounted forever after (hidden via CSS,
  // not unmounted) — real bug report: switching tabs mid-scan (Dashboard's scan, the
  // Antivirus page's live progress, a File Integrity baseline run) lost all progress, because
  // conditionally rendering `{view === "x" && <X/>}` unmounts the component and destroys its
  // local state the moment you navigate away, even though the actual scan keeps running on
  // the Rust side the whole time — the frontend just loses its connection to it. This fixes
  // it for every view uniformly, current and future, without each one needing its own
  // state-lifting workaround.
  const [visited, setVisited] = useState<Set<View>>(() => new Set(["dashboard"]));

  // Marks the view as visited in the same update that changes it, rather than reactively via
  // a useEffect watching `view` — updating one state from another inside an effect causes an
  // extra cascading render on every navigation; doing both together in the event handler that
  // actually causes the change doesn't.
  const setView = useCallback((v: View) => {
    setViewRaw(v);
    setVisited((prev) => (prev.has(v) ? prev : new Set(prev).add(v)));
  }, []);

  const refreshHistoryCount = useCallback(() => {
    invoke<number>("history_count")
      .then(setHistoryCount)
      .catch(() => setHistoryCount(null));
  }, []);

  const refreshMonitoringStatus = useCallback(() => {
    invoke<MonitoringStatus>("monitoring_get_status")
      .then((s) => setMonitoringEnabled(s.enabled))
      .catch(() => setMonitoringEnabled(null));
  }, []);

  useEffect(() => {
    refreshHistoryCount();
    refreshMonitoringStatus();
    // Every background tick both adds to history (if it found something new) and can
    // flip enabled/disabled indirectly via nothing here — but it always means "recheck
    // both," since a tick is the one event that can change either.
    const unlistenPromise = listen("monitoring:tick", () => {
      refreshHistoryCount();
      refreshMonitoringStatus();
    });
    const poll = setInterval(refreshMonitoringStatus, 5000);
    return () => {
      clearInterval(poll);
      unlistenPromise.then((unlisten) => unlisten());
    };
  }, [refreshHistoryCount, refreshMonitoringStatus]);

  return (
    <TooltipProvider>
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
            {/* Mounted once first visited, then kept alive and just hidden on every later
                switch away — see the `visited` state above for why this isn't the more
                obvious `{view === "x" && <X/>}` pattern. */}
            {visited.has("dashboard") && (
              <div className={cn("h-full", view !== "dashboard" && "hidden")}>
                <Dashboard onScanComplete={refreshHistoryCount} onNavigate={setView} />
              </div>
            )}
            {visited.has("threats") && (
              <div className={cn("h-full", view !== "threats" && "hidden")}>
                <ThreatsView />
              </div>
            )}
            {visited.has("rules") && (
              <div className={cn("h-full", view !== "rules" && "hidden")}>
                <RulesView />
              </div>
            )}
            {visited.has("compliance") && (
              <div className={cn("h-full", view !== "compliance" && "hidden")}>
                <ComplianceView />
              </div>
            )}
            {visited.has("history") && (
              <div className={cn("h-full", view !== "history" && "hidden")}>
                <HistoryView />
              </div>
            )}
            {visited.has("monitoring") && (
              <div className={cn("h-full", view !== "monitoring" && "hidden")}>
                <MonitoringView />
              </div>
            )}
            {visited.has("about") && (
              <div className={cn("h-full", view !== "about" && "hidden")}>
                <AboutView />
              </div>
            )}
          </main>
        </div>
      </div>
    </TooltipProvider>
  );
}
