import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AlertTriangle, ShieldAlert } from "lucide-react";
import { PageShell } from "@/components/PageShell";
import { railStyle } from "@/components/Severity";
import { useRevision } from "@/lib/revision";
import { cn } from "@/lib/utils";

interface ScanRunSummary {
  id: string;
  started_at: string;
  finished_at: string | null;
  host_fingerprint: string;
  rules_loaded: number;
  rules_failed: number;
  collectors_failed: number;
  privileged_collectors_skipped: string[];
  total_findings: number;
}

function formatWhen(iso: string): string {
  const d = new Date(iso);
  const time = d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  return d.toDateString() === new Date().toDateString()
    ? `Today ${time}`
    : `${d.toLocaleDateString(undefined, { month: "short", day: "numeric" })} ${time}`;
}

export function HistoryView() {
  const { revision } = useRevision();
  const [runs, setRuns] = useState<ScanRunSummary[] | null>(null);

  // Re-reads on every revision bump. This view is mounted for the life of the process (see
  // App.tsx), and used to fetch exactly once — so a scan run after you'd visited History never
  // appeared here until the app was restarted, even though the sidebar's own scan counter
  // dutifully ticked up.
  useEffect(() => {
    invoke<ScanRunSummary[]>("history_list").then(setRuns);
  }, [revision]);

  const maxFindings = useMemo(() => Math.max(1, ...(runs?.map((r) => r.total_findings) ?? [1])), [runs]);

  return (
    <PageShell
      title="History"
      description="Every scan this host has recorded — manual runs and background monitoring ticks alike — so you can tell whether an issue just appeared or has been open for weeks."
    >
      {runs?.length === 0 && (
        <div className="rounded-lg border border-dashed border-border py-14 text-center">
          <p className="text-sm font-medium">No scans recorded yet.</p>
          <p className="mt-1 text-sm text-muted-foreground">
            Run a scan from the Overview to start building a history.
          </p>
        </div>
      )}

      {runs && runs.length > 0 && (
        <div className="overflow-hidden rounded-lg border border-border bg-card">
          {runs.map((run, i) => {
            const clean = run.total_findings === 0;
            return (
              <div
                key={run.id}
                style={railStyle(clean ? "resolved" : "critical")}
                className={cn(
                  "rail rail-dim flex items-center gap-3 py-2.5 pr-3",
                  i > 0 && "border-t border-border",
                )}
              >
                <span className="w-28 shrink-0 font-mono text-xs text-muted-foreground">
                  {formatWhen(run.started_at)}
                </span>

                {/* The bar is the point of this page: scanning the column tells you at a glance
                    whether things have been getting better or worse, without reading a number. */}
                <span className="h-1.5 min-w-0 flex-1 overflow-hidden rounded-full bg-muted">
                  <span
                    className="block h-full rounded-full"
                    style={{
                      width: `${Math.max(4, (run.total_findings / maxFindings) * 100)}%`,
                      background: `var(--sev-${clean ? "resolved" : "critical"})`,
                    }}
                  />
                </span>

                <span className="w-24 shrink-0 text-right font-mono text-xs text-muted-foreground tabular-nums">
                  {run.total_findings} finding{run.total_findings === 1 ? "" : "s"}
                </span>

                <span className="flex w-12 shrink-0 justify-end gap-1">
                  {run.privileged_collectors_skipped.length > 0 && (
                    <span
                      title={`Privileged checks skipped: ${run.privileged_collectors_skipped.join(", ")}`}
                      className="text-muted-foreground"
                    >
                      <ShieldAlert className="h-3.5 w-3.5" />
                    </span>
                  )}
                  {(run.rules_failed > 0 || run.collectors_failed > 0) && (
                    <span
                      title={`${run.rules_failed} rule error(s), ${run.collectors_failed} collector error(s)`}
                      style={{ color: "var(--sev-medium-fg)" }}
                    >
                      <AlertTriangle className="h-3.5 w-3.5" />
                    </span>
                  )}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </PageShell>
  );
}
