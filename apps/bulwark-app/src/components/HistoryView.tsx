import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AlertTriangle, ShieldAlert } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
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
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  const time = d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  return sameDay
    ? `Today, ${time}`
    : `${d.toLocaleDateString(undefined, { month: "short", day: "numeric" })}, ${time}`;
}

export function HistoryView() {
  const [runs, setRuns] = useState<ScanRunSummary[] | null>(null);

  useEffect(() => {
    invoke<ScanRunSummary[]>("history_list").then(setRuns);
  }, []);

  const maxFindings = Math.max(1, ...(runs?.map((r) => r.total_findings) ?? [1]));

  return (
    <ScrollArea className="h-full">
      <div className="mx-auto max-w-4xl px-8 py-6">
        <h2 className="text-lg font-semibold">History</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Every scan run this host has recorded — manual scans and background monitoring ticks alike — so you
          can see whether an issue just appeared or has been open for a while.
        </p>

        {runs && runs.length === 0 && (
          <Card className="mt-6 p-6 text-center text-sm text-muted-foreground">
            No scans recorded yet. Run a scan from the Dashboard to start building history.
          </Card>
        )}

        {runs && runs.length > 0 && (
          <Card className="mt-6 gap-0 divide-y divide-border overflow-hidden p-0">
            {runs.map((run) => (
              <div key={run.id} className="flex items-center gap-3 px-3 py-2.5">
                <div className="w-28 shrink-0 font-mono text-xs text-muted-foreground">
                  {formatWhen(run.started_at)}
                </div>
                <div className="h-1.5 min-w-0 flex-1 rounded-full bg-muted">
                  <div
                    className={cn(
                      "h-full rounded-full",
                      run.total_findings === 0 ? "bg-[var(--sev-resolved)]" : "bg-destructive",
                    )}
                    style={{ width: `${Math.max(6, (run.total_findings / maxFindings) * 100)}%` }}
                  />
                </div>
                <span className="w-24 shrink-0 text-right font-mono text-xs text-muted-foreground">
                  {run.total_findings} finding{run.total_findings === 1 ? "" : "s"}
                </span>
                <div className="flex w-16 shrink-0 justify-end gap-1">
                  {run.privileged_collectors_skipped.length > 0 && (
                    <Badge
                      variant="outline"
                      title={`Privileged checks skipped: ${run.privileged_collectors_skipped.join(", ")}`}
                      className="gap-1 px-1.5 text-[10px] text-muted-foreground"
                    >
                      <ShieldAlert className="h-3 w-3" />
                    </Badge>
                  )}
                  {(run.rules_failed > 0 || run.collectors_failed > 0) && (
                    <Badge
                      variant="outline"
                      title={`${run.rules_failed} rule error(s), ${run.collectors_failed} collector error(s)`}
                      className="gap-1 px-1.5 text-[10px] text-amber-500"
                    >
                      <AlertTriangle className="h-3 w-3" />
                    </Badge>
                  )}
                </div>
              </div>
            ))}
          </Card>
        )}
      </div>
    </ScrollArea>
  );
}
