import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { PageShell, SectionLabel } from "@/components/PageShell";
import { SEVERITY_ORDER, SeverityDot, railStyle, type Severity } from "@/components/Severity";
import { useRevision } from "@/lib/revision";
import { cn } from "@/lib/utils";

interface ScanRunSummary {
  id: string;
  started_at: string;
  total_findings: number;
}

interface Finding {
  rule_id: string;
  severity: Severity;
}

interface DashboardSnapshot {
  findings: Finding[];
  suppressedFindings: Finding[];
  meta: { started_at: string } | null;
}

const scanOf = (id: string) =>
  id.startsWith("BLWK-AI-") ? "Agent Security" : id.startsWith("BLWK-FIM-") ? "File integrity" : "Compliance";

function shortWhen(iso: string): string {
  const d = new Date(iso);
  const today = d.toDateString() === new Date().toDateString();
  const time = d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  return today
    ? `Today ${time}`
    : `${d.toLocaleDateString(undefined, { month: "short", day: "numeric" })} ${time}`;
}

/**
 * Trends over time. The point of a security tool isn't the number today — it's the direction:
 * whether this host is getting cleaner or drifting, and how much accepted risk has quietly
 * accumulated. Built entirely from what the store already records (per-scan finding counts and the
 * current open/accepted split), so it costs nothing extra to keep.
 */
export function AnalyticsView() {
  const { revision } = useRevision();
  const [runs, setRuns] = useState<ScanRunSummary[] | null>(null);
  const [snap, setSnap] = useState<DashboardSnapshot | null>(null);

  useEffect(() => {
    invoke<ScanRunSummary[]>("history_list")
      .then(setRuns)
      .catch(() => setRuns([]));
    invoke<DashboardSnapshot>("dashboard_snapshot")
      .then(setSnap)
      .catch(() => setSnap(null));
  }, [revision]);

  // history_list is newest-first; a trend reads left-to-right oldest-to-newest.
  const trend = useMemo(() => (runs ? [...runs].reverse() : []), [runs]);
  const open = snap?.findings ?? [];
  const accepted = snap?.suppressedFindings ?? [];

  const severityCounts = useMemo(
    () =>
      SEVERITY_ORDER.map((sev) => ({ sev, count: open.filter((f) => f.severity === sev).length })).filter(
        (c) => c.count > 0,
      ),
    [open],
  );

  const byScanner = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of open) m.set(scanOf(f.rule_id), (m.get(scanOf(f.rule_id)) ?? 0) + 1);
    return ["Compliance", "Agent Security", "File integrity"].map((k) => ({
      label: k,
      count: m.get(k) ?? 0,
    }));
  }, [open]);

  const maxRun = Math.max(1, ...trend.map((r) => r.total_findings));
  const latest = trend.length > 0 ? trend[trend.length - 1].total_findings : null;
  const prev = trend.length > 1 ? trend[trend.length - 2].total_findings : null;
  const delta = latest !== null && prev !== null ? latest - prev : null;

  const empty = runs !== null && runs.length === 0;

  return (
    <PageShell
      title="Analytics"
      description="How this host's security posture is trending over time — findings per scan, what's open now, and how much risk you've accepted — drawn from every scan Bulwark has recorded."
    >
      {empty ? (
        <div className="rounded-lg border border-dashed border-border py-14 text-center">
          <p className="text-sm font-medium">No scans recorded yet.</p>
          <p className="mt-1 text-sm text-muted-foreground">Run a scan from the Overview to start a trend.</p>
        </div>
      ) : (
        <div className="flex flex-col gap-8">
          {/* Headline figures. */}
          <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
            <StatTile label="Open now" value={open.length} tone={open.length > 0 ? "critical" : "resolved"} />
            <StatTile label="Accepted risk" value={accepted.length} tone="info" />
            <StatTile label="Scans recorded" value={runs?.length ?? 0} tone="info" />
            <StatTile
              label="Since last scan"
              value={delta === null ? "—" : delta > 0 ? `+${delta}` : `${delta}`}
              tone={delta === null || delta === 0 ? "info" : delta > 0 ? "critical" : "resolved"}
            />
          </div>

          {/* Findings over time — one bar per recorded scan, oldest to newest. */}
          <section>
            <SectionLabel>Findings over time</SectionLabel>
            <div className="rounded-lg border border-border bg-card px-4 py-4">
              <div className="flex h-36 items-end gap-[3px]">
                {trend.map((r) => {
                  const clean = r.total_findings === 0;
                  return (
                    <div
                      key={r.id}
                      title={`${r.total_findings} finding${r.total_findings === 1 ? "" : "s"} · ${shortWhen(r.started_at)}`}
                      className="min-w-0 flex-1 rounded-sm transition-opacity hover:opacity-80"
                      style={{
                        height: `${Math.max(3, (r.total_findings / maxRun) * 100)}%`,
                        background: clean ? "var(--sev-resolved)" : "var(--sev-critical)",
                        opacity: clean ? 0.55 : 0.85,
                      }}
                    />
                  );
                })}
              </div>
              <div className="mt-2 flex items-center justify-between font-mono text-[10px] text-muted-foreground">
                <span>{trend.length > 0 ? shortWhen(trend[0].started_at) : ""}</span>
                <span>peak {maxRun}</span>
                <span>{trend.length > 0 ? `now ${latest}` : ""}</span>
              </div>
            </div>
          </section>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Current open by severity. */}
            <section>
              <SectionLabel>Open by severity</SectionLabel>
              <div className="overflow-hidden rounded-lg border border-border bg-card">
                {severityCounts.length === 0 ? (
                  <p className="px-4 py-6 text-center text-sm text-muted-foreground">Nothing open — clean.</p>
                ) : (
                  severityCounts.map(({ sev, count }, i) => (
                    <div
                      key={sev}
                      style={railStyle(sev)}
                      className={cn(
                        "rail flex items-center gap-2.5 py-2.5 pr-3",
                        i > 0 && "border-t border-border",
                      )}
                    >
                      <SeverityDot severity={sev} />
                      <span className="flex-1 text-sm capitalize">{sev}</span>
                      <span className="font-mono text-sm font-semibold tabular-nums">{count}</span>
                    </div>
                  ))
                )}
              </div>
            </section>

            {/* Current open by scanner. */}
            <section>
              <SectionLabel>Open by scanner</SectionLabel>
              <div className="overflow-hidden rounded-lg border border-border bg-card">
                {byScanner.map(({ label, count }, i) => (
                  <div
                    key={label}
                    style={railStyle(count > 0 ? "critical" : "resolved")}
                    className={cn(
                      "rail flex items-center gap-2.5 py-2.5 pr-3",
                      i > 0 && "border-t border-border",
                    )}
                  >
                    <span className="flex-1 text-sm">{label}</span>
                    <span className="font-mono text-sm font-semibold tabular-nums text-muted-foreground">
                      {count}
                    </span>
                  </div>
                ))}
              </div>
            </section>
          </div>
        </div>
      )}
    </PageShell>
  );
}

function StatTile({
  label,
  value,
  tone,
}: {
  label: string;
  value: number | string;
  tone: "critical" | "resolved" | "info";
}) {
  return (
    <div className="rail rounded-md border border-border bg-card px-3.5 py-3" style={railStyle(tone)}>
      <div
        className="font-heading text-2xl font-semibold tabular-nums"
        style={{ color: `var(--sev-${tone}-fg)` }}
      >
        {value}
      </div>
      <div className="mt-0.5 font-mono text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
        {label}
      </div>
    </div>
  );
}
