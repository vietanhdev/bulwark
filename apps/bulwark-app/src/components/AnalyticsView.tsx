import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AlertTriangle, Check, ShieldAlert } from "lucide-react";
import { PageShell, SectionLabel } from "@/components/PageShell";
import { SEVERITY_ORDER, SeverityDot, railStyle, severityLabel, type Severity } from "@/components/Severity";
import { useRevision } from "@/lib/revision";
import { cn } from "@/lib/utils";

interface ScanRunSummary {
  id: string;
  started_at: string;
  total_findings: number;
  rules_failed: number;
  collectors_failed: number;
  privileged_collectors_skipped: string[];
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
  // Memoized so the derived useMemos below don't see a new array identity every render.
  const open = useMemo(() => snap?.findings ?? [], [snap]);
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
      title="Activity"
      description="How this host's security posture is trending over time — findings per scan, what's open now, how much risk you've accepted, and the full scan-by-scan history — drawn from every scan Bulwark has recorded."
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

          {/* Findings over time — one bar per recorded scan, oldest to newest. Bars are width-capped
              and the row is centered, so a handful of scans reads as a few slim bars rather than a
              wall of giant blocks, while a long history still fills the width. Height carries the
              magnitude; colour stays calm (brand accent for findings, green for a clean scan) so this
              reads as a trend, not an alarm — severity lives in "Open by severity" below. */}
          <section>
            <SectionLabel>Findings over time</SectionLabel>
            <div className="rounded-lg border border-border bg-card px-4 pt-5 pb-4">
              <div className="relative flex h-36 items-end justify-center gap-[3px] border-b border-border">
                {trend.map((r, i) => {
                  const clean = r.total_findings === 0;
                  const isLast = i === trend.length - 1;
                  const showLabels = trend.length <= 16;
                  return (
                    <div
                      key={r.id}
                      title={`${r.total_findings} finding${r.total_findings === 1 ? "" : "s"} · ${shortWhen(r.started_at)}`}
                      className="flex h-full min-w-0 max-w-[52px] flex-1 flex-col justify-end"
                    >
                      {showLabels && (
                        <span
                          className={cn(
                            "mb-1 text-center font-mono text-[10px] tabular-nums",
                            isLast ? "font-semibold" : "text-muted-foreground",
                          )}
                          style={
                            isLast
                              ? { color: clean ? "var(--sev-resolved-fg)" : "var(--primary)" }
                              : undefined
                          }
                        >
                          {r.total_findings}
                        </span>
                      )}
                      <div
                        className="rounded-t-sm transition-opacity hover:opacity-100"
                        style={{
                          height: `${Math.max(2, (r.total_findings / maxRun) * 100)}%`,
                          background: clean ? "var(--sev-resolved)" : "var(--primary)",
                          opacity: isLast ? 1 : clean ? 0.5 : 0.6,
                        }}
                      />
                    </div>
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
                      <span className="flex-1 text-sm">{severityLabel(sev)}</span>
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

          {/* The per-scan timeline — every run this host recorded, newest first, with the change
              from the previous scan so you can tell whether an issue just appeared or has been
              open for a while. (Folded in from what used to be a separate History tab.) */}
          <section>
            <SectionLabel>Scan history</SectionLabel>
            <div className="overflow-hidden rounded-lg border border-border bg-card">
              {(runs ?? []).map((run, i) => {
                const clean = run.total_findings === 0;
                const older = (runs ?? [])[i + 1];
                const d = older ? run.total_findings - older.total_findings : null;
                return (
                  <div
                    key={run.id}
                    style={railStyle(clean ? "resolved" : "critical")}
                    className={cn(
                      "rail rail-dim flex items-center gap-3 py-3 pr-3",
                      i > 0 && "border-t border-border",
                    )}
                  >
                    <span className="w-28 shrink-0 font-mono text-xs text-muted-foreground">
                      {shortWhen(run.started_at)}
                    </span>
                    {clean ? (
                      <Check
                        className="h-4 w-4 shrink-0"
                        style={{ color: "var(--sev-resolved-fg)" }}
                        strokeWidth={2.5}
                      />
                    ) : (
                      <span
                        className="h-2 w-2 shrink-0 rounded-full"
                        style={{ background: "var(--sev-critical)" }}
                      />
                    )}
                    <span className="min-w-0 flex-1 text-sm">
                      <span className="font-mono font-semibold tabular-nums">{run.total_findings}</span>
                      <span className="text-muted-foreground">
                        {" "}
                        finding{run.total_findings === 1 ? "" : "s"}
                      </span>
                      {d !== null && d !== 0 && (
                        <span
                          className="ml-2 font-mono text-[11px] tabular-nums"
                          style={{ color: `var(--sev-${d > 0 ? "critical" : "resolved"}-fg)` }}
                          title="Change from the previous scan"
                        >
                          {d > 0 ? `+${d}` : d}
                        </span>
                      )}
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
          </section>
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
