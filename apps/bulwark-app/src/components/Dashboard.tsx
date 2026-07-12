import { useEffect, useMemo, useState } from "react";
import { invoke, Channel } from "@tauri-apps/api/core";
import { ShieldAlert, RotateCw, Radar, ListChecks, Check, AlertCircle, Bug, BadgeCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { SeverityBadge, type Severity } from "@/components/SeverityBadge";
import { StatusHero, type ProtectionStatus } from "@/components/StatusHero";
import type { View } from "@/components/Sidebar";
import { cn } from "@/lib/utils";

interface Finding {
  id: string;
  rule_id: string;
  severity: Severity;
  title: string;
  explanation: string;
  fix_hint: string;
}

interface RuleSummary {
  id: string;
  category: string;
  references: string[];
}

interface MonitoringStatus {
  enabled: boolean;
}

interface LatestScanMeta {
  host_fingerprint: string;
  started_at: string;
  privileged_collectors_skipped: string[];
}

interface DashboardSnapshot {
  findings: Finding[];
  meta: LatestScanMeta | null;
}

type ScanEvent =
  | { event: "finding"; data: Finding }
  | { event: "collectorError"; data: { collector: string; message: string } }
  | { event: "privilegedSkipped"; data: { collectors: string[] } }
  | { event: "complete"; data: { total_findings: number; host_fingerprint: string } }
  | { event: "error"; data: { message: string } };

interface ScanRunResult {
  findings: Finding[];
  host_fingerprint: string;
  privileged_collectors_skipped: string[];
  collector_errors: { collector: string; message: string }[];
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function categoryLabel(category: string): string {
  return category.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function Dashboard({
  onScanComplete,
  onNavigate,
}: {
  onScanComplete: () => void;
  onNavigate: (view: View) => void;
}) {
  const [scanning, setScanning] = useState(false);
  const [elevating, setElevating] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [skippedPrivileged, setSkippedPrivileged] = useState<string[]>([]);
  const [errors, setErrors] = useState<string[]>([]);
  const [lastHost, setLastHost] = useState<string | null>(null);
  const [privilegedRunDone, setPrivilegedRunDone] = useState(false);
  const [hasScanned, setHasScanned] = useState(false);
  const [loadingSnapshot, setLoadingSnapshot] = useState(true);
  const [rules, setRules] = useState<RuleSummary[] | null>(null);
  const [monitoringOn, setMonitoringOn] = useState<boolean | null>(null);

  useEffect(() => {
    invoke<MonitoringStatus>("monitoring_get_status")
      .then((s) => setMonitoringOn(s.enabled))
      .catch(() => setMonitoringOn(null));
  }, []);

  // On open, load whatever Bulwark already knows — a manual scan from an earlier session
  // or a background monitoring tick — instead of presenting an empty "not scanned yet"
  // dashboard when real results already exist. This is the fix for a real bug: the
  // sidebar's own scan count proved data existed while the dashboard showed nothing,
  // because it only ever reflected the current session's own button clicks.
  useEffect(() => {
    invoke<DashboardSnapshot>("dashboard_snapshot")
      .then((snap) => {
        if (snap.meta) {
          setFindings([...snap.findings].sort(bySeverity));
          setLastHost(snap.meta.host_fingerprint);
          setSkippedPrivileged(snap.meta.privileged_collectors_skipped);
          setHasScanned(true);
        }
      })
      .finally(() => setLoadingSnapshot(false));

    invoke<RuleSummary[]>("rules_list")
      .then(setRules)
      .catch(() => setRules(null));
  }, []);

  const ruleCategoryById = useMemo(() => {
    const map = new Map<string, string>();
    rules?.forEach((r) => map.set(r.id, r.category));
    return map;
  }, [rules]);

  const categories = useMemo(() => {
    if (!rules) return [];
    const cats = Array.from(new Set(rules.map((r) => r.category))).sort();
    return cats.map((category) => {
      const issues = findings.filter((f) => ruleCategoryById.get(f.rule_id) === category);
      const worst = SEVERITY_ORDER.find((sev) => issues.some((f) => f.severity === sev)) ?? null;
      return { category, issueCount: issues.length, worst };
    });
  }, [rules, findings, ruleCategoryById]);

  const compliance = useMemo(() => {
    const mapped = rules?.filter((r) => r.references.length > 0) ?? [];
    if (mapped.length === 0) return null;
    const openIds = new Set(findings.map((f) => f.rule_id));
    const passing = mapped.filter((r) => !openIds.has(r.id)).length;
    return { passing, total: mapped.length };
  }, [rules, findings]);

  async function runPrivilegedScan() {
    setElevating(true);
    setErrors([]);
    try {
      const result = await invoke<ScanRunResult>("scan_privileged");
      setFindings([...result.findings].sort(bySeverity));
      setSkippedPrivileged(result.privileged_collectors_skipped);
      setErrors(result.collector_errors.map((e) => `${e.collector}: ${e.message}`));
      setLastHost(result.host_fingerprint);
      setPrivilegedRunDone(true);
    } catch (e) {
      setErrors((prev) => [...prev, String(e)]);
    } finally {
      setElevating(false);
    }
  }

  async function runScan() {
    setScanning(true);
    setHasScanned(true);
    setFindings([]);
    setSkippedPrivileged([]);
    setErrors([]);
    setPrivilegedRunDone(false);

    const onEvent = new Channel<ScanEvent>();
    onEvent.onmessage = (msg) => {
      switch (msg.event) {
        case "finding":
          setFindings((prev) => [...prev, msg.data].sort(bySeverity));
          break;
        case "privilegedSkipped":
          setSkippedPrivileged(msg.data.collectors);
          break;
        case "collectorError":
          setErrors((prev) => [...prev, `${msg.data.collector}: ${msg.data.message}`]);
          break;
        case "error":
          setErrors((prev) => [...prev, msg.data.message]);
          break;
        case "complete":
          setLastHost(msg.data.host_fingerprint);
          setScanning(false);
          onScanComplete();
          break;
      }
    };

    try {
      await invoke("scan_start", { onEvent });
    } catch (e) {
      setErrors((prev) => [...prev, String(e)]);
      setScanning(false);
    }
  }

  const counts = SEVERITY_ORDER.map((sev) => ({
    sev,
    count: findings.filter((f) => f.severity === sev).length,
  }));

  const status: ProtectionStatus = scanning
    ? "scanning"
    : loadingSnapshot
      ? "idle"
      : !hasScanned
        ? "idle"
        : findings.some((f) => f.severity === "critical" || f.severity === "high")
          ? "critical"
          : findings.length > 0
            ? "warning"
            : "clean";

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* Last checked already carries the hostname/kernel (see lastScanLabel below), so
          there's no separate metadata row repeating them — that duplication was the biggest
          single space cost in the old vertical hero, shown twice in two different formats. */}
      <div className="flex shrink-0 items-center justify-between gap-4 border-b border-border bg-muted/30 px-8 py-4">
        <StatusHero status={status} lastScanLabel={lastHost ? `Last checked ${lastHost}` : null} />
        <div className="flex shrink-0 items-center gap-4">
          {rules && (
            <span className="hidden items-center gap-1 font-mono text-[11px] text-muted-foreground md:flex">
              <ListChecks className="h-3 w-3" />
              {rules.length} rules · {categories.length} categories
            </span>
          )}
          <Button onClick={runScan} disabled={scanning} size="sm">
            {scanning ? <RotateCw className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
            {scanning ? "Scanning…" : "Run a scan"}
          </Button>
        </div>
      </div>

      {/* One shared gap for this whole non-scrolling header stack, so the rhythm between
          blocks stays identical regardless of which optional pieces (stats, banners) are
          showing — previously each block set its own pb/pt/mb and the gap visibly changed
          depending on `hasScanned` and whether a banner was present. */}
      <div className="flex shrink-0 flex-col gap-3 px-8 py-4">
        {hasScanned && (
          <Card className="flex-row items-stretch gap-0 divide-x divide-border p-0">
            {counts.map(({ sev, count }) => (
              <div key={sev} className="flex flex-1 items-center justify-center gap-2 px-3 py-2.5">
                <span className="font-mono text-lg font-semibold tabular-nums">{count}</span>
                <SeverityBadge severity={sev} />
              </div>
            ))}
          </Card>
        )}

        {/* Ties the app's other pillars back into the one screen people actually land on —
            without this, Threats/Compliance/Monitoring are invisible unless you already know
            to go looking for them in the sidebar. */}
        <div className="grid grid-cols-3 gap-4">
          <button onClick={() => onNavigate("threats")} className="text-left">
            <Card className="flex-row items-center gap-3 p-4 transition-colors hover:bg-accent">
              <Bug className="h-4 w-4 shrink-0 text-muted-foreground" />
              <div className="min-w-0">
                <div className="text-xs text-muted-foreground">Antivirus</div>
                <div className="truncate text-sm font-medium">Run a virus scan</div>
              </div>
            </Card>
          </button>
          <button onClick={() => onNavigate("compliance")} className="text-left">
            <Card className="flex-row items-center gap-3 p-4 transition-colors hover:bg-accent">
              <BadgeCheck className="h-4 w-4 shrink-0 text-muted-foreground" />
              <div className="min-w-0">
                <div className="text-xs text-muted-foreground">Compliance</div>
                <div className="truncate font-mono text-sm font-medium">
                  {compliance ? `${compliance.passing}/${compliance.total} passing` : "Not mapped yet"}
                </div>
              </div>
            </Card>
          </button>
          <button onClick={() => onNavigate("monitoring")} className="text-left">
            <Card className="flex-row items-center gap-3 p-4 transition-colors hover:bg-accent">
              <Radar
                className={cn("h-4 w-4 shrink-0", monitoringOn ? "text-primary" : "text-muted-foreground")}
              />
              <div className="min-w-0">
                <div className="text-xs text-muted-foreground">Monitoring</div>
                <div className="truncate text-sm font-medium">
                  {monitoringOn === null ? "—" : monitoringOn ? "Active" : "Paused"}
                </div>
              </div>
            </Card>
          </button>
        </div>

        {skippedPrivileged.length > 0 && !privilegedRunDone && (
          <div className="flex items-center gap-2 rounded-lg border border-[var(--sev-medium)]/30 bg-[var(--sev-medium)]/10 px-3 py-2 text-sm text-[var(--sev-medium)]">
            <ShieldAlert className="h-4 w-4 shrink-0" />
            <span className="flex-1">
              {skippedPrivileged.length} check(s) skipped (no privilege): {skippedPrivileged.join(", ")}
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={runPrivilegedScan}
              disabled={elevating}
              className="h-7"
            >
              {elevating ? "Waiting for authentication…" : "Run privileged checks"}
            </Button>
          </div>
        )}

        {errors.map((e, i) => (
          <div
            key={i}
            className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive"
          >
            {e}
          </div>
        ))}
      </div>

      <Separator />

      <ScrollArea className="min-h-0 flex-1">
        <div className="flex flex-col gap-6 px-8 py-6">
          {categories.length > 0 && (
            <div>
              <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Protection modules
              </h3>
              <div className="grid grid-cols-3 gap-4">
                {categories.map(({ category, issueCount, worst }) => (
                  <Card key={category} className="flex-row items-center gap-3 p-4">
                    {issueCount === 0 ? (
                      <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-[var(--sev-resolved)]/15 text-[var(--sev-resolved)]">
                        <Check className="h-3.5 w-3.5" strokeWidth={2.5} />
                      </div>
                    ) : (
                      <div
                        className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-white"
                        style={{ backgroundColor: `var(--sev-${worst})` }}
                      >
                        <AlertCircle className="h-3.5 w-3.5" strokeWidth={2.5} />
                      </div>
                    )}
                    <div className="min-w-0">
                      <div className="truncate text-sm font-medium">{categoryLabel(category)}</div>
                      <div className="text-xs text-muted-foreground">
                        {issueCount === 0 ? "No issues" : `${issueCount} issue${issueCount === 1 ? "" : "s"}`}
                      </div>
                    </div>
                  </Card>
                ))}
              </div>
            </div>
          )}

          <div className="flex flex-col gap-3">
            {findings.length > 0 && (
              <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Findings
              </h3>
            )}
            {findings.length === 0 && !scanning && !loadingSnapshot && (
              <Card className="flex flex-col items-center gap-2 p-10 text-center text-muted-foreground">
                <Radar className="h-8 w-8 opacity-40" />
                <p className="text-sm">
                  {hasScanned ? "No findings on the last scan." : "Run a scan to check this host."}
                </p>
              </Card>
            )}
            {findings.map((f) => (
              <Card key={f.id} className={cn("finding-enter flex-row items-start gap-3 p-4")}>
                <SeverityBadge severity={f.severity} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-medium">{f.title}</h3>
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {f.rule_id}
                    </Badge>
                  </div>
                  <p className="mt-1 text-sm text-muted-foreground">{f.explanation}</p>
                  <div className="mt-2 rounded-md bg-muted px-2.5 py-1.5 font-mono text-xs">{f.fix_hint}</div>
                </div>
              </Card>
            ))}
          </div>
        </div>
      </ScrollArea>
    </div>
  );
}

function bySeverity(a: Finding, b: Finding) {
  return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
}
