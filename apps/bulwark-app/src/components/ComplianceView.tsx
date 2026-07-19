import { useEffect, useMemo, useState } from "react";
import { Channel, invoke } from "@tauri-apps/api/core";
import { Radar, RotateCw, ShieldCheck, Square } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { PageShell, SectionLabel } from "@/components/PageShell";
import { CategoryFindings, groupFindingsByCategory } from "@/components/CategoryFindings";
import { FixAllButton } from "@/components/FixActions";
import { useFixCapabilities } from "@/lib/fixes";
import { type Finding } from "@/components/FindingCard";
import { SEVERITY_ORDER } from "@/components/Severity";
import { useRevision } from "@/lib/revision";

interface RuleSummary {
  id: string;
  category: string;
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

interface ScanRunResult {
  findings: Finding[];
  host_fingerprint: string;
  privileged_collectors_skipped: string[];
  collector_errors: { collector: string; message: string }[];
}

type ScanEvent =
  | { event: "finding"; data: Finding }
  | { event: "collectorError"; data: { collector: string; message: string } }
  | { event: "privilegedSkipped"; data: { collectors: string[] } }
  | { event: "complete"; data: { total_findings: number; host_fingerprint: string; cancelled: boolean } }
  | { event: "error"; data: { message: string } };

const bySeverity = (a: Finding, b: Finding) =>
  SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);

// A finding this tab owns: the configuration rule pack, minus the two engines that have their own
// tabs — the agent scanner (BLWK-AI-) and file integrity (BLWK-FIM-). Excluding FIM here is what
// keeps this tab's count equal to the Overview's Compliance tile and distinct from the File
// integrity tab, so the same issue is never counted in two places.
const isComplianceFinding = (f: Finding) =>
  !f.rule_id.startsWith("BLWK-AI-") && !f.rule_id.startsWith("BLWK-FIM-");

/**
 * The Compliance scan's results: every configuration issue the rule pack found on this host —
 * grouped by subsystem, each with the reason it matters and the exact command to fix it. This is
 * the config engine's detail page (the Overview aggregates it with the other scanners; the Rules
 * tab is the reference catalog and framework mapping). You come here to read and fix.
 */
export function ComplianceView() {
  const { revision, bump, running } = useRevision();
  // True when a compliance scan is running here OR was launched from the Overview — either way this
  // tab shows it live.
  const complianceRunning = running.has("compliance");

  const [rules, setRules] = useState<RuleSummary[] | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [skippedPrivileged, setSkippedPrivileged] = useState<string[]>([]);
  const [errors, setErrors] = useState<string[]>([]);
  const [hasScanned, setHasScanned] = useState(false);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [elevating, setElevating] = useState(false);
  const [privilegedRunDone, setPrivilegedRunDone] = useState(false);
  const [streamed, setStreamed] = useState(false);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const fixCapabilities = useFixCapabilities();

  useEffect(() => {
    invoke<RuleSummary[]>("rules_list")
      .then(setRules)
      .catch(() => setRules(null));
  }, []);

  // Load the last stored results on open and whenever anything writes to disk (a scan here, a
  // background monitoring tick, a redaction elsewhere), rather than showing "not scanned yet" when
  // real results already exist. Skipped while a scan streams — a mid-scan refetch would clobber the
  // findings arriving over the Channel with the previous snapshot.
  useEffect(() => {
    if (scanning) return;
    invoke<DashboardSnapshot>("dashboard_snapshot")
      .then((snap) => {
        if (!snap.meta) return;
        setFindings(snap.findings.filter(isComplianceFinding).sort(bySeverity));
        setSkippedPrivileged(snap.meta.privileged_collectors_skipped);
        setHasScanned(true);
        setStreamed(false);
      })
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `scanning` guards, must not retrigger
  }, [revision]);

  const ruleCategoryById = useMemo(() => {
    const m = new Map<string, string>();
    rules?.forEach((r) => m.set(r.id, r.category));
    return m;
  }, [rules]);

  const grouped = useMemo(
    () => groupFindingsByCategory(findings, (id) => ruleCategoryById.get(id) ?? "other"),
    [findings, ruleCategoryById],
  );

  const toggle = (category: string) =>
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (!next.delete(category)) next.add(category);
      return next;
    });

  function runScan() {
    setScanning(true);
    setHasScanned(true);
    setStreamed(true);
    setFindings([]);
    setSkippedPrivileged([]);
    setErrors([]);
    setPrivilegedRunDone(false);

    const onEvent = new Channel<ScanEvent>();
    onEvent.onmessage = (msg) => {
      switch (msg.event) {
        case "finding":
          // The config engine streams file-integrity findings too; they belong to the File
          // integrity tab, so filter them out here to match the reloaded/aggregated views.
          if (isComplianceFinding(msg.data)) {
            setFindings((prev) => [...prev, msg.data].sort(bySeverity));
          }
          break;
        case "privilegedSkipped":
          setSkippedPrivileged(msg.data.collectors);
          break;
        case "collectorError":
          setErrors((prev) => [...prev, `${msg.data.collector}: ${msg.data.message}`]);
          break;
        case "error":
          setErrors((prev) => [...prev, msg.data.message]);
          setScanning(false);
          break;
        case "complete":
          setScanning(false);
          // Re-read the stored snapshot (and let the Overview count refresh) now it's persisted.
          bump();
          break;
      }
    };
    invoke("scan_start", { onEvent, needs: [] }).catch((e) => {
      setErrors((prev) => [...prev, String(e)]);
      setScanning(false);
    });
  }

  async function stopScan() {
    try {
      await invoke("scan_cancel");
    } catch (e) {
      setErrors((prev) => [...prev, String(e)]);
    }
  }

  /** "Ignore this type of issue" from a finding — suppress the rule (mandatory reason), then bump so
   *  the finding moves to accepted risk everywhere. */
  async function ignoreType(ruleId: string, reason: string) {
    try {
      await invoke("rule_suppress", { ruleId, reason });
      bump();
    } catch (e) {
      setErrors((prev) => [...prev, String(e)]);
    }
  }

  async function runPrivilegedScan() {
    setElevating(true);
    setErrors([]);
    try {
      const result = await invoke<ScanRunResult>("scan_privileged");
      setStreamed(false);
      setFindings(result.findings.filter(isComplianceFinding).sort(bySeverity));
      setSkippedPrivileged(result.privileged_collectors_skipped);
      setErrors(result.collector_errors.map((e) => `${e.collector}: ${e.message}`));
      setPrivilegedRunDone(true);
      bump();
    } catch (e) {
      setErrors((prev) => [...prev, String(e)]);
    } finally {
      setElevating(false);
    }
  }

  return (
    <PageShell
      title="Checkups"
      description="Everything the configuration rule pack found on this host — SSH, sudo, kernel, cron, accounts, logging and more — grouped by subsystem, each with the reason it matters and the exact command to fix it."
      action={
        scanning ? (
          <Button onClick={stopScan} variant="outline" size="sm">
            <Square className="h-3.5 w-3.5 fill-current" />
            Stop
          </Button>
        ) : complianceRunning ? (
          <Button variant="outline" size="sm" disabled>
            <RotateCw className="h-3.5 w-3.5 animate-spin" />
            Scanning…
          </Button>
        ) : (
          <Button onClick={runScan} size="sm">
            <Radar className="h-4 w-4" />
            Run compliance scan
          </Button>
        )
      }
    >
      <div className="flex flex-col gap-6">
        {(scanning || complianceRunning) && (
          <div className="flex items-center gap-2.5 rounded-md border border-border bg-muted/40 px-3 py-2.5">
            <RotateCw className="h-3.5 w-3.5 shrink-0 animate-spin text-muted-foreground" />
            <div className="min-w-0 flex-1 truncate font-mono text-[11px] text-muted-foreground">
              {scanning ? "Scanning configuration…" : "Scanning configuration (started from Overview)…"}
            </div>
          </div>
        )}

        {skippedPrivileged.length > 0 && !privilegedRunDone && (
          <Callout
            tone="warning"
            action={
              <Button variant="outline" size="sm" onClick={runPrivilegedScan} disabled={elevating}>
                {elevating ? "Waiting for authentication…" : "Run privileged checks"}
              </Button>
            }
          >
            <span className="font-medium">
              {skippedPrivileged.length} check{skippedPrivileged.length === 1 ? "" : "s"} need root and were
              skipped.
            </span>{" "}
            <span className="font-mono text-xs opacity-80">{skippedPrivileged.join(", ")}</span>
          </Callout>
        )}

        {errors.map((e, i) => (
          <Callout key={i} tone="critical">
            {e}
          </Callout>
        ))}

        <section>
          {findings.length > 0 && (
            <SectionLabel>
              {findings.length} issue{findings.length === 1 ? "" : "s"} to fix
            </SectionLabel>
          )}

          {findings.length === 0 && !scanning && !loading && (
            <div className="rounded-lg border border-dashed border-border py-14 text-center">
              <ShieldCheck className="mx-auto h-7 w-7 text-muted-foreground/40" strokeWidth={1.5} />
              <p className="mt-3 text-sm font-medium">
                {hasScanned
                  ? "This host passes every configuration check."
                  : "No compliance scan has run yet."}
              </p>
              <p className="mt-1 text-sm text-muted-foreground">
                {hasScanned
                  ? "Every rule that ran came back clean."
                  : "Run a compliance scan to check this host's configuration against the rule pack."}
              </p>
            </div>
          )}

          {findings.some((f) => fixCapabilities.has(f.rule_id)) && (
            <div className="mb-4">
              <FixAllButton onFixed={runScan} />
            </div>
          )}

          <div className="flex flex-col gap-6">
            {grouped.map(({ category, items, worst }) => (
              <CategoryFindings
                key={category}
                category={category}
                items={items}
                worst={worst}
                streamed={streamed}
                collapsed={collapsed.has(category)}
                onToggle={() => toggle(category)}
                actions={{
                  onIgnoreType: ignoreType,
                  onRecheck: runScan,
                  fixCapabilities,
                  onFixed: runScan,
                }}
              />
            ))}
          </div>
        </section>
      </div>
    </PageShell>
  );
}
