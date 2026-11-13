import { useEffect, useMemo, useState } from "react";
import { Channel, invoke } from "@tauri-apps/api/core";
import { ChevronRight, Radar, RotateCw, Square } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { TaskActivity } from "@/components/TaskActivity";
import { PageShell, SectionLabel } from "@/components/PageShell";
import { CategoryFindings, groupFindingsByCategory } from "@/components/CategoryFindings";
import { FixAllButton } from "@/components/FixActions";
import { useFixCapabilities } from "@/lib/fixes";
import { type Finding } from "@/components/FindingCard";
import { RedactButton } from "@/components/RedactButton";
import { SshKeyProtect } from "@/components/SshKeyProtect";
import { withLocation } from "@/lib/findings";
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
  collector_errors: { collector: string; message: string; skipped?: boolean }[];
}

type ScanEvent =
  | { event: "finding"; data: Finding }
  | { event: "collectorError"; data: { collector: string; message: string; skipped?: boolean } }
  | { event: "privilegedSkipped"; data: { collectors: string[] } }
  | { event: "complete"; data: { total_findings: number; host_fingerprint: string; cancelled: boolean } }
  | { event: "error"; data: { message: string } };

const bySeverity = (a: Finding, b: Finding) =>
  SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);

// A finding this tab owns: every Checkups issue, AI assistant checks included, minus file integrity
// (BLWK-FIM-), which has its own tab, so the same issue is never counted in two places.
const isComplianceFinding = (f: Finding) => !f.rule_id.startsWith("BLWK-FIM-");

/**
 * The Compliance scan's results: every configuration issue the rule pack found on this host —
 * grouped by subsystem, each with the reason it matters and the exact command to fix it. This is
 * the config engine's detail page (the Overview aggregates it with the other scanners; the Rules
 * tab is the reference catalog and framework mapping). You come here to read and fix.
 */
export function ComplianceView({ active }: { active: boolean }) {
  const [scope, setScope] = useState<"developer" | "all">("developer");
  const { revision, bump, running } = useRevision();
  // True when a compliance scan is running here OR was launched from the Overview — either way this
  // tab shows it live.
  const complianceRunning = running.has("compliance");

  const [rules, setRules] = useState<RuleSummary[] | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [skippedPrivileged, setSkippedPrivileged] = useState<string[]>([]);
  const [errors, setErrors] = useState<string[]>([]);
  const [unreadFiles, setUnreadFiles] = useState<string[]>([]);
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
        setFindings(snap.findings.filter(isComplianceFinding).map(withLocation).sort(bySeverity));
        setSkippedPrivileged(snap.meta.privileged_collectors_skipped);
        setHasScanned(true);
        setStreamed(false);
      })
      .catch(() => setErrors((prev) => [...prev, "Could not load saved scan results. Run the check again."]))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `scanning` guards, must not retrigger
  }, [revision]);

  const ruleCategoryById = useMemo(() => {
    const m = new Map<string, string>();
    rules?.forEach((r) => m.set(r.id, r.category));
    return m;
  }, [rules]);

  const visibleFindings = useMemo(
    () =>
      scope === "all"
        ? findings
        : findings.filter((f) => /^(BLWK-DEV-|BLWK-SSH-|BLWK-CRED-|BLWK-AI-)/.test(f.rule_id)),
    [findings, scope],
  );
  const grouped = useMemo(
    () => groupFindingsByCategory(visibleFindings, (id) => ruleCategoryById.get(id) ?? "other"),
    [visibleFindings, ruleCategoryById],
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
    setUnreadFiles([]);
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
          if (msg.data.skipped) setUnreadFiles((prev) => [...prev, msg.data.message]);
          else setErrors((prev) => [...prev, `${msg.data.collector}: ${msg.data.message}`]);
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

  async function ignorePlace(ruleId: string, location: string, reason: string) {
    try {
      await invoke("finding_ignore", { ruleId, location, reason });
      bump();
    } catch (e) {
      setErrors((prev) => [...prev, String(e)]);
    }
  }

  async function runPrivilegedScan() {
    setElevating(true);
    setErrors([]);
    setUnreadFiles([]);
    try {
      const result = await invoke<ScanRunResult>("scan_privileged");
      setStreamed(false);
      // The privileged run re-checks system settings only; keep the AI assistant findings already shown.
      setFindings((prev) =>
        [
          ...prev.filter((f) => f.rule_id.startsWith("BLWK-AI-")),
          ...result.findings.filter(isComplianceFinding),
        ].sort(bySeverity),
      );
      setSkippedPrivileged(result.privileged_collectors_skipped);
      // As on Scan: a file that could not be read is a note about a skipped check, not a failure.
      setErrors(result.collector_errors.filter((e) => !e.skipped).map((e) => `${e.collector}: ${e.message}`));
      setUnreadFiles(result.collector_errors.filter((e) => e.skipped).map((e) => e.message));
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
      title="Configuration"
      description="Developer settings, SSH and credential hygiene. Expand a finding for context and fixes."
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
            Check configuration
          </Button>
        )
      }
    >
      <div className="flex flex-col gap-6">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-3">
          <div className="flex gap-1" aria-label="Finding scope">
            {(["developer", "all"] as const).map((value) => (
              <Button
                key={value}
                size="sm"
                variant={scope === value ? "secondary" : "ghost"}
                aria-pressed={scope === value}
                onClick={() => setScope(value)}
              >
                {value === "developer" ? "Developer focus" : "All configuration"}
              </Button>
            ))}
          </div>
          <span className="text-xs text-muted-foreground">
            {visibleFindings.length} shown · {findings.length} total findings
          </span>
        </div>
        <details className="credential-disclosure text-xs text-muted-foreground">
          <summary className="flex w-fit cursor-pointer list-none items-center gap-1.5 rounded focus-visible:outline-2 focus-visible:outline-primary">
            <ChevronRight className="disclosure-chevron size-3.5" aria-hidden="true" />
            What gets checked?
          </summary>
          <p className="mt-2 max-w-2xl leading-relaxed">
            Check configuration runs the host rule pack, including Git, package managers, Docker, SSH and
            broader system settings. Developer focus filters the results; it does not narrow the scan. Stored
            AI-assistant findings appear here too; run those checks from Scan.
          </p>
        </details>
        {(scanning || complianceRunning) && <TaskActivity task="scan" active={active} />}

        {unreadFiles.length > 0 && (
          <details className="credential-disclosure rounded-md bg-muted/50 px-3 py-2 text-xs">
            <summary className="flex cursor-pointer list-none items-center gap-1.5 rounded focus-visible:outline-2 focus-visible:outline-primary">
              <ChevronRight className="disclosure-chevron size-3.5" aria-hidden="true" />
              {unreadFiles.length} {unreadFiles.length === 1 ? "file" : "files"} could not be checked. The
              checks that read {unreadFiles.length === 1 ? "it" : "them"} are not counted as passed.
            </summary>
            <ul className="mt-2 space-y-1 pl-5 text-muted-foreground">
              {unreadFiles.map((m) => (
                <li key={m} className="[overflow-wrap:anywhere]">
                  {m.charAt(0).toUpperCase() + m.slice(1)}
                </li>
              ))}
            </ul>
          </details>
        )}

        {skippedPrivileged.length > 0 && !privilegedRunDone && (
          <div className="flex flex-wrap items-center justify-between gap-2 border-y border-border py-3 text-xs text-muted-foreground">
            <div>
              <p>
                {skippedPrivileged.length} check{skippedPrivileged.length === 1 ? " needs" : "s need"}{" "}
                administrator access.
              </p>
              <details className="credential-disclosure mt-1">
                <summary className="flex w-fit cursor-pointer list-none items-center gap-1.5 rounded focus-visible:outline-2 focus-visible:outline-primary">
                  <ChevronRight className="disclosure-chevron size-3.5" aria-hidden="true" />
                  Skipped checks
                </summary>
                <p className="mt-1 font-mono">{skippedPrivileged.join(", ")}</p>
              </details>
            </div>
            <Button variant="outline" size="sm" onClick={runPrivilegedScan} disabled={elevating}>
              {elevating ? "Waiting for authentication…" : "Run privileged checks"}
            </Button>
          </div>
        )}

        {errors.map((e, i) => (
          <Callout key={i} tone="critical">
            {e}
          </Callout>
        ))}

        <section>
          {visibleFindings.length > 0 && (
            <SectionLabel>
              {visibleFindings.length} issue{visibleFindings.length === 1 ? "" : "s"} to fix
            </SectionLabel>
          )}

          {visibleFindings.length === 0 && !scanning && !loading && (
            <div className="border-y border-border py-6 text-sm">
              <p className="font-medium">
                {!hasScanned
                  ? "No configuration results yet."
                  : skippedPrivileged.length > 0
                    ? "Some checks still need administrator access."
                    : errors.length > 0
                      ? "Some checks could not finish."
                      : "No findings in this view."}
              </p>
              <p className="mt-1 text-xs text-muted-foreground">
                {!hasScanned
                  ? "Run a check to inspect this computer’s configuration."
                  : "This view shows recorded findings; skipped or failed checks are not passes."}
              </p>
            </div>
          )}

          {scope === "all" && findings.some((f) => fixCapabilities.has(f.rule_id)) && (
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
                  onIgnorePlace: ignorePlace,
                  onRecheck: runScan,
                  fixCapabilities,
                  onFixed: runScan,
                  footerFor: (f) =>
                    f.redactable && f.file ? <RedactButton file={f.file} onDone={bump} /> : null,
                  groupActionFor: (ruleId) =>
                    ruleId === "BLWK-SSH-012" ? <SshKeyProtect variant="inline" onDone={runScan} /> : null,
                }}
              />
            ))}
          </div>
        </section>
      </div>
    </PageShell>
  );
}
