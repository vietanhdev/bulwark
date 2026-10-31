import { useEffect, useMemo, useRef, useState } from "react";
import { Channel, invoke } from "@tauri-apps/api/core";
import { Check, ChevronRight, Radar, RotateCw, Square } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { PageShell } from "@/components/PageShell";
import { RedactButton } from "@/components/RedactButton";
import { SshKeyProtect } from "@/components/SshKeyProtect";
import { CopyButton } from "@/components/ui/copy-button";
import { withLocation } from "@/lib/findings";
import { type ProtectionStatus } from "@/components/StatusHero";
import { type Finding } from "@/components/FindingCard";
import { CategoryFindings, groupFindingsByCategory } from "@/components/CategoryFindings";
import { FixAllButton } from "@/components/FixActions";
import { useFixCapabilities } from "@/lib/fixes";
import { SEVERITY_ORDER, SeverityDot, severityLabel, type Severity } from "@/components/Severity";
import { type View } from "@/components/Sidebar";
import { computeHardeningIndex, type HardeningIndex } from "@/lib/hardening";
import { useRevision, type ScannerId } from "@/lib/revision";
import { cn } from "@/lib/utils";

interface RuleSummary {
  id: string;
  category: string;
  collector: string;
  references: string[];
  os: string[];
  profiles: string[];
}

interface LatestScanMeta {
  host_fingerprint: string;
  started_at: string;
  privileged_collectors_skipped: string[];
}

interface DashboardSnapshot {
  findings: Finding[];
  /** Findings whose rule the user has explicitly suppressed — accepted risk, not resolved. Kept
   *  separate so the Overview can show "N to fix · M accepted" rather than pretending it's gone. */
  suppressedFindings: Finding[];
  meta: LatestScanMeta | null;
  agent_scanned: boolean;
}

type ScanEvent =
  | { event: "finding"; data: Finding }
  | { event: "collectorError"; data: { collector: string; message: string } }
  | { event: "privilegedSkipped"; data: { collectors: string[] } }
  | {
      event: "complete";
      data: { total_findings: number; host_fingerprint: string; cancelled: boolean };
    }
  | { event: "error"; data: { message: string } };

/* Bulwark has three scanners, and the Overview drives all of them — that's what makes this
   page's "every issue on this host" claim true rather than aspirational. Each is independently
   enableable because they cost wildly different amounts of time: compliance and agent are
   seconds, a full ClamAV sweep is minutes. Making the slow one opt-in is the difference between
   a button people press and one they learn to avoid.

   "Compliance" is the configuration rule pack (SSH, sudo, kernel, cron, file integrity) — the
   engine whose results the Compliance and Rules tabs are a view over. It has no scanner tab of
   its own precisely because its home *is* this page. */
type ScanKind = "compliance" | "antivirus";

const SCAN_KINDS: { id: ScanKind; label: string; hint: string }[] = [
  {
    id: "compliance",
    label: "Checkups",
    hint: "System settings, SSH, startup programs, stored credentials and AI assistants",
  },
  { id: "antivirus", label: "Virus scan", hint: "ClamAV signature scan — minutes, not seconds" },
];

// Fast, safe, and what you almost always want. Antivirus is deliberately off by default: it's a
// minutes-long filesystem sweep, and silently making the headline button take that long would be
// a worse default than making the user ask for it.
const DEFAULT_KINDS: ScanKind[] = ["compliance"];

type AgentScanEvent =
  | { event: "artifact"; data: { path: string } }
  | { event: "finding"; data: Finding }
  | { event: "complete"; data: { totalFindings: number; cancelled: boolean } }
  | { event: "error"; data: { message: string } };

type AvScanEvent =
  | { event: "fileScanned"; data: { path: string } }
  | { event: "threatFound"; data: { path: string; signature: string } }
  | { event: "complete"; data: { threats: { path: string; signature: string }[]; cancelled: boolean } }
  | { event: "error"; data: { message: string } };

interface ScanRunResult {
  findings: Finding[];
  host_fingerprint: string;
  privileged_collectors_skipped: string[];
  collector_errors: { collector: string; message: string }[];
}

// Opt-in "need" tags a rule's `profiles` field can reference — a process-accounting check is
// real, but mostly a server concern rather than something a laptop user needs surfaced by
// default. Kept as a list here rather than derived from the loaded pack so a need can be
// offered before any rule uses it, matching the "declarative, no Rust required" spirit of
// adding a rule (docs/guide/architecture.md, Profiles).
const PROFILE_NEEDS = ["server"];

const bySeverity = (a: Finding, b: Finding) =>
  SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);

export function OverviewView({ onNavigate }: { onNavigate: (v: View) => void }) {
  const { revision, bump, setScannerRunning } = useRevision();

  const [scanning, setScanning] = useState(false);
  const [elevating, setElevating] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  // Findings whose rule was suppressed: accepted risk, still present. Tracked separately so the
  // page shows "N to fix · M accepted" and — critically — so a suppressed rule still counts against
  // the hardening index rather than silently moving into the passing column.
  const [suppressed, setSuppressed] = useState<Finding[]>([]);
  const [skippedPrivileged, setSkippedPrivileged] = useState<string[]>([]);
  const [errors, setErrors] = useState<string[]>([]);
  const [host, setHost] = useState<string | null>(null);
  const [privilegedRunDone, setPrivilegedRunDone] = useState(false);
  const [hasScanned, setHasScanned] = useState(false);
  const [loading, setLoading] = useState(true);
  const [rules, setRules] = useState<RuleSummary[] | null>(null);
  const [activeNeeds, setActiveNeeds] = useState<Set<string>>(new Set());
  // Which scanners the next run will drive. See SCAN_KINDS.
  const [scopeOpen, setScopeOpen] = useState(false);
  const [selectedKinds, setSelectedKinds] = useState<Set<ScanKind>>(() => new Set(DEFAULT_KINDS));
  // The file/artifact currently being examined, for the slow scans that have one.
  const [progress, setProgress] = useState<string | null>(null);
  // ClamAV detections from this run. Not findings — no rule fired, a signature matched.
  const [threats, setThreats] = useState<{ path: string; signature: string }[]>([]);
  const [, setAgentScanned] = useState(false);
  // Whether an antivirus sweep ran in this session. Unlike compliance/agent findings, ClamAV
  // results aren't persisted to the dashboard snapshot, so on a fresh open the Antivirus tile has
  // no stored state to restore — it stays "unknown" until a sweep runs, rather than faking a tick.
  const [, setAvScanned] = useState(false);
  // Set when the user pressed Stop. Held in a ref as well as state because the sequential runner
  // below reads it *between* awaits, where a state value captured at render time would be stale
  // and it would cheerfully start the next scan you just asked it not to run.
  const [cancelled, setCancelled] = useState(false);
  const cancelledRef = useRef(false);
  // True only when the findings on screen arrived live over the scan Channel, so the
  // arrival animation plays for a scan you are watching happen and not for results restored
  // from disk when you merely opened the tab. See FindingCard.
  const [streamed, setStreamed] = useState(false);

  // On open — and again whenever anything writes to disk — load whatever Bulwark already
  // knows, rather than presenting an empty "not scanned yet" screen when real results exist
  // from an earlier session or a background monitoring tick.
  //
  // Skipped while a scan is streaming: a mid-scan refetch would overwrite the findings
  // arriving over the Channel with the previous run's stored snapshot.
  useEffect(() => {
    if (scanning) return;
    invoke<DashboardSnapshot>("dashboard_snapshot")
      .then((snap) => {
        // `findings` spans every engine's *active* (unsuppressed) issues; `suppressedFindings`
        // carries the accepted-risk ones. Together they're the complete picture this page owes you —
        // neither pretends a suppressed issue was fixed.
        setAgentScanned(snap.agent_scanned);
        if (!snap.meta) return;
        setFindings(snap.findings.map(withLocation).sort(bySeverity));
        setSuppressed([...(snap.suppressedFindings ?? [])].sort(bySeverity));
        setHost(snap.meta.host_fingerprint);
        setSkippedPrivileged(snap.meta.privileged_collectors_skipped);
        setHasScanned(true);
        setStreamed(false);
      })
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `scanning` guards, it must not retrigger
  }, [revision]);

  useEffect(() => {
    invoke<RuleSummary[]>("rules_list")
      .then(setRules)
      .catch(() => setRules(null));
  }, []);

  // Both active and suppressed rules count as "not passing" for the hardening index: a suppressed
  // finding is accepted risk, not a fixed issue, so suppressing must never move a rule into the
  // passing numerator (that would let the mute button silently raise the security score).
  const openRuleIds = useMemo(
    () => new Set([...findings, ...suppressed].map((f) => f.rule_id)),
    [findings, suppressed],
  );

  const hardening = useMemo(() => {
    if (!rules || !hasScanned) return null;
    return computeHardeningIndex(rules, openRuleIds, new Set(skippedPrivileged));
  }, [rules, openRuleIds, skippedPrivileged, hasScanned]);

  const ruleCategoryById = useMemo(() => {
    const m = new Map<string, string>();
    rules?.forEach((r) => m.set(r.id, r.category));
    return m;
  }, [rules]);

  // Findings filters. A machine with issues across every subsystem is a long list; a reader who
  // wants "just the criticals" or "just Agent Security" should be able to say so. The posture bar's
  // legend doubles as the severity control — clicking a severity there filters the list to it.
  const [severityFilter, setSeverityFilter] = useState<Severity | null>(null);
  const [scanFilter, setScanFilter] = useState<"compliance" | "file-integrity" | null>(null);

  // AI assistant checks are part of Checkups; only file integrity has its own filter.
  const scanOf = (f: Finding): "compliance" | "file-integrity" =>
    f.rule_id.startsWith("BLWK-FIM-") ? "file-integrity" : "compliance";

  const visibleFindings = useMemo(
    () =>
      findings.filter(
        (f) =>
          (!severityFilter || f.severity === severityFilter) && (!scanFilter || scanOf(f) === scanFilter),
      ),
    [findings, severityFilter, scanFilter],
  );

  // Findings grouped by the category that produced them, worst-severity group first. Browsing and
  // fixing a machine's issues one category at a time — all the SSH problems together, then all the
  // kernel ones — matches how you'd actually remediate: you open one config file and fix every
  // finding that lives in it, rather than hopping between subsystems down a flat list.
  // Low and informational findings are real but not urgent; they fold into "minor suggestions" so
  // the main list holds only problems worth acting on now.
  const isMinor = (f: Finding) => f.severity === "low" || f.severity === "info";
  const mainFindings = useMemo(() => visibleFindings.filter((f) => !isMinor(f)), [visibleFindings]);
  const minorFindings = useMemo(() => visibleFindings.filter(isMinor), [visibleFindings]);
  const groupedFindings = useMemo(
    () => groupFindingsByCategory(mainFindings, (id) => ruleCategoryById.get(id) ?? "other"),
    [mainFindings, ruleCategoryById],
  );
  const minorGrouped = useMemo(
    () => groupFindingsByCategory(minorFindings, (id) => ruleCategoryById.get(id) ?? "other"),
    [minorFindings, ruleCategoryById],
  );
  const [showMinor, setShowMinor] = useState(false);
  const countProblems = (fs: Finding[]) => new Set(fs.map((f) => f.rule_id)).size;
  const mainProblemCount = countProblems(mainFindings);
  const minorProblemCount = countProblems(minorFindings);
  // Problems (one per rule) by their worst severity, for the summary's severity counts.
  const problemsBySeverity = useMemo(() => {
    const worst = new Map<string, Severity>();
    for (const f of visibleFindings) {
      const cur = worst.get(f.rule_id);
      if (!cur || SEVERITY_ORDER.indexOf(f.severity) < SEVERITY_ORDER.indexOf(cur))
        worst.set(f.rule_id, f.severity);
    }
    return SEVERITY_ORDER.map((sev) => ({
      sev,
      count: [...worst.values()].filter((v) => v === sev).length,
    })).filter((c) => c.count > 0);
  }, [visibleFindings]);

  // Which category sections are collapsed. Everything starts expanded — the findings are what you
  // opened this page for — but a machine with issues across many subsystems can collapse the ones
  // it has already dealt with.
  const [collapsedCategories, setCollapsedCategories] = useState<Set<string>>(new Set());
  const fixCapabilities = useFixCapabilities();
  // Only offer the bulk fix when at least one issue on screen actually has a fixer — otherwise the
  // button previews an empty change set, which reads as a broken feature rather than an honest one.
  const anyFixable = visibleFindings.some((f) => fixCapabilities.has(f.rule_id));
  const toggleCategory = (category: string) =>
    setCollapsedCategories((prev) => {
      const next = new Set(prev);
      if (!next.delete(category)) next.add(category);
      return next;
    });

  const status: ProtectionStatus = scanning
    ? "scanning"
    : loading || !hasScanned
      ? "idle"
      : findings.some((f) => f.severity === "critical" || f.severity === "high")
        ? "critical"
        : findings.length > 0
          ? "warning"
          : "clean";

  /** The compliance (configuration rule pack) pass. Resolves once its Channel completes. */
  function runComplianceScan(): Promise<void> {
    return new Promise((resolve) => {
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
            resolve();
            break;
          case "complete":
            setHost(msg.data.host_fingerprint);
            if (msg.data.cancelled) markCancelled();
            resolve();
            break;
        }
      };
      invoke("scan_start", { onEvent, needs: Array.from(activeNeeds) }).catch((e) => {
        setErrors((prev) => [...prev, String(e)]);
        resolve();
      });
    });
  }

  /** The agent-security pass. Its findings share the common Finding shape, so they land in the
   *  same list as the compliance ones — the Overview doesn't care which engine produced an issue. */
  function runAgentScan(): Promise<void> {
    return new Promise((resolve) => {
      const onEvent = new Channel<AgentScanEvent>();
      onEvent.onmessage = (msg) => {
        switch (msg.event) {
          case "artifact":
            setProgress(msg.data.path);
            break;
          case "finding":
            setFindings((prev) => [...prev, msg.data].sort(bySeverity));
            break;
          case "error":
            setErrors((prev) => [...prev, msg.data.message]);
            resolve();
            break;
          case "complete":
            if (msg.data.cancelled) markCancelled();
            resolve();
            break;
        }
      };
      invoke("ai_scan_start", { onEvent, targets: undefined }).catch((e) => {
        setErrors((prev) => [...prev, String(e)]);
        resolve();
      });
    });
  }

  /** The ClamAV pass. Its detections aren't rule findings (no rule fired — a signature matched),
   *  so they're surfaced as their own result rather than faked into the findings list. The
   *  Antivirus tab remains their detailed home. */
  function runAntivirusScan(): Promise<void> {
    return new Promise((resolve) => {
      const onEvent = new Channel<AvScanEvent>();
      onEvent.onmessage = (msg) => {
        switch (msg.event) {
          case "fileScanned":
            setProgress(msg.data.path);
            break;
          case "threatFound":
            setThreats((prev) => [...prev, msg.data]);
            break;
          case "error":
            setErrors((prev) => [...prev, msg.data.message]);
            resolve();
            break;
          case "complete":
            setAvScanned(true);
            if (msg.data.cancelled) markCancelled();
            resolve();
            break;
        }
      };
      invoke("run_virus_scan", { onEvent, paths: undefined }).catch((e) => {
        setErrors((prev) => [...prev, String(e)]);
        resolve();
      });
    });
  }

  function markCancelled() {
    cancelledRef.current = true;
    setCancelled(true);
  }

  /** Stop whatever is running. The backend kills the in-flight engine (including the clamscan
   *  child process); `cancelledRef` stops the runner from starting any scan still queued. */
  async function stopScan() {
    markCancelled();
    try {
      await invoke("scan_cancel");
    } catch (e) {
      setErrors((prev) => [...prev, String(e)]);
    }
  }

  async function runScan() {
    if (selectedKinds.size === 0) return;

    cancelledRef.current = false;
    setCancelled(false);
    setScanning(true);
    setHasScanned(true);
    setStreamed(true);
    setFindings([]);
    // Cleared while streaming so the live (unpartitioned) findings aren't double-counted against a
    // stale suppressed set; the post-scan bump reloads the correctly partitioned snapshot.
    setSuppressed([]);
    setSkippedPrivileged([]);
    setErrors([]);
    setThreats([]);
    setProgress(null);
    setPrivilegedRunDone(false);

    // Sequential, not concurrent: these engines all hammer the filesystem, and running a ClamAV
    // sweep alongside an agent-artifact walk would make both slower while producing an
    // interleaved progress line nobody can read. Stop is honoured between each one, so pressing
    // it during the compliance pass doesn't leave a five-minute antivirus sweep still to come.
    // Each pass is bracketed with the shared running-flag so its tab (Compliance / Agent Security /
    // Antivirus) shows "scanning…" live even though the run was launched here, and bump()ed on
    // completion so that tab reloads its own results the moment its pass finishes — not only at the
    // very end. The Overview is just the launcher; the tabs are where results live.
    const pass = async (ids: ScannerId[], run: () => Promise<void>) => {
      ids.forEach((id) => setScannerRunning(id, true));
      try {
        await run();
      } finally {
        ids.forEach((id) => setScannerRunning(id, false));
        bump();
      }
    };
    // The compliance pass is also what computes the file-integrity (BLWK-FIM-) findings, so it marks
    // "fim" running too — the File integrity tab then shows the same live "scanning" state as the
    // other scanner tabs instead of sitting silent while a scan populates it.
    if (!cancelledRef.current && selectedKinds.has("compliance"))
      await pass(["compliance", "fim"], runComplianceScan);
    // AI assistant checks are part of Checkups, not a separate scanner.
    if (!cancelledRef.current && selectedKinds.has("compliance")) await pass(["agent"], runAgentScan);
    if (!cancelledRef.current && selectedKinds.has("antivirus")) await pass(["antivirus"], runAntivirusScan);

    setProgress(null);
    setScanning(false);
    // A stopped scan was never persisted, so re-read from disk to show the last complete picture
    // rather than the partial one that happens to be sitting in component state.
    bump();
  }

  async function runPrivilegedScan() {
    setElevating(true);
    setErrors([]);
    try {
      const result = await invoke<ScanRunResult>("scan_privileged");
      // Arrives as one complete result, not a stream — so it lands at rest rather than having
      // every card fade in simultaneously, which reads as a flash rather than as arrival.
      setStreamed(false);
      setFindings([...result.findings].map(withLocation).sort(bySeverity));
      setSkippedPrivileged(result.privileged_collectors_skipped);
      setErrors(result.collector_errors.map((e) => `${e.collector}: ${e.message}`));
      setHost(result.host_fingerprint);
      setPrivilegedRunDone(true);
      bump();
    } catch (e) {
      setErrors((prev) => [...prev, String(e)]);
    } finally {
      setElevating(false);
    }
  }

  /** Suppress a rule straight from one of its findings ("ignore this type of issue"). The reason is
   *  mandatory (enforced in core too); the bump re-reads the snapshot so the finding moves from the
   *  active list to accepted risk everywhere at once. */
  async function ignoreType(ruleId: string, reason: string) {
    try {
      await invoke("rule_suppress", { ruleId, reason });
      bump();
    } catch (e) {
      setErrors((prev) => [...prev, String(e)]);
    }
  }

  return (
    <PageShell
      title="Home"
      action={
        <>
          {/* The same scan from a terminal or CI: the CLI ships in the same package. */}
          <span
            className="hidden items-center gap-1 rounded-md border border-border bg-muted/50 py-0.5 pr-0.5 pl-2 font-mono text-[11px] text-muted-foreground md:flex"
            title="Run the same scan from a terminal or CI"
          >
            $ bulwark scan
            <CopyButton value="bulwark scan" className="h-5 w-5" />
          </span>
          {scanning ? (
            <Button onClick={stopScan} variant="outline" size="sm">
              <Square className="h-3.5 w-3.5 fill-current" />
              Stop
            </Button>
          ) : (
            <Button onClick={runScan} disabled={selectedKinds.size === 0} size="sm">
              <Radar className="h-4 w-4" />
              Scan now
            </Button>
          )}
        </>
      }
    >
      <div className="flex flex-col gap-8">
        <HomeSummary
          status={status}
          problemCount={mainProblemCount}
          minorCount={minorProblemCount}
          bySeverity={problemsBySeverity}
          host={host}
          hardening={hardening}
          scanLabel={
            SCAN_KINDS.filter((k) => selectedKinds.has(k.id))
              .map((k) => k.label)
              .join(", ") + (activeNeeds.size > 0 ? " + server checks" : "")
          }
          onToggleOptions={() => setScopeOpen((o) => !o)}
          optionsOpen={scopeOpen}
          fixAll={anyFixable ? <FixAllButton onFixed={runScan} /> : null}
          skippedPrivileged={privilegedRunDone ? 0 : skippedPrivileged.length}
          onRunPrivileged={runPrivilegedScan}
          elevating={elevating}
        />

        {scopeOpen && (
          <section className="rounded-lg border border-border bg-card">
            <div className="flex flex-col gap-3 border-t border-border px-4 py-3">
              <div className="flex flex-wrap gap-2">
                {SCAN_KINDS.map(({ id, label, hint }) => {
                  const on = selectedKinds.has(id);
                  return (
                    <button
                      key={id}
                      type="button"
                      role="switch"
                      aria-checked={on}
                      title={hint}
                      disabled={scanning}
                      onClick={() =>
                        setSelectedKinds((prev) => {
                          const next = new Set(prev);
                          if (!next.delete(id)) next.add(id);
                          return next;
                        })
                      }
                      className={cn(
                        "flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs transition-colors",
                        "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
                        "disabled:cursor-not-allowed disabled:opacity-60",
                        on
                          ? "border-primary bg-primary/10 font-medium text-primary"
                          : "border-border text-muted-foreground hover:bg-accent",
                      )}
                    >
                      <span
                        className={cn(
                          "flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-[3px] border",
                          on
                            ? "border-primary bg-primary text-primary-foreground"
                            : "border-muted-foreground/50",
                        )}
                      >
                        {on && <Check className="h-2.5 w-2.5" strokeWidth={3.5} />}
                      </span>
                      {label}
                    </button>
                  );
                })}
              </div>
              <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Extra checks">
                {PROFILE_NEEDS.map((need) => {
                  const on = activeNeeds.has(need);
                  return (
                    <button
                      key={need}
                      type="button"
                      aria-pressed={on}
                      onClick={() =>
                        setActiveNeeds((prev) => {
                          const next = new Set(prev);
                          if (!next.delete(need)) next.add(need);
                          return next;
                        })
                      }
                      title={`Also run the checks meant for ${need} machines`}
                      className={cn(
                        "flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs transition-colors",
                        "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
                        on
                          ? "border-primary bg-primary/10 text-primary"
                          : "border-border text-muted-foreground hover:bg-accent",
                      )}
                    >
                      <span
                        className={cn(
                          "flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-[3px] border",
                          on
                            ? "border-primary bg-primary text-primary-foreground"
                            : "border-muted-foreground/50",
                        )}
                      >
                        {on && <Check className="h-2.5 w-2.5" strokeWidth={3.5} />}
                      </span>
                      {need === "server" ? "Server checks" : need}
                    </button>
                  );
                })}
              </div>
              <p className="text-xs text-muted-foreground">
                Virus scan is off by default because a full ClamAV sweep takes minutes. Server checks add
                rules that only matter on machines other people connect to.
              </p>
            </div>
          </section>
        )}

        {scanning && (
          <div className="flex items-center gap-2.5 rounded-md border border-border bg-muted/40 px-3 py-2.5">
            <RotateCw className="h-3.5 w-3.5 shrink-0 animate-spin text-muted-foreground" />
            <div className="min-w-0 flex-1 truncate font-mono text-[11px] text-muted-foreground">
              {progress ?? "Scanning…"}
            </div>
          </div>
        )}

        {cancelled && !scanning && (
          <Callout tone="warning">
            <span className="font-medium">Scan stopped.</span> These results are partial and weren't saved —
            the checks that hadn't run yet have proved nothing either way. Run a full scan when you want a
            complete picture.
          </Callout>
        )}

        {threats.length > 0 && (
          <Callout tone="critical">
            <span className="font-medium">
              Antivirus found {threats.length} threat{threats.length === 1 ? "" : "s"}.
            </span>{" "}
            <span className="font-mono text-xs opacity-80">
              {threats
                .slice(0, 3)
                .map((t) => t.signature)
                .join(", ")}
            </span>{" "}
            Open the Antivirus tab for the full list.
          </Callout>
        )}

        {errors.map((e, i) => (
          <Callout key={i} tone="critical">
            {e}
          </Callout>
        ))}

        <section>
          <div className="mb-3 flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
            <div className="flex items-baseline gap-2">
              {suppressed.length > 0 && (
                // Accepted risk is present, not resolved — surface it here (and it still counts
                // against the hardening index) rather than letting suppression hide it. The audit
                // and management of these live under Rules › Suppressed.
                <button
                  type="button"
                  onClick={() => onNavigate("rules")}
                  title="Review accepted risk under Rules › Suppressed"
                  className="font-mono text-[11px] text-muted-foreground/70 underline-offset-2 hover:text-foreground hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
                >
                  · {suppressed.length} accepted
                </button>
              )}
            </div>
            {new Set(findings.map(scanOf)).size > 1 && (
              <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter findings">
                {(["compliance", "file-integrity"] as const)
                  .filter((k) => findings.some((f) => scanOf(f) === k))
                  .map((k) => {
                    const on = scanFilter === k;
                    const label = k === "file-integrity" ? "File changes" : "Checkups";
                    const count = findings.filter((f) => scanOf(f) === k).length;
                    return (
                      <button
                        key={k}
                        type="button"
                        aria-pressed={on}
                        onClick={() => setScanFilter(on ? null : k)}
                        className={cn(
                          "rounded-md border px-2 py-1 text-[11px] transition-colors",
                          "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
                          on
                            ? "border-foreground/25 bg-accent font-medium text-accent-foreground"
                            : "border-border text-muted-foreground hover:bg-accent/50",
                        )}
                      >
                        {label} <span className="tabular-nums opacity-70">{count}</span>
                      </button>
                    );
                  })}
                {(severityFilter || scanFilter) && (
                  <button
                    type="button"
                    onClick={() => {
                      setSeverityFilter(null);
                      setScanFilter(null);
                    }}
                    className="rounded-md px-2 py-1 text-[11px] text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
                  >
                    Clear
                  </button>
                )}
              </div>
            )}
          </div>

          {findings.length === 0 && !scanning && !loading && (
            <div className="rounded-lg border border-dashed border-border py-14 text-center">
              <p className="text-sm font-medium">
                {hasScanned ? "Nothing to fix on the last scan." : "This host hasn't been scanned yet."}
              </p>
              <p className="mt-1 text-sm text-muted-foreground">
                {hasScanned
                  ? "Every rule that ran came back clean."
                  : "Run a scan to check its configuration against the rule pack."}
              </p>
            </div>
          )}

          {findings.length > 0 && visibleFindings.length === 0 && (
            <div className="rounded-lg border border-dashed border-border py-10 text-center">
              <p className="text-sm font-medium">No findings match this filter.</p>
              <p className="mt-1 text-sm text-muted-foreground">
                Clear the filter to see all {findings.length} findings.
              </p>
            </div>
          )}

          <div className="flex flex-col gap-6">
            {groupedFindings.map(({ category, items, worst }) => (
              <CategoryFindings
                key={category}
                category={category}
                items={items}
                worst={worst}
                streamed={streamed}
                collapsed={collapsedCategories.has(category)}
                onToggle={() => toggleCategory(category)}
                actions={{
                  onIgnoreType: ignoreType,
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

          {minorGrouped.length > 0 && (
            <div className="mt-8">
              <button
                type="button"
                onClick={() => setShowMinor((v) => !v)}
                aria-expanded={showMinor}
                className="flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
              >
                <ChevronRight className={cn("h-3.5 w-3.5 transition-transform", showMinor && "rotate-90")} />
                {minorProblemCount} low-risk {minorProblemCount === 1 ? "suggestion" : "suggestions"}
                <span className="font-normal">· Low and Info, fix when convenient</span>
              </button>
              {showMinor && (
                <div className="mt-4 flex flex-col gap-6">
                  {minorGrouped.map(({ category, items, worst }) => (
                    <CategoryFindings
                      key={`minor-${category}`}
                      category={category}
                      items={items}
                      worst={worst}
                      streamed={streamed}
                      collapsed={false}
                      onToggle={() => {}}
                      actions={{
                        onIgnoreType: ignoreType,
                        onRecheck: runScan,
                        fixCapabilities,
                        onFixed: runScan,
                        footerFor: (f) =>
                          f.redactable && f.file ? <RedactButton file={f.file} onDone={bump} /> : null,
                      }}
                    />
                  ))}
                </div>
              )}
            </div>
          )}
        </section>
      </div>
    </PageShell>
  );
}

/**
 * Home's one summary card: what state the machine is in, how many problems there are and how
 * urgent, the one action that fixes the most with the least effort, and anything that limited the
 * scan. Everything else on Home is the problem list.
 */
function HomeSummary({
  status,
  problemCount,
  minorCount,
  bySeverity,
  host,
  hardening,
  scanLabel,
  onToggleOptions,
  optionsOpen,
  fixAll,
  skippedPrivileged,
  onRunPrivileged,
  elevating,
}: {
  status: ProtectionStatus;
  problemCount: number;
  minorCount: number;
  bySeverity: { sev: Severity; count: number }[];
  host: string | null;
  hardening: HardeningIndex | null;
  scanLabel: string;
  onToggleOptions: () => void;
  optionsOpen: boolean;
  fixAll: React.ReactNode;
  skippedPrivileged: number;
  onRunPrivileged: () => void;
  elevating: boolean;
}) {
  const scanned = status !== "idle" && status !== "scanning";
  const headline =
    status === "scanning"
      ? "Checking this computer…"
      : !scanned
        ? "Let's check this computer"
        : problemCount === 0
          ? minorCount > 0
            ? "No urgent problems"
            : "All clear"
          : `${problemCount} ${problemCount === 1 ? "problem" : "problems"} to fix`;
  const detail = !scanned
    ? "Scan now checks secrets, supply chain, exposed services, AI agents, SSH and the OS."
    : problemCount === 0
      ? minorCount > 0
        ? `${minorCount} low-risk ${minorCount === 1 ? "suggestion" : "suggestions"} below, when you have time.`
        : "Every check that ran came back clean."
      : null;

  return (
    <section className="rounded-lg border border-border bg-card px-5 py-4">
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
        <div className="min-w-0">
          <h2 className="font-heading text-xl font-semibold">{headline}</h2>
          {detail ? (
            <p className="mt-0.5 text-sm text-muted-foreground">{detail}</p>
          ) : (
            <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
              {bySeverity.map(({ sev, count }) => (
                <span key={sev} className="flex items-center gap-1.5">
                  <SeverityDot severity={sev} />
                  <span className="font-semibold tabular-nums">{count}</span>
                  <span className="text-muted-foreground">{severityLabel(sev)}</span>
                </span>
              ))}
            </p>
          )}
        </div>
        {fixAll && <div className="shrink-0">{fixAll}</div>}
      </div>

      {skippedPrivileged > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 rounded-md bg-muted/50 px-3 py-2 text-xs">
          <span>
            {skippedPrivileged} {skippedPrivileged === 1 ? "check was" : "checks were"} skipped because{" "}
            {skippedPrivileged === 1 ? "it needs" : "they need"} administrator access.
          </span>
          <button
            type="button"
            onClick={onRunPrivileged}
            disabled={elevating}
            className="font-medium text-primary underline-offset-2 hover:underline disabled:opacity-60"
          >
            {elevating ? "Waiting for your password…" : "Run them"}
          </button>
        </div>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
        <span>
          Checks: <span className="text-foreground">{scanLabel || "nothing selected"}</span>{" "}
          <button
            type="button"
            onClick={onToggleOptions}
            aria-expanded={optionsOpen}
            className="text-primary underline-offset-2 hover:underline"
          >
            {optionsOpen ? "Done" : "Change"}
          </button>
        </span>
        {hardening && (
          <span className="tabular-nums">
            {hardening.passing} of {hardening.evaluated} checks pass
          </span>
        )}
        {host && <span className="truncate font-mono">{host}</span>}
      </div>
    </section>
  );
}
