import { useEffect, useMemo, useRef, useState } from "react";
import { Channel, invoke } from "@tauri-apps/api/core";
import { Check, ChevronRight, Radar, RotateCw, Square } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { PageShell, SectionLabel } from "@/components/PageShell";
import { StatusHero, type ProtectionStatus } from "@/components/StatusHero";
import { type Finding } from "@/components/FindingCard";
import { CategoryFindings, groupFindingsByCategory } from "@/components/CategoryFindings";
import { SEVERITY_ORDER, SeverityDot, railStyle, severityLabel, type Severity } from "@/components/Severity";
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
type ScanKind = "compliance" | "agent" | "antivirus";

const SCAN_KINDS: { id: ScanKind; label: string; hint: string }[] = [
  {
    id: "compliance",
    label: "Checkups",
    hint: "The rule pack — SSH, sudo, kernel, cron, file integrity",
  },
  { id: "agent", label: "AI assistants", hint: "AI assistant context, MCP configs, transcripts" },
  { id: "antivirus", label: "Virus scan", hint: "ClamAV signature scan — minutes, not seconds" },
];

// Fast, safe, and what you almost always want. Antivirus is deliberately off by default: it's a
// minutes-long filesystem sweep, and silently making the headline button take that long would be
// a worse default than making the user ask for it.
const DEFAULT_KINDS: ScanKind[] = ["compliance", "agent"];

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
  const [selectedKinds, setSelectedKinds] = useState<Set<ScanKind>>(() => new Set(DEFAULT_KINDS));
  // The file/artifact currently being examined, for the slow scans that have one.
  const [progress, setProgress] = useState<string | null>(null);
  // ClamAV detections from this run. Not findings — no rule fired, a signature matched.
  const [threats, setThreats] = useState<{ path: string; signature: string }[]>([]);
  const [agentScanned, setAgentScanned] = useState(false);
  // Whether an antivirus sweep ran in this session. Unlike compliance/agent findings, ClamAV
  // results aren't persisted to the dashboard snapshot, so on a fresh open the Antivirus tile has
  // no stored state to restore — it stays "unknown" until a sweep runs, rather than faking a tick.
  const [avScanned, setAvScanned] = useState(false);
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
        setFindings([...snap.findings].sort(bySeverity));
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

  // The four scanners, not the fine-grained rule categories: the Overview answers "which of my
  // engines is finding problems," and its tiles mirror the four Scans tabs one-to-one — Compliance,
  // Antivirus, Agent Security, File integrity. A tile only claims a clean tick once that engine has
  // actually run this session; an unscanned engine renders as unknown, never as a false all-clear.
  const scanModules = useMemo(() => {
    const worstOf = (fs: Finding[]): Severity | null =>
      SEVERITY_ORDER.find((s) => fs.some((f) => f.severity === s)) ?? null;
    // Bucket by the same rule-id identity each detail tab uses, so a tile's count always matches
    // the tab it links to: File integrity keys on BLWK-FIM- (see IntegrityView), Agent Security on
    // BLWK-AI-, and Compliance is everything else from the config engine (file-integrity excluded —
    // it has its own tab).
    const isFim = (f: Finding) => f.rule_id.startsWith("BLWK-FIM-");
    const isAgent = (f: Finding) => f.rule_id.startsWith("BLWK-AI-");
    const compliance = findings.filter((f) => !isAgent(f) && !isFim(f));
    const fim = findings.filter(isFim);
    const agent = findings.filter(isAgent);
    return [
      {
        key: "compliance",
        view: "compliance" as View,
        label: "Checkups",
        issueCount: compliance.length,
        worst: worstOf(compliance),
        scanned: hasScanned,
      },
      {
        key: "antivirus",
        view: "antivirus" as View,
        label: "Virus scan",
        issueCount: threats.length,
        worst: threats.length > 0 ? ("critical" as Severity) : null,
        scanned: avScanned,
      },
      {
        key: "agent-security",
        view: "agent-security" as View,
        label: "AI assistants",
        issueCount: agent.length,
        worst: worstOf(agent),
        scanned: agentScanned,
      },
      {
        key: "file-integrity",
        view: "integrity" as View,
        label: "File changes",
        issueCount: fim.length,
        worst: worstOf(fim),
        scanned: hasScanned,
      },
    ];
  }, [findings, threats, hasScanned, agentScanned, avScanned]);

  const counts = useMemo(
    () => SEVERITY_ORDER.map((sev) => ({ sev, count: findings.filter((f) => f.severity === sev).length })),
    [findings],
  );

  // Findings filters. A machine with issues across every subsystem is a long list; a reader who
  // wants "just the criticals" or "just Agent Security" should be able to say so. The posture bar's
  // legend doubles as the severity control — clicking a severity there filters the list to it.
  const [severityFilter, setSeverityFilter] = useState<Severity | null>(null);
  const [scanFilter, setScanFilter] = useState<"compliance" | "agent-security" | "file-integrity" | null>(
    null,
  );
  const toggleSeverityFilter = (sev: Severity) => setSeverityFilter((cur) => (cur === sev ? null : sev));

  const scanOf = (f: Finding): "compliance" | "agent-security" | "file-integrity" =>
    f.rule_id.startsWith("BLWK-AI-")
      ? "agent-security"
      : f.rule_id.startsWith("BLWK-FIM-")
        ? "file-integrity"
        : "compliance";

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
  const groupedFindings = useMemo(
    () => groupFindingsByCategory(visibleFindings, (id) => ruleCategoryById.get(id) ?? "other"),
    [visibleFindings, ruleCategoryById],
  );

  // Which category sections are collapsed. Everything starts expanded — the findings are what you
  // opened this page for — but a machine with issues across many subsystems can collapse the ones
  // it has already dealt with.
  const [collapsedCategories, setCollapsedCategories] = useState<Set<string>>(new Set());
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
    if (!cancelledRef.current && selectedKinds.has("agent")) await pass(["agent"], runAgentScan);
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
      setFindings([...result.findings].sort(bySeverity));
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
          <div className="hidden items-center gap-1 sm:flex" role="group" aria-label="Scan profile">
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
                  title={`Also run rules tagged for "${need}" hosts`}
                  className={cn(
                    "rounded-full border px-2.5 py-1 font-mono text-[11px] font-medium capitalize transition-colors",
                    "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
                    on
                      ? "border-primary bg-primary/10 text-primary"
                      : "border-border text-muted-foreground hover:bg-accent",
                  )}
                >
                  {need}
                </button>
              );
            })}
          </div>
          {scanning ? (
            <Button onClick={stopScan} variant="outline" size="sm">
              <Square className="h-3.5 w-3.5 fill-current" />
              Stop
            </Button>
          ) : (
            <Button onClick={runScan} disabled={selectedKinds.size === 0} size="sm">
              <Radar className="h-4 w-4" />
              {selectedKinds.size === SCAN_KINDS.length
                ? "Run all scans"
                : selectedKinds.size === 1
                  ? "Run 1 scan"
                  : `Run ${selectedKinds.size} scans`}
            </Button>
          )}
        </>
      }
    >
      <div className="flex flex-col gap-8">
        <VerdictPanel
          status={status}
          counts={counts}
          host={host}
          hardening={hardening}
          severityFilter={severityFilter}
          onToggleSeverity={toggleSeverityFilter}
        />

        {/* The four scanners, at a glance and one click from their detail page. */}
        <section>
          <SectionLabel>Scans</SectionLabel>
          <div className="grid grid-cols-2 gap-2.5 lg:grid-cols-4">
            {scanModules.map((m) => (
              <ScanTile key={m.key} module={m} onClick={() => onNavigate(m.view)} />
            ))}
          </div>
        </section>

        <section>
          <SectionLabel>Scan scope</SectionLabel>
          <div className="flex flex-wrap gap-2 rounded-lg border border-border bg-card p-3">
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
                      on ? "border-primary bg-primary text-primary-foreground" : "border-muted-foreground/50",
                    )}
                  >
                    {on && <Check className="h-2.5 w-2.5" strokeWidth={3.5} />}
                  </span>
                  {label}
                </button>
              );
            })}
          </div>
          <p className="mt-2 text-xs text-muted-foreground">
            Every scanner Bulwark has, driven from one button. Antivirus is off by default — it's a full
            ClamAV sweep and takes minutes, not seconds.
          </p>
        </section>

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
          <div className="mb-3 flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
            <div className="flex items-baseline gap-2">
              <span className="font-mono text-[11px] font-semibold tracking-widest text-muted-foreground uppercase">
                {severityFilter || scanFilter
                  ? `${visibleFindings.length} of ${findings.length} to fix`
                  : `${findings.length} to fix`}
              </span>
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
            {findings.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter findings">
                {(["compliance", "agent-security", "file-integrity"] as const)
                  .filter((k) => findings.some((f) => scanOf(f) === k))
                  .map((k) => {
                    const on = scanFilter === k;
                    const label =
                      k === "agent-security" ? "Agent" : k === "file-integrity" ? "Integrity" : "Compliance";
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
                        {label}
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
                actions={{ onIgnoreType: ignoreType, onRecheck: runScan }}
              />
            ))}
          </div>
        </section>
      </div>
    </PageShell>
  );
}

/** score → the severity token that colours the hardening figure, on the same scale Lynis uses. */
function hardeningColor(score: number): string {
  if (score >= 85) return "var(--sev-resolved-fg)";
  if (score >= 65) return "var(--sev-medium-fg)";
  return "var(--sev-critical-fg)";
}

/**
 * The Overview's thesis, as one panel: the verdict in plain words (the shield, coloured by how the
 * host is doing), the hardening index as a plain figure rather than a gauge, and — the signature —
 * a full-width *posture bar* that shows the machine's threat surface as a proportioned band of its
 * open findings by severity. The band's legend is also the severity filter for the list below, so
 * the picture of what's wrong and the control for reading it are the same object.
 */
function VerdictPanel({
  status,
  counts,
  host,
  hardening,
  severityFilter,
  onToggleSeverity,
}: {
  status: ProtectionStatus;
  counts: { sev: Severity; count: number }[];
  host: string | null;
  hardening: HardeningIndex | null;
  severityFilter: Severity | null;
  onToggleSeverity: (sev: Severity) => void;
}) {
  const present = counts.filter((c) => c.count > 0);
  const total = present.reduce((n, c) => n + c.count, 0);

  return (
    <div className="rounded-lg border border-border bg-card px-6 py-5">
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-4">
        <StatusHero status={status} counts={counts} host={host} showBreakdown={false} />
        {hardening && (
          <div className="text-right">
            <div className="font-mono text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
              Safety score
            </div>
            <div className="mt-0.5 flex items-baseline justify-end gap-1">
              <span
                className="font-heading text-3xl font-semibold tabular-nums"
                style={{ color: hardeningColor(hardening.score) }}
              >
                {hardening.score}
              </span>
              <span className="font-mono text-xs text-muted-foreground">/100</span>
            </div>
            <div className="font-mono text-[11px] text-muted-foreground">
              {hardening.passing}/{hardening.evaluated} checks passing
            </div>
          </div>
        )}
      </div>

      {total > 0 && (
        <div className="mt-5">
          {/* The bar: one segment per present severity, width proportional to its share of the
              open findings — the machine's threat surface at a glance, not just a count. */}
          <div
            className="flex h-2 w-full overflow-hidden rounded-full bg-muted"
            role="img"
            aria-label="Findings by severity"
          >
            {present.map(({ sev, count }) => (
              <div
                key={sev}
                style={{ width: `${(count / total) * 100}%`, background: `var(--sev-${sev})` }}
                className={cn(
                  "h-full transition-opacity",
                  severityFilter && severityFilter !== sev && "opacity-30",
                )}
              />
            ))}
          </div>
          <div className="mt-2.5 flex flex-wrap items-center gap-x-2 gap-y-1.5">
            {present.map(({ sev, count }) => {
              const on = severityFilter === sev;
              return (
                <button
                  key={sev}
                  type="button"
                  aria-pressed={on}
                  onClick={() => onToggleSeverity(sev)}
                  title={`Show only ${severityLabel(sev)} findings`}
                  className={cn(
                    "flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs transition-colors",
                    "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
                    on
                      ? "border-foreground/25 bg-accent"
                      : "border-transparent text-muted-foreground hover:bg-accent/50",
                  )}
                >
                  <SeverityDot severity={sev} />
                  <span className="font-mono font-semibold tabular-nums text-foreground">{count}</span>
                  <span>{severityLabel(sev)}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

/** One scanner, as a button into its detail tab: a severity-railed tile showing the engine name and
 *  its status — a tick when clean, the open-issue count when not, a dash when it hasn't run this
 *  session (unknown, never a false all-clear). */
function ScanTile({
  module: m,
  onClick,
}: {
  module: {
    key: string;
    label: string;
    issueCount: number;
    worst: Severity | null;
    scanned: boolean;
  };
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "rail group flex items-center gap-2.5 rounded-md border border-border bg-card py-2.5 pr-2.5 pl-3 text-left transition-colors",
        "hover:bg-accent/40 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring",
      )}
      style={railStyle(!m.scanned ? "info" : (m.worst ?? "resolved"))}
    >
      {!m.scanned ? (
        <span className="flex h-4 w-4 shrink-0 items-center justify-center font-mono text-[11px] text-muted-foreground/60">
          –
        </span>
      ) : m.issueCount === 0 ? (
        <Check className="h-4 w-4 shrink-0" style={{ color: "var(--sev-resolved)" }} strokeWidth={2.5} />
      ) : (
        <span
          className="flex h-4 w-4 shrink-0 items-center justify-center font-mono text-[11px] font-semibold"
          style={{ color: `var(--sev-${m.worst}-fg)` }}
        >
          {m.issueCount}
        </span>
      )}
      <span className="min-w-0 flex-1 truncate text-sm">{m.label}</span>
      <ChevronRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground/40 transition-transform group-hover:translate-x-0.5 group-hover:text-muted-foreground" />
    </button>
  );
}
