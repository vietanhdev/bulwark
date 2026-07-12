import { useEffect, useMemo, useState } from "react";
import { Channel, invoke } from "@tauri-apps/api/core";
import { Check, Radar, RotateCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { CommandBlock } from "@/components/ui/copy-button";
import { PageShell, SectionLabel } from "@/components/PageShell";
import { HardeningRing } from "@/components/HardeningRing";
import { StatusHero, type ProtectionStatus } from "@/components/StatusHero";
import { SEVERITY_ORDER, SeverityLabel, railStyle, type Severity } from "@/components/Severity";
import { computeHardeningIndex } from "@/lib/hardening";
import { categoryLabel } from "@/lib/format";
import { useRevision } from "@/lib/revision";
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

// Opt-in "need" tags a rule's `profiles` field can reference — a process-accounting check is
// real, but mostly a server concern rather than something a laptop user needs surfaced by
// default. Kept as a list here rather than derived from the loaded pack so a need can be
// offered before any rule uses it, matching the "declarative, no Rust required" spirit of
// adding a rule (docs/guide/architecture.md, Profiles).
const PROFILE_NEEDS = ["server"];

const bySeverity = (a: Finding, b: Finding) =>
  SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);

export function OverviewView() {
  const { revision, bump } = useRevision();

  const [scanning, setScanning] = useState(false);
  const [elevating, setElevating] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [skippedPrivileged, setSkippedPrivileged] = useState<string[]>([]);
  const [errors, setErrors] = useState<string[]>([]);
  const [host, setHost] = useState<string | null>(null);
  const [privilegedRunDone, setPrivilegedRunDone] = useState(false);
  const [hasScanned, setHasScanned] = useState(false);
  const [loading, setLoading] = useState(true);
  const [rules, setRules] = useState<RuleSummary[] | null>(null);
  const [activeNeeds, setActiveNeeds] = useState<Set<string>>(new Set());
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
        if (!snap.meta) return;
        setFindings([...snap.findings].sort(bySeverity));
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

  const openRuleIds = useMemo(() => new Set(findings.map((f) => f.rule_id)), [findings]);

  const hardening = useMemo(() => {
    if (!rules || !hasScanned) return null;
    return computeHardeningIndex(rules, openRuleIds, new Set(skippedPrivileged));
  }, [rules, openRuleIds, skippedPrivileged, hasScanned]);

  const ruleCategoryById = useMemo(() => {
    const m = new Map<string, string>();
    rules?.forEach((r) => m.set(r.id, r.category));
    return m;
  }, [rules]);

  const modules = useMemo(() => {
    if (!rules) return [];
    return Array.from(new Set(rules.map((r) => r.category)))
      .sort()
      .map((category) => {
        const issues = findings.filter((f) => ruleCategoryById.get(f.rule_id) === category);
        const worst = SEVERITY_ORDER.find((s) => issues.some((f) => f.severity === s)) ?? null;
        return { category, issueCount: issues.length, worst };
      });
  }, [rules, findings, ruleCategoryById]);

  const counts = useMemo(
    () => SEVERITY_ORDER.map((sev) => ({ sev, count: findings.filter((f) => f.severity === sev).length })),
    [findings],
  );

  const status: ProtectionStatus = scanning
    ? "scanning"
    : loading || !hasScanned
      ? "idle"
      : findings.some((f) => f.severity === "critical" || f.severity === "high")
        ? "critical"
        : findings.length > 0
          ? "warning"
          : "clean";

  async function runScan() {
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
          setHost(msg.data.host_fingerprint);
          setScanning(false);
          // Tells History, Compliance and the sidebar's scan count to re-read from disk.
          bump();
          break;
      }
    };

    try {
      await invoke("scan_start", { onEvent, needs: Array.from(activeNeeds) });
    } catch (e) {
      setErrors((prev) => [...prev, String(e)]);
      setScanning(false);
    }
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

  return (
    <PageShell
      title="Overview"
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
          <Button onClick={runScan} disabled={scanning} size="sm">
            {scanning ? <RotateCw className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
            {scanning ? "Scanning…" : "Run a scan"}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-8">
        {/* The verdict, and the number behind it, side by side — the two things you open this
            app to find out. */}
        <div className="flex flex-wrap items-center justify-between gap-6 rounded-lg border border-border bg-card px-6 py-5">
          <StatusHero status={status} counts={counts} host={host} />
          {hardening && <HardeningRing index={hardening} />}
        </div>

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

        {modules.length > 0 && (
          <section>
            <SectionLabel>Protection modules</SectionLabel>
            <div className="grid grid-cols-2 gap-2.5 lg:grid-cols-3">
              {modules.map(({ category, issueCount, worst }) => (
                <div
                  key={category}
                  className="rail flex items-center gap-2.5 rounded-md border border-border bg-card py-2.5 pr-3"
                  style={railStyle(worst ?? "resolved")}
                >
                  {issueCount === 0 ? (
                    <Check
                      className="h-4 w-4 shrink-0"
                      style={{ color: "var(--sev-resolved)" }}
                      strokeWidth={2.5}
                    />
                  ) : (
                    <span
                      className="flex h-4 w-4 shrink-0 items-center justify-center font-mono text-[11px] font-semibold"
                      style={{ color: `var(--sev-${worst}-fg)` }}
                    >
                      {issueCount}
                    </span>
                  )}
                  <span className="min-w-0 flex-1 truncate text-sm">{categoryLabel(category)}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        <section>
          {findings.length > 0 && (
            <SectionLabel>
              {findings.length} finding{findings.length === 1 ? "" : "s"}
            </SectionLabel>
          )}

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

          <div className="flex flex-col gap-2.5">
            {findings.map((f) => (
              <FindingCard key={f.id} finding={f} animate={streamed} />
            ))}
          </div>
        </section>
      </div>
    </PageShell>
  );
}

/**
 * A finding, typeset as a clause in an audit report: the rule ID is the clause number and sits
 * in the gutter in mono, the severity rail runs down the left edge, and the fix is a real
 * command you can copy rather than a grey box you have to retype.
 *
 * `animate` is only true for findings arriving live over the scan Channel. Findings restored
 * from the stored snapshot on open render at rest — re-playing the arrival animation for
 * results that were already there before you opened the window is a lie about what just
 * happened, and it made the whole list flicker on every visit to this tab.
 */
function FindingCard({ finding: f, animate }: { finding: Finding; animate: boolean }) {
  return (
    <article
      className={cn(
        "rail rail-dim rounded-md border border-border bg-card py-3.5 pr-4",
        animate && "finding-enter",
      )}
      style={railStyle(f.severity)}
    >
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
        <span className="font-mono text-xs font-semibold tracking-tight text-muted-foreground">
          {f.rule_id}
        </span>
        <SeverityLabel severity={f.severity} />
      </div>
      <h3 className="mt-1.5 text-sm font-semibold">{f.title}</h3>
      <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{f.explanation}</p>
      <CommandBlock command={f.fix_hint} className="mt-2.5" />
    </article>
  );
}
