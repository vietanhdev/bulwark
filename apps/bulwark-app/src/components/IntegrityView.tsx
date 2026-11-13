import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ChevronRight, FileCheck2, Fingerprint, Info, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { CommandBlock } from "@/components/ui/copy-button";
import { FixSteps } from "@/components/FixSteps";
import { PageShell, SectionLabel } from "@/components/PageShell";
import { SeverityLabel, railStyle, type Severity } from "@/components/Severity";
import { useRevision } from "@/lib/revision";
import { usePlatform } from "@/lib/platform";

interface Finding {
  id: string;
  rule_id: string;
  severity: Severity;
  title: string;
  explanation: string;
  fix_hint: string;
}

interface DashboardSnapshot {
  findings: Finding[];
  /** Findings the user chose to ignore: still true of the machine, only hidden from the list. */
  suppressedFindings?: Finding[];
  meta: unknown | null;
  /** The checks the stored scan actually ran. */
  rules_evaluated?: string[];
}

/* File-integrity findings are the ones the FIM collector raises. Matching on the rule-ID
   prefix keeps this a view over data the engine already produces — the alternative would be a
   second, GUI-only notion of "which rules count as integrity", which would then need keeping
   in sync with the rule pack by hand. */
const FIM_RULE_PREFIX = "BLWK-FIM-";

export function IntegrityView() {
  const platform = usePlatform();
  const { revision, bump, running } = useRevision();
  // The compliance scan (launched from Scan) is what recomputes file-integrity findings, and
  // it marks "fim" running for the duration — so this tab shows a live indicator instead of sitting
  // silent while that scan populates it.
  const fimRunning = running.has("fim");

  const [baselining, setBaselining] = useState(false);
  const [baselineCount, setBaselineCount] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  // No findings means "nothing has drifted" only if a scan has actually run. Before that it
  // means nothing at all, and the empty state must not claim a clean bill of health nobody has
  // earned — the same mistake the Compliance view used to make with its rows of green ticks.
  const [hasScanned, setHasScanned] = useState(false);
  // A scan having run is not enough either: "no file has changed" is only true when that scan ran
  // the file checks. They do not run on every system, and a scan can skip them.
  const [checked, setChecked] = useState(false);
  const [ignored, setIgnored] = useState(0);
  const [loadFailed, setLoadFailed] = useState(false);

  useEffect(() => {
    const isFim = (id: string) => id.startsWith(FIM_RULE_PREFIX);
    invoke<DashboardSnapshot>("dashboard_snapshot")
      .then((snap) => {
        const fim = snap.findings.filter((f) => isFim(f.rule_id));
        const hidden = (snap.suppressedFindings ?? []).filter((f) => isFim(f.rule_id)).length;
        setFindings(fim);
        setIgnored(hidden);
        setHasScanned(snap.meta !== null);
        setChecked(fim.length > 0 || hidden > 0 || (snap.rules_evaluated ?? []).some(isFim));
        setLoadFailed(false);
      })
      .catch(() => {
        setFindings([]);
        setLoadFailed(true);
      });
  }, [revision]);

  const drift = useMemo(() => findings.length > 0, [findings]);

  async function runBaseline() {
    setBaselining(true);
    setError(null);
    // Cleared first, so a failed attempt is not followed by the previous "recorded" message.
    setBaselineCount(null);
    try {
      setBaselineCount(await invoke<number>("fim_baseline"));
      // A fresh baseline changes what the next scan will consider "changed", so anything
      // reading stored state should re-read.
      bump();
    } catch (e) {
      setError(String(e));
    } finally {
      setBaselining(false);
    }
  }

  // The file checks (BLWK-FIM-*) are Linux rules and their collector is Linux-only. Anywhere else a
  // baseline could be recorded, but no scan would ever compare against it, and "no file has
  // changed" would be a claim with no check behind it.
  if (platform !== "linux") {
    return (
      <PageShell title="File changes" description="Compare tracked system files with a saved baseline.">
        <div className="rounded-lg border border-dashed border-border px-6 py-14 text-center">
          <FileCheck2 className="mx-auto h-7 w-7 text-muted-foreground/40" strokeWidth={1.5} />
          <p className="mt-3 text-sm font-medium">
            Not available on {platform === "windows" ? "Windows" : "macOS"} yet.
          </p>
          <p className="mx-auto mt-1 max-w-xl text-sm text-muted-foreground">
            The checks behind this page — accounts, sign-in and SSH configuration, sudo — run on Linux only
            for now, so there is nothing here to compare.
          </p>
        </div>
      </PageShell>
    );
  }

  return (
    <PageShell
      title="File changes"
      description="Compare tracked system files with a saved baseline."
      action={
        <Button onClick={runBaseline} disabled={baselining}>
          {baselining ? <Loader2 className="h-4 w-4 animate-spin" /> : <Fingerprint className="h-4 w-4" />}
          {baselining ? "Recording…" : baselineCount !== null ? "Re-record baseline" : "Record baseline"}
        </Button>
      }
    >
      <div className="flex flex-col gap-6">
        {/* The single most important thing to understand about this feature, and the reason it
            is a deliberate button rather than something Bulwark does for you on first run. Kept to
            one visible line so the results stay above the fold; the reasoning is one click away. */}
        <p className="flex items-start gap-2 text-xs leading-relaxed text-muted-foreground">
          <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
          <span>
            Record a baseline only when you believe this machine is clean — it becomes &ldquo;known
            good&rdquo;. Bulwark never records one automatically.
          </span>
        </p>

        {error && <Callout tone="critical">{error}</Callout>}

        {baselineCount !== null && (
          <Callout tone="success">
            Baseline recorded for {baselineCount} file{baselineCount === 1 ? "" : "s"}. Future scans will
            compare against it.
          </Callout>
        )}

        <section>
          <SectionLabel>Integrity findings</SectionLabel>
          {fimRunning && (
            <div className="mb-3 flex items-center gap-2.5 rounded-md border border-border bg-muted/40 px-3 py-2.5">
              <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-muted-foreground" />
              <div className="font-mono text-[11px] text-muted-foreground">
                Checking file integrity (started from Scan)…
              </div>
            </div>
          )}
          {!drift ? (
            <div className="rounded-lg border border-dashed border-border py-14 text-center">
              <FileCheck2 className="mx-auto h-7 w-7 text-muted-foreground/40" strokeWidth={1.5} />
              <p className="mt-3 text-sm font-medium">
                {loadFailed
                  ? "The saved results could not be read."
                  : !hasScanned
                    ? "This host hasn't been scanned yet."
                    : !checked
                      ? "The last scan did not check these files."
                      : ignored > 0
                        ? "No other watched file has changed."
                        : "No watched file has changed."}
              </p>
              <p className="mt-1 text-sm text-muted-foreground">
                {loadFailed || !hasScanned || !checked
                  ? "Run a scan from Scan to compare these files against the baseline."
                  : ignored > 0
                    ? `${ignored} ${ignored === 1 ? "change is" : "changes are"} hidden because you chose to ignore ${ignored === 1 ? "it" : "them"}. Rule catalog → Ignored lists what is ignored.`
                    : "Nothing has drifted from the recorded baseline."}
              </p>
            </div>
          ) : (
            <div className="flex flex-col gap-2.5">
              {findings.map((f) => (
                <article
                  key={f.id}
                  className="rail rail-dim rounded-md border border-border bg-card py-3.5 pr-4"
                  style={railStyle(f.severity)}
                >
                  <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                    <h3 className="text-sm font-semibold">{f.title}</h3>
                    <SeverityLabel severity={f.severity} />
                  </div>
                  <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{f.explanation}</p>
                  <FixSteps text={f.fix_hint} className="mt-2.5" />
                  <div className="mt-2 text-right font-mono text-[10px] text-muted-foreground/70">
                    {f.rule_id}
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>

        <details className="credential-disclosure border-t border-border pt-3 text-sm text-muted-foreground">
          <summary className="flex w-fit cursor-pointer list-none items-center gap-2 rounded py-1 text-xs focus-visible:outline-2 focus-visible:outline-primary">
            <ChevronRight className="disclosure-chevron size-3.5" aria-hidden="true" />
            <span className="font-medium text-foreground">What&apos;s watched, and why</span>
          </summary>
          <div className="mt-2 max-w-3xl space-y-3 pl-5 leading-relaxed">
            <p>
              A small, curated set of files that actually matter for this threat model — account and
              authentication config (<code className="font-mono">/etc/passwd</code>, PAM), the SSH daemon
              config (<code className="font-mono">sshd_config</code>), and the privilege-escalation binaries (
              <code className="font-mono">sudo</code>, <code className="font-mono">su</code>). Deliberately
              not a whole-filesystem baseline: AIDE already does that, and a diff with thousands of benign
              entries is one nobody reads.
            </p>
            <p>
              A baseline is only as trustworthy as the moment you take it: one captured after a compromise
              would quietly enshrine the compromise as &ldquo;known good&rdquo;.
            </p>
            <p>
              Those are the world-readable files. <code className="font-mono">/etc/shadow</code> and{" "}
              <code className="font-mono">/etc/sudoers</code> can only be read by root, so baselining them has
              to happen from the CLI:
            </p>
            <CommandBlock command="sudo bulwark fim baseline --privileged" />
          </div>
        </details>
      </div>
    </PageShell>
  );
}
