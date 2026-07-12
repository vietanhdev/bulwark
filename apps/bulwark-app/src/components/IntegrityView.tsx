import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { FileCheck2, Fingerprint, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { CommandBlock } from "@/components/ui/copy-button";
import { PageShell, SectionLabel } from "@/components/PageShell";
import { SeverityLabel, railStyle, type Severity } from "@/components/Severity";
import { useRevision } from "@/lib/revision";

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
  meta: unknown | null;
}

/* File-integrity findings are the ones the FIM collector raises. Matching on the rule-ID
   prefix keeps this a view over data the engine already produces — the alternative would be a
   second, GUI-only notion of "which rules count as integrity", which would then need keeping
   in sync with the rule pack by hand. */
const FIM_RULE_PREFIX = "BLWK-FIM-";

export function IntegrityView() {
  const { revision, bump } = useRevision();

  const [baselining, setBaselining] = useState(false);
  const [baselineCount, setBaselineCount] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  // No findings means "nothing has drifted" only if a scan has actually run. Before that it
  // means nothing at all, and the empty state must not claim a clean bill of health nobody has
  // earned — the same mistake the Compliance view used to make with its rows of green ticks.
  const [hasScanned, setHasScanned] = useState(false);

  useEffect(() => {
    invoke<DashboardSnapshot>("dashboard_snapshot")
      .then((snap) => {
        setFindings(snap.findings.filter((f) => f.rule_id.startsWith(FIM_RULE_PREFIX)));
        setHasScanned(snap.meta !== null);
      })
      .catch(() => setFindings([]));
  }, [revision]);

  const drift = useMemo(() => findings.length > 0, [findings]);

  async function runBaseline() {
    setBaselining(true);
    setError(null);
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

  return (
    <PageShell
      title="File integrity"
      description="Bulwark hashes a curated set of security-critical files and tells you when one of them changes."
      action={
        <Button onClick={runBaseline} disabled={baselining}>
          {baselining ? <Loader2 className="h-4 w-4 animate-spin" /> : <Fingerprint className="h-4 w-4" />}
          {baselining ? "Recording…" : baselineCount !== null ? "Re-record baseline" : "Record baseline"}
        </Button>
      }
    >
      <div className="flex flex-col gap-8">
        {/* The single most important thing to understand about this feature, and the reason it
            is a deliberate button rather than something Bulwark does for you on first run. */}
        <Callout tone="info">
          A baseline is only as trustworthy as the moment you take it. Bulwark never records one
          automatically, because a baseline captured after a compromise would quietly enshrine the compromise
          as "known good". Record one when you have reason to believe the host is clean.
        </Callout>

        {error && <Callout tone="critical">{error}</Callout>}

        {baselineCount !== null && (
          <Callout tone="success">
            Baseline recorded for {baselineCount} file{baselineCount === 1 ? "" : "s"}. Future scans will
            compare against it.
          </Callout>
        )}

        <section>
          <SectionLabel>What's watched</SectionLabel>
          <div className="rounded-lg border border-border bg-card p-4">
            <p className="text-sm leading-relaxed text-muted-foreground">
              A small, curated set of files that actually matter for this threat model — account and
              authentication config (<code className="font-mono">/etc/passwd</code>, PAM), the SSH daemon
              config (<code className="font-mono">sshd_config</code>), and the privilege-escalation binaries (
              <code className="font-mono">sudo</code>, <code className="font-mono">su</code>). Deliberately
              not a whole-filesystem baseline: AIDE already does that, and a diff with thousands of benign
              entries is one nobody reads.
            </p>
            <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
              Those are the world-readable ones. <code className="font-mono">/etc/shadow</code> and{" "}
              <code className="font-mono">/etc/sudoers</code> can only be read by root, so baselining them has
              to happen from the CLI:
            </p>
            <CommandBlock command="sudo bulwarkctl fim baseline --privileged" className="mt-2.5" />
          </div>
        </section>

        <section>
          <SectionLabel>Integrity findings</SectionLabel>
          {!drift ? (
            <div className="rounded-lg border border-dashed border-border py-14 text-center">
              <FileCheck2 className="mx-auto h-7 w-7 text-muted-foreground/40" strokeWidth={1.5} />
              <p className="mt-3 text-sm font-medium">
                {hasScanned ? "No watched file has changed." : "This host hasn't been scanned yet."}
              </p>
              <p className="mt-1 text-sm text-muted-foreground">
                {hasScanned
                  ? "Nothing has drifted from the recorded baseline."
                  : "Run a scan from the Overview to compare these files against the baseline."}
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
                    <span className="font-mono text-xs font-semibold tracking-tight text-muted-foreground">
                      {f.rule_id}
                    </span>
                    <SeverityLabel severity={f.severity} />
                  </div>
                  <h3 className="mt-1.5 text-sm font-semibold">{f.title}</h3>
                  <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{f.explanation}</p>
                  <CommandBlock command={f.fix_hint} className="mt-2.5" />
                </article>
              ))}
            </div>
          )}
        </section>
      </div>
    </PageShell>
  );
}
