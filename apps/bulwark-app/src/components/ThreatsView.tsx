import { useEffect, useState } from "react";
import { invoke, Channel } from "@tauri-apps/api/core";
import { ShieldCheck, ShieldX, ShieldAlert, Loader2, Bug, FileCheck2, Clock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface ThreatDetection {
  path: string;
  signature: string;
}

interface AvScanResult {
  scanned_paths: string[];
  files_scanned: number | null;
  threats: ThreatDetection[];
  clamscan_available: boolean;
}

interface Finding {
  rule_id: string;
}

interface DashboardSnapshot {
  findings: Finding[];
  meta: unknown | null;
}

interface ClamavVersionInfo {
  engine_version: string;
  database_version: string;
  database_date: string;
}

interface ClamavInfoResponse {
  version: ClamavVersionInfo | null;
  install_command: string | null;
}

type AvScanEvent =
  | { event: "fileScanned"; data: { path: string } }
  | { event: "threatFound"; data: ThreatDetection }
  | { event: "complete"; data: AvScanResult }
  | { event: "error"; data: { message: string } };

export function ThreatsView() {
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<AvScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [clamavInfo, setClamavInfo] = useState<ClamavInfoResponse | null>(null);
  // BLWK-AV-002 (stale database) isn't something `clamscan -V` itself flags — the same
  // 14-day-old-file check the Dashboard's own finding already computed, reused here rather
  // than duplicated.
  const [dbStale, setDbStale] = useState(false);

  // Live progress while a scan is running — a ClamAV pass over even the default target set
  // can take minutes, and a button that just spins with zero feedback for that whole window
  // reads as hung, not as working.
  const [currentFile, setCurrentFile] = useState<string | null>(null);
  const [filesScanned, setFilesScanned] = useState(0);
  const [liveThreats, setLiveThreats] = useState<ThreatDetection[]>([]);

  const [baselining, setBaselining] = useState(false);
  const [baselineCount, setBaselineCount] = useState<number | null>(null);
  const [baselineError, setBaselineError] = useState<string | null>(null);

  useEffect(() => {
    invoke<ClamavInfoResponse>("clamav_info").then(setClamavInfo);
    invoke<DashboardSnapshot>("dashboard_snapshot").then((snap) => {
      const ids = new Set(snap.findings.map((f) => f.rule_id));
      setDbStale(ids.has("BLWK-AV-002"));
    });
  }, []);

  async function runScan() {
    setScanning(true);
    setError(null);
    setResult(null);
    setCurrentFile(null);
    setFilesScanned(0);
    setLiveThreats([]);

    const onEvent = new Channel<AvScanEvent>();
    onEvent.onmessage = (msg) => {
      switch (msg.event) {
        case "fileScanned":
          setCurrentFile(msg.data.path);
          setFilesScanned((n) => n + 1);
          break;
        case "threatFound":
          setLiveThreats((prev) => [...prev, msg.data]);
          break;
        case "complete":
          setResult(msg.data);
          setScanning(false);
          break;
        case "error":
          setError(msg.data.message);
          setScanning(false);
          break;
      }
    };

    try {
      await invoke("run_virus_scan", { onEvent });
    } catch (e) {
      setError(String(e));
      setScanning(false);
    }
  }

  async function runBaseline() {
    setBaselining(true);
    setBaselineError(null);
    try {
      const n = await invoke<number>("fim_baseline");
      setBaselineCount(n);
    } catch (e) {
      setBaselineError(String(e));
    } finally {
      setBaselining(false);
    }
  }

  return (
    <div className="mx-auto max-w-5xl px-8 py-6">
      <h2 className="text-lg font-semibold">Antivirus &amp; File Integrity</h2>
      <p className="mt-1 text-sm text-muted-foreground">
        Two independent protective checks: signature-based malware scanning and baseline-and-diff integrity
        monitoring for the files that matter most.
      </p>

      {/* Two equal-weight, independent features side by side rather than stacked — each has
          its own explanation, action button, and result card, so there's no shared state
          that would force them into a single-column flow. */}
      <div className="mt-6 grid grid-cols-1 gap-8 lg:grid-cols-2">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <Bug className="h-4 w-4 text-muted-foreground" />
            Antivirus
          </h3>
          <p className="mt-1 text-sm text-muted-foreground">
            Signature-based malware scanning via ClamAV — Bulwark shells out to it rather than reimplementing
            detection. Checks Downloads and the world-writable temp directories (
            <code className="font-mono">/tmp</code>, <code className="font-mono">/var/tmp</code>) by default,
            not the whole filesystem.
          </p>

          {/* Visible the moment this page opens — real engine/database version detail when
              installed, or the correct install command for *this* distro when it isn't, not
              a generic "apt install" that's simply wrong on Fedora/Arch/openSUSE/Alpine. */}
          {clamavInfo && !clamavInfo.version && (
            <div className="mt-4 rounded-lg border border-[var(--sev-medium)]/30 bg-[var(--sev-medium)]/10 px-3 py-2.5 text-sm text-[var(--sev-medium)]">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 shrink-0" />
                ClamAV isn't installed.
              </div>
              {clamavInfo.install_command && (
                <div className="mt-1.5 rounded bg-background/60 px-2 py-1 font-mono text-xs text-foreground">
                  {clamavInfo.install_command}
                </div>
              )}
            </div>
          )}
          {clamavInfo?.version && dbStale && (
            <div className="mt-4 flex items-center gap-2 rounded-lg border border-[var(--sev-medium)]/30 bg-[var(--sev-medium)]/10 px-3 py-2 text-sm text-[var(--sev-medium)]">
              <Clock className="h-4 w-4 shrink-0" />
              Database is more than 14 days old (built {clamavInfo.version.database_date}) — run{" "}
              <code className="font-mono">freshclam</code> before relying on a scan.
            </div>
          )}
          {clamavInfo?.version && !dbStale && (
            <div className="mt-4 flex items-center gap-2 rounded-lg border border-[var(--sev-resolved)]/30 bg-[var(--sev-resolved)]/10 px-3 py-2 text-sm text-[var(--sev-resolved)]">
              <ShieldCheck className="h-4 w-4 shrink-0" />
              <div>
                <div>ClamAV {clamavInfo.version.engine_version} — database current</div>
                <div className="font-mono text-xs opacity-80">
                  DB version {clamavInfo.version.database_version} · built {clamavInfo.version.database_date}
                </div>
              </div>
            </div>
          )}

          <Button onClick={runScan} disabled={scanning} className="mt-4">
            {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Bug className="h-4 w-4" />}
            {scanning ? "Scanning…" : "Run a virus scan"}
          </Button>

          {/* Live progress: what's actually happening right now, not just "scanning…" — a
              running file count plus the current path, so a multi-minute scan doesn't read
              as stalled. */}
          {scanning && (
            <div className="mt-4 rounded-lg border border-border bg-muted/30 px-3 py-2.5">
              <div className="flex items-center justify-between gap-3">
                <span className="text-xs font-medium text-muted-foreground">
                  {filesScanned} file{filesScanned === 1 ? "" : "s"} scanned
                </span>
                {liveThreats.length > 0 && (
                  <span className="text-xs font-semibold text-destructive">
                    {liveThreats.length} threat{liveThreats.length === 1 ? "" : "s"} found so far
                  </span>
                )}
              </div>
              {currentFile && (
                <div className="mt-1 truncate font-mono text-[11px] text-muted-foreground">{currentFile}</div>
              )}
            </div>
          )}

          {error && (
            <div className="mt-4 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </div>
          )}

          {result && result.clamscan_available && (
            <Card
              className={cn(
                "mt-4 flex-row items-center gap-3 p-4",
                result.threats.length > 0 && "border-destructive/40",
              )}
            >
              {result.threats.length === 0 ? (
                <ShieldCheck className="h-6 w-6 shrink-0 text-[var(--sev-resolved)]" strokeWidth={1.75} />
              ) : (
                <ShieldX className="h-6 w-6 shrink-0 text-destructive" strokeWidth={1.75} />
              )}
              <div>
                <div className="text-sm font-medium">
                  {result.threats.length === 0
                    ? "No threats found"
                    : `${result.threats.length} threat${result.threats.length === 1 ? "" : "s"} found`}
                </div>
                <div className="font-mono text-xs text-muted-foreground">
                  {result.files_scanned ?? filesScanned} file
                  {(result.files_scanned ?? filesScanned) === 1 ? "" : "s"} scanned in{" "}
                  {result.scanned_paths.join(", ")}
                </div>
              </div>
            </Card>
          )}

          {(scanning ? liveThreats : (result?.threats ?? [])).length > 0 && (
            <div className="mt-3 flex flex-col gap-2">
              {(scanning ? liveThreats : (result?.threats ?? [])).map((t, i) => (
                <div
                  key={i}
                  className="finding-enter flex items-center justify-between gap-3 rounded-lg border border-destructive/30 bg-destructive/5 px-3 py-2.5"
                >
                  <span className="min-w-0 truncate font-mono text-xs">{t.path}</span>
                  <span className="shrink-0 text-xs font-medium text-destructive">{t.signature}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <FileCheck2 className="h-4 w-4 text-muted-foreground" />
            File integrity
          </h3>
          <p className="mt-1 text-sm text-muted-foreground">
            Bulwark hashes a curated set of security-critical files (
            <code className="font-mono">/etc/passwd</code>, PAM configs,{" "}
            <code className="font-mono">sshd_config</code>, <code className="font-mono">sudo</code>/
            <code className="font-mono">su</code>) and flags any change against a baseline you establish
            explicitly — never automatically, since a baseline recorded after a compromise would just enshrine
            it as "known good." This covers the world-readable files;{" "}
            <code className="font-mono">/etc/shadow</code> and <code className="font-mono">/etc/sudoers</code>{" "}
            need <code className="font-mono">sudo bulwark fim baseline --privileged</code> from the CLI.
          </p>

          <Button onClick={runBaseline} disabled={baselining} className="mt-4">
            {baselining ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileCheck2 className="h-4 w-4" />}
            {baselining ? "Recording baseline…" : "Establish baseline now"}
          </Button>

          {baselineError && (
            <div className="mt-4 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {baselineError}
            </div>
          )}

          {baselineCount !== null && (
            <Card className="mt-4 flex-row items-center gap-3 p-4">
              <ShieldCheck className="h-6 w-6 shrink-0 text-[var(--sev-resolved)]" strokeWidth={1.75} />
              <div className="text-sm font-medium">
                Baseline recorded for {baselineCount} file{baselineCount === 1 ? "" : "s"}
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
