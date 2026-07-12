import { useEffect, useState } from "react";
import { Channel, invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Bug, Eye, Loader2, ShieldCheck, ShieldX, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Switch } from "@/components/ui/switch";
import { PageShell, SectionLabel } from "@/components/PageShell";
import { PathDropZone } from "@/components/PathDropZone";
import { railStyle } from "@/components/Severity";
import { useRevision } from "@/lib/revision";
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

interface DashboardSnapshot {
  findings: { rule_id: string }[];
}

interface ClamavInfoResponse {
  version: { engine_version: string; database_version: string; database_date: string } | null;
  install_command: string | null;
}

interface RealtimeAvStatus {
  enabled: boolean;
  watched_paths: string[];
  files_scanned: number;
  threats_found: number;
  recent_threats: ThreatDetection[];
}

type AvScanEvent =
  | { event: "fileScanned"; data: { path: string } }
  | { event: "threatFound"; data: ThreatDetection }
  | { event: "complete"; data: AvScanResult }
  | { event: "error"; data: { message: string } };

type RealtimeAvEvent =
  | { event: "fileScanned"; data: { path: string } }
  | { event: "threatFound"; data: ThreatDetection }
  | { event: "error"; data: { path: string; message: string } };

export function AntivirusView({ active }: { active: boolean }) {
  const { revision } = useRevision();

  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<AvScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [clamav, setClamav] = useState<ClamavInfoResponse | null>(null);
  // BLWK-AV-002 (stale signature database) isn't something `clamscan -V` reports — it's the
  // same 14-day-old-file check the config scan already computed, read back off the snapshot
  // rather than reimplemented here.
  const [dbStale, setDbStale] = useState(false);

  const [currentFile, setCurrentFile] = useState<string | null>(null);
  const [filesScanned, setFilesScanned] = useState(0);
  const [liveThreats, setLiveThreats] = useState<ThreatDetection[]>([]);

  const [customPaths, setCustomPaths] = useState<string[]>([]);

  const [realtime, setRealtime] = useState<RealtimeAvStatus | null>(null);
  const [realtimeBusy, setRealtimeBusy] = useState(false);
  const [realtimeError, setRealtimeError] = useState<string | null>(null);
  // Paths the watcher flagged while this tab has been open. Only these animate in — see the
  // event listener below.
  const [liveDetected, setLiveDetected] = useState<Set<string>>(new Set());

  useEffect(() => {
    invoke<ClamavInfoResponse>("clamav_info").then(setClamav);
    invoke<DashboardSnapshot>("dashboard_snapshot").then((snap) =>
      setDbStale(snap.findings.some((f) => f.rule_id === "BLWK-AV-002")),
    );
    invoke<RealtimeAvStatus>("realtime_av_get_status").then(setRealtime);
  }, [revision]);

  useEffect(() => {
    // Real-time detections come from a background watcher with no command invocation to hang a
    // Channel off (see realtime_av.rs), so the plain event bus backs live updates here — same
    // mechanism as `monitoring:tick`.
    const unlistenPromise = listen<RealtimeAvEvent>("realtime_av:event", ({ payload: msg }) => {
      setRealtime((prev) => {
        if (!prev) return prev;
        if (msg.event === "fileScanned") return { ...prev, files_scanned: prev.files_scanned + 1 };
        if (msg.event === "threatFound") {
          // Mark it as caught in front of the user, so it animates in. The watcher's
          // already-known detections, restored from `realtime_av_get_status` when this tab
          // first opened, are history and render at rest.
          setLiveDetected((prev) => new Set(prev).add(msg.data.path));
          return {
            ...prev,
            threats_found: prev.threats_found + 1,
            recent_threats: [msg.data, ...prev.recent_threats].slice(0, 20),
          };
        }
        return prev;
      });
    });
    return () => {
      unlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  const unavailable = clamav !== null && !clamav.version;

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
      await invoke("run_virus_scan", {
        onEvent,
        paths: customPaths.length > 0 ? customPaths : undefined,
      });
    } catch (e) {
      setError(String(e));
      setScanning(false);
    }
  }

  async function toggleRealtime(enabled: boolean) {
    setRealtimeBusy(true);
    setRealtimeError(null);
    try {
      setRealtime(await invoke<RealtimeAvStatus>("realtime_av_set_enabled", { enabled }));
    } catch (e) {
      setRealtimeError(String(e));
    } finally {
      setRealtimeBusy(false);
    }
  }

  async function addWatchFolders(paths: string[]) {
    setRealtimeError(null);
    for (const path of paths) {
      try {
        setRealtime(await invoke<RealtimeAvStatus>("realtime_av_add_folder", { path }));
      } catch (e) {
        setRealtimeError(String(e));
      }
    }
  }

  async function removeWatchFolder(path: string) {
    try {
      setRealtime(await invoke<RealtimeAvStatus>("realtime_av_remove_folder", { path }));
    } catch (e) {
      setRealtimeError(String(e));
    }
  }

  const threats = scanning ? liveThreats : (result?.threats ?? []);

  return (
    <PageShell
      title="Antivirus"
      description="Signature-based malware scanning through ClamAV. Bulwark shells out to it rather than reimplementing detection."
      action={
        <Button onClick={runScan} disabled={scanning || unavailable}>
          {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Bug className="h-4 w-4" />}
          {scanning
            ? "Scanning…"
            : customPaths.length > 0
              ? `Scan ${customPaths.length} item${customPaths.length === 1 ? "" : "s"}`
              : "Run a virus scan"}
        </Button>
      }
    >
      <div className="flex flex-col gap-8">
        {/* Engine state first: whether ClamAV is even installed, and whether its signatures are
            current, decide whether anything below this is worth trusting. */}
        {clamav && !clamav.version && (
          <Callout tone="warning">
            <div className="font-medium">ClamAV isn't installed, so there's nothing to scan with.</div>
            {clamav.install_command && (
              <div className="mt-1.5 rounded bg-card/70 px-2 py-1 font-mono text-xs text-foreground">
                {clamav.install_command}
              </div>
            )}
          </Callout>
        )}
        {clamav?.version && dbStale && (
          <Callout tone="warning">
            Signatures are more than 14 days old (built {clamav.version.database_date}). Run{" "}
            <code>freshclam</code> before trusting a scan.
          </Callout>
        )}
        {clamav?.version && !dbStale && (
          <Callout tone="success">
            <span className="font-medium">ClamAV {clamav.version.engine_version} — signatures current</span>
            <span className="ml-2 font-mono text-xs opacity-80">
              db {clamav.version.database_version} · built {clamav.version.database_date}
            </span>
          </Callout>
        )}

        <section>
          <SectionLabel>Real-time protection</SectionLabel>
          <div className="flex flex-col gap-3.5 rounded-lg border border-border bg-card p-4">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div
                  className={cn(
                    "flex h-9 w-9 shrink-0 items-center justify-center rounded-full",
                    realtime?.enabled ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground",
                  )}
                >
                  <Eye className={cn("h-4 w-4", realtime?.enabled && "animate-pulse")} strokeWidth={1.75} />
                </div>
                <div>
                  <div className="text-sm font-medium">
                    {realtime?.enabled ? "Watching for new files" : "Not watching"}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    Scans files the moment they land in a watched folder
                  </div>
                </div>
              </div>
              <Switch
                checked={realtime?.enabled ?? false}
                disabled={realtimeBusy || !realtime || unavailable}
                onCheckedChange={toggleRealtime}
                aria-label="Real-time protection"
              />
            </div>

            {unavailable && (
              <p className="text-xs text-muted-foreground">
                Install ClamAV to turn this on — the watcher has no engine to scan with.
              </p>
            )}

            {realtimeError && <Callout tone="critical">{realtimeError}</Callout>}

            {realtime && (
              <>
                {realtime.watched_paths.length > 0 ? (
                  <PathChips paths={realtime.watched_paths} onRemove={removeWatchFolder} />
                ) : (
                  <p className="text-xs text-muted-foreground">No folders are being watched yet.</p>
                )}

                <PathDropZone
                  active={active}
                  mode="folders-only"
                  label="Drop a folder here to watch it"
                  onPaths={addWatchFolders}
                />

                {realtime.enabled && (
                  <div className="flex items-center gap-4 font-mono text-xs text-muted-foreground">
                    <span>{realtime.files_scanned} scanned live</span>
                    {realtime.threats_found > 0 && (
                      <span className="font-semibold" style={{ color: "var(--sev-critical-fg)" }}>
                        {realtime.threats_found} threat{realtime.threats_found === 1 ? "" : "s"} found
                      </span>
                    )}
                  </div>
                )}

                {realtime.recent_threats.length > 0 && (
                  <div className="flex flex-col gap-2">
                    {realtime.recent_threats.map((t, i) => (
                      <ThreatRow key={`${t.path}-${i}`} threat={t} animate={liveDetected.has(t.path)} />
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        </section>

        <section>
          <SectionLabel>Manual scan</SectionLabel>
          <p className="mb-3 text-sm leading-relaxed text-muted-foreground">
            Checks Downloads and the world-writable temp directories (<code className="font-mono">/tmp</code>,{" "}
            <code className="font-mono">/var/tmp</code>) by default — not the whole filesystem. Drop in your
            own targets to scan those instead.
          </p>

          <PathDropZone
            active={active}
            mode="files-and-folders"
            label="Drop files or a folder here to scan them instead"
            onPaths={(paths) => setCustomPaths((prev) => Array.from(new Set([...prev, ...paths])))}
          />

          {customPaths.length > 0 && (
            <div className="mt-2.5 flex flex-col gap-1.5">
              <PathChips
                paths={customPaths}
                onRemove={(p) => setCustomPaths((prev) => prev.filter((x) => x !== p))}
              />
              <button
                type="button"
                className="self-start text-xs text-muted-foreground underline-offset-2 hover:underline"
                onClick={() => setCustomPaths([])}
              >
                Clear these and use the default targets
              </button>
            </div>
          )}

          {scanning && (
            <div className="mt-4 rounded-md border border-border bg-muted/40 px-3 py-2.5">
              <div className="flex items-center justify-between gap-3">
                <span className="font-mono text-xs font-medium">
                  {filesScanned} file{filesScanned === 1 ? "" : "s"} scanned
                </span>
                {liveThreats.length > 0 && (
                  <span
                    className="font-mono text-xs font-semibold"
                    style={{ color: "var(--sev-critical-fg)" }}
                  >
                    {liveThreats.length} threat{liveThreats.length === 1 ? "" : "s"} so far
                  </span>
                )}
              </div>
              {currentFile && (
                <div className="mt-1 truncate font-mono text-[11px] text-muted-foreground">{currentFile}</div>
              )}
            </div>
          )}

          {error && (
            <Callout tone="critical" className="mt-4">
              {error}
            </Callout>
          )}

          {result?.clamscan_available && (
            <div
              className="rail mt-4 flex items-center gap-3 rounded-md border border-border bg-card py-3.5 pr-4"
              style={railStyle(result.threats.length > 0 ? "critical" : "resolved")}
            >
              {result.threats.length === 0 ? (
                <ShieldCheck
                  className="h-6 w-6 shrink-0"
                  style={{ color: "var(--sev-resolved)" }}
                  strokeWidth={1.75}
                />
              ) : (
                <ShieldX
                  className="h-6 w-6 shrink-0"
                  style={{ color: "var(--sev-critical)" }}
                  strokeWidth={1.75}
                />
              )}
              <div className="min-w-0">
                <div className="text-sm font-semibold">
                  {result.threats.length === 0
                    ? "No threats found"
                    : `${result.threats.length} threat${result.threats.length === 1 ? "" : "s"} found`}
                </div>
                <div className="truncate font-mono text-xs text-muted-foreground">
                  {result.files_scanned ?? filesScanned} files scanned in {result.scanned_paths.join(", ")}
                </div>
              </div>
            </div>
          )}

          {threats.length > 0 && (
            <div className="mt-2.5 flex flex-col gap-2">
              {threats.map((t, i) => (
                // A manual scan's detections always arrive live, in front of the user.
                <ThreatRow key={`${t.path}-${i}`} threat={t} animate />
              ))}
            </div>
          )}
        </section>
      </div>
    </PageShell>
  );
}

function ThreatRow({ threat, animate }: { threat: ThreatDetection; animate: boolean }) {
  return (
    <div
      className={cn(
        "rail flex items-center justify-between gap-3 rounded-md border border-border bg-card py-2.5 pr-3",
        animate && "finding-enter",
      )}
      style={railStyle("critical")}
    >
      <span className="min-w-0 truncate font-mono text-xs" title={threat.path}>
        {threat.path}
      </span>
      <span className="shrink-0 font-mono text-xs font-semibold" style={{ color: "var(--sev-critical-fg)" }}>
        {threat.signature}
      </span>
    </div>
  );
}

function PathChips({ paths, onRemove }: { paths: string[]; onRemove: (path: string) => void }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {paths.map((p) => (
        <span
          key={p}
          title={p}
          className="flex items-center gap-1 rounded-full border border-border bg-muted/50 py-0.5 pr-1 pl-2.5 text-xs"
        >
          <span className="max-w-48 truncate font-mono">{p}</span>
          <button
            type="button"
            onClick={() => onRemove(p)}
            aria-label={`Stop using ${p}`}
            className="rounded-full p-0.5 text-muted-foreground hover:bg-background hover:text-foreground"
          >
            <X className="h-3 w-3" />
          </button>
        </span>
      ))}
    </div>
  );
}
