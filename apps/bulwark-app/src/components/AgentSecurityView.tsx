import { useEffect, useMemo, useState } from "react";
import { Channel, invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Bot, Eraser, Loader2, ScanSearch, ShieldCheck, Square, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { CommandBlock } from "@/components/ui/copy-button";
import { Switch } from "@/components/ui/switch";
import { PageShell, SectionLabel } from "@/components/PageShell";
import { PathDropZone } from "@/components/PathDropZone";
import { FileLocation } from "@/components/FileLocation";
import { SeverityLabel, railStyle, SEVERITY_ORDER, type Severity } from "@/components/Severity";
import { useRevision } from "@/lib/revision";
import { cn } from "@/lib/utils";

interface AiFinding {
  id: string;
  rule_id: string;
  severity: Severity;
  tool: string;
  title: string;
  explanation: string;
  fix_hint: string;
  file: string;
  line: number | null;
  evidence: string;
  references: string[];
  redactable: boolean;
}

interface AiSnapshot {
  started_at: string;
  host_fingerprint: string;
  workspaces_scanned: string[];
  artifacts_scanned: number;
  workspaces_capped: boolean;
  findings: AiFinding[];
}

interface AiSettings {
  configured_roots: string[];
  excluded_roots: string[];
  auto_scan_enabled: boolean;
}

interface RedactionReport {
  dry_run: boolean;
  entries: { path: string; secrets_redacted: number; applied: boolean }[];
  total_secrets: number;
  errors: string[];
}

type AiScanEvent =
  | { event: "artifact"; data: { path: string } }
  | { event: "finding"; data: AiFinding }
  | {
      event: "complete";
      data: {
        totalFindings: number;
        artifactsScanned: number;
        workspacesScanned: number;
        workspacesCapped: boolean;
        cancelled: boolean;
        errors: string[];
      };
    }
  | { event: "error"; data: { message: string } };

interface Complete {
  artifactsScanned: number;
  workspacesScanned: number;
  workspacesCapped: boolean;
  errors: string[];
}

export function AgentSecurityView({ active }: { active: boolean }) {
  const { revision, bump, running } = useRevision();
  // True when an agent scan is running here or was launched from the Overview.
  const agentRunning = running.has("agent");

  const [findings, setFindings] = useState<AiFinding[]>([]);
  const [summary, setSummary] = useState<Complete | null>(null);
  const [hasScanned, setHasScanned] = useState(false);

  const [scanning, setScanning] = useState(false);
  const [currentFile, setCurrentFile] = useState<string | null>(null);
  const [artifactCount, setArtifactCount] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const [settings, setSettings] = useState<AiSettings | null>(null);
  const [redacting, setRedacting] = useState(false);
  const [redactResult, setRedactResult] = useState<RedactionReport | null>(null);
  // A stopped sweep saw only part of the machine, and wasn't persisted. Say so, rather than
  // letting a partial "0 findings" read as an all-clear.
  const [cancelled, setCancelled] = useState(false);

  // Restore the last (possibly background) scan whenever this tab is re-read — first mount, a
  // background `ai_security:tick`, or any other revision bump.
  useEffect(() => {
    invoke<{ snapshot: AiSnapshot | null }>("ai_scan_snapshot")
      .then(({ snapshot }) => {
        if (!snapshot) {
          setHasScanned(false);
          return;
        }
        setFindings(snapshot.findings);
        setSummary({
          artifactsScanned: snapshot.artifacts_scanned,
          workspacesScanned: snapshot.workspaces_scanned.length,
          workspacesCapped: snapshot.workspaces_capped,
          errors: [],
        });
        setHasScanned(true);
      })
      .catch(() => setHasScanned(false));
    invoke<AiSettings>("ai_settings_get")
      .then(setSettings)
      .catch(() => setSettings(null));
  }, [revision]);

  useEffect(() => {
    // A background auto-scan can change stored state with no user action — refresh on its tick,
    // the same mechanism the config dashboard uses for `monitoring:tick`.
    const unlisten = listen("ai_security:tick", bump);
    return () => {
      unlisten.then((u) => u());
    };
  }, [bump]);

  const redactableFiles = useMemo(
    () => Array.from(new Set(findings.filter((f) => f.redactable).map((f) => f.file))),
    [findings],
  );
  const secretCount = useMemo(() => findings.filter((f) => f.redactable).length, [findings]);

  async function stopScan() {
    setCancelled(true);
    try {
      await invoke("scan_cancel");
    } catch (e) {
      setError(String(e));
    }
  }

  async function runScan() {
    setScanning(true);
    setCancelled(false);
    setError(null);
    setRedactResult(null);
    setCurrentFile(null);
    setArtifactCount(0);
    const streamed: AiFinding[] = [];

    const onEvent = new Channel<AiScanEvent>();
    onEvent.onmessage = (msg) => {
      switch (msg.event) {
        case "artifact":
          setCurrentFile(msg.data.path);
          setArtifactCount((n) => n + 1);
          break;
        case "finding":
          streamed.push(msg.data);
          break;
        case "complete":
          if (msg.data.cancelled) setCancelled(true);
          setFindings([...streamed]);
          setSummary({
            artifactsScanned: msg.data.artifactsScanned,
            workspacesScanned: msg.data.workspacesScanned,
            workspacesCapped: msg.data.workspacesCapped,
            errors: msg.data.errors,
          });
          setHasScanned(true);
          setScanning(false);
          // Persisted server-side; let other views (Overview count etc.) re-read.
          bump();
          break;
        case "error":
          setError(msg.data.message);
          setScanning(false);
          break;
      }
    };

    try {
      await invoke("ai_scan_start", { onEvent, targets: undefined });
    } catch (e) {
      setError(String(e));
      setScanning(false);
    }
  }

  async function redactAll() {
    if (redactableFiles.length === 0) return;
    await applyRedaction(redactableFiles);
  }

  /**
   * Rewrites the secrets out of exactly `paths` and prunes the findings they resolved. Shared by
   * the bulk button (every redactable file) and the per-issue button (one file), so a single-file
   * redact goes through the same allowlist-checked command and the same post-redact bookkeeping —
   * there is no second, weaker path.
   *
   * The backend intersects `paths` against the files the latest scan flagged as redactable and
   * drops anything else; passing one path here narrows what is touched, it does not bypass that.
   */
  async function applyRedaction(paths: string[]) {
    setRedacting(true);
    setError(null);
    try {
      const report = await invoke<RedactionReport>("ai_redact", {
        paths,
        apply: true,
      });
      setRedactResult(report);
      // The secrets in these files are now gone — drop their leak findings from the list right away
      // for instant feedback, rather than re-running a whole-machine scan (which would re-walk the
      // entire home directory, minutes on a large one) to rediscover what we just fixed.
      const redactedFiles = new Set(
        report.entries.filter((e) => e.applied && e.secrets_redacted > 0).map((e) => e.path),
      );
      setFindings((prev) => prev.filter((f) => !(f.redactable && redactedFiles.has(f.file))));
      // Then bump the revision so *every* view — this tab and the Overview's Agent tile/count —
      // re-reads the persisted snapshot the backend already pruned. Without this the Overview kept
      // counting the just-redacted secrets until an unrelated refresh, and it also makes the
      // authoritative pruned snapshot, not the optimistic local filter above, the final word.
      bump();
    } catch (e) {
      setError(String(e));
    } finally {
      setRedacting(false);
    }
  }

  async function updateSettings(patch: Partial<AiSettings>) {
    // Callers (the auto-scan Switch, the folder drop zones) are fire-and-forget, so a rejection here
    // would otherwise be an uncaught promise with no user feedback — surface it in the error callout
    // like every other action on this tab.
    try {
      const next = await invoke<AiSettings>("ai_settings_set", {
        configuredRoots: patch.configured_roots,
        excludedRoots: patch.excluded_roots,
        autoScanEnabled: patch.auto_scan_enabled,
      });
      setSettings(next);
    } catch (e) {
      setError(String(e));
    }
  }

  const sorted = useMemo(
    () =>
      [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)),
    [findings],
  );

  return (
    <PageShell
      title="AI assistants"
      description="Scans the AI coding assistants on this machine — Claude Code, Cursor, Copilot, Codex and more — for secrets leaked into context or transcripts and for agent configuration that a prompt injection could turn into code execution."
      action={
        scanning ? (
          <Button onClick={stopScan} variant="outline">
            <Square className="h-3.5 w-3.5 fill-current" />
            Stop
          </Button>
        ) : agentRunning ? (
          <Button variant="outline" disabled>
            <Loader2 className="h-4 w-4 animate-spin" />
            Scanning…
          </Button>
        ) : (
          <Button onClick={runScan}>
            <ScanSearch className="h-4 w-4" />
            {hasScanned ? "Re-scan" : "Scan AI artifacts"}
          </Button>
        )
      }
    >
      <div className="flex flex-col gap-8">
        <Callout tone="info">
          Bulwark reads these files but never changes them on its own. Redaction is a separate, explicit step
          — and when you run it, the original is backed up first (owner-only) and each file's permissions are
          preserved.
        </Callout>

        {error && <Callout tone="critical">{error}</Callout>}

        {cancelled && !scanning && (
          <Callout tone="warning">
            <span className="font-medium">Scan stopped.</span> These results are partial and weren't saved —
            the artifacts that weren't reached have proved nothing either way.
          </Callout>
        )}

        {redactResult && (
          <Callout tone="success">
            Redacted {redactResult.total_secrets} secret{redactResult.total_secrets === 1 ? "" : "s"} across{" "}
            {redactResult.entries.length} file{redactResult.entries.length === 1 ? "" : "s"}. Originals were
            backed up. Remember to <strong>rotate</strong> the exposed credentials — redaction removes them
            from disk, it can't un-leak them.
          </Callout>
        )}

        {scanning && (
          <div className="rounded-md border border-border bg-muted/40 px-3 py-2.5">
            <div className="font-mono text-xs font-medium">
              {artifactCount} artifact{artifactCount === 1 ? "" : "s"} examined
            </div>
            {currentFile && (
              <div className="mt-1 truncate font-mono text-[11px] text-muted-foreground">{currentFile}</div>
            )}
          </div>
        )}

        {agentRunning && !scanning && (
          <div className="flex items-center gap-2.5 rounded-md border border-border bg-muted/40 px-3 py-2.5">
            <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-muted-foreground" />
            <div className="font-mono text-[11px] text-muted-foreground">
              Scanning AI artifacts (started from Overview)…
            </div>
          </div>
        )}

        {summary && !scanning && !agentRunning && (
          <div className="flex flex-wrap items-center gap-x-6 gap-y-1 font-mono text-xs text-muted-foreground">
            <span>
              {summary.workspacesScanned} workspace{summary.workspacesScanned === 1 ? "" : "s"}
            </span>
            <span>
              {summary.artifactsScanned} artifact{summary.artifactsScanned === 1 ? "" : "s"} scanned
            </span>
            <span>
              {findings.length} finding{findings.length === 1 ? "" : "s"}
            </span>
          </div>
        )}

        {summary?.workspacesCapped && (
          <Callout tone="warning">
            The workspace limit was reached, so some projects weren't scanned. Add specific roots below, or
            exclude large trees you don't need scanned.
          </Callout>
        )}

        {secretCount > 0 && (
          <Callout
            tone="warning"
            action={
              <Button size="sm" variant="outline" onClick={redactAll} disabled={redacting}>
                {redacting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Eraser className="h-4 w-4" />}
                {redacting ? "Redacting…" : `Redact ${secretCount} secret${secretCount === 1 ? "" : "s"}`}
              </Button>
            }
          >
            <span className="font-medium">
              {secretCount} exposed secret{secretCount === 1 ? "" : "s"} in {redactableFiles.length} file
              {redactableFiles.length === 1 ? "" : "s"}
            </span>{" "}
            can be redacted in place. Rotate them regardless — a leaked key stays leaked.
          </Callout>
        )}

        <section>
          <SectionLabel>Findings</SectionLabel>
          {sorted.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border py-14 text-center">
              {hasScanned ? (
                <ShieldCheck className="mx-auto h-7 w-7 text-muted-foreground/40" strokeWidth={1.5} />
              ) : (
                <Bot className="mx-auto h-7 w-7 text-muted-foreground/40" strokeWidth={1.5} />
              )}
              <p className="mt-3 text-sm font-medium">
                {hasScanned ? "No AI security issues found." : "No AI scan has run yet."}
              </p>
              <p className="mt-1 text-sm text-muted-foreground">
                {hasScanned
                  ? "No leaked secrets or dangerous agent config across the artifacts scanned."
                  : "Run a scan to check your assistants' context, memory, MCP configs and transcripts."}
              </p>
            </div>
          ) : (
            <div className="flex flex-col gap-2.5">
              {sorted.map((f) => (
                <AiFindingCard
                  key={f.id}
                  f={f}
                  busy={redacting}
                  onRedact={f.redactable ? () => applyRedaction([f.file]) : undefined}
                />
              ))}
            </div>
          )}
        </section>

        <DiscoverySettings settings={settings} onChange={updateSettings} active={active} />
      </div>
    </PageShell>
  );
}

/**
 * One agent-security finding.
 *
 * A `redactable` finding carries its own Redact button, which acts on **this file only**. It exists
 * because the bulk "Redact N secrets" button was previously the only way to act: a user who wanted
 * one secret gone from one transcript had to rewrite every flagged file at once, or do it by hand.
 *
 * Like every other mutating action in the app it previews before it writes: the first click runs
 * the redactor with `apply = false` and reports how many secrets it would remove from this file;
 * only a second, explicit click rewrites it. Non-redactable findings get no button — a live key in
 * a `.env` is reported so you rotate it, and is deliberately never rewritten, because something
 * reads that value back and redacting it would destroy the working config along with the only copy
 * of the key.
 */
function AiFindingCard({
  f,
  busy,
  onRedact,
}: {
  f: AiFinding;
  busy?: boolean;
  /** Only supplied for redactable findings; absent means no button is drawn at all. */
  onRedact?: () => Promise<void>;
}) {
  const [preview, setPreview] = useState<RedactionReport | null>(null);
  const [pending, setPending] = useState(false);
  const [cardError, setCardError] = useState<string | null>(null);

  async function runPreview() {
    setPending(true);
    setCardError(null);
    try {
      setPreview(await invoke<RedactionReport>("ai_redact", { paths: [f.file], apply: false }));
    } catch (e) {
      setCardError(String(e));
    } finally {
      setPending(false);
    }
  }

  const wouldRedact = preview?.total_secrets ?? 0;

  return (
    <article
      className="rail rail-dim rounded-lg border border-border bg-card py-3.5 pr-4"
      style={railStyle(f.severity)}
    >
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
        <span className="font-mono text-xs font-semibold tracking-tight text-muted-foreground">
          {f.rule_id}
        </span>
        <SeverityLabel severity={f.severity} />
        <span className="rounded-full border border-border bg-muted/50 px-2 py-0.5 font-mono text-[10px] text-muted-foreground">
          {f.tool}
        </span>
        {f.redactable && (
          <span
            className="rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold"
            style={{ background: "var(--sev-critical-tint)", color: "var(--sev-critical-fg)" }}
          >
            REDACTABLE
          </span>
        )}
      </div>
      <h3 className="mt-1.5 text-sm font-semibold">{f.title}</h3>
      <FileLocation file={f.file} line={f.line} />
      <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">{f.explanation}</p>
      {f.evidence && (
        <div className="mt-2 inline-block rounded bg-muted/60 px-2 py-1 font-mono text-[11px] text-foreground">
          {f.evidence}
        </div>
      )}
      <CommandBlock command={f.fix_hint} className="mt-2.5" />

      {onRedact && (
        <div className="mt-2.5">
          {cardError && (
            <Callout tone="critical" className="mb-2">
              {cardError}
            </Callout>
          )}
          {preview === null ? (
            <Button size="sm" variant="outline" onClick={runPreview} disabled={pending || busy}>
              {pending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Eraser className="h-3.5 w-3.5" />
              )}
              Redact this file
            </Button>
          ) : (
            <div className="rounded-md border border-border bg-muted/40 p-3">
              <p className="text-xs font-medium">
                {wouldRedact === 0
                  ? "Nothing left to redact in this file."
                  : `${wouldRedact} secret${wouldRedact === 1 ? "" : "s"} would be removed from this file. Nothing has been written yet.`}
              </p>
              {preview.errors.length > 0 && (
                <ul className="mt-1.5 space-y-0.5 text-[11px] text-[var(--sev-critical-fg)]">
                  {preview.errors.map((e) => (
                    <li key={e}>{e}</li>
                  ))}
                </ul>
              )}
              <p className="mt-1.5 text-[11px] text-muted-foreground">
                The original is backed up first. Redaction removes the secret from disk — it can't un-leak it,
                so <strong>rotate</strong> the credential either way.
              </p>
              <div className="mt-2.5 flex flex-wrap items-center gap-2">
                {wouldRedact > 0 && (
                  <Button size="sm" onClick={() => onRedact()} disabled={busy}>
                    {busy ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <Eraser className="h-3.5 w-3.5" />
                    )}
                    Redact {wouldRedact} secret{wouldRedact === 1 ? "" : "s"}
                  </Button>
                )}
                <Button size="sm" variant="ghost" onClick={() => setPreview(null)} disabled={busy}>
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </div>
      )}

      {f.references.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {f.references.map((r) => (
            <span key={r} className="font-mono text-[10px] text-muted-foreground/70">
              {r}
            </span>
          ))}
        </div>
      )}
    </article>
  );
}

function DiscoverySettings({
  settings,
  onChange,
  active,
}: {
  settings: AiSettings | null;
  onChange: (patch: Partial<AiSettings>) => void;
  active: boolean;
}) {
  if (!settings) return null;
  return (
    <section>
      <SectionLabel>Discovery &amp; automation</SectionLabel>
      <div className="flex flex-col gap-4 rounded-lg border border-border bg-card p-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <div className="text-sm font-medium">Automatic background scans</div>
            <div className="text-xs text-muted-foreground">
              Re-scans your workspaces periodically and notifies you when a new secret or risky config
              appears.
            </div>
          </div>
          <Switch
            checked={settings.auto_scan_enabled}
            onCheckedChange={(v) => onChange({ auto_scan_enabled: v })}
            aria-label="Automatic background scans"
          />
        </div>

        <div>
          <div className="mb-1.5 text-sm font-medium">Extra folders to scan</div>
          <p className="mb-2 text-xs text-muted-foreground">
            Bulwark already sweeps the usual code roots (~/Workspaces, ~/Projects, ~/src, …) and every project
            your assistants have opened. Add a root here if your code lives somewhere unusual.
          </p>
          {settings.configured_roots.length > 0 && (
            <PathChips
              paths={settings.configured_roots}
              onRemove={(p) =>
                onChange({ configured_roots: settings.configured_roots.filter((x) => x !== p) })
              }
            />
          )}
          <PathDropZone
            active={active}
            mode="folders-only"
            label="Drop a folder here to also scan it"
            className="mt-2"
            onPaths={(paths) =>
              onChange({
                configured_roots: Array.from(new Set([...settings.configured_roots, ...paths])),
              })
            }
          />
        </div>

        <div>
          <div className="mb-1.5 text-sm font-medium">Folders to exclude</div>
          {settings.excluded_roots.length > 0 && (
            <PathChips
              paths={settings.excluded_roots}
              onRemove={(p) => onChange({ excluded_roots: settings.excluded_roots.filter((x) => x !== p) })}
            />
          )}
          <PathDropZone
            active={active}
            mode="folders-only"
            label="Drop a folder here to skip it"
            className="mt-2"
            onPaths={(paths) =>
              onChange({ excluded_roots: Array.from(new Set([...settings.excluded_roots, ...paths])) })
            }
          />
        </div>
      </div>
    </section>
  );
}

function PathChips({ paths, onRemove }: { paths: string[]; onRemove: (path: string) => void }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {paths.map((p) => (
        <span
          key={p}
          title={p}
          className={cn(
            "flex items-center gap-1 rounded-full border border-border bg-muted/50 py-0.5 pr-1 pl-2.5 text-xs",
          )}
        >
          <span className="max-w-48 truncate font-mono">{p}</span>
          <button
            type="button"
            onClick={() => onRemove(p)}
            aria-label={`Remove ${p}`}
            className="rounded-full p-0.5 text-muted-foreground hover:bg-background hover:text-foreground"
          >
            <X className="h-3 w-3" />
          </button>
        </span>
      ))}
    </div>
  );
}
