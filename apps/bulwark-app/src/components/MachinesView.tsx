import { useCallback, useEffect, useMemo, useState, type CSSProperties } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  ArrowLeft,
  Bell,
  ChevronRight,
  Eye,
  KeyRound,
  Loader2,
  Network,
  Plus,
  RefreshCw,
  Server,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Callout, type CalloutTone } from "@/components/ui/callout";
import { CommandBlock } from "@/components/ui/copy-button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { type Finding } from "@/components/FindingCard";
import { PageShell, SectionLabel } from "@/components/PageShell";
import { SEVERITY_ORDER, SeverityDot, severityLabel } from "@/components/Severity";
import { AddMachineDialog } from "@/components/machines/AddMachineDialog";
import { OsIcon } from "@/components/machines/OsIcon";
import { CategoryFindings, groupFindingsByCategory } from "@/components/CategoryFindings";
import { ConnectionCheck } from "@/components/machines/ConnectionCheck";
import { Field, HealthPill, Modal, RichText } from "@/components/machines/parts";
import {
  ago,
  connectionState,
  scanProblem,
  type Dot,
  HEALTH,
  HEALTH_ORDER,
  INTERVALS,
  intervalLabel,
  openTotal,
  targetLabel,
  until,
  type Counts,
  type ErrorKind,
  type Machine,
  type MachinesOverview,
  type SshSuggestions,
} from "@/lib/machines";
import { cn } from "@/lib/utils";

/**
 * Other computers, watched over SSH.
 *
 * The model is deliberately agentless — Bulwark connects with the user's own SSH access, runs its
 * checks, and leaves — so the page's job is mostly to make *connection state* legible: which
 * machines are current, which are stale, which can't be reached and why, with the fix one click
 * away. A machine Bulwark couldn't reach is never shown as clean (see `fleet::health`).
 */
export function MachinesView({
  active = true,
  onNavigate,
}: {
  active?: boolean;
  onNavigate?: (view: "settings") => void;
}) {
  const [overview, setOverview] = useState<MachinesOverview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  // Leaving the tab returns it to the machine list, so coming back always starts from the overview
  // rather than the last machine opened. Adjusted during render (React's pattern for "reset state
  // when a prop changes") rather than in an effect, which would render the stale detail first.
  const [wasActive, setWasActive] = useState(active);
  if (active !== wasActive) {
    setWasActive(active);
    if (!active) setSelected(null);
  }
  const [adding, setAdding] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  const refresh = useCallback(() => {
    invoke<MachinesOverview>("machines_list")
      .then((o) => {
        setOverview(o);
        setError(null);
      })
      .catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    refresh();
    const un = listen("machines:changed", refresh);
    return () => {
      un.then((f) => f());
    };
  }, [refresh]);

  useEffect(() => {
    if (!active) return;
    refresh();
    const poll = setInterval(refresh, 15000);
    const tick = setInterval(() => setNow(Date.now()), 30000);
    return () => {
      clearInterval(poll);
      clearInterval(tick);
    };
  }, [active, refresh]);

  const machines = useMemo(
    () =>
      [...(overview?.machines ?? [])].sort(
        (a, b) =>
          HEALTH_ORDER.indexOf(a.health) - HEALTH_ORDER.indexOf(b.health) || a.name.localeCompare(b.name),
      ),
    [overview],
  );
  const current = machines.find((m) => m.id === selected) ?? null;

  if (current) {
    return (
      <MachineDetail
        machine={current}
        now={now}
        onBack={() => setSelected(null)}
        onChanged={refresh}
        onRemoved={() => {
          setSelected(null);
          refresh();
        }}
      />
    );
  }

  const attention = machines.filter(
    (m) => m.health === "needs_attention" || m.health === "unreachable",
  ).length;
  const risky = machines.reduce((n, m) => n + m.counts.critical + m.counts.high, 0);

  return (
    <PageShell
      title="Remote machines"
      description="Keep watch over your servers and other computers over SSH. No agent runs on them, and nothing listens on them between scans."
      action={
        machines.length > 0 && (
          <>
            <Button
              variant="outline"
              onClick={() => invoke("machines_scan_all").then(refresh)}
              disabled={machines.every((m) => m.scanning)}
            >
              <RefreshCw /> Scan all
            </Button>
            <Button onClick={() => setAdding(true)}>
              <Plus /> Add machine
            </Button>
          </>
        )
      }
    >
      {error && <Callout tone="critical">{error}</Callout>}

      {overview && machines.length === 0 && <EmptyState onAdd={() => setAdding(true)} />}

      {machines.length > 0 && (
        <>
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-muted-foreground">
              {machines.length} machine{machines.length === 1 ? "" : "s"}
              {risky > 0 && (
                <>
                  {" · "}
                  <span style={{ color: "var(--sev-high-fg)" }}>
                    {risky} critical or high issue{risky === 1 ? "" : "s"}
                  </span>
                </>
              )}
              {attention > 0 && (
                <>
                  {" · "}
                  <span style={{ color: "var(--sev-critical-fg)" }}>
                    {attention} need{attention === 1 ? "s" : ""} attention
                  </span>
                </>
              )}
            </p>
            <label className="flex items-center gap-2 text-sm text-muted-foreground">
              Scheduled scans
              <Switch
                checked={overview?.enabled ?? true}
                onCheckedChange={(v) => invoke("machines_set_enabled", { enabled: v }).then(refresh)}
              />
            </label>
          </div>
          {overview && !overview.enabled && (
            <Callout tone="warning" className="mb-4">
              Scheduled scans are paused for every machine. Scan now still works.
            </Callout>
          )}
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {machines.map((m) => (
              <MachineCard key={m.id} machine={m} now={now} onOpen={() => setSelected(m.id)} />
            ))}
          </div>
          <button
            type="button"
            onClick={() => {
              onNavigate?.("settings");
              // Land on the Alerts section, not the top of Settings. The view is mounted (and
              // un-hidden) by the navigation, so wait a frame before scrolling.
              setTimeout(
                () =>
                  document.getElementById("alerts")?.scrollIntoView({ behavior: "smooth", block: "start" }),
                60,
              );
            }}
            className="mt-6 flex items-center gap-2 rounded-md text-sm text-muted-foreground hover:text-foreground outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
          >
            <Bell className="h-4 w-4" />
            Get alerts on Telegram or by e-mail — set up in Settings → Alerts
          </button>
        </>
      )}

      {adding && (
        <AddMachineDialog
          onClose={() => {
            setAdding(false);
            refresh();
          }}
          onAdded={(id) => {
            setAdding(false);
            refresh();
            setSelected(id);
          }}
        />
      )}
    </PageShell>
  );
}

function EmptyState({ onAdd }: { onAdd: () => void }) {
  const points = [
    {
      icon: Server,
      title: "No agent",
      body: "Bulwark connects over SSH, runs its checks, and leaves. No open port, no server to run — and a Linux server needs nothing installed.",
    },
    {
      icon: KeyRound,
      title: "Your SSH, your way",
      body: "Use an ~/.ssh/config alias, your key or agent, a jump host — or a password once, and Bulwark sets up its own restricted key.",
    },
    {
      icon: ShieldCheck,
      title: "Every connection verified",
      body: "You confirm each machine's identity once; a changed host key stops scans and alerts you.",
    },
  ];
  return (
    <div className="flex flex-col items-start gap-6 rounded-xl border border-dashed border-border px-8 py-10">
      <div>
        <h2 className="font-heading text-lg font-semibold">Watch more than this computer</h2>
        <p className="mt-1.5 max-w-xl text-sm leading-relaxed text-muted-foreground">
          Add a server, a home lab box or a teammate's workstation you can SSH into. Bulwark scans it on a
          schedule and shows its issues here, with the same explanations and fixes.
        </p>
      </div>
      <div className="grid w-full gap-4 md:grid-cols-3">
        {points.map(({ icon: Icon, title, body }) => (
          <div key={title} className="flex flex-col gap-1.5">
            <Icon className="h-5 w-5 text-primary" strokeWidth={1.75} />
            <div className="text-sm font-medium">{title}</div>
            <p className="text-sm leading-relaxed text-muted-foreground">{body}</p>
          </div>
        ))}
      </div>
      <Button onClick={onAdd}>
        <Plus /> Add your first machine
      </Button>
    </div>
  );
}

function CountChips({ counts }: { counts: Counts }) {
  const shown = SEVERITY_ORDER.filter((s) => counts[s] > 0);
  if (shown.length === 0) return <span className="text-sm text-muted-foreground">No open issues</span>;
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
      {shown.map((s) => (
        <span key={s} className="inline-flex items-center gap-1.5 text-sm">
          <SeverityDot severity={s} />
          <span className="font-medium tabular-nums">{counts[s]}</span>
          <span className="text-muted-foreground">{severityLabel(s).toLowerCase()}</span>
        </span>
      ))}
    </div>
  );
}

function railStyleFor(m: Machine): CSSProperties {
  const tone = m.scanning ? "muted" : HEALTH[m.health].tone;
  return { "--rail-color": tone === "muted" ? "var(--border)" : `var(--sev-${tone})` } as CSSProperties;
}

const DOT_COLOR: Record<Dot, string> = {
  ok: "var(--sev-resolved)",
  warn: "var(--sev-medium)",
  bad: "var(--sev-critical)",
  idle: "var(--muted-foreground)",
};

function StatusDot({ dot, pulse }: { dot: Dot; pulse?: boolean }) {
  return (
    <span
      aria-hidden
      className={cn("inline-block h-2 w-2 shrink-0 rounded-full", pulse && "animate-pulse")}
      style={{ background: DOT_COLOR[dot] }}
    />
  );
}

/** "Can Bulwark reach it?" and "what did the last scan find?" are different questions with
 *  different answers — a machine can be unreachable today with yesterday's results still worth
 *  reading — so they get a line each instead of one merged status. */
function ConnectionLine({ m, now }: { m: Machine; now: number }) {
  const c = connectionState(m);
  return (
    <span className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5">
      <StatusDot dot={c.dot} pulse={m.scanning} />
      <span
        className="min-w-0"
        style={
          c.problem
            ? {
                color:
                  PROBLEM_COLOR[
                    problemTone(
                      m.last_status && m.last_status.state === "failed" ? m.last_status.kind : "other",
                    )
                  ],
              }
            : undefined
        }
      >
        {c.label}
      </span>
      {m.last_attempt_at && !m.scanning && (
        <span className="shrink-0 text-xs text-muted-foreground">· {ago(m.last_attempt_at, now)}</span>
      )}
    </span>
  );
}

function ScanLine({ m, now }: { m: Machine; now: number }) {
  const p = scanProblem(m);
  if (m.scanning) return <span className="text-muted-foreground">Scanning…</span>;
  if (p) {
    return (
      <span className="line-clamp-2" style={{ color: PROBLEM_COLOR[problemTone(p.kind)] }}>
        {p.title}
      </span>
    );
  }
  if (!m.last_success_at) return <span className="text-muted-foreground">Not scanned yet</span>;
  return (
    <span className="flex min-w-0 flex-col gap-1">
      <CountChips counts={m.counts} />
      <span className="text-xs text-muted-foreground">
        {m.checks_run != null && `${m.checks_run} check${m.checks_run === 1 ? "" : "s"} · `}
        {ago(m.last_success_at, now)}
        {m.counts.suppressed > 0 && ` · ${m.counts.suppressed} ignored`}
      </span>
    </span>
  );
}

function MachineCard({ machine: m, now, onOpen }: { machine: Machine; now: number; onOpen: () => void }) {
  return (
    <button
      type="button"
      onClick={onOpen}
      // The same severity rail findings carry, coloured by the machine's state — so the grid reads
      // peripherally the way a findings list does: what needs a person is the bright bar.
      className="group/card rail rail-dim flex flex-col gap-3 rounded-lg border border-border bg-card py-4 pr-4 text-left outline-none transition-colors hover:border-ring/50 hover:bg-muted/30 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
      style={railStyleFor(m)}
    >
      <div className="flex items-start gap-3">
        <OsIcon
          kind={m.os_kind}
          name={m.os_name}
          size={38}
          className="transition-transform group-hover/card:-rotate-3 group-hover/card:scale-105"
        />
        <div className="min-w-0 flex-1">
          <div className="truncate font-semibold">{m.name}</div>
          <div className="truncate text-xs text-muted-foreground" title={targetLabel(m)}>
            {m.os_name ?? "System not detected yet"}
          </div>
        </div>
        <HealthPill health={m.health} scanning={m.scanning} />
      </div>
      <dl className="grid grid-cols-[5.5rem_1fr] items-start gap-x-2 gap-y-2 text-sm">
        <dt className="pt-px text-xs text-muted-foreground">Connection</dt>
        <dd className="min-w-0">
          <ConnectionLine m={m} now={now} />
        </dd>
        <dt className="pt-px text-xs text-muted-foreground">Last scan</dt>
        <dd className="min-w-0">
          <ScanLine m={m} now={now} />
        </dd>
      </dl>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 border-t border-border pt-2.5 text-xs text-muted-foreground">
        <span>{m.enabled ? `Next scan ${until(m.next_due_at, now)}` : "Scheduled scans paused"}</span>
        {m.privileged && (
          <>
            <span aria-hidden>·</span>
            <span>root checks</span>
          </>
        )}
      </div>
    </button>
  );
}

// ---- detail ---------------------------------------------------------------------------------------

type Tab = "issues" | "connection" | "settings";

interface MachineFindings {
  active: Finding[];
  suppressed: Finding[];
  suppressions: { rule_id: string; reason: string; created_at: string; created_by: string }[];
  /** Single findings ignored at one place on this machine. */
  ignores?: { rule_id: string; location: string; reason: string; created_at: string; created_by: string }[];
  last_scan_at: string | null;
}

const PROBLEM_COLOR: Record<CalloutTone, string> = {
  critical: "var(--sev-critical-fg)",
  warning: "var(--sev-medium-fg)",
  success: "var(--sev-resolved-fg)",
  info: "var(--muted-foreground)",
};

function problemTone(kind: ErrorKind): CalloutTone {
  if (kind === "unsupported_os" || kind === "nothing_assessed") return "info";
  if (kind === "host_key_changed" || kind === "identity_changed") return "critical";
  return "warning";
}

function MachineDetail({
  machine: m,
  now,
  onBack,
  onChanged,
  onRemoved,
}: {
  machine: Machine;
  now: number;
  onBack: () => void;
  onChanged: () => void;
  onRemoved: () => void;
}) {
  const [tab, setTab] = useState<Tab>("issues");
  const [findings, setFindings] = useState<MachineFindings | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [findingsRev, setFindingsRev] = useState(0);
  useEffect(() => {
    invoke<MachineFindings>("machine_findings", { id: m.id })
      .then(setFindings)
      .catch((e) => setError(String(e)));
  }, [m.id, m.last_success_at, findingsRev]);

  async function act(f: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await f();
      onChanged();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  const scanNow = () => act(() => invoke("machine_scan_now", { id: m.id }));

  /** The one button that resolves the current problem, where there is one. */
  function problemAction(kind: ErrorKind) {
    switch (kind) {
      case "host_key_unknown":
      case "host_key_changed":
        return (
          <Button size="sm" variant="outline" onClick={() => setTab("connection")}>
            Review host key
          </Button>
        );
      case "auth_failed":
        return (
          <Button size="sm" variant="outline" onClick={() => setTab("connection")}>
            Set up key access
          </Button>
        );
      case "identity_changed":
        return (
          <Button
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() =>
              act(async () => {
                await invoke("machine_update", { id: m.id, patch: { reset_identity: true } });
                await invoke("machine_scan_now", { id: m.id });
              })
            }
          >
            Accept new identity
          </Button>
        );
      case "unsupported_os":
      case "nothing_assessed":
        return undefined;
      case "sudo_requires_password":
        return (
          <Button
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() =>
              act(async () => {
                await invoke("machine_update", { id: m.id, patch: { privileged: false } });
                await invoke("machine_scan_now", { id: m.id });
              })
            }
          >
            Turn off root checks
          </Button>
        );
      default:
        return (
          <Button size="sm" variant="outline" onClick={() => setTab("connection")}>
            Check connection
          </Button>
        );
    }
  }

  return (
    <PageShell
      title={m.name}
      description={
        <span className="inline-flex flex-wrap items-center gap-2">
          <OsIcon kind={m.os_kind} name={m.os_name} size={22} />
          {m.os_name && <span className="text-sm">{m.os_name}</span>}
          <span className="font-mono text-xs">{targetLabel(m)}</span>
          <HealthPill health={m.health} scanning={m.scanning} />
        </span>
      }
      action={
        <>
          <Button variant="ghost" onClick={onBack}>
            <ArrowLeft /> All machines
          </Button>
          <Button onClick={scanNow} disabled={m.scanning || busy}>
            {m.scanning ? <Loader2 className="animate-spin" /> : <RefreshCw />}
            {m.scanning ? "Scanning…" : "Scan now"}
          </Button>
        </>
      }
    >
      {error && (
        <Callout tone="critical" className="mb-4">
          {error}
        </Callout>
      )}
      {m.scanning && m.problem && (
        <Callout tone="info" className="mb-4">
          Scanning {m.name} now — the last attempt's problem ("{m.problem.title}") clears if this one
          succeeds.
        </Callout>
      )}
      {!m.scanning && m.problem && (
        <Callout tone={problemTone(m.problem.kind)} className="mb-4" action={problemAction(m.problem.kind)}>
          <div className="font-medium">{m.problem.title}</div>
          <div className="mt-1 leading-relaxed">
            <RichText text={m.problem.hint} />
          </div>
          {m.problem.detail && <div className="mt-1 font-mono text-xs opacity-80">{m.problem.detail}</div>}
        </Callout>
      )}

      <div className="mb-5 grid gap-3 md:grid-cols-2">
        <Panel
          title="Connection"
          dot={connectionState(m).dot}
          pulse={m.scanning}
          status={
            connectionState(m).problem
              ? (m.problem?.title ?? connectionState(m).label)
              : connectionState(m).label
          }
        >
          <Row label="Last attempt" value={ago(m.last_attempt_at, now)} />
          <Row
            label="Next attempt"
            value={
              !m.enabled
                ? "Paused"
                : m.health === "unsupported" && m.interval_minutes < 24 * 60
                  ? `${until(m.next_due_at, now)} · re-checked daily`
                  : m.health === "unreachable" && m.consecutive_failures > 0
                    ? `${until(m.next_due_at, now)} · retrying less often until it answers`
                    : `${until(m.next_due_at, now)} · ${intervalLabel(m.interval_minutes).toLowerCase()}`
            }
          />
          <Row
            label="Signs in with"
            value={
              m.identity_file?.includes("bulwark_ed25519")
                ? "Bulwark's restricted key"
                : (m.identity_file ?? "your SSH agent / default keys")
            }
          />
          {m.jump_host && <Row label="Through" value={m.jump_host} />}
        </Panel>
        <Panel
          title="Last scan"
          dot={
            scanProblem(m)
              ? problemTone(scanProblem(m)!.kind) === "info"
                ? "idle"
                : "warn"
              : m.last_success_at
                ? openTotal(m.counts) > 0
                  ? "warn"
                  : "ok"
                : "idle"
          }
          status={
            scanProblem(m)?.title ??
            (m.last_success_at
              ? `${openTotal(m.counts)} open issue${openTotal(m.counts) === 1 ? "" : "s"}`
              : "Not scanned yet")
          }
        >
          <Row label="Scanned" value={ago(m.last_success_at, now)} />
          <Row label="Checks run" value={m.checks_run != null ? String(m.checks_run) : "—"} />
          {m.counts.suppressed > 0 && <Row label="Ignored" value={String(m.counts.suppressed)} />}
          {m.engine && <Row label="Scanner" value={m.engine} />}
        </Panel>
      </div>

      <div role="tablist" className="mb-5 flex gap-1 border-b border-border">
        {(
          [
            ["issues", "Issues"],
            ["connection", "Connection"],
            ["settings", "Settings"],
          ] as [Tab, string][]
        ).map(([id, label]) => (
          <button
            key={id}
            role="tab"
            aria-selected={tab === id}
            onClick={() => setTab(id)}
            className={cn(
              "-mb-px rounded-t-md border-b-2 px-3 py-2 text-sm font-medium transition-colors outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50",
              tab === id
                ? "border-primary text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "issues" && (
        <IssuesTab
          machine={m}
          findings={findings}
          onChanged={() => {
            setFindingsRev((r) => r + 1);
            onChanged();
          }}
        />
      )}
      {tab === "connection" && (
        <ConnectionCheck
          machineId={m.id}
          machineName={m.name}
          privileged={m.privileged}
          onResult={(r) => {
            // A passing check on a machine with a recorded failure means the cause was just fixed
            // (key set up, host key approved…). Scan now so the stale problem clears immediately
            // instead of lingering until the next scheduled attempt.
            if (r.ok && m.problem && !m.scanning)
              void invoke("machine_scan_now", { id: m.id }).then(onChanged);
            else onChanged();
          }}
        />
      )}
      {tab === "settings" && <SettingsTab machine={m} onChanged={onChanged} onRemoved={onRemoved} />}
    </PageShell>
  );
}

function Panel({
  title,
  dot,
  pulse,
  status,
  children,
}: {
  title: string;
  dot: Dot;
  pulse?: boolean;
  status: string;
  children: React.ReactNode;
}) {
  return (
    <section className="flex flex-col gap-2.5 rounded-lg border border-border bg-card p-4">
      <h3 className="font-mono text-[11px] font-semibold tracking-widest text-muted-foreground uppercase">
        {title}
      </h3>
      <div className="flex items-center gap-2 text-sm font-semibold">
        <StatusDot dot={dot} pulse={pulse} />
        <span className="min-w-0 truncate">{status}</span>
      </div>
      <dl className="grid grid-cols-[7rem_1fr] gap-x-2 gap-y-1 text-sm">{children}</dl>
    </section>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 truncate" title={value}>
        {value}
      </dd>
    </>
  );
}

function IssuesTab({
  machine: m,
  findings,
  onChanged,
}: {
  machine: Machine;
  findings: MachineFindings | null;
  onChanged: () => void;
}) {
  // One dialog for both directions: ignoring a type, and restoring one. Both are recorded with a
  // reason in the machine's own audit log (enforced in core).
  const [dialog, setDialog] = useState<{
    mode: "ignore" | "restore";
    ruleId: string;
    title: string;
    location?: string;
  } | null>(null);
  if (!findings) return <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />;
  // Results are only ever written by a successful scan, so a machine without one has none to show.
  if (!m.last_success_at) {
    return (
      <p className="text-sm text-muted-foreground">
        {m.health === "unsupported"
          ? `There's nothing to show for ${m.name} yet — Bulwark can't scan its system. Issues will appear here once a version adds support for it.`
          : `${m.name} hasn't been scanned successfully yet. Its issues will appear here after the first scan.`}
      </p>
    );
  }
  const ignoredCount = (ruleId: string) => findings.suppressed.filter((f) => f.rule_id === ruleId).length;
  return (
    <div className="flex flex-col gap-4">
      {m.health === "stale" || m.last_status?.state === "failed" ? (
        <Callout tone="warning">
          These results are from {ago(m.last_success_at)} — the machine hasn't been scanned since, so they may
          be out of date.
        </Callout>
      ) : null}
      <div className="flex flex-col gap-2 rounded-lg border border-border bg-card p-3">
        <div className="flex items-center gap-2 text-sm font-medium">
          <Terminal className="h-4 w-4 text-muted-foreground" />
          Fixes run on {m.name}, not on this computer
        </div>
        <p className="text-sm text-muted-foreground">
          Open a session there and run the commands below each issue:
        </p>
        <CommandBlock command={m.ssh_command} />
      </div>
      {m.privileged_collectors_skipped.length > 0 && (
        <Callout tone="info">
          {m.privileged_collectors_skipped.length} check
          {m.privileged_collectors_skipped.length === 1 ? "" : "s"} that need root were skipped. Turn on root
          checks in this machine's Settings to include them.
        </Callout>
      )}
      {findings.active.length === 0 ? (
        <Callout tone="success">No open issues on {m.name}.</Callout>
      ) : (
        <GroupedIssues machine={m} findings={findings.active} onChanged={onChanged} />
      )}
      {(findings.suppressions.length > 0 || (findings.ignores?.length ?? 0) > 0) && (
        <section className="flex flex-col gap-2">
          <SectionLabel className="mb-0">Ignored on {m.name}</SectionLabel>
          <ul className="flex flex-col divide-y divide-border rounded-lg border border-border bg-card">
            {findings.suppressions.map((sup) => (
              <li key={sup.rule_id} className="flex items-start gap-3 px-4 py-3">
                <div className="min-w-0 flex-1 text-sm">
                  <div className="font-medium">
                    {findings.suppressed.find((f) => f.rule_id === sup.rule_id)?.title ?? "Issue type"}{" "}
                    <span className="whitespace-nowrap font-mono text-xs font-normal text-muted-foreground">
                      {sup.rule_id}
                    </span>
                    {ignoredCount(sup.rule_id) > 0 && (
                      <span className="ml-2 whitespace-nowrap text-muted-foreground">
                        {ignoredCount(sup.rule_id)} open issue{ignoredCount(sup.rule_id) === 1 ? "" : "s"}{" "}
                        hidden
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 text-muted-foreground">“{sup.reason}”</p>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    {sup.created_by} · {new Date(sup.created_at).toLocaleDateString()}
                  </p>
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setDialog({ mode: "restore", ruleId: sup.rule_id, title: sup.rule_id })}
                >
                  <Eye /> Stop ignoring
                </Button>
              </li>
            ))}
            {(findings.ignores ?? []).map((ig) => (
              <li key={`${ig.rule_id}@${ig.location}`} className="flex items-start gap-3 px-4 py-3">
                <div className="min-w-0 flex-1 text-sm">
                  <div className="font-medium">
                    {findings.suppressed.find((f) => f.rule_id === ig.rule_id)?.title ?? "Issue"}{" "}
                    <span className="whitespace-nowrap font-mono text-xs font-normal text-muted-foreground">
                      {ig.rule_id}
                    </span>
                  </div>
                  <p className="mt-0.5 font-mono text-xs break-all text-muted-foreground">
                    only at {ig.location}
                  </p>
                  <p className="mt-0.5 text-muted-foreground">“{ig.reason}”</p>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    {ig.created_by} · {new Date(ig.created_at).toLocaleDateString()}
                  </p>
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    setDialog({
                      mode: "restore",
                      ruleId: ig.rule_id,
                      title: ig.rule_id,
                      location: ig.location,
                    })
                  }
                >
                  <Eye /> Stop ignoring
                </Button>
              </li>
            ))}
          </ul>
        </section>
      )}
      {dialog && (
        <IgnoreDialog
          machine={m}
          mode={dialog.mode}
          ruleId={dialog.ruleId}
          title={dialog.title}
          location={dialog.location}
          onClose={() => setDialog(null)}
          onDone={() => {
            setDialog(null);
            onChanged();
          }}
        />
      )}
    </div>
  );
}

interface RuleSummary {
  id: string;
  category: string;
}

/** The same grouped view as Home — issues by what they protect, worst first, a rule that fired many
 *  times collapsed to one row, low-risk suggestions folded away — so a remote machine's issues read
 *  exactly like this computer's. The local fix buttons are left out: fixes run on that machine. */
function GroupedIssues({
  machine: m,
  findings,
  onChanged,
}: {
  machine: Machine;
  findings: Finding[];
  onChanged: () => void;
}) {
  const [rules, setRules] = useState<RuleSummary[] | null>(null);
  const [collapsed, setCollapsed] = useState<Set<string>>(() => new Set());
  const [showMinor, setShowMinor] = useState(false);
  useEffect(() => {
    invoke<RuleSummary[]>("rules_list")
      .then(setRules)
      .catch(() => setRules([]));
  }, []);
  const categoryOf = useMemo(() => {
    const map = new Map((rules ?? []).map((r) => [r.id, r.category]));
    return (id: string) => map.get(id) ?? (id.startsWith("BLWK-AI-") ? "agent-security" : "other");
  }, [rules]);
  const isMinor = (f: Finding) => f.severity === "low" || f.severity === "info";
  const main = useMemo(
    () =>
      groupFindingsByCategory(
        findings.filter((f) => !isMinor(f)),
        categoryOf,
      ),
    [findings, categoryOf],
  );
  const minorFindings = findings.filter(isMinor);
  const minor = useMemo(
    () => groupFindingsByCategory(minorFindings, categoryOf),
    [minorFindings, categoryOf],
  );
  const minorCount = new Set(minorFindings.map((f) => f.rule_id)).size;
  const actions = {
    onIgnoreType: async (ruleId: string, reason: string) => {
      await invoke("machine_suppress", { id: m.id, ruleId, reason });
      onChanged();
    },
    onIgnorePlace: async (ruleId: string, location: string, reason: string) => {
      await invoke("machine_suppress", { id: m.id, ruleId, reason, location });
      onChanged();
    },
    onRecheck: () => {
      void invoke("machine_scan_now", { id: m.id }).then(onChanged);
    },
  };
  const toggle = (c: string) =>
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(c)) next.delete(c);
      else next.add(c);
      return next;
    });
  return (
    <div className="flex flex-col gap-6">
      {main.map(({ category, items, worst }) => (
        <CategoryFindings
          key={category}
          category={category}
          items={items}
          worst={worst}
          collapsed={collapsed.has(category)}
          onToggle={() => toggle(category)}
          actions={actions}
        />
      ))}
      {minor.length > 0 && (
        <div>
          <button
            type="button"
            onClick={() => setShowMinor((v) => !v)}
            aria-expanded={showMinor}
            className="flex items-center gap-2 rounded-md text-sm font-medium text-muted-foreground outline-none hover:text-foreground focus-visible:ring-[3px] focus-visible:ring-ring/50"
          >
            <ChevronRight className={cn("h-3.5 w-3.5 transition-transform", showMinor && "rotate-90")} />
            {minorCount} low-risk {minorCount === 1 ? "suggestion" : "suggestions"}
            <span className="font-normal">· Low and Info, fix when convenient</span>
          </button>
          {showMinor && (
            <div className="mt-4 flex flex-col gap-6">
              {minor.map(({ category, items, worst }) => (
                <CategoryFindings
                  key={`minor-${category}`}
                  category={category}
                  items={items}
                  worst={worst}
                  collapsed={false}
                  onToggle={() => {}}
                  actions={actions}
                />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function IgnoreDialog({
  machine: m,
  mode,
  ruleId,
  title,
  location,
  onClose,
  onDone,
}: {
  machine: Machine;
  mode: "ignore" | "restore";
  ruleId: string;
  title: string;
  /** Set when restoring a single-finding ignore. */
  location?: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const [reason, setReason] = useState(mode === "restore" ? "No longer accepted" : "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await invoke(mode === "ignore" ? "machine_suppress" : "machine_unsuppress", {
        id: m.id,
        ruleId,
        reason,
        location: location ?? null,
      });
      onDone();
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  }
  return (
    <Modal
      title={
        mode === "ignore"
          ? `Ignore this issue type on ${m.name}?`
          : location
            ? `Report ${ruleId} at ${location} again?`
            : `Stop ignoring ${ruleId} on ${m.name}?`
      }
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy || !reason.trim()}>
            {busy && <Loader2 className="animate-spin" />}
            {mode === "ignore" ? "Ignore" : "Stop ignoring"}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        {mode === "ignore" && (
          <p className="text-sm leading-relaxed text-muted-foreground">
            <span className="font-medium text-foreground">{title}</span> and every other{" "}
            <span className="font-mono text-xs">{ruleId}</span> issue on {m.name} will be hidden from the open
            issues and from alerts. It is still checked on every scan and counted as ignored, and you can
            restore it here any time. Other machines are not affected.
          </p>
        )}
        <Field
          label={mode === "ignore" ? "Why is this acceptable?" : "Why restore it?"}
          htmlFor="ignore-reason"
          help="Saved with your name and the date in this machine's audit log."
        >
          <Input
            id="ignore-reason"
            autoFocus
            value={reason}
            placeholder="e.g. only reachable over the office VPN"
            onChange={(e) => setReason(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && reason.trim()) void submit();
            }}
          />
        </Field>
        {error && <Callout tone="critical">{error}</Callout>}
      </div>
    </Modal>
  );
}

function SettingsTab({
  machine: m,
  onChanged,
  onRemoved,
}: {
  machine: Machine;
  onChanged: () => void;
  onRemoved: () => void;
}) {
  const [name, setName] = useState(m.name);
  const [spec, setSpec] = useState(m.spec);
  const [port, setPort] = useState(m.port ? String(m.port) : "");
  const [identity, setIdentity] = useState(m.identity_file ?? "");
  const [jump, setJump] = useState(m.jump_host ?? "");
  const [interval, setIntervalMinutes] = useState(m.interval_minutes);
  const [privileged, setPrivileged] = useState(m.privileged);
  const [enabled, setEnabled] = useState(m.enabled);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [suggest, setSuggest] = useState<SshSuggestions | null>(null);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [deleteHistory, setDeleteHistory] = useState(true);

  useEffect(() => {
    invoke<SshSuggestions>("ssh_suggestions")
      .then(setSuggest)
      .catch(() => setSuggest(null));
  }, []);

  const keyOptions = useMemo(() => {
    const set = new Set<string>(suggest?.keys ?? []);
    if (suggest?.bulwark_key) set.add(suggest.bulwark_key);
    if (m.identity_file) set.add(m.identity_file);
    return [...set];
  }, [suggest, m.identity_file]);

  async function save() {
    setBusy(true);
    setError(null);
    setSaved(false);
    const p = port.trim() ? Number(port) : null;
    try {
      await invoke("machine_update", {
        id: m.id,
        patch: {
          name: name.trim(),
          spec: spec.trim(),
          port: p,
          identity_file: identity.trim() || null,
          jump_host: jump.trim() || null,
          interval_minutes: interval,
          privileged,
          enabled,
        },
      });
      setSaved(true);
      onChanged();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setBusy(true);
    try {
      await invoke("machine_remove", { id: m.id, deleteHistory });
      onRemoved();
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  }

  return (
    <div className="flex max-w-2xl flex-col gap-6">
      <section className="grid gap-4 sm:grid-cols-2">
        <Field label="Name" htmlFor="s-name">
          <Input id="s-name" value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Address" htmlFor="s-spec">
          <Input id="s-spec" value={spec} onChange={(e) => setSpec(e.target.value)} spellCheck={false} />
        </Field>
        <Field label="Port" htmlFor="s-port">
          <Input
            id="s-port"
            inputMode="numeric"
            placeholder="22 (default)"
            value={port}
            onChange={(e) => setPort(e.target.value.replace(/[^0-9]/g, ""))}
          />
        </Field>
        <Field label="Key file" htmlFor="s-key">
          <Select id="s-key" value={identity} onChange={(e) => setIdentity(e.target.value)}>
            <option value="">Default (agent and ~/.ssh)</option>
            {keyOptions.map((k) => (
              <option key={k} value={k}>
                {k === suggest?.bulwark_key ? "Bulwark's monitoring key" : k}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Jump host" htmlFor="s-jump">
          <Input
            id="s-jump"
            placeholder="Optional, e.g. me@bastion.example.com"
            value={jump}
            onChange={(e) => setJump(e.target.value)}
            spellCheck={false}
          />
        </Field>
        <Field label="Scan" htmlFor="s-interval">
          <Select
            id="s-interval"
            value={interval}
            onChange={(e) => setIntervalMinutes(Number(e.target.value))}
          >
            {[...new Set([...INTERVALS.map((i) => i.minutes), interval])].map((mins) => (
              <option key={mins} value={mins}>
                {intervalLabel(mins)}
              </option>
            ))}
          </Select>
        </Field>
      </section>

      <section className="flex flex-col divide-y divide-border rounded-lg border border-border bg-card">
        <ToggleRow
          title="Scheduled scans"
          body="Paused machines keep their history and can still be scanned on demand."
          checked={enabled}
          onChange={setEnabled}
        />
        <ToggleRow
          title="Include checks that need root"
          body="Runs through passwordless sudo on the machine. Prefer a sudo rule that allows only the scanner — the Connection tab shows it."
          checked={privileged}
          onChange={setPrivileged}
        />
      </section>

      {error && <Callout tone="critical">{error}</Callout>}
      <div className="flex items-center gap-3">
        <Button onClick={save} disabled={busy}>
          {busy && <Loader2 className="animate-spin" />}
          Save changes
        </Button>
        {saved && <span className="text-sm text-muted-foreground">Saved.</span>}
      </div>

      <section className="flex flex-col gap-3 rounded-lg border border-[var(--sev-critical)]/30 bg-card p-4">
        <SectionLabel className="mb-0">Remove</SectionLabel>
        <p className="text-sm text-muted-foreground">
          Stops monitoring {m.name}. If you used Bulwark's monitoring key, also delete its line (ending in{" "}
          <code className="font-mono">bulwark-monitoring@…</code>) from{" "}
          <code className="font-mono">~/.ssh/authorized_keys</code> on the machine.
        </p>
        {!confirmRemove ? (
          <Button variant="destructive" className="w-fit" onClick={() => setConfirmRemove(true)}>
            Remove machine…
          </Button>
        ) : (
          <Modal
            title={`Remove ${m.name}?`}
            onClose={() => setConfirmRemove(false)}
            footer={
              <>
                <Button variant="ghost" onClick={() => setConfirmRemove(false)}>
                  Cancel
                </Button>
                <Button variant="destructive" onClick={remove} disabled={busy}>
                  Remove
                </Button>
              </>
            }
          >
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-0.5 h-4 w-4 shrink-0 accent-primary"
                checked={deleteHistory}
                onChange={(e) => setDeleteHistory(e.target.checked)}
              />
              <span>Also delete its scan history from this computer</span>
            </label>
          </Modal>
        )}
      </section>

      <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
        <Network className="h-3.5 w-3.5" />
        Advanced SSH options (ProxyCommand, ciphers, …) belong in ~/.ssh/config — use its Host alias as the
        address.
      </p>
    </div>
  );
}

function ToggleRow({
  title,
  body,
  checked,
  onChange,
}: {
  title: string;
  body: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-start justify-between gap-4 px-4 py-3">
      <div>
        <div className="text-sm font-medium">{title}</div>
        <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{body}</p>
      </div>
      <Switch checked={checked} onCheckedChange={onChange} />
    </div>
  );
}
