import { useCallback, useEffect, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  AlertTriangle,
  CheckCircle2,
  Circle,
  KeyRound,
  Loader2,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Lightbulb,
  XCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { CommandBlock } from "@/components/ui/copy-button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { RichText } from "@/components/machines/parts";
import type { CheckStep, SshSuggestions, TestReport } from "@/lib/machines";
import { cn } from "@/lib/utils";

const STEP_ICON = {
  ok: { icon: CheckCircle2, color: "var(--sev-resolved-fg)" },
  warn: { icon: AlertTriangle, color: "var(--sev-medium-fg)" },
  fail: { icon: XCircle, color: "var(--sev-critical-fg)" },
  skipped: { icon: Circle, color: "var(--muted-foreground)" },
} as const;

/**
 * The connection checklist, with the fix for each failure built in — used by the add-machine flow
 * and by a machine's Connection tab.
 *
 * The stance on connections is "flexible, but say what's better": any working setup is accepted
 * (your own key, the agent, an ~/.ssh/config alias, a jump host, or a password used once), and the
 * advice section underneath says plainly how the setup compares with good practice, with the safer
 * option one click away. What is *not* flexible: host keys are always verified, and a changed one
 * always stops scans until a person confirms it.
 */
export function ConnectionCheck({
  machineId,
  machineName,
  privileged,
  onResult,
  autoRun = true,
}: {
  machineId: string;
  machineName: string;
  privileged: boolean;
  onResult?: (report: TestReport) => void;
  autoRun?: boolean;
}) {
  const [report, setReport] = useState<TestReport | null>(null);
  // Starts "running" when the check runs on mount, so the effect below never has to set state
  // synchronously.
  const [running, setRunning] = useState(autoRun);
  const [error, setError] = useState<string | null>(null);

  const check = useCallback(
    () =>
      invoke<TestReport>("machine_test", { args: { host: machineId, privileged } }).then(
        (r) => {
          setReport(r);
          setError(null);
          onResult?.(r);
        },
        (e) => setError(String(e)),
      ),
    [machineId, privileged, onResult],
  );

  const run = useCallback(async () => {
    setRunning(true);
    setError(null);
    await check();
    setRunning(false);
  }, [check]);

  useEffect(() => {
    if (!autoRun) return;
    let live = true;
    check().finally(() => {
      if (live) setRunning(false);
    });
    return () => {
      live = false;
    };
    // Once per machine; later checks are explicit (the "Check again" button).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [machineId]);

  const connect = report?.steps.find((s) => s.id === "connect");
  const kind = connect?.problem?.kind;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm text-muted-foreground">
          {running
            ? `Connecting to ${machineName}…`
            : report?.ok
              ? `${machineName} is ready to scan.`
              : report
                ? "Fix the step marked below, then check again."
                : "Check that Bulwark can reach and scan this machine."}
        </p>
        <Button variant="outline" size="sm" onClick={run} disabled={running}>
          {running ? <Loader2 className="animate-spin" /> : <RefreshCw />}
          {report ? "Check again" : "Check connection"}
        </Button>
      </div>

      {error && <Callout tone="critical">{error}</Callout>}

      {report && (
        <ol className="flex flex-col divide-y divide-border rounded-lg border border-border bg-card">
          {report.steps.map((s) => {
            // The remedy for a failed connection goes *in* the failed step, where the eye already
            // is, and replaces the generic hint it would otherwise repeat.
            let remedy = null;
            if (s.id === "connect" && (kind === "host_key_unknown" || kind === "host_key_changed")) {
              remedy = (
                <HostKeyApproval
                  report={report}
                  machineId={machineId}
                  machineName={machineName}
                  changed={kind === "host_key_changed"}
                  onTrusted={run}
                />
              );
            } else if (s.id === "connect" && kind === "auth_failed") {
              remedy = <KeyAccess machineId={machineId} machineName={machineName} onDone={run} />;
            }
            return (
              <StepRow key={s.id} step={s} running={running}>
                {remedy}
              </StepRow>
            );
          })}
        </ol>
      )}

      {report && report.advice.length > 0 && (
        <AdviceList report={report} machineId={machineId} machineName={machineName} onChanged={run} />
      )}
    </div>
  );
}

function StepRow({
  step,
  running,
  children,
}: {
  step: CheckStep;
  running: boolean;
  /** A remedy panel that replaces the generic hint. */
  children?: ReactNode;
}) {
  const { icon: Icon, color } = STEP_ICON[step.status];
  return (
    <li className={cn("flex gap-3 px-3.5 py-3", running && "opacity-60")}>
      <Icon className="mt-0.5 h-4 w-4 shrink-0" style={{ color }} strokeWidth={2} />
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium">{step.label}</div>
        <div className="mt-0.5 text-sm leading-relaxed break-words text-muted-foreground">
          {step.problem ? step.problem.title : step.detail}
        </div>
        {children && <div className="mt-3">{children}</div>}
        {step.problem && (
          <div className="mt-2 flex flex-col gap-1.5 text-sm leading-relaxed">
            {!children && <RichText text={step.problem.hint} />}
            {step.problem.detail && (
              <details className="text-xs text-muted-foreground">
                <summary className="cursor-pointer select-none">What ssh said</summary>
                <pre className="mt-1 font-mono break-words whitespace-pre-wrap">{step.problem.detail}</pre>
              </details>
            )}
          </div>
        )}
      </div>
    </li>
  );
}

/** First contact, or a changed key: show the fingerprint, say how to compare it, and only then
 *  trust it — into Bulwark's own known_hosts, never ~/.ssh. */
function HostKeyApproval({
  report,
  machineId,
  machineName,
  changed,
  onTrusted,
}: {
  report: TestReport;
  machineId: string;
  machineName: string;
  changed: boolean;
  onTrusted: () => void;
}) {
  const [confirmed, setConfirmed] = useState(false);
  const [mismatch, setMismatch] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const key = report.host_keys[0];

  if (!key) {
    return (
      <Callout tone="warning">
        Bulwark couldn't read this machine's host key directly. Connect once from a terminal with{" "}
        <code>{report.ssh_command}</code> and accept the key there, then check again.
      </Callout>
    );
  }

  async function trust() {
    setBusy(true);
    setError(null);
    try {
      await invoke("machine_trust", {
        id: machineId,
        fingerprint: key.fingerprint,
        replace: changed,
      });
      onTrusted();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className={cn(
        "flex flex-col gap-3 rounded-lg border p-4",
        changed
          ? "border-[var(--sev-critical)]/40 bg-[var(--sev-critical-tint)]"
          : "border-border bg-muted/40",
      )}
    >
      <div className="flex items-center gap-2">
        {changed ? (
          <ShieldAlert className="h-4 w-4" style={{ color: "var(--sev-critical-fg)" }} />
        ) : (
          <ShieldCheck className="h-4 w-4 text-primary" />
        )}
        <h3 className="text-sm font-semibold">
          {changed ? `${machineName} presented a different identity key` : `Is this really ${machineName}?`}
        </h3>
      </div>
      <p className="text-sm leading-relaxed text-muted-foreground">
        {changed
          ? "Its key no longer matches the one Bulwark trusted. That is expected after a reinstall — and it is exactly what interception looks like. Scans stay blocked until you confirm the new key with whoever manages the machine."
          : "Every machine has an identity key. Comparing it once, now, is what lets Bulwark refuse an impostor later. The machine offered:"}
      </p>
      <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card px-3 py-2">
        <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] font-semibold">
          {key.key_type}
        </span>
        <code className="min-w-0 flex-1 font-mono text-sm break-all">{key.fingerprint}</code>
      </div>
      {report.verify_command && (
        <div className="flex flex-col gap-1.5">
          <p className="text-sm text-muted-foreground">
            Compare it with what the machine itself reports — run this on its console, or in a session you
            already trust:
          </p>
          <CommandBlock command={report.verify_command} />
        </div>
      )}
      {changed && (
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-0.5 h-4 w-4 shrink-0 accent-primary"
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
          />
          <span>I confirmed with whoever manages {machineName} that it was reinstalled or re-keyed.</span>
        </label>
      )}
      {mismatch ? (
        <Callout tone="critical">
          Don't continue. A fingerprint that doesn't match means you may not be talking to {machineName} —
          something on the network could be intercepting the connection. Check the address, and the network
          you're on.
        </Callout>
      ) : (
        <div className="flex flex-wrap gap-2">
          <Button onClick={trust} disabled={busy || (changed && !confirmed)}>
            {busy && <Loader2 className="animate-spin" />}
            {changed ? "Replace the stored key" : "They match — trust this machine"}
          </Button>
          <Button variant="ghost" onClick={() => setMismatch(true)}>
            They don't match
          </Button>
        </div>
      )}
      {error && <Callout tone="critical">{error}</Callout>}
    </div>
  );
}

/** The machine refused our keys: offer the two ways in, safest first. */
function KeyAccess({
  machineId,
  machineName,
  onDone,
}: {
  machineId: string;
  machineName: string;
  onDone: () => void;
}) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState<"password" | "key" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [suggest, setSuggest] = useState<SshSuggestions | null>(null);
  const [keyFile, setKeyFile] = useState("");

  useEffect(() => {
    invoke<SshSuggestions>("ssh_suggestions")
      .then(setSuggest)
      .catch(() => setSuggest(null));
  }, []);

  async function setupWithPassword() {
    setBusy("password");
    setError(null);
    try {
      const r = await invoke<{ ok: boolean }>("machine_setup_key", { id: machineId, password });
      setPassword("");
      if (!r.ok)
        setError("The key was added, but signing in with it didn't work. Check the machine's sshd settings.");
      onDone();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function useKeyFile() {
    setBusy("key");
    setError(null);
    try {
      await invoke("machine_update", { id: machineId, patch: { identity_file: keyFile || null } });
      onDone();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="flex flex-col gap-4 rounded-lg border border-border bg-muted/40 p-4">
      <div className="flex items-center gap-2">
        <KeyRound className="h-4 w-4 text-primary" />
        <h3 className="text-sm font-semibold">Give Bulwark key access to {machineName}</h3>
      </div>

      <div className="flex flex-col gap-2">
        <div className="text-sm font-medium">
          Recommended: let Bulwark set up its own key{" "}
          <span className="font-normal text-muted-foreground">— sign in once with your password</span>
        </div>
        <p className="text-sm leading-relaxed text-muted-foreground">
          Bulwark creates a key used only for monitoring and installs it on the machine with the{" "}
          <code className="font-mono text-[0.9em]">restrict</code> option: it can run the scan, but can't
          forward ports, reach your SSH agent or open a terminal. The password is used for this one sign-in
          and never stored.
        </p>
        <form
          className="flex flex-wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (password) void setupWithPassword();
          }}
        >
          <Input
            type="password"
            autoComplete="off"
            placeholder={`Password on ${machineName}`}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="max-w-xs"
          />
          <Button type="submit" disabled={!password || busy !== null}>
            {busy === "password" && <Loader2 className="animate-spin" />}
            Set up key access
          </Button>
        </form>
      </div>

      <div className="flex flex-col gap-2 border-t border-border pt-3">
        <div className="text-sm font-medium">Or use a key you already have</div>
        <p className="text-sm leading-relaxed text-muted-foreground">
          If your key has a passphrase, load it into your SSH agent (
          <code className="font-mono">ssh-add</code>) so Bulwark can use it without asking.
        </p>
        <div className="flex flex-wrap gap-2">
          <Select
            className="max-w-xs"
            value={keyFile}
            onChange={(e) => setKeyFile(e.target.value)}
            aria-label="Key file"
          >
            <option value="">ssh's default keys and agent</option>
            {suggest?.keys.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </Select>
          <Button variant="outline" onClick={useKeyFile} disabled={busy !== null}>
            {busy === "key" && <Loader2 className="animate-spin" />}
            Use this key
          </Button>
        </div>
      </div>
      {error && <Callout tone="critical">{error}</Callout>}
    </div>
  );
}

const ADVICE_ICON = {
  good: { icon: CheckCircle2, color: "var(--sev-resolved-fg)" },
  suggest: { icon: Lightbulb, color: "var(--primary)" },
  warn: { icon: AlertTriangle, color: "var(--sev-medium-fg)" },
} as const;

function AdviceList({
  report,
  machineId,
  machineName,
  onChanged,
}: {
  report: TestReport;
  machineId: string;
  machineName: string;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function dedicatedKey() {
    setBusy(true);
    setError(null);
    try {
      // Uses the access that works today to install the restricted key — no password needed.
      await invoke("machine_setup_key", { id: machineId, password: null });
      onChanged();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="flex flex-col gap-2">
      <h3 className="font-mono text-[11px] font-semibold tracking-widest text-muted-foreground uppercase">
        Connection security
      </h3>
      <ul className="flex flex-col gap-2">
        {report.advice.map((a) => {
          const { icon: Icon, color } = ADVICE_ICON[a.level];
          return (
            <li key={a.id} className="flex gap-3 rounded-lg border border-border bg-card px-3.5 py-3">
              <Icon className="mt-0.5 h-4 w-4 shrink-0" style={{ color }} strokeWidth={2} />
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium">{a.title}</div>
                <p className="mt-0.5 text-sm leading-relaxed text-muted-foreground">{a.detail}</p>
                {a.id === "key" && a.level === "suggest" ? (
                  <Button className="mt-2" size="sm" variant="outline" onClick={dedicatedKey} disabled={busy}>
                    {busy ? <Loader2 className="animate-spin" /> : <KeyRound />}
                    Switch {machineName} to a dedicated key
                  </Button>
                ) : (
                  a.command && a.level !== "good" && <CommandBlock command={a.command} className="mt-2" />
                )}
              </div>
            </li>
          );
        })}
      </ul>
      {error && <Callout tone="critical">{error}</Callout>}
    </section>
  );
}
