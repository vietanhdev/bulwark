// Types and helpers for the Remote machines page. Shapes mirror `bulwark_core::fleet` (serialized via the
// `machines_*` Tauri commands) and the CLI's `hosts test --json` report.
import type { Severity } from "@/components/Severity";

export type Health =
  "new" | "needs_attention" | "unsupported" | "unreachable" | "stale" | "at_risk" | "issues" | "healthy";

export type ErrorKind =
  | "invalid_target"
  | "ssh_missing"
  | "unresolvable"
  | "unreachable"
  | "timeout"
  | "host_key_unknown"
  | "host_key_changed"
  | "auth_failed"
  | "arch_unsupported"
  | "engine_missing"
  | "sudo_requires_password"
  | "incompatible_engine"
  | "no_rules"
  | "identity_changed"
  | "unsupported_os"
  | "nothing_assessed"
  | "local_storage"
  | "other";

export interface Problem {
  kind: ErrorKind;
  title: string;
  hint: string;
  detail: string | null;
}

export interface Counts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  suppressed: number;
}

export interface Machine {
  id: string;
  name: string;
  spec: string;
  port: number | null;
  identity_file: string | null;
  jump_host: string | null;
  privileged: boolean;
  enabled: boolean;
  interval_minutes: number;
  created_at: string;
  expected_hostname: string | null;
  last_attempt_at: string | null;
  last_success_at: string | null;
  last_status: { state: "ok" } | { state: "failed"; kind: ErrorKind } | null;
  last_error: string | null;
  consecutive_failures: number;
  engine: string | null;
  /** Short OS key for the icon (`ubuntu`, `macos`, `wsl`, `windows`, …) and its readable name. */
  os_kind: string | null;
  os_name: string | null;
  health: Health;
  counts: Counts;
  next_due_at: string | null;
  privileged_collectors_skipped: string[];
  /** Checks the last successful scan ran; null before the first one. */
  checks_run: number | null;
  ssh_command: string;
  problem: Problem | null;
  scanning: boolean;
}

export interface MachinesOverview {
  enabled: boolean;
  machines: Machine[];
  can_copy_engine: boolean;
}

export type StepStatus = "ok" | "warn" | "fail" | "skipped";

export interface CheckStep {
  id: "address" | "connect" | "engine" | "root";
  label: string;
  status: StepStatus;
  detail: string;
  problem: Problem | null;
}

export interface Advice {
  id: string;
  level: "good" | "suggest" | "warn";
  title: string;
  detail: string;
  command: string | null;
}

export interface TestReport {
  target: string;
  ssh_command: string;
  ok: boolean;
  steps: CheckStep[];
  host_keys: { key_type: string; fingerprint: string }[];
  verify_command: string | null;
  host_key_changed: boolean;
  host_ref: string;
  os: string | null;
  install_command: string | null;
  advice: Advice[];
}

export interface SshAlias {
  alias: string;
  hostname: string | null;
  user: string | null;
  port: number | null;
  jump: string | null;
}

export interface SshSuggestions {
  aliases: SshAlias[];
  keys: string[];
  bulwark_key: string | null;
}

/** The severity token that colours each state, so a machine reads with the same palette as a
 *  finding of matching weight. */
export const HEALTH: Record<Health, { label: string; tone: Severity | "resolved" | "muted" }> = {
  new: { label: "Not scanned yet", tone: "muted" },
  needs_attention: { label: "Needs attention", tone: "critical" },
  // Reachable, but no checks for its system yet: neutral, because there is nothing to fix.
  unsupported: { label: "Not supported yet", tone: "muted" },
  unreachable: { label: "Unreachable", tone: "medium" },
  stale: { label: "Out of date", tone: "low" },
  at_risk: { label: "At risk", tone: "high" },
  issues: { label: "Minor issues", tone: "medium" },
  healthy: { label: "Healthy", tone: "resolved" },
};

/** Sort order for the grid: what needs a person first. */
export const HEALTH_ORDER: Health[] = [
  "needs_attention",
  "at_risk",
  "unreachable",
  "issues",
  "stale",
  "new",
  "healthy",
  "unsupported",
];

export const INTERVALS: { minutes: number; label: string }[] = [
  { minutes: 15, label: "Every 15 minutes" },
  { minutes: 60, label: "Every hour" },
  { minutes: 360, label: "Every 6 hours" },
  { minutes: 1440, label: "Once a day" },
];

export function intervalLabel(minutes: number): string {
  return (
    INTERVALS.find((i) => i.minutes === minutes)?.label ??
    (minutes % 60 === 0 ? `Every ${minutes / 60} hours` : `Every ${minutes} minutes`)
  );
}

export function ago(iso: string | null, now = Date.now()): string {
  if (!iso) return "never";
  const s = Math.round((now - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.round(h / 24)} days ago`;
}

export function until(iso: string | null, now = Date.now()): string {
  if (!iso) return "paused";
  const s = Math.round((new Date(iso).getTime() - now) / 1000);
  if (s <= 0) return "due now";
  const m = Math.ceil(s / 60);
  if (m < 60) return `in ${m} min`;
  const h = Math.round(m / 60);
  if (h < 48) return `in ${h} h`;
  return `in ${Math.round(h / 24)} days`;
}

/** Display form of a machine's address: `deploy@10.0.0.5:2222 via bastion`. */
export function targetLabel(m: Pick<Machine, "spec" | "port" | "jump_host">): string {
  let s = m.spec;
  if (m.port) s += `:${m.port}`;
  if (m.jump_host) s += ` via ${m.jump_host}`;
  return s;
}

export function openTotal(c: Counts): number {
  return c.critical + c.high + c.medium + c.low + c.info;
}

/** A sensible default name for an address — the host part of `user@host`. */
export function defaultName(spec: string): string {
  const host = spec.trim().split("@").pop() ?? "";
  return host.replace(/^\[|\]$/g, "");
}

/** Failures about *reaching* the machine. Everything else happened after a successful sign-in, so
 *  it belongs to the scan, not the connection. */
const CONNECTION_KINDS: ReadonlySet<ErrorKind> = new Set<ErrorKind>([
  "invalid_target",
  "ssh_missing",
  "unresolvable",
  "unreachable",
  "timeout",
  "host_key_unknown",
  "host_key_changed",
  "auth_failed",
]);

export type Dot = "ok" | "warn" | "bad" | "idle";

/** Two- or three-word connection states for a card, where the full sentence (shown on the detail
 *  page) would be cut off. */
const SHORT: Partial<Record<ErrorKind, string>> = {
  invalid_target: "Invalid address",
  ssh_missing: "No SSH client here",
  unresolvable: "Name not found",
  unreachable: "Not answering",
  timeout: "Timed out",
  host_key_unknown: "Not trusted yet",
  host_key_changed: "Identity key changed",
  auth_failed: "Key refused",
};

/** The connection, on its own: can Bulwark reach and sign in to the machine right now? */
export function connectionState(m: Machine): { dot: Dot; label: string; problem: boolean } {
  if (m.scanning) return { dot: "idle", label: "Connecting…", problem: false };
  if (!m.last_status) return { dot: "idle", label: "Not checked yet", problem: false };
  if (m.last_status.state === "failed" && CONNECTION_KINDS.has(m.last_status.kind)) {
    const bad = m.last_status.kind === "host_key_changed" || m.last_status.kind === "auth_failed";
    return { dot: bad ? "bad" : "warn", label: SHORT[m.last_status.kind] ?? "Can't connect", problem: true };
  }
  return { dot: "ok", label: "Connected", problem: false };
}

/** The last scan's own failure, if the connection worked but the scan didn't. */
export function scanProblem(m: Machine): Problem | null {
  if (m.last_status?.state === "failed" && !CONNECTION_KINDS.has(m.last_status.kind)) return m.problem;
  return null;
}
