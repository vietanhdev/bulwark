import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AlertTriangle, Check, Loader2, ShieldCheck, Wrench } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import {
  combinedChangeCount,
  fixNotes,
  flattenChanges,
  type CombinedFixReport,
  type FixCapability,
} from "@/lib/fixes";

/**
 * The autofix UI: a per-issue "Fix this" button and a "Fix all safe issues" button.
 *
 * Both follow the same two-step contract, and it is the whole point of this file: **the first click
 * only ever previews.** It runs the real fixer with `apply = false`, renders the exact set of
 * changes it would make — every path with its current mode → new mode, every sshd directive with
 * its current and desired value — and then waits for a second, explicit confirmation before running
 * anything with `apply = true`. Nothing on this screen can write to disk in one click.
 *
 * Root-scoped fixes raise a polkit prompt for the preview *and* again for the apply. That is not an
 * oversight: reading `/etc/ssh/sshd_config` (mode 600) already needs root, and the project's polkit
 * action is deliberately `auth_admin` rather than `auth_admin_keep`, so authorization is never
 * cached (architecture doc §4 / ADR-0004).
 */

function ChangeRows({ report }: { report: CombinedFixReport | null | undefined }) {
  return (
    <>
      {flattenChanges(report).map((c) => (
        <li key={c.key} className="flex items-center justify-between gap-3">
          <span className="truncate text-muted-foreground">{c.label}</span>
          <span className="shrink-0 text-[var(--sev-resolved-fg)]">{c.detail}</span>
        </li>
      ))}
    </>
  );
}

const FIX_TITLES: Record<FixCapability["kind"], string> = {
  ssh_perms: "~/.ssh permission tightening",
  etc_perms: "/etc permission tightening",
  sshd: "sshd_config hardening",
  sysctl: "Kernel network settings",
  banner: "Login warning banner",
  login_defs: "Password aging policy",
};

/** One line per fixer explaining how the change is made safe — shown with the preview. */
const FIX_BLURBS: Record<FixCapability["kind"], string> = {
  ssh_perms: "Permissions are only ever tightened, never loosened, and symlinks are never followed.",
  etc_perms: "Permissions are only ever tightened, never loosened, and symlinks are never followed.",
  sshd: "Written as one marked block at the top of the config; the original is backed up first and validated with sshd -t before it is kept.",
  sysctl:
    "Saved to a drop-in under /etc/sysctl.d so it survives a reboot — not just applied to the running kernel — and every affected interface is set, not only the 'all' pseudo-scope.",
  banner:
    "Writes a generic legal warning to /etc/issue and /etc/issue.net, backing up the originals. A banner you have already customised is never overwritten.",
  login_defs:
    "The original /etc/login.defs is backed up and each directive is replaced in place rather than appended, so the value actually takes effect.",
};

/** Shared shell for the preview → confirm flow: the change list, the confirm/cancel pair, errors. */
function FixPanel({
  title,
  report,
  applied,
  busy,
  error,
  note,
  danger,
  onApply,
  onDismiss,
}: {
  title: string;
  report: CombinedFixReport | null;
  applied: boolean;
  busy: boolean;
  error: string | null;
  note?: React.ReactNode;
  danger?: React.ReactNode;
  onApply: () => void;
  onDismiss: () => void;
}) {
  const changeCount = report ? combinedChangeCount(report) : 0;
  const notes = fixNotes(report);
  return (
    <div className="mt-2 rounded-md border border-border bg-muted/40 p-3">
      {error && (
        <Callout tone="critical" className="mb-2">
          {error}
        </Callout>
      )}

      {applied ? (
        <p className="flex items-center gap-1.5 text-xs font-medium text-[var(--sev-resolved-fg)]">
          <ShieldCheck className="h-3.5 w-3.5" />
          {changeCount === 0
            ? "Nothing needed changing."
            : `Applied ${changeCount} change${changeCount === 1 ? "" : "s"}.`}
        </p>
      ) : (
        <p className="text-xs font-medium">
          {changeCount === 0
            ? "Nothing to change — this is already in the state the fix would put it in."
            : `${title}: ${changeCount} change${changeCount === 1 ? "" : "s"} would be made. Nothing has been written yet.`}
        </p>
      )}

      {changeCount > 0 && (
        <ul className="mt-2 space-y-1 font-mono text-[11px]">
          <ChangeRows report={report} />
        </ul>
      )}

      {notes.length > 0 && (
        <ul className="mt-2 space-y-0.5 text-[11px] text-muted-foreground">
          {notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}

      {note && <p className="mt-2 text-[11px] text-muted-foreground">{note}</p>}

      {danger && !applied && changeCount > 0 && (
        <Callout tone="warning" className="mt-2">
          {danger}
        </Callout>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-2">
        {!applied && changeCount > 0 && (
          <Button size="sm" onClick={onApply} disabled={busy}>
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
            Apply {changeCount} change{changeCount === 1 ? "" : "s"}
          </Button>
        )}
        <Button size="sm" variant="ghost" onClick={onDismiss} disabled={busy}>
          {applied || changeCount === 0 ? "Close" : "Cancel"}
        </Button>
      </div>
    </div>
  );
}

/**
 * "Fix this" for one rule, rendered only when `capability` exists — i.e. only where a real fixer in
 * `bulwark-core::remediation` can address that exact rule.
 *
 * For the two lockout-risky sshd directives (`PasswordAuthentication`, `PermitRootLogin`) the
 * confirmation additionally spells out that you can be locked out of a password-only host, and it
 * is the *only* path that passes `include_auth` — "Fix all" structurally cannot.
 */
export function FixIssueButton({
  capability,
  onFixed,
}: {
  capability: FixCapability;
  /** Called after a successful apply so the view can re-scan and drop the resolved finding. */
  onFixed?: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<CombinedFixReport | null>(null);
  const [applied, setApplied] = useState(false);

  async function run(apply: boolean) {
    setBusy(true);
    setError(null);
    try {
      setReport(await invoke<CombinedFixReport>("fix_rule", { ruleId: capability.rule_id, apply }));
      setOpen(true);
      if (apply) {
        setApplied(true);
        onFixed?.();
      }
    } catch (e) {
      setError(String(e));
      setOpen(true);
    } finally {
      setBusy(false);
    }
  }

  function dismiss() {
    setOpen(false);
    setApplied(false);
    setReport(null);
    setError(null);
  }

  if (!open) {
    return (
      <div className="mt-2">
        <Button size="sm" variant="outline" onClick={() => run(false)} disabled={busy}>
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Wrench className="h-3.5 w-3.5" />}
          Fix this
        </Button>
        <span className="ml-2 align-middle text-[11px] text-muted-foreground">
          Shows what would change first
          {capability.needs_root ? " — asks for your password" : ""}.
        </span>
      </div>
    );
  }

  return (
    <FixPanel
      title={FIX_TITLES[capability.kind]}
      report={report}
      applied={applied}
      busy={busy}
      error={error}
      note={FIX_BLURBS[capability.kind]}
      danger={
        capability.lockout_risk ? (
          <span className="flex items-start gap-1.5">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>
              This can lock you out. Only apply it once you have confirmed key-based login to this host
              already works — if you reach this machine by password, you will not be able to log back in.
            </span>
          </span>
        ) : null
      }
      onApply={() => run(true)}
      onDismiss={dismiss}
    />
  );
}

/**
 * "Fix all safe issues" — the whole mechanical remediation set in one pass: `~/.ssh` permissions,
 * sensitive `/etc` permissions, and the non-lockout sshd directives.
 *
 * The two lockout-risky auth directives are excluded, matching `bulwarkctl fix all`, where they sit
 * behind `--include-auth`. That exclusion is enforced in the backend (this button has no way to
 * request them), not by this component remembering to leave them out.
 */
export function FixAllButton({ onFixed }: { onFixed?: () => void }) {
  const [report, setReport] = useState<CombinedFixReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [applied, setApplied] = useState(false);

  async function run(apply: boolean) {
    setBusy(true);
    setError(null);
    try {
      const r = await invoke<CombinedFixReport>("fix_all", { apply });
      setReport(r);
      if (apply) {
        setApplied(true);
        onFixed?.();
      }
    } catch (e) {
      setError(String(e));
      setReport(report ?? null);
    } finally {
      setBusy(false);
    }
  }

  if (!report && !error) {
    return (
      <Button size="sm" variant="outline" onClick={() => run(false)} disabled={busy}>
        {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Wrench className="h-3.5 w-3.5" />}
        Fix all safe issues
      </Button>
    );
  }

  return (
    <FixPanel
      title="Safe autofix set"
      report={report}
      applied={applied}
      busy={busy}
      error={error}
      note={
        <>
          The two SSH directives that can lock you out — <code>PasswordAuthentication</code> and{" "}
          <code>PermitRootLogin</code> — are deliberately excluded here. Fix those one at a time from the
          issue itself, once you have confirmed key-based login works.
        </>
      }
      onApply={() => run(true)}
      onDismiss={() => {
        setReport(null);
        setApplied(false);
        setError(null);
      }}
    />
  );
}
