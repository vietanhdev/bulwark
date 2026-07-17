import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { FileLock2, KeyRound, Loader2, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Callout } from "@/components/ui/callout";
import { cn } from "@/lib/utils";

interface KeyResult {
  path: string;
  key_format: string;
  outcome: { status: string; reason?: string };
  backup_path: string | null;
}
interface ProtectReport {
  results: KeyResult[];
  protected: number;
  already_encrypted: number;
  undetermined: number;
  failed: number;
}

/**
 * Adds one passphrase to every unencrypted SSH private key at once. A single password across the
 * set is far better than leaving plaintext keys on disk. Calls the linked `ssh_protect_keys`
 * Tauri command — which runs `bulwark-core` in-process (no CLI), feeds the passphrase to
 * ssh-keygen via SSH_ASKPASS (never argv), backs each key up, and only touches keys it can
 * confirm are unencrypted.
 */
export function SshKeyProtect() {
  const [pass, setPass] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<ProtectReport | null>(null);

  const mismatch = confirm.length > 0 && pass !== confirm;
  const canSubmit = pass.length > 0 && pass === confirm && !busy;

  async function run() {
    setError(null);
    setReport(null);
    setBusy(true);
    try {
      const r = await invoke<ProtectReport>("ssh_protect_keys", { passphrase: pass });
      setReport(r);
      setPass("");
      setConfirm("");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <div className="flex items-start gap-3">
        <KeyRound className="mt-0.5 h-5 w-5 shrink-0 text-muted-foreground" />
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold">Protect SSH keys</h3>
          <p className="mt-1 text-sm text-muted-foreground">
            Add one passphrase to every unencrypted private key in <code>~/.ssh</code> at once. A single
            password is far better than plaintext keys on disk. Already-encrypted keys are left alone, and
            each modified key is backed up first.
          </p>

          <form
            className="mt-3 flex flex-col gap-2 sm:max-w-sm"
            onSubmit={(e) => {
              e.preventDefault();
              if (canSubmit) void run();
            }}
          >
            <Input
              type="password"
              autoComplete="new-password"
              placeholder="New passphrase"
              value={pass}
              onChange={(e) => setPass(e.target.value)}
              disabled={busy}
            />
            <Input
              type="password"
              autoComplete="new-password"
              placeholder="Confirm passphrase"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              disabled={busy}
              aria-invalid={mismatch}
            />
            {mismatch && <p className="text-xs text-[var(--sev-high-fg)]">Passphrases don't match.</p>}
            <Button type="submit" disabled={!canSubmit} className="self-start">
              {busy ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" /> Protecting…
                </>
              ) : (
                <>
                  <ShieldCheck className="h-4 w-4" /> Protect unencrypted keys
                </>
              )}
            </Button>
          </form>

          {error && (
            <Callout tone="critical" className="mt-3">
              {error}
            </Callout>
          )}

          {report && (
            <div className="mt-3 text-sm">
              <p className="font-medium">
                {report.protected} protected
                {report.already_encrypted > 0 && `, ${report.already_encrypted} already encrypted`}
                {report.undetermined > 0 && `, ${report.undetermined} skipped`}
                {report.failed > 0 && `, ${report.failed} failed`}.
              </p>
              {report.protected > 0 && (
                <p className="mt-1 text-muted-foreground">
                  Rotate anything that may have leaked while unprotected, and load a key into your agent with{" "}
                  <code>ssh-add</code> to avoid retyping the passphrase.
                </p>
              )}
              <ul className="mt-2 space-y-1 font-mono text-xs">
                {report.results.map((r) => (
                  <li key={r.path} className="flex items-center justify-between gap-2">
                    <span className="truncate text-muted-foreground">{r.path}</span>
                    <span
                      className={cn(
                        "shrink-0",
                        r.outcome.status === "protected" && "text-[var(--sev-resolved-fg)]",
                        r.outcome.status === "failed" && "text-[var(--sev-critical-fg)]",
                      )}
                    >
                      {r.outcome.status.replace(/_/g, " ")}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

interface PermResult {
  path: string;
  label: string;
  current_mode: string | null;
  desired_mode: string;
  outcome: { status: string; from?: string; to?: string };
}
interface PermReport {
  results: PermResult[];
  tightened: number;
  would_tighten: number;
  already_ok: number;
  missing: number;
  skipped_symlink: number;
  failed: number;
}

/**
 * Tightens over-permissive files in `~/.ssh` (directory to 700, private keys / config /
 * authorized_keys to 600). Preview first (dry run), then apply — mirroring the CLI's
 * `bulwarkctl fix ssh-perms`. Only ever tightens, never loosens, and never follows a symlink;
 * calls the linked `fix_ssh_permissions` command in-process (no privilege needed for your own
 * `~/.ssh`).
 */
export function SshPermFix() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<PermReport | null>(null);
  const [applied, setApplied] = useState(false);

  const changes = (report?.tightened ?? 0) + (report?.would_tighten ?? 0);
  const previewed = report !== null;

  async function run(apply: boolean) {
    setError(null);
    setBusy(true);
    try {
      const r = await invoke<PermReport>("fix_ssh_permissions", { apply });
      setReport(r);
      setApplied(apply);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-3 rounded-lg border border-border bg-card p-4">
      <div className="flex items-start gap-3">
        <FileLock2 className="mt-0.5 h-5 w-5 shrink-0 text-muted-foreground" />
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold">Fix ~/.ssh permissions</h3>
          <p className="mt-1 text-sm text-muted-foreground">
            Tighten loose permissions in <code>~/.ssh</code>: the directory to <code>700</code> and private
            keys, <code>config</code>, and <code>authorized_keys</code> to <code>600</code>. Only ever
            tightens, never loosens, and never follows a symlink.
          </p>

          <div className="mt-3 flex flex-wrap gap-2">
            <Button variant="outline" onClick={() => run(false)} disabled={busy} className="self-start">
              {busy && !applied ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
              {previewed ? "Re-check" : "Check permissions"}
            </Button>
            {previewed && changes > 0 && (
              <Button onClick={() => run(true)} disabled={busy} className="self-start">
                {busy && applied ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <ShieldCheck className="h-4 w-4" />
                )}
                {applied ? "Tighten again" : `Tighten ${changes} file${changes === 1 ? "" : "s"}`}
              </Button>
            )}
          </div>

          {error && (
            <Callout tone="critical" className="mt-3">
              {error}
            </Callout>
          )}

          {report && (
            <div className="mt-3 text-sm">
              {changes === 0 ? (
                <p className="flex items-center gap-1.5 font-medium text-[var(--sev-resolved-fg)]">
                  <ShieldCheck className="h-4 w-4" /> All checked permissions are already correct.
                </p>
              ) : (
                <p className="font-medium">
                  {applied
                    ? `${report.tightened} tightened${report.failed > 0 ? `, ${report.failed} failed` : ""}.`
                    : `${report.would_tighten} file${report.would_tighten === 1 ? "" : "s"} would be tightened.`}
                </p>
              )}
              <ul className="mt-2 space-y-1 font-mono text-xs">
                {report.results
                  .filter((r) => r.outcome.status === "would_tighten" || r.outcome.status === "tightened")
                  .map((r) => (
                    <li key={r.path} className="flex items-center justify-between gap-2">
                      <span className="truncate text-muted-foreground">{r.path}</span>
                      <span className="shrink-0 text-[var(--sev-resolved-fg)]">
                        {r.outcome.from} → {r.outcome.to}
                      </span>
                    </li>
                  ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
