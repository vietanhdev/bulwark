import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

/**
 * Client types for the autofix commands. These mirror `bulwark-core::remediation` exactly — the
 * fixers themselves live there, and nothing in the frontend decides *what* a fix does, only when to
 * ask for one.
 */

export type FixKind = "ssh_perms" | "etc_perms" | "sshd" | "sysctl" | "banner" | "login_defs";

export interface FixCapability {
  rule_id: string;
  kind: FixKind;
  /** The two sshd auth directives that can lock you out of a password-only host. Never bulk-fixed. */
  lockout_risk: boolean;
  /** Applying needs root, so the GUI raises a polkit prompt. */
  needs_root: boolean;
}

export interface PermResult {
  path: string;
  label: string;
  current_mode: string | null;
  desired_mode: string;
  outcome: { status: string; from?: string; to?: string; reason?: string };
}

export interface PermReport {
  results: PermResult[];
  tightened: number;
  would_tighten: number;
  already_ok: number;
  missing: number;
  skipped_symlink: number;
  failed: number;
}

export interface SshdChange {
  keyword: string;
  current: string;
  desired: string;
  lockout_risk: boolean;
  why: string;
  status: { status: "would_set" | "set" | "skipped_lockout" };
}

export interface SshdHardeningReport {
  config_path: string;
  changes: SshdChange[];
  applied: boolean;
  backup_path: string | null;
  validated: boolean | null;
  note: string | null;
}

export interface SysctlChange {
  key: string;
  current: string;
  desired: string;
  why: string;
  status: { status: "would_set" | "set" | "set_but_not_live" };
}

export interface SysctlHardeningReport {
  conf_path: string;
  changes: SysctlChange[];
  applied: boolean;
  backup_path: string | null;
  verified: boolean | null;
  note: string | null;
}

export interface BannerResult {
  path: string;
  label: string;
  outcome: { status: string; reason?: string };
  backup_path: string | null;
}

export interface BannerReport {
  results: BannerResult[];
  written: number;
  would_write: number;
  already_custom: number;
  missing: number;
  failed: number;
  applied: boolean;
}

export interface LoginDefsChange {
  key: string;
  current: string;
  desired: string;
  why: string;
  status: { status: "would_set" | "set" };
}

export interface LoginDefsReport {
  config_path: string;
  changes: LoginDefsChange[];
  applied: boolean;
  backup_path: string | null;
  note: string | null;
}

export interface CombinedFixReport {
  ssh_perms: PermReport | null;
  etc_perms: PermReport | null;
  sshd: SshdHardeningReport | null;
  sysctl: SysctlHardeningReport | null;
  banner: BannerReport | null;
  login_defs: LoginDefsReport | null;
  sshd_error: string | null;
  errors?: string[];
  applied: boolean;
}

/** Banner files this run would rewrite (a file already carrying a custom warning is left alone). */
export function bannerChanges(r: BannerReport | null | undefined): BannerResult[] {
  if (!r) return [];
  return r.results.filter((x) => x.outcome.status === "would_write" || x.outcome.status === "written");
}

/** Rows a permission report would actually change — the only ones worth showing in a preview. */
export function permChanges(r: PermReport | null | undefined): PermResult[] {
  if (!r) return [];
  return r.results.filter((x) => x.outcome.status === "would_tighten" || x.outcome.status === "tightened");
}

/** sshd directives that would actually be written (excludes ones skipped as a lockout risk). */
export function sshdChanges(r: SshdHardeningReport | null | undefined): SshdChange[] {
  if (!r) return [];
  return r.changes.filter((c) => c.status.status === "would_set" || c.status.status === "set");
}

/**
 * Every change a report describes, flattened into one `label → before → after` list the UI can
 * render without knowing which fixer produced which row. Keeping this in one place is what lets a
 * new fixer show up in both the per-issue preview and Fix All with no new rendering code.
 */
export interface FlatChange {
  key: string;
  label: string;
  detail: string;
}

export function flattenChanges(r: CombinedFixReport | null | undefined): FlatChange[] {
  if (!r) return [];
  const out: FlatChange[] = [];
  for (const [scope, report] of [
    ["ssh", r.ssh_perms],
    ["etc", r.etc_perms],
  ] as const) {
    for (const p of permChanges(report)) {
      out.push({
        key: `${scope}:${p.path}`,
        label: p.path,
        detail: `${p.outcome.from} → ${p.outcome.to}`,
      });
    }
  }
  for (const c of sshdChanges(r.sshd)) {
    out.push({ key: `sshd:${c.keyword}`, label: c.keyword, detail: `${c.current} → ${c.desired}` });
  }
  for (const c of r.sysctl?.changes ?? []) {
    out.push({ key: `sysctl:${c.key}`, label: c.key, detail: `${c.current} → ${c.desired}` });
  }
  for (const b of bannerChanges(r.banner)) {
    out.push({ key: `banner:${b.path}`, label: b.path, detail: "write warning banner" });
  }
  for (const c of r.login_defs?.changes ?? []) {
    out.push({ key: `ld:${c.key}`, label: c.key, detail: `${c.current} → ${c.desired}` });
  }
  return out;
}

export function combinedChangeCount(r: CombinedFixReport): number {
  return flattenChanges(r).length;
}

/** Backup paths and post-apply notes worth telling the user about, from whichever fixer ran. */
export function fixNotes(r: CombinedFixReport | null | undefined): string[] {
  if (!r) return [];
  const notes: string[] = [];
  if (r.sshd?.backup_path) notes.push(`sshd_config backed up to ${r.sshd.backup_path}`);
  if (r.sysctl?.backup_path) notes.push(`previous sysctl drop-in backed up to ${r.sysctl.backup_path}`);
  if (r.login_defs?.backup_path) notes.push(`login.defs backed up to ${r.login_defs.backup_path}`);
  for (const b of bannerChanges(r.banner)) {
    if (b.backup_path) notes.push(`${b.path} backed up to ${b.backup_path}`);
  }
  if (r.sshd?.note) notes.push(r.sshd.note);
  if (r.sysctl?.note) notes.push(r.sysctl.note);
  if (r.login_defs?.note) notes.push(r.login_defs.note);
  if (r.sysctl?.applied) {
    notes.push("Kernel settings were written to /etc/sysctl.d, so they survive a reboot.");
  }
  if (r.sshd?.applied) notes.push("Reload sshd for the new config to take effect.");
  for (const e of r.errors ?? []) notes.push(e);
  if (r.sshd_error) notes.push(r.sshd_error);
  return notes;
}

/**
 * The rule → fixer map, fetched from the backend once per mount.
 *
 * Fetched rather than hardcoded here so `bulwark-core::FIX_CAPABILITIES` stays the single source of
 * truth for "is there a real fixer for this rule?". Most rules have none — kernel/sysctl hardening,
 * account policy and rootkit indicators have no mechanical, reversible remediation — and those
 * findings get no Fix button at all rather than a disabled one, because a greyed-out button still
 * promises a fix that does not exist.
 */
export function useFixCapabilities(): Map<string, FixCapability> {
  const [caps, setCaps] = useState<Map<string, FixCapability>>(new Map());
  useEffect(() => {
    let alive = true;
    invoke<FixCapability[]>("fix_capabilities")
      .then((list) => {
        if (alive) setCaps(new Map(list.map((c) => [c.rule_id, c])));
      })
      // A failure here means no Fix buttons render — the safe direction. Nothing else on the page
      // depends on it, so it stays silent rather than pushing an error banner over the findings.
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);
  return caps;
}
