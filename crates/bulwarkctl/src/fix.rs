//! `bulwarkctl fix …` — the front door to the autofixes in `bulwark_core::remediation`.
//!
//! Nothing here decides *what* a fix does; this file decides what is said about it, and three
//! rules shape that:
//!
//!   * **The words follow what happened.** Each line is written from the status the fixer
//!     returned, never from what was attempted. The sysctl fixer used to print "saved + applied
//!     now" for a setting whose write to the running system had just failed.
//!   * **A change that could not be made is a non-zero exit code**, in the report for people and
//!     in the JSON one alike, so a script cannot take a half-applied fix for a finished one.
//!   * **`fix all` does what its help says and nothing else**: permissions, the sshd settings
//!     that cannot lock anyone out, and the kernel network settings. The banner and password-age
//!     fixers change wording and policy, so `fix all` lists them and leaves them to be run by
//!     name.

use crate::{engine, FixAction};
use anyhow::Context;
use bulwark_core::remediation::BaselineUpdate;
use bulwark_core::{
    etc_permission_targets, harden_login_defs, harden_sshd_config, harden_sysctl,
    ssh_permission_targets, tighten_permissions, write_banners, CombinedFixReport, FixKind,
};
use std::path::{Path, PathBuf};

/// `println!`, with Bulwark's own symbols in ASCII when the terminal's locale is not UTF-8.
macro_rules! say {
    () => { println!() };
    ($($arg:tt)*) => { println!("{}", crate::term::for_locale(&format!($($arg)*))) };
}

/// Exit code of a fix run in which something could not be changed.
const SOMETHING_FAILED: i32 = 1;

/// Runs a `fix` subcommand and returns the process exit code.
pub(crate) fn run(action: FixAction) -> anyhow::Result<i32> {
    let home = bulwark_core::paths::home_var().context("HOME not set")?;
    let ssh_dir = PathBuf::from(&home).join(".ssh");
    let backup_dir = PathBuf::from(&home).join(".local/share/bulwark/sshd-config-backups");
    let mut failed = false;

    match action {
        FixAction::List => {
            // A pure preview of everything, so a user can see the whole surface at a glance before
            // choosing what to apply. Nothing here writes.
            say!("Available autofixes (preview — nothing changed):\n");

            match ssh_dir_scope(&ssh_dir) {
                SshDirScope::AnotherAccounts => {
                    say!("• fix ssh-perms   ~/.ssh permissions — not checked");
                    say!("    {}", another_accounts_ssh_dir(&ssh_dir));
                }
                scope => {
                    let ssh_report = tighten_permissions(&ssh_permission_targets(&ssh_dir), false);
                    say!(
                        "• fix ssh-perms   ~/.ssh permissions — {} to tighten",
                        ssh_report.changes()
                    );
                    if scope == SshDirScope::RootsUnderSudo {
                        say!("    {}", roots_ssh_dir_under_sudo(&ssh_dir, false));
                    }
                    print_perm_report(&ssh_report, "    ");
                }
            }

            let etc_report = tighten_permissions(&etc_permission_targets(), false);
            say!(
                "\n• fix etc-perms   /etc sensitive files — {} to tighten (needs root to apply)",
                etc_report.changes()
            );
            print_perm_report(&etc_report, "    ");

            match harden_sshd_config(None, &backup_dir, false, true) {
                Ok(sshd_report) => {
                    say!(
                        "\n• fix sshd        sshd_config hardening — {} directive(s) to set (needs root to apply)",
                        sshd_report.changes.len()
                    );
                    print_sshd_changes(&sshd_report, "    ");
                    print_by_hand(sshd_report.by_hand, sshd_report.note.as_deref(), "    ");
                }
                Err(e) => {
                    say!("\n• fix sshd        sshd_config hardening — unavailable: {e}");
                }
            }

            match harden_sysctl(
                &bulwark_core::rules_for_kind(FixKind::Sysctl),
                &sysctl_backup_dir(&home),
                false,
            ) {
                Ok(r) => {
                    say!(
                        "\n• fix sysctl      kernel network settings — {} to save and apply (needs root to apply)",
                        r.pending_count()
                    );
                    print_sysctl_changes(&r, "    ");
                }
                Err(e) => say!("\n• fix sysctl      unavailable: {e}"),
            }

            let banner_report = write_banners(&banner_backup_dir(&home), false);
            say!(
                "\n• fix banner      login warning banners — {} file(s) to write (needs root to apply; not part of fix all)",
                banner_report.pending_count()
            );
            print_banner_changes(&banner_report, "    ");

            match harden_login_defs(
                &bulwark_core::rules_for_kind(FixKind::LoginDefs),
                None,
                &login_defs_backup_dir(&home),
                false,
            ) {
                Ok(r) => {
                    say!(
                        "\n• fix login-defs  password aging policy — {} directive(s) to set (needs root to apply; not part of fix all)",
                        r.pending_count()
                    );
                    print_login_defs_changes(&r, "    ");
                    print_by_hand(r.by_hand, r.note.as_deref(), "    ");
                }
                Err(e) => say!("\n• fix login-defs  unavailable: {e}"),
            }

            say!("\nOther fixes (their own commands, need interactive input):");
            say!("    ssh protect     add one passphrase to every unencrypted ~/.ssh key");
            say!("    ai redact       remove leaked secrets from AI-assistant context files");
            say!("\nApply one with e.g.:  bulwarkctl fix ssh-perms --apply");
            say!("Or the safe set:      sudo bulwarkctl fix all --apply");
            say!(
                "    (/etc permissions, sshd and kernel settings; under sudo, ~/.ssh is root's, \
                 so run `bulwarkctl fix ssh-perms --apply` without sudo for your own)"
            );
        }

        FixAction::SshPerms { apply } => {
            let scope = ssh_dir_scope(&ssh_dir);
            if scope == SshDirScope::AnotherAccounts {
                // Refused, not skipped: this command has nothing else to do.
                anyhow::bail!("{}", another_accounts_ssh_dir(&ssh_dir));
            }
            if scope == SshDirScope::RootsUnderSudo {
                say!("{}\n", roots_ssh_dir_under_sudo(&ssh_dir, apply));
            }
            let targets = ssh_permission_targets(&ssh_dir);
            if targets.is_empty() {
                say!("No {} folder found — nothing to fix.", ssh_dir.display());
                return Ok(0);
            }
            let report = tighten_permissions(&targets, apply);
            print_perm_report(&report, "");
            report_perm_summary(&report, apply);
            failed |= report.failed > 0;
        }

        FixAction::EtcPerms { apply, json } => {
            if apply && !engine::is_running_as_root() {
                anyhow::bail!(
                    "fix etc-perms --apply changes root-owned files — re-run as: \
                     sudo bulwarkctl fix etc-perms --apply"
                );
            }
            let report = tighten_permissions(&etc_permission_targets(), apply);
            failed |= report.failed > 0;
            if json {
                print_fix_json(&CombinedFixReport {
                    etc_perms: Some(report),
                    applied: apply,
                    ..Default::default()
                })?;
            } else {
                print_perm_report(&report, "");
                report_perm_summary(&report, apply);
            }
        }

        FixAction::Sshd {
            apply,
            json,
            include_auth,
            config,
        } => {
            // Root is only required to write the real system config; an explicit --config path (used
            // for testing or a user-owned copy) the caller can already write is exempt.
            if apply && config.is_none() && !engine::is_running_as_root() {
                anyhow::bail!(
                    "fix sshd --apply edits /etc/ssh/sshd_config — re-run as: \
                     sudo bulwarkctl fix sshd --apply"
                );
            }
            if include_auth {
                eprintln!(
                    "{}",
                    crate::term::for_locale(
                        "⚠  --include-auth will set PasswordAuthentication no and PermitRootLogin no.\n\
                         ⚠  Make sure key-based login already works, or you can be locked out.\n"
                    )
                );
            }
            let report = harden_sshd_config(config.as_deref(), &backup_dir, apply, include_auth)?;
            if json {
                print_fix_json(&CombinedFixReport {
                    sshd: Some(report),
                    applied: apply,
                    ..Default::default()
                })?;
            } else {
                print_sshd_report(&report, apply);
            }
        }

        FixAction::Sysctl { apply, json } => {
            if apply && !engine::is_running_as_root() {
                anyhow::bail!(
                    "fix sysctl --apply writes /etc/sysctl.d — re-run as: \
                     sudo bulwarkctl fix sysctl --apply"
                );
            }
            let report = harden_sysctl(
                &bulwark_core::rules_for_kind(FixKind::Sysctl),
                &sysctl_backup_dir(&home),
                apply,
            )?;
            failed |= report.not_in_effect() > 0;
            if json {
                print_fix_json(&CombinedFixReport {
                    sysctl: Some(report),
                    applied: apply,
                    ..Default::default()
                })?;
            } else {
                print_sysctl_report(&report, apply);
            }
        }

        FixAction::Banner { apply, json } => {
            if apply && !engine::is_running_as_root() {
                anyhow::bail!(
                    "fix banner --apply writes /etc/issue — re-run as: \
                     sudo bulwarkctl fix banner --apply"
                );
            }
            let report = write_banners(&banner_backup_dir(&home), apply);
            failed |= report.failed > 0;
            if json {
                print_fix_json(&CombinedFixReport {
                    banner: Some(report),
                    applied: apply,
                    ..Default::default()
                })?;
            } else {
                print_banner_report(&report, apply);
            }
        }

        FixAction::LoginDefs {
            apply,
            json,
            config,
        } => {
            if apply && config.is_none() && !engine::is_running_as_root() {
                anyhow::bail!(
                    "fix login-defs --apply edits /etc/login.defs — re-run as: \
                     sudo bulwarkctl fix login-defs --apply"
                );
            }
            let report = harden_login_defs(
                &bulwark_core::rules_for_kind(FixKind::LoginDefs),
                config.as_deref(),
                &login_defs_backup_dir(&home),
                apply,
            )?;
            failed |= login_defs_failed(&report);
            if json {
                print_fix_json(&CombinedFixReport {
                    login_defs: Some(report),
                    applied: apply,
                    ..Default::default()
                })?;
            } else {
                print_login_defs_report(&report, apply);
            }
        }

        FixAction::All {
            apply,
            json,
            root_only,
        } => {
            let is_root = engine::is_running_as_root();
            // Applying the root-scoped fixers without root would fail file by file; the JSON form
            // (what the app reads back from `pkexec`) refuses up front with one clear reason.
            if json && apply && !is_root {
                anyhow::bail!(
                    "fix all --apply changes root-owned files — re-run as: sudo bulwarkctl fix all --apply"
                );
            }
            let (report, notes) = fix_all(&home, &ssh_dir, &backup_dir, apply, root_only, is_root);
            failed |= fix_all_failed(&report);
            if json {
                print_fix_json(&report)?;
            } else {
                print_fix_all(&report, &notes, apply);
            }
        }
    }
    Ok(if failed { SOMETHING_FAILED } else { 0 })
}

// ---- whose ~/.ssh --------------------------------------------------------------------------------

/// Whose `~/.ssh` this process would be tightening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SshDirScope {
    /// The account's own: the ordinary case, and a real root login's.
    Own,
    /// Root's, reached through `sudo`/`pkexec`. Fixed, and said out loud: someone who typed
    /// `sudo bulwarkctl fix all` usually has their own `~/.ssh` in mind, and it is not this one.
    RootsUnderSudo,
    /// Another account's, because `sudo -E` (or macOS's `sudo`) kept that account's `HOME`. Root
    /// does not change files in a folder its owner can rearrange under it; the owner runs the fix.
    AnotherAccounts,
}

fn ssh_dir_scope(ssh_dir: &Path) -> SshDirScope {
    if !(engine::is_running_as_root() && crate::elevated_from_another_user()) {
        return SshDirScope::Own;
    }
    #[cfg(not(unix))]
    let _ = ssh_dir;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // The folder itself, or the home it would be in when there is no `.ssh` yet.
        let owner = std::fs::symlink_metadata(ssh_dir)
            .or_else(|_| std::fs::symlink_metadata(ssh_dir.parent().unwrap_or(ssh_dir)))
            .map(|m| m.uid());
        if owner.is_ok_and(|uid| uid != 0) {
            return SshDirScope::AnotherAccounts;
        }
    }
    SshDirScope::RootsUnderSudo
}

fn roots_ssh_dir_under_sudo(ssh_dir: &Path, apply: bool) -> String {
    format!(
        "This ran with sudo, so ~/.ssh here is root's ({}). To fix your own, run it without \
         sudo: bulwarkctl fix ssh-perms{}",
        ssh_dir.display(),
        if apply { " --apply" } else { "" }
    )
}

fn another_accounts_ssh_dir(ssh_dir: &Path) -> String {
    format!(
        "{} belongs to another account, and root does not change another account's files. Run \
         it as that account, without sudo: bulwarkctl fix ssh-perms --apply",
        ssh_dir.display()
    )
}

// ---- fix all -------------------------------------------------------------------------------------

/// What `fix all` says beside its report: lines that are not about one changed file.
#[derive(Default)]
struct FixAllNotes {
    /// Why the `~/.ssh` part did not run, or whose folder it ran on.
    ssh_perms: Option<String>,
    /// True when the root-scoped fixers were left out because this is not root.
    needs_root: bool,
}

/// The whole bulk set, once, for both output forms — so the printed report and the JSON one are
/// the same run and cannot half-agree.
///
/// `root_only` drops the user-scoped `~/.ssh` pass. The app passes it: under `pkexec`, `HOME` is
/// root's, and the app has already tightened the signed-in user's `~/.ssh` itself. The
/// lockout-risky sshd auth directives are **never** included here; they stay behind
/// `fix sshd --include-auth`, an explicit per-issue decision.
fn fix_all(
    home: &str,
    ssh_dir: &Path,
    backup_dir: &Path,
    apply: bool,
    root_only: bool,
    is_root: bool,
) -> (CombinedFixReport, FixAllNotes) {
    let mut report = CombinedFixReport {
        applied: apply,
        ..Default::default()
    };
    let mut notes = FixAllNotes::default();

    // 1. ~/.ssh — the only part that needs no privilege.
    if root_only {
        notes.ssh_perms = Some("skipped (--root-only)".into());
    } else {
        match ssh_dir_scope(ssh_dir) {
            SshDirScope::AnotherAccounts => {
                notes.ssh_perms = Some(format!("skipped: {}", another_accounts_ssh_dir(ssh_dir)));
            }
            scope => {
                if scope == SshDirScope::RootsUnderSudo {
                    notes.ssh_perms = Some(roots_ssh_dir_under_sudo(ssh_dir, apply));
                }
                let targets = ssh_permission_targets(ssh_dir);
                if targets.is_empty() {
                    let missing = format!("no {} folder — skipped", ssh_dir.display());
                    notes.ssh_perms = Some(match notes.ssh_perms.take() {
                        Some(whose) => format!("{missing}. {whose}"),
                        None => missing,
                    });
                } else {
                    report.ssh_perms = Some(tighten_permissions(&targets, apply));
                }
            }
        }
    }

    // 2–4. The root-scoped part of the bulk set: /etc permissions, the sshd settings that cannot
    // lock anyone out, the kernel network settings. Previewed by anyone, applied only by root.
    if apply && !is_root {
        notes.needs_root = true;
    } else {
        report.etc_perms = Some(tighten_permissions(&etc_permission_targets(), apply));
        match harden_sshd_config(None, backup_dir, apply, false) {
            Ok(r) => report.sshd = Some(r),
            // A missing sshd_config is not an error — but it must be *reported*, never dropped.
            Err(e) => report.sshd_error = Some(e.to_string()),
        }
        match harden_sysctl(
            &bulwark_core::rules_for_kind(FixKind::Sysctl),
            &sysctl_backup_dir(home),
            apply,
        ) {
            Ok(r) => report.sysctl = Some(r),
            Err(e) => report.errors.push(format!("sysctl: {e}")),
        }
    }

    // Looked at, never applied here: these two change wording and policy. Always a preview.
    let banner = write_banners(&banner_backup_dir(home), false);
    if banner.pending_count() > 0 {
        report.not_included.push(format!(
            "fix banner: {} login banner file(s) still hold the distribution's default text. \
             Replace them with a warning banner by running: sudo bulwarkctl fix banner --apply",
            banner.pending_count()
        ));
    }
    if let Ok(login_defs) = harden_login_defs(
        &bulwark_core::rules_for_kind(FixKind::LoginDefs),
        None,
        &login_defs_backup_dir(home),
        false,
    ) {
        if login_defs.by_hand {
            if let Some(note) = &login_defs.note {
                report.not_included.push(format!("fix login-defs: {note}"));
            }
        } else if login_defs.pending_count() > 0 {
            let settings: Vec<String> = login_defs
                .changes
                .iter()
                .map(|c| format!("{} {}", c.key, c.desired))
                .collect();
            report.not_included.push(format!(
                "fix login-defs: the password-age policy in /etc/login.defs would change ({}). \
                 Set it by running: sudo bulwarkctl fix login-defs --apply",
                settings.join(", ")
            ));
        }
    }

    (report, notes)
}

/// Whether any part of a `fix all` run could not make a change it set out to make.
fn fix_all_failed(report: &CombinedFixReport) -> bool {
    report.ssh_perms.as_ref().is_some_and(|r| r.failed > 0)
        || report.etc_perms.as_ref().is_some_and(|r| r.failed > 0)
        || report
            .sysctl
            .as_ref()
            .is_some_and(|r| r.not_in_effect() > 0)
        || !report.errors.is_empty()
}

fn print_fix_all(report: &CombinedFixReport, notes: &FixAllNotes, apply: bool) {
    say!(
        "Running the safe autofix set{}:\n",
        if apply { " (applying)" } else { " (preview)" }
    );

    match &report.ssh_perms {
        Some(r) => {
            say!("[ssh-perms] {} change(s)", r.changes());
            if let Some(whose) = &notes.ssh_perms {
                say!("    {whose}");
            }
            print_perm_report(r, "    ");
        }
        None => say!(
            "[ssh-perms] {}",
            notes.ssh_perms.as_deref().unwrap_or("skipped")
        ),
    }

    if notes.needs_root {
        say!(
            "\n[etc-perms] [sshd] [sysctl] need root — skipped. Re-run with sudo to include \
             them: sudo bulwarkctl fix all --apply"
        );
    }
    if let Some(r) = &report.etc_perms {
        say!("\n[etc-perms] {} change(s)", r.changes());
        print_perm_report(r, "    ");
    }
    if let Some(r) = &report.sshd {
        say!(
            "\n[sshd] {} directive(s){}",
            r.pending_count(),
            if r.applied { " set" } else { " to set" }
        );
        print_sshd_changes(r, "    ");
        if let Some(note) = &r.note {
            say!("    note: {note}");
        }
    }
    if let Some(e) = &report.sshd_error {
        say!("\n[sshd] skipped: {e}");
    }
    if let Some(r) = &report.sysctl {
        say!("\n[sysctl] {} setting(s)", r.pending_count());
        print_sysctl_changes(r, "    ");
        print_sysctl_not_in_effect(r, "    ");
    }
    for e in &report.errors {
        match e.split_once(": ") {
            Some((fixer, why)) => say!("\n[{fixer}] skipped: {why}"),
            None => say!("\nskipped: {e}"),
        }
    }

    if !apply {
        say!("\nPreview only. Re-run with --apply (and sudo for the root-owned fixes).");
    }
    if !report.not_included.is_empty() {
        say!("\nNot applied by fix all — these change wording or policy, so they are run by name:");
        for line in &report.not_included {
            say!("    {line}");
        }
    }
    say!(
        "\nAlso not included (need a decision or a secret): the lockout-risky sshd auth \
         directives (fix sshd --include-auth), key passphrases (ssh protect), secret \
         redaction (ai redact)."
    );
    if fix_all_failed(report) {
        say!(
            "\nSome changes could not be made — see the lines marked FAILED or NOT applied above."
        );
    }
}

// ---- where backups go ----------------------------------------------------------------------------

/// Backup directories for the file-rewriting fixers. All under the user's own data dir, next to
/// the sshd-config backups the sshd fixer already writes there.
fn sysctl_backup_dir(home: &str) -> PathBuf {
    PathBuf::from(home).join(".local/share/bulwark/sysctl-backups")
}
fn banner_backup_dir(home: &str) -> PathBuf {
    PathBuf::from(home).join(".local/share/bulwark/banner-backups")
}
fn login_defs_backup_dir(home: &str) -> PathBuf {
    PathBuf::from(home).join(".local/share/bulwark/login-defs-backups")
}

// ---- sysctl --------------------------------------------------------------------------------------

/// What happened to one setting, from the status the fixer returned — never from what it tried.
fn sysctl_outcome(c: &bulwark_core::SysctlChange) -> String {
    use bulwark_core::SysctlChangeStatus as S;
    match (&c.status, c.persisted) {
        (S::WouldSet, true) => "would be saved and applied".into(),
        (S::WouldSet, false) => {
            "would be applied now (new interfaces get the value from conf.default)".into()
        }
        (S::Set, true) => "saved and applied".into(),
        (S::Set, false) => "applied (new interfaces get the value from conf.default)".into(),
        (S::SetButNotLive, true) => {
            "saved, but NOT applied: the running system did not take the value".into()
        }
        (S::SetButNotLive, false) => {
            "NOT applied: the running system did not take the value".into()
        }
        (S::Failed { reason }, true) => {
            format!("saved, but NOT applied to the running system ({reason})")
        }
        (S::Failed { reason }, false) => format!("NOT applied ({reason})"),
    }
}

fn print_sysctl_changes(report: &bulwark_core::SysctlHardeningReport, indent: &str) {
    for c in &report.changes {
        // A persisted key and a live-only interface write are different promises to the user, and
        // so are a setting that took effect and one that did not: each row says which it is.
        say!(
            "{indent}{} = {} ({} {}) — {}",
            c.key,
            c.desired,
            if report.applied { "was" } else { "currently" },
            c.current,
            sysctl_outcome(c)
        );
        if !c.interfaces.is_empty() {
            say!(
                "{indent}    {} interface(s): {}",
                c.interfaces.len(),
                c.interfaces.join(", ")
            );
        }
    }
    for k in &report.stale_persisted_keys {
        say!("{indent}stale entry to remove: {k}");
    }
}

/// Says, once, what it means that settings did not reach the running system and what to do.
fn print_sysctl_not_in_effect(report: &bulwark_core::SysctlHardeningReport, indent: &str) {
    let n = report.not_in_effect();
    if n == 0 {
        return;
    }
    say!(
        "{indent}{n} setting(s) could not be applied to the running system. What was saved in {} \
         takes effect at the next start. In a container the kernel's settings belong to the \
         host: apply them there.",
        report.conf_path
    );
}

fn print_sysctl_report(report: &bulwark_core::SysctlHardeningReport, apply: bool) {
    if report.changes.is_empty() {
        say!("Kernel network settings are already hardened. Nothing to do.");
        return;
    }
    let saved = report.changes.iter().filter(|c| c.persisted).count();
    say!(
        "{saved} setting(s) {} {}:",
        if report.applied {
            "written to"
        } else {
            "would be written to"
        },
        report.conf_path
    );
    print_sysctl_changes(report, "    ");
    if let Some(b) = &report.backup_path {
        say!("Previous file backed up to {b}");
    }
    if let Some(n) = &report.note {
        say!("note: {n}");
    }
    print_sysctl_not_in_effect(report, "");
    if !apply {
        say!("\nPreview only. Re-run with --apply (as root) to write them.");
    }
}

// ---- banner --------------------------------------------------------------------------------------

fn print_banner_changes(report: &bulwark_core::BannerReport, indent: &str) {
    use bulwark_core::BannerOutcome;
    for r in &report.results {
        match &r.outcome {
            BannerOutcome::WouldWrite => {
                say!("{indent}would write {} ({})", r.path, r.label);
                if let Some(target) = &r.was_link_to {
                    say!(
                        "{indent}    it is a link to {target}: the link would be replaced by a \
                         file, and {target} itself is not changed"
                    );
                }
            }
            BannerOutcome::Written => {
                say!("{indent}wrote {} ({})", r.path, r.label);
                if let Some(target) = &r.was_link_to {
                    say!(
                        "{indent}    it was a link to {target}: the link is now a file, and \
                         {target} itself was not changed"
                    );
                }
                if let Some(b) = &r.backup_path {
                    say!("{indent}    previous text saved to {b}");
                }
            }
            BannerOutcome::CustomisedLeftAlone { empty } => say!(
                "{indent}left alone: {} {}. Bulwark never overwrites a banner someone set, so \
                 the finding stays until you add a warning to it yourself.",
                r.path,
                if *empty {
                    "is empty"
                } else {
                    "holds text someone wrote, without a warning that access is restricted"
                }
            ),
            BannerOutcome::Failed { reason } => say!("{indent}FAILED {}: {reason}", r.path),
            BannerOutcome::AlreadyCustom | BannerOutcome::Missing => {}
        }
    }
}

fn print_banner_report(report: &bulwark_core::BannerReport, apply: bool) {
    print_banner_changes(report, "");
    if report.pending_count() == 0 && report.failed == 0 {
        say!(
            "{}",
            if report.left_customised > 0 {
                "No banner still holds the distribution's default text. Nothing was changed."
            } else if report.already_custom > 0 {
                "The login banners already carry a warning. Nothing to do."
            } else {
                "No login banner files (/etc/issue, /etc/issue.net) found. Nothing to do."
            }
        );
        return;
    }
    if !apply {
        say!("\nPreview only. Re-run with --apply (as root) to write them.");
    }
}

// ---- login.defs ----------------------------------------------------------------------------------

fn print_login_defs_changes(report: &bulwark_core::LoginDefsReport, indent: &str) {
    for c in &report.changes {
        say!(
            "{indent}{} {} ({} {})",
            c.key,
            c.desired,
            if report.applied { "was" } else { "currently" },
            c.current
        );
    }
}

/// The fixer wrote the file and something about the result is not as intended.
fn login_defs_failed(report: &bulwark_core::LoginDefsReport) -> bool {
    report.applied
        && (report.note.is_some() || matches!(report.baseline, Some(BaselineUpdate::Failed { .. })))
}

fn print_login_defs_report(report: &bulwark_core::LoginDefsReport, apply: bool) {
    if report.changes.is_empty() {
        say!("Password-aging policy is already within the rule thresholds. Nothing to do.");
        return;
    }
    say!(
        "{} directive(s) {} in {}:",
        report.changes.len(),
        if report.applied { "set" } else { "to set" },
        report.config_path
    );
    print_login_defs_changes(report, "    ");
    if let Some(b) = &report.backup_path {
        say!("Original backed up to {b}");
    }
    if let Some(n) = &report.note {
        say!("note: {n}");
    }
    print_baseline_note(report.baseline.as_ref(), "");
    if report.by_hand {
        say!("\nNothing is written on this system: make the change by hand as the note says.");
    } else if !apply {
        say!("\nPreview only. Re-run with --apply (as root) to set them.");
    }
}

/// The note of a fixer that cannot write on this system and says what to do by hand.
fn print_by_hand(by_hand: bool, note: Option<&str>, indent: &str) {
    if let (true, Some(note)) = (by_hand, note) {
        say!("{indent}by hand: {note}");
    }
}

/// What a fixer did about the file-integrity baseline of a file it rewrote: one line, or nothing
/// when the file has no baseline entry. Every fixer that rewrites a watched file prints this.
fn print_baseline_note(update: Option<&BaselineUpdate>, indent: &str) {
    if let Some(update) = update {
        say!("{indent}note: {}", update.message());
    }
}

// ---- output shared by several fixers -------------------------------------------------------------

/// Emit a fix report as one JSON document on stdout.
fn print_fix_json(report: &CombinedFixReport) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string(report)?);
    Ok(())
}

/// Print a permission report's per-file lines. `indent` prefixes each line so `fix list`/`fix all`
/// can nest them under a heading. Files already fine and files that aren't there are left out —
/// a change, a refusal and a failure each get a line.
fn print_perm_report(report: &bulwark_core::PermReport, indent: &str) {
    use bulwark_core::PermOutcome;
    for r in &report.results {
        match &r.outcome {
            PermOutcome::WouldTighten { from, to } => {
                say!(
                    "{indent}would chmod {from} → {to}  {} ({})",
                    r.path,
                    r.label
                );
            }
            PermOutcome::Tightened { from, to } => {
                say!("{indent}chmod {from} → {to}  {} ({})", r.path, r.label);
            }
            PermOutcome::SkippedSymlink => say!(
                "{indent}skipped {} ({}): it is a symbolic link, and a link is never changed",
                r.path,
                r.label
            ),
            PermOutcome::Failed { reason } => say!("{indent}FAILED {}: {reason}", r.path),
            PermOutcome::AlreadyOk | PermOutcome::Missing => continue,
        }
        if let Some(note) = &r.note {
            say!("{indent}    note: {note}");
        }
    }
}

fn report_perm_summary(report: &bulwark_core::PermReport, apply: bool) {
    if report.changes() == 0 && report.failed == 0 {
        say!("All checked permissions are already correct. Nothing to do.");
        return;
    }
    if apply {
        say!(
            "\n{} tightened, {} already ok, {} missing, {} failed.",
            report.tightened,
            report.already_ok,
            report.missing,
            report.failed
        );
        if report.failed > 0 {
            say!("Some changes failed — see the lines above (often: needs root).");
        }
    } else {
        say!(
            "\n{} file(s) would be tightened. Re-run with --apply to make the change.",
            report.would_tighten
        );
    }
}

fn print_sshd_changes(report: &bulwark_core::SshdHardeningReport, indent: &str) {
    use bulwark_core::SshdChangeStatus;
    for c in &report.changes {
        let verb = match c.status {
            SshdChangeStatus::WouldSet => "would set",
            SshdChangeStatus::Set => "set",
            SshdChangeStatus::SkippedLockout => "skipped (lockout risk — use --include-auth)",
        };
        say!(
            "{indent}{verb}: {} {} (was {}) — {}",
            c.keyword,
            c.desired,
            c.current,
            c.why
        );
    }
}

fn print_sshd_report(report: &bulwark_core::SshdHardeningReport, apply: bool) {
    if report.changes.is_empty() {
        say!("sshd_config is already hardened against the SSH rules. Nothing to do.");
        return;
    }
    say!("sshd_config: {}", report.config_path);
    print_sshd_changes(report, "  ");
    if let Some(note) = &report.note {
        say!("note: {note}");
    }
    if report.applied {
        say!(
            "\nApplied. Check it and reload the SSH service for it to take effect:\n    \
             sudo sshd -t && sudo systemctl reload ssh\n\
             (the service is called sshd, not ssh, on Fedora, RHEL, Arch and openSUSE)"
        );
        if let Some(b) = &report.backup_path {
            say!("Backup of the original: {b}");
        }
        say!("Undo: restore the backup, or delete the '# BEGIN bulwark-hardening' block.");
    } else if report.by_hand {
        say!("\nNothing is written on this system: make the change by hand as the note says.");
    } else if apply {
        say!("\nNothing was applied (only lockout-risky directives were pending — add --include-auth).");
    } else {
        say!("\nPreview only. Re-run with --apply (as root) to make the change.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulwark_core::{SysctlChange, SysctlChangeStatus};

    fn change(status: SysctlChangeStatus, persisted: bool) -> SysctlChange {
        SysctlChange {
            key: "net.ipv4.conf.all.log_martians".into(),
            current: "0".into(),
            desired: "1".into(),
            why: String::new(),
            status,
            persisted,
            interfaces: Vec::new(),
        }
    }

    /// The tester's case: the write to the running system failed ("Read-only file system") and
    /// the line still read "saved + applied now". A preview read the same.
    #[test]
    fn a_sysctl_line_says_what_happened_not_what_was_tried() {
        let failed = SysctlChangeStatus::Failed {
            reason: "all: Read-only file system".into(),
        };
        let line = sysctl_outcome(&change(failed.clone(), true));
        assert!(line.contains("NOT applied"), "{line}");
        assert!(line.contains("Read-only file system"), "{line}");
        assert!(line.starts_with("saved"), "the file was written: {line}");
        assert!(sysctl_outcome(&change(failed, false)).starts_with("NOT applied"));
        assert!(
            sysctl_outcome(&change(SysctlChangeStatus::SetButNotLive, true))
                .contains("NOT applied")
        );

        // A preview promises nothing in the past tense.
        let preview = sysctl_outcome(&change(SysctlChangeStatus::WouldSet, true));
        assert!(preview.starts_with("would be"), "{preview}");
        // And the words for a real success are kept for a real success.
        assert_eq!(
            sysctl_outcome(&change(SysctlChangeStatus::Set, true)),
            "saved and applied"
        );
    }

    #[test]
    fn a_setting_that_did_not_take_effect_fails_the_run() {
        let mut sysctl = bulwark_core::SysctlHardeningReport {
            applied: true,
            ..Default::default()
        };
        sysctl.changes.push(change(SysctlChangeStatus::Set, true));
        let mut report = CombinedFixReport {
            sysctl: Some(sysctl.clone()),
            ..Default::default()
        };
        assert!(!fix_all_failed(&report));

        sysctl.changes.push(change(
            SysctlChangeStatus::Failed {
                reason: "all: Read-only file system".into(),
            },
            true,
        ));
        report.sysctl = Some(sysctl);
        assert!(fix_all_failed(&report));
    }
}
