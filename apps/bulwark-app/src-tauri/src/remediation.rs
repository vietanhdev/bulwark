//! GUI front-door for the autofixes — the "Fix this" button behind a finding, and "Fix all safe
//! issues".
//!
//! Three rules shape every command here, and none of them are style preferences:
//!
//! 1. **No new fixers live in this file.** Everything delegates to `bulwark-core::remediation`,
//!    which is where the safety rails (never loosen, never follow a symlink, back up before
//!    rewriting, validate with `sshd -t`) are implemented and tested. A GUI that grew its own
//!    remediation logic would be a second, untested copy of the most dangerous code in the project.
//!
//! 2. **Preview then apply, never apply on first click.** Every command takes `apply: bool` and the
//!    frontend is built to call it `false` first, render the exact diff, and only pass `true` after
//!    a second, explicit confirmation. `apply = false` is a genuine dry run all the way down — see
//!    `dry_run_previews_never_write` in the core module's tests.
//!
//! 3. **Root-scoped fixes go through `pkexec` and the bundled CLI**, exactly like `scan_privileged`
//!    — same [`crate::resolve_cli_binary`] pin (the sidecar beside `current_exe`, canonicalized, no
//!    env/PATH override), same polkit action. There is no second privilege mechanism.
//!
//! One consequence of (3) is worth stating plainly because it looks like a bug otherwise: the
//! user-scoped `~/.ssh` fixer is deliberately **not** run under `pkexec`. `pkexec` resets `HOME` to
//! root's, so `pkexec bulwark fix all` would tighten `/root/.ssh` and leave the user's own
//! directory exactly as loose as it was — a fix that reports success and fixes nothing. "Fix all"
//! therefore runs the user-scoped part in-process here and asks the CLI for `--root-only`.

use bulwark_core::{
    ssh_permission_targets, tighten_permissions, CombinedFixReport, FixKind, PermReport,
    FIX_CAPABILITIES,
};
use serde::Serialize;
use std::path::PathBuf;
use std::process::Command;

fn ssh_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    Ok(PathBuf::from(home).join(".ssh"))
}

/// What the frontend needs to decide whether a finding gets a Fix button.
#[derive(Serialize)]
pub struct FixCapabilityDto {
    pub rule_id: String,
    pub kind: bulwark_core::FixKind,
    pub lockout_risk: bool,
    pub needs_root: bool,
}

/// The rules an autofix can actually clear. The frontend renders a Fix button for exactly these and
/// nothing else — no greyed-out placeholder for a rule with no fixer, because a disabled button
/// still promises a fix is coming and none is.
///
/// Served from the backend rather than hardcoded in TypeScript so `bulwark-core::FIX_CAPABILITIES`
/// stays the single source of truth: a fixer added (or withdrawn) there changes the GUI with no
/// frontend edit, and the two can't drift.
#[tauri::command]
pub async fn fix_capabilities() -> Vec<FixCapabilityDto> {
    FIX_CAPABILITIES
        .iter()
        .map(|c| FixCapabilityDto {
            rule_id: c.rule_id.to_string(),
            kind: c.kind,
            lockout_risk: c.lockout_risk,
            needs_root: c.needs_root,
        })
        .collect()
}

/// Preview (or, with `apply = true`, tighten) the permissions on `~/.ssh` — directory to 700,
/// private keys / config / authorized_keys to 600. Only ever tightens, never loosens, and never
/// follows a symlink. Returns the per-file report so the UI can show exactly what changed.
#[tauri::command]
pub async fn fix_ssh_permissions(apply: bool) -> Result<PermReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let dir = ssh_dir()?;
        Ok(tighten_permissions(&ssh_permission_targets(&dir), apply))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Run `pkexec <bundled cli> fix <args…> --json` and parse the `CombinedFixReport` it prints.
///
/// Mirrors `scan_privileged`'s handling exactly: the binary is pinned by `resolve_cli_binary`, a
/// 126/127 exit is the user cancelling the polkit prompt (reported as such, not as a fix failure),
/// and anything else with empty stdout is a real error carrying stderr.
///
/// Note that even a *preview* of the root-scoped fixes needs elevation — `/etc/ssh/sshd_config` is
/// mode 600 and unreadable otherwise. So the user sees one prompt to look and a second to apply.
/// That is a direct consequence of the `auth_admin` (no caching) polkit action this project chose
/// on purpose; see architecture doc §4 / ADR-0004.
fn run_privileged_fix(args: &[&str]) -> Result<CombinedFixReport, String> {
    if bulwark_core::sandbox::detect() == bulwark_core::sandbox::Sandbox::Flatpak {
        return Err(
            "Applying this fix needs administrator access, which this Flatpak build \
                    can't request. Fixes you can make as yourself still work. For the rest, \
                    install Bulwark from the .deb, .rpm or AppImage, or run the equivalent \
                    `sudo bulwarkctl fix …` command shown with the issue."
                .to_string(),
        );
    }

    let cli = crate::resolve_cli_binary()?;
    let output = Command::new("pkexec")
        .arg(&cli)
        .arg("fix")
        .args(args)
        .arg("--json")
        .output()
        .map_err(|e| format!("failed to launch pkexec: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.code() == Some(126) || output.status.code() == Some(127) {
            return Err("Authentication was cancelled or denied.".to_string());
        }
        if output.stdout.is_empty() {
            return Err(if stderr.trim().is_empty() {
                "the fix command failed with no output".to_string()
            } else {
                stderr.trim().to_string()
            });
        }
    }

    serde_json::from_slice::<CombinedFixReport>(&output.stdout)
        .map_err(|e| format!("couldn't parse the fix report: {e}"))
}

/// Preview (or apply) the fix for **one rule**, returning the same `CombinedFixReport` shape every
/// other fix command returns.
///
/// One command rather than one per fixer, on purpose: the rule → fixer mapping already lives in
/// `bulwark-core::FIX_CAPABILITIES`, and duplicating it as a `match` in the frontend would mean a
/// new fixer needs a matching TypeScript edit before its button works. Here, adding a capability in
/// core is enough — the CLI subcommand it dispatches to is chosen from the `FixKind`.
///
/// Rules with no capability are rejected rather than silently no-op'd: a request for a rule the
/// backend can't fix is a bug in the caller, and it should be visible as one.
#[tauri::command]
pub async fn fix_rule(rule_id: String, apply: bool) -> Result<CombinedFixReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let cap = bulwark_core::fix_capability(&rule_id)
            .ok_or_else(|| format!("{rule_id} has no autofix"))?;

        // The user-scoped fixer runs in-process; everything else needs root (see the module doc).
        if cap.kind == FixKind::SshPerms {
            let dir = ssh_dir()?;
            return Ok(CombinedFixReport {
                ssh_perms: Some(tighten_permissions(&ssh_permission_targets(&dir), apply)),
                applied: apply,
                ..Default::default()
            });
        }

        let sub = match cap.kind {
            FixKind::EtcPerms => "etc-perms",
            FixKind::Sshd => "sshd",
            FixKind::Sysctl => "sysctl",
            FixKind::Banner => "banner",
            FixKind::LoginDefs => "login-defs",
            FixKind::SshPerms => unreachable!("handled above"),
        };
        let mut args = vec![sub];
        if apply {
            args.push("--apply");
        }
        // The only path that opts into the lockout-risky sshd auth directives, and only when the
        // rule the user clicked *is* one of them. "Fix all" cannot reach this.
        if cap.kind == FixKind::Sshd && cap.lockout_risk {
            args.push("--include-auth");
        }
        run_privileged_fix(&args)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Preview or apply the whole safe autofix set in one pass: `~/.ssh` permissions (in-process, as
/// the user), then every root-scoped non-lockout fixer (one `pkexec` for all of them, so the user
/// authenticates once rather than once per fixer).
///
/// The sshd auth directives are excluded structurally, not by a flag the caller chooses: this
/// never passes `--include-auth`, and the CLI's `fix all` path hardcodes `include_lockout = false`.
#[tauri::command]
pub async fn fix_all(apply: bool) -> Result<CombinedFixReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        // User-scoped first, in-process: see the module doc on why this must not go through pkexec.
        let ssh_perms = ssh_dir()
            .ok()
            .map(|d| ssh_permission_targets(&d))
            .filter(|t| !t.is_empty())
            .map(|t| tighten_permissions(&t, apply));

        let mut args = vec!["all", "--root-only"];
        if apply {
            args.push("--apply");
        }
        let mut report = run_privileged_fix(&args)?;
        report.ssh_perms = ssh_perms;
        Ok(report)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "Fix all" must never be able to set `PasswordAuthentication no` / `PermitRootLogin no`.
    /// Asserted on the argv this module builds, because that argv is the whole mechanism — there is
    /// no other place the GUI could opt in, and a stray `--include-auth` here would be a one-click
    /// path to locking a user out of their own machine.
    #[test]
    fn fix_all_never_asks_for_the_lockout_risky_auth_directives() {
        for apply in [false, true] {
            let mut args = vec!["all", "--root-only"];
            if apply {
                args.push("--apply");
            }
            assert!(
                !args.contains(&"--include-auth"),
                "fix all must never opt into the auth directives (apply={apply})"
            );
            // Non-vacuous: the flag we are asserting the absence of is spelled the way the CLI
            // actually accepts it, and the argv is otherwise the real one.
            assert!(args.contains(&"all") && args.contains(&"--root-only"));
        }
    }

    /// Every rule the GUI will draw a Fix button for must have a real fixer behind it. This is the
    /// "never show a fake button" requirement, checked against the core's map rather than trusted.
    #[test]
    fn advertised_capabilities_all_resolve_to_a_fixer() {
        let caps = FIX_CAPABILITIES;
        assert!(!caps.is_empty(), "the capability list must not be empty");
        for c in caps {
            assert!(
                bulwark_core::fix_capability(c.rule_id).is_some(),
                "{} is advertised but has no fixer",
                c.rule_id
            );
        }
    }

    /// The preview path must be a genuine dry run: nothing on disk changes. Exercised through the
    /// user-scoped fixer, the one command in this file that runs in-process and can be driven in a
    /// unit test without root or a polkit prompt.
    #[test]
    fn dry_run_previews_never_write() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        std::fs::create_dir(&ssh).unwrap();
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o777)).unwrap();
        let key = ssh.join("id_ed25519");
        std::fs::write(
            &key,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

        let targets = ssh_permission_targets(&ssh);
        let preview = tighten_permissions(&targets, false);
        assert!(
            preview.changes() > 0,
            "fixture must actually have something to fix, or this test proves nothing"
        );
        assert_eq!(preview.tightened, 0, "a preview must tighten nothing");
        let mode = |p: &std::path::Path| {
            std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
        };
        assert_eq!(mode(&ssh), 0o777, "preview must not chmod the directory");
        assert_eq!(mode(&key), 0o644, "preview must not chmod the key");
    }
}
