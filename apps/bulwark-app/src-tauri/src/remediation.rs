//! GUI front-door for the user-scoped permission autofix.
//!
//! Like `ssh_protect`, this calls the linked `bulwark-core::remediation` function directly,
//! in-process — no `bulwarkctl` shell-out and no privilege needed, because `~/.ssh` is owned by the
//! user running the app. The root-scoped fixes (`/etc` permissions, `sshd_config` hardening) are
//! deliberately *not* exposed here: those need elevation and belong on the CLI's `pkexec` path, not
//! a one-click GUI button. Dry-run vs apply is the caller's choice, mirroring the CLI's default.

use bulwark_core::{ssh_permission_targets, tighten_permissions, PermReport};
use std::path::PathBuf;

fn ssh_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    Ok(PathBuf::from(home).join(".ssh"))
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
