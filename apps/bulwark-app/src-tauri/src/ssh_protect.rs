//! GUI front-door for adding a passphrase to unencrypted SSH keys.
//!
//! This calls the linked core function `bulwark_core::protect_unencrypted_keys` directly,
//! in-process — no `bulwarkctl` shell-out. See that function for the security details (the
//! passphrase reaches `ssh-keygen` via `SSH_ASKPASS` + an environment variable, never argv; each
//! key is backed up and rolled back on failure; only confidently-unencrypted keys are touched).

use bulwark_core::{protect_unencrypted_keys, BulkProtectionReport};
use std::path::PathBuf;

fn ssh_backup_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    Ok(PathBuf::from(home).join(".local/share/bulwark/ssh-key-backups"))
}

/// Adds one `passphrase` to every confidently-unencrypted key in `~/.ssh`, in a single pass.
/// Runs on a blocking thread because it spawns `ssh-keygen` once per key. Returns the per-key
/// report so the UI can show what was protected, skipped, or failed.
#[tauri::command]
pub async fn ssh_protect_keys(passphrase: String) -> Result<BulkProtectionReport, String> {
    if passphrase.is_empty() {
        return Err("passphrase must not be empty".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let dir = ssh_backup_dir()?;
        protect_unencrypted_keys(&passphrase, &dir).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
