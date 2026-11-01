//! Where Bulwark keeps its on-disk state — one resolver shared by both front-doors.
//!
//! This used to be re-implemented in three places (the CLI, the GUI's command layer, and the GUI's
//! monitoring loop), and they had already drifted: two honoured `XDG_DATA_HOME` and one did not.
//! Inside a Flatpak `$HOME` is read-only and `XDG_DATA_HOME` is the only writable data dir, so the
//! drift was a real bug, not a cosmetic one. Remote monitoring adds a fourth and fifth consumer
//! (the per-host databases and Bulwark's own `known_hosts`), which is the point at which a shared
//! function stops being optional.
//!
//! Pure path logic: no I/O beyond reading environment variables.

use std::path::{Path, PathBuf};

/// The current user's home directory, as `std::env::var_os("HOME")` would return it: `$HOME` when
/// set and non-empty, else — on Windows, which has no `HOME` — `%USERPROFILE%`. Every reader of the
/// home directory goes through this; a bare `env::var("HOME")` is how the Windows build once
/// reported "HOME not set" on every scan.
pub fn home_var_os() -> Option<std::ffi::OsString> {
    if let Some(h) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return Some(h);
    }
    if cfg!(windows) {
        return std::env::var_os("USERPROFILE").filter(|v| !v.is_empty());
    }
    None
}

/// [`home_var_os`] as a `String`, shaped like `std::env::var("HOME")` so call sites keep their
/// error handling.
pub fn home_var() -> Result<String, std::env::VarError> {
    match home_var_os() {
        Some(h) => h.into_string().map_err(std::env::VarError::NotUnicode),
        None => Err(std::env::VarError::NotPresent),
    }
}

/// Resolves the main findings database: `BULWARK_DB_PATH`, else `$XDG_DATA_HOME/bulwark/bulwark.db`,
/// else `%LOCALAPPDATA%\com.vietanhdev.bulwark\bulwark.db` on Windows, else `~/.local/share/bulwark/bulwark.db`.
pub fn default_db_path() -> anyhow::Result<PathBuf> {
    if let Some(p) = std::env::var_os("BULWARK_DB_PATH").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(dir).join("bulwark").join("bulwark.db"));
    }
    // Windows keeps per-user application state in %LOCALAPPDATA%, not under a dot-directory — and
    // in the app identifier's folder, not `bulwark`: a per-user install puts the program itself in
    // %LOCALAPPDATA%\bulwark, while %LOCALAPPDATA%\com.vietanhdev.bulwark is the app-data folder the
    // uninstaller's "delete application data" option removes (and where WebView2 keeps its state).
    if cfg!(windows) {
        if let Some(dir) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
            return Ok(PathBuf::from(dir)
                .join("com.vietanhdev.bulwark")
                .join("bulwark.db"));
        }
    }
    let home =
        home_var_os().ok_or_else(|| anyhow::anyhow!("no home directory (HOME is not set)"))?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("bulwark")
        .join("bulwark.db"))
}

/// The user's own rules folder: checks they wrote themselves, in the same YAML format as the shipped
/// pack, loaded next to it on this computer. `$XDG_CONFIG_HOME/bulwark/rules`, else
/// `~/.config/bulwark/rules`; `%APPDATA%\bulwark\rules` on Windows. Never created implicitly.
pub fn custom_rules_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        if let Some(dir) = std::env::var_os("APPDATA").filter(|v| !v.is_empty()) {
            return Some(PathBuf::from(dir).join("bulwark").join("rules"));
        }
    }
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(dir).join("bulwark").join("rules"));
    }
    home_var_os().map(|h| {
        PathBuf::from(h)
            .join(".config")
            .join("bulwark")
            .join("rules")
    })
}

/// The directory that holds `db_path`. Everything else Bulwark stores sits beside the main
/// database, so a test (or a user) that points `--db-path` / `BULWARK_DB_PATH` somewhere else
/// moves the whole set of state with it rather than half of it.
fn state_dir(db_path: &Path) -> PathBuf {
    db_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Directory of per-remote-host databases.
pub fn remotes_dir(db_path: &Path) -> PathBuf {
    state_dir(db_path).join("remotes")
}

/// The isolated findings database for one registered remote host, keyed by its stable id — not by
/// its address, so renaming a machine or fixing a typo in its address keeps its history.
pub fn remote_host_db_path(db_path: &Path, host_id: &str) -> PathBuf {
    remotes_dir(db_path).join(format!("{}.db", slugify(host_id)))
}

/// The database used by an ad-hoc `bulwarkctl scan --ssh <spec>` of a machine that was never
/// registered. Kept for compatibility with history recorded before machines could be registered.
pub fn adhoc_remote_db_path(db_path: &Path, spec: &str) -> PathBuf {
    remotes_dir(db_path).join(format!("{}.db", slugify(spec)))
}

/// Bulwark's own `known_hosts`, holding only host keys the user approved inside Bulwark. Kept
/// separate from `~/.ssh/known_hosts` so Bulwark never edits the user's SSH configuration; ssh is
/// pointed at it in addition to (never instead of) the user's files.
pub fn known_hosts_path(db_path: &Path) -> PathBuf {
    state_dir(db_path).join("known_hosts")
}

/// Bulwark's dedicated monitoring key — a separate ed25519 key installed on monitored machines
/// with the `restrict` option, so it can run commands but never forward ports, agents or X11, nor
/// open an interactive terminal. Kept apart from the user's personal keys so it can be revoked on
/// its own.
pub fn monitoring_key_path(db_path: &Path) -> PathBuf {
    state_dir(db_path).join("keys").join("bulwark_ed25519")
}

/// Filesystem-safe name: `user@host:22` → `user_host_22`. Only `[A-Za-z0-9.-]` survive, so the
/// result can never contain a path separator or traverse upward (`..` alone is replaced below).
pub fn slugify(s: &str) -> String {
    let slug: String = s
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '.' => c,
            _ => '_',
        })
        .collect();
    if slug.is_empty() || slug.chars().all(|c| c == '.') {
        "host".to_string()
    } else {
        slug
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_lives_beside_the_main_database() {
        let db = Path::new("/x/y/bulwark.db");
        assert_eq!(remotes_dir(db), Path::new("/x/y/remotes"));
        assert_eq!(known_hosts_path(db), Path::new("/x/y/known_hosts"));
        assert_eq!(
            remote_host_db_path(db, "abc-123"),
            Path::new("/x/y/remotes/abc-123.db")
        );
    }

    #[test]
    fn slugify_cannot_escape_the_directory() {
        assert_eq!(slugify("user@host:22"), "user_host_22");
        assert_eq!(slugify("../../etc/passwd"), ".._.._etc_passwd");
        assert_eq!(slugify(".."), "host");
        assert_eq!(slugify(""), "host");
        assert!(!slugify("a/b").contains('/'));
    }
}
