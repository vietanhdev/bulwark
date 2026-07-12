//! Real-time antivirus protection: watches a small set of user-facing folders (Downloads and
//! Desktop by default, extendable from the UI) and scans a file shortly after it settles,
//! instead of only on a manual "Run a virus scan" click. This is still "shell out to ClamAV,
//! don't reimplement detection" (`av_scan`'s own module doc) — the only thing that changes is
//! *what triggers* a scan, a file-system event instead of a button. It's also the same
//! category of thing `monitoring.rs`'s `spawn_file_watcher` already does for sensitive config
//! paths (a userspace `notify` watch), not the kernel-level eBPF/syscall monitoring the
//! architecture doc explicitly defers (§2, §13 Option C).
//!
//! Deliberately shells out to `clamscan` per file rather than talking to a `clamd` daemon:
//! `clamd` would scan faster, but requires the user to separately install and keep a system
//! daemon running, which cuts against this project's "personal tool, no daemon complexity"
//! stance. A file is scanned within a couple of seconds of settling, not milliseconds — an
//! honest trade, and a large improvement over "never, unless you click the button."

use bulwark_core::av_scan::default_realtime_watch_targets;
use bulwark_core::{run_av_scan, Store, ThreatDetection};
use notify::{RecursiveMode, Watcher};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

/// How long a path must sit untouched in the debounce map before it's considered "settled"
/// and worth scanning — long enough that a large file still being written (a slow download,
/// an archive being extracted) doesn't get scanned half-finished or scanned repeatedly as it
/// grows.
const SETTLE: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Capped rather than unbounded — this feeds a small "recent detections" list in the UI, not
/// a full audit log (the manual scan's own results / the History view already cover that).
const MAX_RECENT_THREATS: usize = 20;

const KEY_ENABLED: &str = "realtime_av_enabled";
const KEY_WATCHED_PATHS: &str = "realtime_av_watched_paths";

/// Browsers and download managers write to a temporary name and rename to the real one only
/// once the transfer completes. Scanning the in-progress temp file is pure waste — it's
/// half-written by definition, and the rename to its final name fires its own Create event
/// that gets scanned properly anyway.
const PARTIAL_DOWNLOAD_SUFFIXES: &[&str] = &[
    ".crdownload",
    ".part",
    ".partial",
    ".download",
    ".opdownload",
];

pub struct RealtimeAvState(pub Mutex<Inner>);

pub struct Inner {
    pub enabled: bool,
    pub watched_paths: Vec<PathBuf>,
    pub files_scanned: u64,
    pub threats_found: u64,
    pub recent_threats: Vec<ThreatDetection>,
    /// `Some` only while actively watching — dropping it (see `stop_watching`) is what tells
    /// the OS to remove the underlying inotify watches.
    watcher: Option<notify::RecommendedWatcher>,
    /// Bumped on every start/stop. A worker thread carries the generation it was spawned with
    /// and exits the moment it observes a different one — without this, toggling protection
    /// off and straight back on within one `POLL_INTERVAL` leaves the previous worker alive
    /// (it hasn't woken up to notice `enabled == false` yet) *and* spawns a second one, so
    /// every file gets scanned twice and both counters double-count.
    generation: u64,
}

#[derive(Clone, Serialize)]
pub struct RealtimeAvStatus {
    pub enabled: bool,
    pub watched_paths: Vec<String>,
    pub files_scanned: u64,
    pub threats_found: u64,
    pub recent_threats: Vec<ThreatDetection>,
}

impl From<&Inner> for RealtimeAvStatus {
    fn from(i: &Inner) -> Self {
        RealtimeAvStatus {
            enabled: i.enabled,
            watched_paths: i
                .watched_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            files_scanned: i.files_scanned,
            threats_found: i.threats_found,
            recent_threats: i.recent_threats.clone(),
        }
    }
}

/// Streamed to the frontend via the plain event bus (`app.emit`), not a Channel — this is
/// ambient background activity with no single pending command invocation to stream a response
/// to (the same reasoning `monitoring.rs`'s `monitoring:tick` event already follows), unlike
/// `run_virus_scan`'s Channel-based per-invocation stream (ADR-0003).
#[derive(Clone, Serialize)]
#[serde(tag = "event", content = "data", rename_all = "camelCase")]
pub enum RealtimeAvEvent {
    FileScanned { path: String },
    ThreatFound(ThreatDetection),
    Error { path: String, message: String },
}

// Duplicated from lib.rs's `db_path()` / monitoring.rs's `super_db_path()` deliberately — see
// monitoring.rs's own comment on why this project keeps this small resolution helper local to
// each call site rather than sharing it.
fn db_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BULWARK_DB_PATH") {
        return Some(PathBuf::from(p));
    }
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".local/share/bulwark/bulwark.db"))
}

/// Loads persisted enabled/watched-folder state at app startup, falling back to sane defaults
/// (disabled, `Downloads`+`Desktop`) whenever nothing's been saved yet or the DB can't be
/// read — a fresh install or a locked-down `HOME` shouldn't prevent the app from starting.
pub fn initial_state() -> Inner {
    let home = std::env::var("HOME").ok().map(PathBuf::from);
    let defaults = || {
        home.as_deref()
            .map(default_realtime_watch_targets)
            .unwrap_or_default()
    };

    let mut stored = db_path()
        .filter(|p| p.exists())
        .and_then(|p| Store::open(&p).ok());

    let enabled = stored
        .as_mut()
        .and_then(|s| s.get_setting(KEY_ENABLED).ok().flatten())
        .map(|v| v == "true")
        .unwrap_or(false);

    let watched_paths = stored
        .as_mut()
        .and_then(|s| s.get_setting(KEY_WATCHED_PATHS).ok().flatten())
        .and_then(|v| serde_json::from_str::<Vec<String>>(&v).ok())
        .map(|paths| paths.into_iter().map(PathBuf::from).collect::<Vec<_>>())
        .unwrap_or_else(defaults);

    Inner {
        enabled,
        watched_paths,
        files_scanned: 0,
        threats_found: 0,
        recent_threats: Vec::new(),
        watcher: None,
        generation: 0,
    }
}

fn is_partial_download(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|name| {
            let lower = name.to_ascii_lowercase();
            PARTIAL_DOWNLOAD_SUFFIXES
                .iter()
                .any(|suffix| lower.ends_with(suffix))
        })
        .unwrap_or(false)
}

fn persist_enabled(enabled: bool) {
    let Some(path) = db_path() else { return };
    if let Ok(mut store) = Store::open(&path) {
        let _ = store.set_setting(KEY_ENABLED, if enabled { "true" } else { "false" });
    }
}

fn persist_watched_paths(paths: &[PathBuf]) {
    let Some(path) = db_path() else { return };
    let Ok(mut store) = Store::open(&path) else {
        return;
    };
    let strs: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
    if let Ok(json) = serde_json::to_string(&strs) {
        let _ = store.set_setting(KEY_WATCHED_PATHS, &json);
    }
}

/// Called once at app startup (from `lib.rs`'s `.setup()`) to resume protection if it was
/// left enabled on a previous run — "persists across restarts" means protection actually
/// restarts, not just that the toggle remembers its position.
pub fn start_if_enabled(app: AppHandle) {
    let state = app.state::<RealtimeAvState>();
    let mut inner = state.0.lock().unwrap_or_else(|e| e.into_inner());
    if inner.enabled {
        begin_watching(&app, &mut inner);
    }
}

/// Starts watching `inner.watched_paths` if not already watching. Idempotent — a no-op if a
/// watcher is already active, so re-enabling twice can't double-watch.
///
/// Deliberately still builds the watcher when `watched_paths` is empty: the watcher has to
/// exist for [`realtime_av_add_folder`] to have something to `.watch()` a newly-added folder
/// on. Bailing out here instead (the obvious-looking guard) meant enabling protection with no
/// folders left `enabled = true` with `watcher = None` forever — every folder added afterwards
/// was recorded and persisted but never actually watched, so protection read as "on" and
/// silently scanned nothing until the next app restart.
fn begin_watching(app: &AppHandle, inner: &mut Inner) {
    if inner.watcher.is_some() {
        return;
    }

    let pending: Arc<Mutex<HashMap<PathBuf, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let callback_pending = pending.clone();

    let mut watcher =
        match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            let Ok(event) = res else { return };
            if !matches!(
                event.kind,
                notify::EventKind::Create(_) | notify::EventKind::Modify(_)
            ) {
                return;
            }
            let mut map = callback_pending.lock().unwrap_or_else(|e| e.into_inner());
            for path in event.paths {
                // Only files get scanned — a new subdirectory just needs its own watch (which
                // `RecursiveMode::Recursive` adds automatically), not a scan of the directory
                // entry itself.
                if path.is_file() && !is_partial_download(&path) {
                    map.insert(path, Instant::now());
                }
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("[bulwark] warning: couldn't start real-time AV watcher: {e}");
                return;
            }
        };

    for path in &inner.watched_paths {
        if let Err(e) = watcher.watch(path, RecursiveMode::Recursive) {
            eprintln!(
                "[bulwark] warning: couldn't watch {} for real-time AV: {e}",
                path.display()
            );
        }
    }

    println!(
        "[bulwark] real-time AV protection watching {} folder(s)",
        inner.watched_paths.len()
    );

    inner.generation += 1;
    inner.watcher = Some(watcher);
    spawn_worker(app.clone(), pending, inner.generation);
}

/// Dropping the `Watcher` removes every OS-level inotify watch it was holding. Bumping the
/// generation is what retires the worker thread — it exits on its next tick once it sees a
/// generation that isn't its own, so a restart can't end up with two workers racing.
fn stop_watching(inner: &mut Inner) {
    inner.watcher = None;
    inner.generation += 1;
}

/// The settle-and-scan loop: every `POLL_INTERVAL`, pulls any debounce-map entry idle for at
/// least `SETTLE` and runs a real ClamAV pass on it — one file at a time, deliberately
/// serialized, since every `clamscan` invocation reloads the full signature database and
/// running several concurrently would just make all of them slower for no benefit. Exits on
/// its own once protection is off, or once a newer worker has superseded it (see `generation`).
fn spawn_worker(app: AppHandle, pending: Arc<Mutex<HashMap<PathBuf, Instant>>>, generation: u64) {
    std::thread::spawn(move || loop {
        std::thread::sleep(POLL_INTERVAL);

        let still_ours = {
            let state = app.state::<RealtimeAvState>();
            let guard = state.0.lock().unwrap_or_else(|e| e.into_inner());
            guard.enabled && guard.generation == generation
        };
        if !still_ours {
            break;
        }

        let ready: Vec<PathBuf> = {
            let mut map = pending.lock().unwrap_or_else(|e| e.into_inner());
            let ready_paths: Vec<PathBuf> = map
                .iter()
                .filter(|(_, t)| t.elapsed() >= SETTLE)
                .map(|(p, _)| p.clone())
                .collect();
            for p in &ready_paths {
                map.remove(p);
            }
            ready_paths
        };

        for path in ready {
            if path.is_file() {
                scan_one(&app, &path);
            }
        }
    });
}

fn scan_one(app: &AppHandle, path: &Path) {
    let result = match run_av_scan(&[path.to_path_buf()]) {
        Ok(r) => r,
        Err(e) => {
            let _ = app.emit(
                "realtime_av:event",
                RealtimeAvEvent::Error {
                    path: path.display().to_string(),
                    message: e.to_string(),
                },
            );
            return;
        }
    };

    let threats = {
        let state = app.state::<RealtimeAvState>();
        let mut inner = state.0.lock().unwrap_or_else(|e| e.into_inner());
        inner.files_scanned += 1;
        for threat in &result.threats {
            inner.threats_found += 1;
            inner.recent_threats.insert(0, threat.clone());
        }
        inner.recent_threats.truncate(MAX_RECENT_THREATS);
        result.threats
    };

    let _ = app.emit(
        "realtime_av:event",
        RealtimeAvEvent::FileScanned {
            path: path.display().to_string(),
        },
    );

    for threat in threats {
        let _ = app.emit(
            "realtime_av:event",
            RealtimeAvEvent::ThreatFound(threat.clone()),
        );
        let _ = app
            .notification()
            .builder()
            .title("Bulwark real-time protection")
            .body(format!(
                "Threat found: {} ({})",
                threat.path, threat.signature
            ))
            .show();
    }
}

#[tauri::command]
pub fn realtime_av_get_status(state: tauri::State<RealtimeAvState>) -> RealtimeAvStatus {
    let inner = state.0.lock().unwrap_or_else(|e| e.into_inner());
    RealtimeAvStatus::from(&*inner)
}

#[tauri::command]
pub fn realtime_av_set_enabled(app: AppHandle, enabled: bool) -> RealtimeAvStatus {
    let state = app.state::<RealtimeAvState>();
    let status = {
        let mut inner = state.0.lock().unwrap_or_else(|e| e.into_inner());
        inner.enabled = enabled;
        if enabled {
            begin_watching(&app, &mut inner);
        } else {
            stop_watching(&mut inner);
        }
        RealtimeAvStatus::from(&*inner)
    };
    persist_enabled(enabled);
    status
}

#[tauri::command]
pub fn realtime_av_add_folder(app: AppHandle, path: String) -> Result<RealtimeAvStatus, String> {
    let candidate = PathBuf::from(&path);
    if !candidate.is_dir() {
        return Err(format!("{path} isn't a folder that exists on this machine"));
    }

    let state = app.state::<RealtimeAvState>();
    let mut inner = state.0.lock().unwrap_or_else(|e| e.into_inner());

    if inner.watched_paths.contains(&candidate) {
        return Ok(RealtimeAvStatus::from(&*inner));
    }

    // Register the OS-level watch *before* recording the folder, so a folder that can't
    // actually be watched (permissions, inotify watch limit exhausted) surfaces as a real
    // error the user sees rather than a chip in the list that silently protects nothing.
    if let Some(watcher) = inner.watcher.as_mut() {
        watcher
            .watch(&candidate, RecursiveMode::Recursive)
            .map_err(|e| format!("couldn't watch {path}: {e}"))?;
    }

    inner.watched_paths.push(candidate);
    persist_watched_paths(&inner.watched_paths);

    Ok(RealtimeAvStatus::from(&*inner))
}

#[tauri::command]
pub fn realtime_av_remove_folder(app: AppHandle, path: String) -> Result<RealtimeAvStatus, String> {
    let candidate = PathBuf::from(&path);

    let state = app.state::<RealtimeAvState>();
    let mut inner = state.0.lock().unwrap_or_else(|e| e.into_inner());

    let before = inner.watched_paths.len();
    inner.watched_paths.retain(|p| p != &candidate);
    if inner.watched_paths.len() != before {
        if let Some(watcher) = inner.watcher.as_mut() {
            let _ = watcher.unwatch(&candidate);
        }
        persist_watched_paths(&inner.watched_paths);
    }

    Ok(RealtimeAvStatus::from(&*inner))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_progress_downloads_are_skipped() {
        // Chrome, Firefox, and Opera each write to their own temp suffix and rename on
        // completion — scanning the half-written file is wasted work, and the rename to the
        // final name fires its own Create event that gets scanned properly.
        for name in [
            "/home/u/Downloads/foo.zip.crdownload",
            "/home/u/Downloads/foo.zip.part",
            "/home/u/Downloads/foo.zip.partial",
            "/home/u/Downloads/foo.iso.download",
            "/home/u/Downloads/foo.iso.opdownload",
        ] {
            assert!(
                is_partial_download(Path::new(name)),
                "{name} should be treated as an in-progress download"
            );
        }
    }

    #[test]
    fn completed_downloads_are_scanned() {
        for name in [
            "/home/u/Downloads/foo.zip",
            "/home/u/Downloads/installer.deb",
            "/home/u/Downloads/eicar.com",
            // A real file whose name merely *contains* a temp suffix mid-string, rather than
            // ending in one, must not be skipped.
            "/home/u/Downloads/my.part.notes.txt",
        ] {
            assert!(
                !is_partial_download(Path::new(name)),
                "{name} is a finished file and must still be scanned"
            );
        }
    }

    #[test]
    fn partial_download_matching_is_case_insensitive() {
        // Windows-origin files copied onto a Linux box routinely carry uppercase extensions.
        assert!(is_partial_download(Path::new("/tmp/Foo.ZIP.CRDOWNLOAD")));
    }
}
