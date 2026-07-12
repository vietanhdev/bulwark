//! Continuous monitoring, architected honestly: this is periodic re-scanning (plus a file
//! watcher for the handful of sensitive paths below) with cross-run finding reconciliation —
//! not a kernel-level real-time hook (that's eBPF/syscall monitoring, explicitly deferred,
//! see architecture doc §2, §13 Option C). What Bulwark checks (sshd_config, systemd units,
//! sudoers, cron, ...) doesn't change second-to-second, so a periodic loop plus "wake up
//! immediately when one of these specific files changes" is the architecturally correct
//! shape for *this* category of check — genuinely faster than the timer without touching
//! kernel infrastructure. Ticks only ever run the unprivileged collector set — `pkexec`
//! needs an interactive prompt, which an unattended background loop can never provide
//! (architecture doc §4, ADR-0004 extends naturally to this: no silent privilege escalation).

use bulwark_core::{all_collectors, engine, Profile, Store};
use chrono::{DateTime, Utc};
use notify::{RecursiveMode, Watcher};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

/// Persisted-preference keys (see `bulwark_core::Store` k/v settings). Continuous monitoring's
/// enabled/interval state used to live only in memory and reset to the defaults on every
/// launch — so a user who turned monitoring off found it silently back on next start. These
/// keys make the toggle actually stick, mirroring how real-time AV persists its own state.
const KEY_ENABLED: &str = "monitoring_enabled";
const KEY_INTERVAL: &str = "monitoring_interval_minutes";

pub struct MonitoringState(pub Mutex<Inner>);

pub struct Inner {
    pub enabled: bool,
    pub interval_minutes: u64,
    pub last_tick_at: Option<DateTime<Utc>>,
    pub next_tick_at: Option<DateTime<Utc>>,
    pub ticks_completed: u64,
    pub last_tick_new_findings: usize,
}

impl Default for Inner {
    fn default() -> Self {
        // 15 minutes: frequent enough that a persisting issue is caught same-session, not
        // so frequent that a periodic re-scan of ~20 checks becomes background noise. Real
        // deployments should tune this from the Monitoring view, not rely on this default.
        Inner {
            enabled: true,
            interval_minutes: 15,
            last_tick_at: None,
            next_tick_at: Some(Utc::now() + chrono::Duration::minutes(15)),
            ticks_completed: 0,
            last_tick_new_findings: 0,
        }
    }
}

/// Builds the initial monitoring state from persisted settings, falling back to the in-memory
/// [`Inner::default`] (enabled, 15-minute interval) whenever nothing has been saved yet or the
/// DB can't be read — a fresh install or a locked-down `HOME` must never block startup. This is
/// what makes the enable/interval toggles survive a restart, mirroring `realtime_av::initial_state`.
pub fn initial_inner() -> Inner {
    let stored = super_db_path()
        .ok()
        .filter(|p| p.exists())
        .and_then(|p| Store::open(&p).ok());

    let mut inner = Inner::default();
    if let Some(store) = &stored {
        if let Ok(Some(v)) = store.get_setting(KEY_ENABLED) {
            inner.enabled = v == "true";
        }
        if let Ok(Some(v)) = store.get_setting(KEY_INTERVAL) {
            if let Ok(minutes) = v.parse::<u64>() {
                inner.interval_minutes = minutes.max(1);
            }
        }
    }
    // Only schedule a first tick if monitoring is actually on; a persisted-off state should
    // start genuinely idle rather than counting down to a tick the loop will then skip.
    inner.next_tick_at = if inner.enabled {
        Some(Utc::now() + chrono::Duration::minutes(inner.interval_minutes as i64))
    } else {
        None
    };
    inner
}

fn persist_enabled(enabled: bool) {
    let Ok(path) = super_db_path() else { return };
    if let Ok(mut store) = Store::open(&path) {
        let _ = store.set_setting(KEY_ENABLED, if enabled { "true" } else { "false" });
    }
}

fn persist_interval(minutes: u64) {
    let Ok(path) = super_db_path() else { return };
    if let Ok(mut store) = Store::open(&path) {
        let _ = store.set_setting(KEY_INTERVAL, &minutes.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression cover for the actual gap this change closed: monitoring enable/interval used
    /// to be in-memory only, so a user who paused monitoring found it back on after a restart.
    /// Persist-then-reload must round-trip, and a paused state must start genuinely idle (no
    /// scheduled first tick). Uses a unique `BULWARK_DB_PATH` — the only test in this crate that
    /// touches that env var, so no cross-test race.
    #[test]
    fn monitoring_enabled_and_interval_persist_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("bulwark.db");
        std::env::set_var("BULWARK_DB_PATH", &db);

        // A fresh DB with nothing stored falls back to the on/15min default.
        let fresh = initial_inner();
        assert!(fresh.enabled);
        assert_eq!(fresh.interval_minutes, 15);

        // Persist "paused, 45-minute interval" the way the Tauri commands do.
        persist_enabled(false);
        persist_interval(45);

        let reloaded = initial_inner();
        assert!(!reloaded.enabled, "paused state must survive a restart");
        assert_eq!(reloaded.interval_minutes, 45);
        assert!(
            reloaded.next_tick_at.is_none(),
            "a paused start must be idle, not counting down to a skipped tick"
        );

        std::env::remove_var("BULWARK_DB_PATH");
    }
}

#[derive(Clone, Serialize)]
pub struct MonitoringStatus {
    pub enabled: bool,
    pub interval_minutes: u64,
    pub last_tick_at: Option<DateTime<Utc>>,
    pub next_tick_at: Option<DateTime<Utc>>,
    pub ticks_completed: u64,
    pub last_tick_new_findings: usize,
}

impl From<&Inner> for MonitoringStatus {
    fn from(i: &Inner) -> Self {
        MonitoringStatus {
            enabled: i.enabled,
            interval_minutes: i.interval_minutes,
            last_tick_at: i.last_tick_at,
            next_tick_at: i.next_tick_at,
            ticks_completed: i.ticks_completed,
            last_tick_new_findings: i.last_tick_new_findings,
        }
    }
}

#[tauri::command]
pub fn monitoring_get_status(state: tauri::State<MonitoringState>) -> MonitoringStatus {
    let inner = state.0.lock().unwrap();
    MonitoringStatus::from(&*inner)
}

#[tauri::command]
pub fn monitoring_set_enabled(
    state: tauri::State<MonitoringState>,
    enabled: bool,
) -> MonitoringStatus {
    let mut inner = state.0.lock().unwrap();
    inner.enabled = enabled;
    if enabled && inner.next_tick_at.is_none() {
        inner.next_tick_at =
            Some(Utc::now() + chrono::Duration::minutes(inner.interval_minutes as i64));
    }
    let status = MonitoringStatus::from(&*inner);
    drop(inner);
    persist_enabled(enabled);
    status
}

#[tauri::command]
pub fn monitoring_set_interval_minutes(
    state: tauri::State<MonitoringState>,
    minutes: u64,
) -> MonitoringStatus {
    let mut inner = state.0.lock().unwrap();
    inner.interval_minutes = minutes.max(1);
    inner.next_tick_at =
        Some(Utc::now() + chrono::Duration::minutes(inner.interval_minutes as i64));
    let effective = inner.interval_minutes;
    let status = MonitoringStatus::from(&*inner);
    drop(inner);
    persist_interval(effective);
    status
}

/// The background loop itself. Polls once a second rather than sleeping for the whole
/// interval in one shot — that's what lets `monitoring_set_interval_minutes` and
/// `monitoring_set_enabled` take effect immediately instead of only after the current
/// sleep finishes, and it's what lets the UI show a live "next scan in mm:ss" countdown
/// against `next_tick_at` between ticks.
pub fn spawn(app: AppHandle, rules_dir: PathBuf) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let due = {
                let state = app.state::<MonitoringState>();
                let inner = state.0.lock().unwrap();
                inner.enabled && inner.next_tick_at.is_some_and(|t| Utc::now() >= t)
            };
            if !due {
                continue;
            }

            run_tick(&app, &rules_dir);
        }
    });
}

/// The specific paths worth watching — deliberately the small set the bundled rule pack
/// actually reads (sshd_config, systemd units, sudoers, cron, the current user's
/// authorized_keys), not a broad filesystem watch. A directory that doesn't exist on this
/// distro (e.g. no `/etc/sudoers.d`) is skipped rather than erroring the whole watcher.
fn watched_paths() -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from("/etc/ssh/sshd_config"),
        PathBuf::from("/etc/ssh/sshd_config.d"),
        PathBuf::from("/etc/systemd/system"),
        PathBuf::from("/etc/sudoers"),
        PathBuf::from("/etc/sudoers.d"),
        PathBuf::from("/etc/cron.d"),
        PathBuf::from("/etc/crontab"),
    ];
    if let Ok(home) = std::env::var("HOME") {
        paths.push(PathBuf::from(home).join(".ssh/authorized_keys"));
    }
    paths.into_iter().filter(|p| p.exists()).collect()
}

/// Runs on its own OS thread because `notify`'s watcher owns a blocking event loop and its
/// callback fires synchronously — bridging that into the async runtime buys nothing here,
/// since the only thing the callback does is call the same synchronous `run_tick` the
/// periodic loop already uses.
pub fn spawn_file_watcher(app: AppHandle, rules_dir: PathBuf) {
    let paths = watched_paths();
    if paths.is_empty() {
        eprintln!(
            "[bulwark] no watchable sensitive paths found — file-triggered monitoring disabled"
        );
        return;
    }

    std::thread::spawn(move || {
        let last_triggered: Mutex<Option<Instant>> = Mutex::new(None);
        // A single logical change (e.g. an editor's write-temp-then-rename) often fires
        // several raw filesystem events in quick succession — this debounce collapses them
        // into one re-scan instead of several back-to-back ones.
        const DEBOUNCE: Duration = Duration::from_secs(3);

        let watcher_app = app.clone();
        let watcher_rules_dir = rules_dir.clone();
        let mut watcher =
            match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                let Ok(event) = res else { return };
                if !matches!(
                    event.kind,
                    notify::EventKind::Modify(_)
                        | notify::EventKind::Create(_)
                        | notify::EventKind::Remove(_)
                ) {
                    return;
                }

                let should_run = {
                    let state = watcher_app.state::<MonitoringState>();
                    let enabled = state.0.lock().unwrap().enabled;
                    if !enabled {
                        false
                    } else {
                        let mut last = last_triggered.lock().unwrap();
                        let due = last.is_none_or(|t| t.elapsed() >= DEBOUNCE);
                        if due {
                            *last = Some(Instant::now());
                        }
                        due
                    }
                };

                if should_run {
                    run_tick(&watcher_app, &watcher_rules_dir);
                }
            }) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("[bulwark] warning: couldn't start file watcher: {e}");
                    return;
                }
            };

        for path in &paths {
            // A path this process can't read (e.g. /etc/sudoers.d without root) just isn't
            // watched — the periodic timer still covers it, consistent with how the
            // collectors themselves degrade when a path needs privilege they don't have.
            if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
                eprintln!("[bulwark] warning: couldn't watch {}: {e}", path.display());
            }
        }

        println!(
            "[bulwark] watching {} path(s) for immediate re-checks",
            paths.len()
        );
        // Park forever — the watcher itself does the work via its callback; this thread's
        // only job is to keep `watcher` alive (dropping it stops the underlying OS watch).
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    });
}

fn run_tick(app: &AppHandle, rules_dir: &Path) {
    println!("[bulwark] monitoring tick at {}", Utc::now().to_rfc3339());
    let collectors = all_collectors();
    // Unprivileged only — see module doc. `privileged_collectors_skipped` on the resulting
    // scan still gets recorded like any other scan; the UI's existing "run privileged
    // checks" affordance is what covers that gap, on demand, with a real auth prompt.
    // Default profile (host OS, no opted-in needs) — the background loop doesn't currently
    // know the user's active profile selection from the Dashboard; see the Profiles section
    // of the architecture doc's open questions for wiring a persisted selection through here.
    let scan = engine::run_scan(rules_dir, &collectors, false, &Profile::default());

    let new_findings = if let Ok(db_path) = super_db_path() {
        Store::open(&db_path)
            .and_then(|mut store| store.persist_and_reconcile(&scan))
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    if !new_findings.is_empty() {
        let title = if new_findings.len() == 1 {
            "Bulwark found a new issue".to_string()
        } else {
            format!("Bulwark found {} new issues", new_findings.len())
        };
        let body = new_findings
            .iter()
            .take(3)
            .map(|f| f.title.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = app.notification().builder().title(title).body(body).show();
    }

    let _ = app.emit("monitoring:tick", ());

    let state = app.state::<MonitoringState>();
    let mut inner = state.0.lock().unwrap();
    inner.last_tick_at = Some(Utc::now());
    inner.next_tick_at =
        Some(Utc::now() + chrono::Duration::minutes(inner.interval_minutes as i64));
    inner.ticks_completed += 1;
    inner.last_tick_new_findings = new_findings.len();
}

// Duplicated in lib.rs deliberately kept private there — this module only needs the same
// small resolution logic, not a shared-crate abstraction for two call sites.
fn super_db_path() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("BULWARK_DB_PATH") {
        return Ok(PathBuf::from(p));
    }
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    Ok(PathBuf::from(home).join(".local/share/bulwark/bulwark.db"))
}
