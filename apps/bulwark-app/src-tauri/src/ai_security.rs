//! The AI Security feature's Tauri surface: a streaming on-demand scan of AI coding-assistant
//! artifacts, the "show the last scan on open" snapshot, opt-in secret redaction, the
//! persisted discovery config (extra roots / exclusions), and a background auto-scan.
//!
//! All the actual work lives in `bulwark_core::ai_scan` — this module is a thin front-door over
//! it, exactly as `lib.rs` is over the config engine and `realtime_av.rs` is over ClamAV. The
//! streaming scan uses a Tauri Channel (per-invocation, ordered — ADR-0003), while the ambient
//! background auto-scan uses the plain event bus (`ai_security:tick`), matching how
//! `run_virus_scan` vs. `monitoring:tick` already split.

use bulwark_core::{ai_redact_paths, run_ai_scan, AiFinding, AiScanOptions, AiScanReport, Store};
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;
use tauri::ipc::Channel;
use tauri::{AppHandle, Emitter};
use tauri_plugin_notification::NotificationExt;

const KEY_CONFIGURED_ROOTS: &str = "ai_configured_roots";
const KEY_EXCLUDED_ROOTS: &str = "ai_excluded_roots";
const KEY_AUTO_SCAN: &str = "ai_auto_scan_enabled";

/// How often the background auto-scan re-sweeps. Long, because AI artifacts change on a
/// human-edit cadence (you don't paste a new key every minute), and a full workspace sweep is
/// heavier than a config tick — six hours keeps the tab fresh without being background noise.
const AUTO_SCAN_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

// Same local db-path resolver every module in this app keeps private to itself — see
// monitoring.rs's comment on why it isn't factored into a shared helper.
fn db_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BULWARK_DB_PATH") {
        return Some(PathBuf::from(p));
    }
    // XDG_DATA_HOME before ~/.local/share — see monitoring.rs's resolver for why this
    // matters (Flatpak: $HOME is read-only, XDG_DATA_HOME is the writable app dir).
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(dir).join("bulwark/bulwark.db"));
    }
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".local/share/bulwark/bulwark.db"))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

fn read_roots(key: &str) -> Vec<PathBuf> {
    db_path()
        .filter(|p| p.exists())
        .and_then(|p| Store::open(&p).ok())
        .and_then(|mut s| s.get_setting(key).ok().flatten())
        .and_then(|v| serde_json::from_str::<Vec<String>>(&v).ok())
        .map(|v| v.into_iter().map(PathBuf::from).collect())
        .unwrap_or_default()
}

/// Builds scan options from the persisted discovery config plus any explicit targets a caller
/// (e.g. a GUI "scan this folder" drop) passed.
fn options(explicit_targets: Vec<PathBuf>) -> Result<AiScanOptions, String> {
    let home = home_dir().ok_or_else(|| "HOME not set".to_string())?;
    Ok(AiScanOptions {
        home,
        configured_roots: read_roots(KEY_CONFIGURED_ROOTS),
        excluded_roots: read_roots(KEY_EXCLUDED_ROOTS),
        explicit_targets,
        max_workspaces: bulwark_core::ai_scan::DEFAULT_MAX_WORKSPACES,
    })
}

fn backup_dir() -> PathBuf {
    db_path()
        .and_then(|p| p.parent().map(|d| d.join("redaction-backups")))
        .unwrap_or_else(|| PathBuf::from("redaction-backups"))
}

/// Streamed to the frontend one message at a time over a Channel (ordered delivery — ADR-0003),
/// so a scan of many workspaces shows live progress rather than a spinner that hangs until the
/// whole sweep finishes.
#[derive(Clone, Serialize)]
#[serde(tag = "event", content = "data", rename_all = "camelCase")]
pub enum AiScanEvent {
    /// The artifact currently being examined — drives a live "scanning: <path>" line.
    Artifact {
        path: String,
    },
    Finding(AiFinding),
    Complete {
        total_findings: usize,
        artifacts_scanned: usize,
        workspaces_scanned: usize,
        workspaces_capped: bool,
        /// Stopped early — the findings are partial and were not persisted.
        cancelled: bool,
        errors: Vec<String>,
    },
    Error {
        message: String,
    },
}

/// Runs a full AI-artifact scan, streaming progress. `targets`, when non-empty, scans exactly
/// those folders and skips whole-machine discovery — the GUI's "scan this project" path.
#[tauri::command]
pub async fn ai_scan_start(
    control: tauri::State<'_, crate::ScanControl>,
    on_event: Channel<AiScanEvent>,
    targets: Option<Vec<String>>,
) -> Result<(), String> {
    let control = control.inner().clone();
    control.begin();

    tauri::async_runtime::spawn_blocking(move || {
        let explicit = targets
            .unwrap_or_default()
            .into_iter()
            .map(PathBuf::from)
            .collect();
        let opts = match options(explicit) {
            Ok(o) => o,
            Err(e) => {
                let _ = on_event.send(AiScanEvent::Error { message: e });
                return;
            }
        };

        let report = bulwark_core::ai_scan::scan_cancellable(
            &opts,
            |path| {
                let _ = on_event.send(AiScanEvent::Artifact {
                    path: path.to_string(),
                });
            },
            &control.is_cancelled(),
        );

        for f in &report.findings {
            let _ = on_event.send(AiScanEvent::Finding(f.clone()));
        }

        // A stopped sweep saw only some of the machine. Persisting it would replace a complete
        // picture with a partial one (this table is latest-run-wins), so it doesn't get stored.
        if !report.cancelled {
            if let Some(p) = db_path() {
                if let Ok(mut store) = Store::open(&p) {
                    let _ = store.persist_ai_scan(&report);
                }
            }
        }

        let _ = on_event.send(AiScanEvent::Complete {
            total_findings: report.findings.len(),
            artifacts_scanned: report.artifacts_scanned,
            workspaces_scanned: report.workspaces_scanned.len(),
            workspaces_capped: report.workspaces_capped,
            cancelled: report.cancelled,
            errors: report.errors.clone(),
        });
    })
    .await
    .map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct AiSnapshotResponse {
    /// `None` until the first AI scan has run — the tab shows an unscanned empty state, never a
    /// false "all clear."
    snapshot: Option<bulwark_core::AiScanSnapshot>,
}

/// What a freshly-opened AI Security tab loads — the most recent scan's findings and summary,
/// straight from the store, so opening the app after a background auto-scan shows real data
/// instead of "not scanned yet" (the exact regression `dashboard_snapshot` fixed for config).
#[tauri::command]
pub async fn ai_scan_snapshot() -> Result<AiSnapshotResponse, String> {
    let Some(p) = db_path() else {
        return Ok(AiSnapshotResponse { snapshot: None });
    };
    if !p.exists() {
        return Ok(AiSnapshotResponse { snapshot: None });
    }
    let mut store = Store::open(&p).map_err(|e| e.to_string())?;
    Ok(AiSnapshotResponse {
        snapshot: store.latest_ai_scan().map_err(|e| e.to_string())?,
    })
}

/// Set of files the most recent persisted AI scan flagged with a **redactable** secret. `ai_redact`
/// uses this as an allowlist: redaction may only touch a file the user already saw reported *and*
/// which the scan marked safe to rewrite — never an arbitrary path the caller supplies, and never a
/// file whose secret is functional. Each qualifying file contributes BOTH its raw stored string and
/// its canonicalized form to the set, and a request matches if *either* form matches — so a scan
/// that stored a display path and a frontend that sends the same string still line up even when
/// `canonicalize` would resolve them differently (or fail), without ever widening the allowlist
/// beyond the exact files the scan reported.
///
/// The `f.redactable` filter is load-bearing, not an optimization: a scan reports a live key sitting
/// in a project `.env` (so the user knows to rotate it), but marks that finding non-redactable
/// because rewriting a `.env` in place destroys the working config. Without this filter the allowlist
/// would contain that `.env` and the IPC command would rewrite it — the exact data-loss bug this
/// guards against. It is the server-side twin of the core's `kind_allows_redaction`.
fn redactable_files() -> BTreeSet<PathBuf> {
    db_path()
        .filter(|p| p.exists())
        .and_then(|p| Store::open(&p).ok())
        .and_then(|mut s| s.latest_ai_scan().ok().flatten())
        .map(|snap| {
            let mut set = BTreeSet::new();
            for f in snap.findings.iter().filter(|f| f.redactable) {
                set.insert(PathBuf::from(&f.file));
                if let Ok(canon) = std::fs::canonicalize(&f.file) {
                    set.insert(canon);
                }
            }
            set
        })
        .unwrap_or_default()
}

/// Redacts (or, with `apply = false`, previews redacting) leaked secrets in the given files —
/// the paths the frontend collected from the current scan's redactable findings. Never scans or
/// rewrites anything the user didn't already see flagged. Returns the per-file outcome.
///
/// The "already flagged" guarantee is enforced **here**, server-side, not merely trusted from the
/// frontend: `ai_redact` is an IPC command callable by any script in the webview, so an unfiltered
/// path list would be an arbitrary-file-rewrite primitive (point it at `~/.aws/credentials` and it
/// would overwrite the live secret). Every requested path is intersected with the files the last
/// scan reported; anything else is dropped with an error entry rather than opened.
#[tauri::command]
pub async fn ai_redact(
    paths: Vec<String>,
    apply: bool,
) -> Result<bulwark_core::RedactionReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let allowed = redactable_files();
        let mut files: Vec<PathBuf> = Vec::new();
        let mut rejected: Vec<String> = Vec::new();
        for p in paths {
            // Match on either the raw path or its canonical form — mirrors how the allowlist is
            // built, so a legitimately-flagged file is never wrongly rejected.
            let raw = PathBuf::from(&p);
            let canon = std::fs::canonicalize(&p).ok();
            let ok = allowed.contains(&raw) || canon.as_ref().is_some_and(|c| allowed.contains(c));
            if ok {
                files.push(raw);
            } else {
                rejected.push(format!(
                    "{p}: not redacting a path the latest scan did not flag"
                ));
            }
        }

        let mut report = ai_redact_paths(&files, apply, &backup_dir());
        report.errors.extend(rejected);

        // When we actually rewrote files (not a dry-run preview), the secrets in them are gone, so
        // the persisted snapshot must stop listing them. Do it surgically here rather than letting
        // the frontend trigger a whole-machine re-scan to "refresh" — that re-walk of the entire
        // home directory is minutes of work to remove findings we already know are resolved.
        if apply {
            let redacted_files: Vec<String> = report
                .entries
                .iter()
                .filter(|e| e.applied && e.secrets_redacted > 0)
                .map(|e| e.path.clone())
                .collect();
            if !redacted_files.is_empty() {
                if let Some(mut store) = db_path()
                    .filter(|p| p.exists())
                    .and_then(|p| Store::open(&p).ok())
                {
                    // Best-effort: the files are already redacted on disk, which is the real work.
                    // A failure to prune the snapshot is cosmetic (a stale row until the next scan),
                    // not a reason to fail the redaction the user asked for.
                    let _ = store.remove_redacted_ai_findings(&redacted_files);
                }
            }
        }
        report
    })
    .await
    .map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct AiSettings {
    configured_roots: Vec<String>,
    excluded_roots: Vec<String>,
    auto_scan_enabled: bool,
}

#[tauri::command]
pub async fn ai_settings_get() -> Result<AiSettings, String> {
    Ok(AiSettings {
        configured_roots: read_roots(KEY_CONFIGURED_ROOTS)
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        excluded_roots: read_roots(KEY_EXCLUDED_ROOTS)
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        auto_scan_enabled: auto_scan_enabled(),
    })
}

/// Persists the discovery config (extra roots / exclusions) and the auto-scan toggle. Absent
/// keys are left untouched, so the UI can update one axis without clobbering the others.
#[tauri::command]
pub async fn ai_settings_set(
    configured_roots: Option<Vec<String>>,
    excluded_roots: Option<Vec<String>>,
    auto_scan_enabled: Option<bool>,
) -> Result<AiSettings, String> {
    if let Some(p) = db_path() {
        if let Ok(mut store) = Store::open(&p) {
            if let Some(roots) = &configured_roots {
                let _ = store.set_setting(
                    KEY_CONFIGURED_ROOTS,
                    &serde_json::to_string(roots).unwrap_or_default(),
                );
            }
            if let Some(roots) = &excluded_roots {
                let _ = store.set_setting(
                    KEY_EXCLUDED_ROOTS,
                    &serde_json::to_string(roots).unwrap_or_default(),
                );
            }
            if let Some(enabled) = auto_scan_enabled {
                let _ = store.set_setting(KEY_AUTO_SCAN, if enabled { "true" } else { "false" });
            }
        }
    }
    ai_settings_get().await
}

fn auto_scan_enabled() -> bool {
    db_path()
        .filter(|p| p.exists())
        .and_then(|p| Store::open(&p).ok())
        .and_then(|mut s| s.get_setting(KEY_AUTO_SCAN).ok().flatten())
        // Default on — "auto scanning" is the point of the feature; a user can pause it.
        .map(|v| v == "true")
        .unwrap_or(true)
}

/// Starts the background auto-scan loop: one sweep shortly after launch (so the tab has fresh
/// data without the user clicking anything), then every [`AUTO_SCAN_INTERVAL`]. Each run
/// persists its report and emits `ai_security:tick`; a run that surfaces a *newly-appeared*
/// critical/high finding also raises a desktop notification, the same "tell me when something
/// new is wrong" contract the config monitor keeps.
pub fn spawn(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        // A short initial delay so the first sweep doesn't compete with app startup I/O.
        tokio::time::sleep(Duration::from_secs(20)).await;
        loop {
            if auto_scan_enabled() {
                let app = app.clone();
                let _ =
                    tauri::async_runtime::spawn_blocking(move || run_background_scan(&app)).await;
            }
            tokio::time::sleep(AUTO_SCAN_INTERVAL).await;
        }
    });
}

/// Serious (critical/high) findings keyed by (rule, file) — the identity used to decide what's
/// "newly appeared" between two background scans, so a standing issue doesn't re-notify every
/// six hours but a freshly-pasted key does.
fn serious_keys(findings: &[AiFinding]) -> BTreeSet<(String, String)> {
    use bulwark_core::models::Severity;
    findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
        .map(|f| (f.rule_id.clone(), f.file.clone()))
        .collect()
}

fn run_background_scan(app: &AppHandle) {
    let Some(p) = db_path() else { return };
    let opts = match options(Vec::new()) {
        Ok(o) => o,
        Err(_) => return,
    };

    let previous_serious = Store::open(&p)
        .ok()
        .and_then(|mut s| s.latest_ai_scan().ok().flatten())
        .map(|snap| serious_keys(&snap.findings))
        .unwrap_or_default();

    let report = run_ai_scan(&opts, |_| {});
    notify_new_serious(app, &report, &previous_serious);

    if let Ok(mut store) = Store::open(&p) {
        let _ = store.persist_ai_scan(&report);
    }
    let _ = app.emit("ai_security:tick", ());
}

fn notify_new_serious(
    app: &AppHandle,
    report: &AiScanReport,
    previous: &BTreeSet<(String, String)>,
) {
    let current = serious_keys(&report.findings);
    let new_count = current.difference(previous).count();
    if new_count == 0 {
        return;
    }
    let title = if new_count == 1 {
        "Bulwark found a new AI security issue".to_string()
    } else {
        format!("Bulwark found {new_count} new AI security issues")
    };
    let body = report
        .findings
        .iter()
        .filter(|f| current.contains(&(f.rule_id.clone(), f.file.clone())))
        .filter(|f| !previous.contains(&(f.rule_id.clone(), f.file.clone())))
        .take(3)
        .map(|f| f.title.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let _ = app.notification().builder().title(title).body(body).show();
}
