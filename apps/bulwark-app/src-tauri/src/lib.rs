mod monitoring;
mod realtime_av;
mod tray;

use bulwark_core::av_scan::ClamscanLine;
use bulwark_core::models::Severity;
use bulwark_core::{
    all_collectors, av_scan, clamav_install_command, clamav_version_info, engine,
    fim_establish_baseline, AvScanResult, ClamavVersionInfo, Finding, LatestScanMeta, Profile,
    ScanRun, ScanRunSummary, Store, FIM_UNPRIVILEGED_WATCHED_PATHS,
};
use monitoring::MonitoringState;
use realtime_av::RealtimeAvState;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::ipc::Channel;
use tauri::Manager;

#[derive(Clone, Serialize)]
struct RuleSummary {
    id: String,
    title: String,
    category: String,
    severity: Severity,
    collector: String,
    references: Vec<String>,
    explain: String,
    fix: String,
    os: Vec<String>,
    profiles: Vec<String>,
}

/// Streamed to the frontend one message at a time over a Tauri Channel — Channels, not the
/// global event system, per architecture doc §4 ADR-0003 (ordered delivery under load).
#[derive(Clone, Serialize)]
#[serde(tag = "event", content = "data", rename_all = "camelCase")]
enum ScanEvent {
    Finding(Finding),
    CollectorError {
        collector: String,
        message: String,
    },
    PrivilegedSkipped {
        collectors: Vec<String>,
    },
    Complete {
        total_findings: usize,
        host_fingerprint: String,
    },
    Error {
        message: String,
    },
}

/// Dev-mode heuristic: walk up from the current directory (src-tauri when run via
/// `cargo tauri dev`) looking for the workspace's `rules/` dir.
fn find_workspace_rules_dir() -> Option<PathBuf> {
    let mut candidate = std::env::current_dir().ok()?;
    for _ in 0..4 {
        let rules = candidate.join("rules");
        if rules.is_dir() {
            return Some(rules);
        }
        if !candidate.pop() {
            break;
        }
    }
    None
}

/// Resolution order: explicit env override, dev-mode workspace walk-up, then the rule pack
/// bundled as a Tauri resource (`tauri.conf.json`'s `bundle.resources`) — the path a real
/// packaged install actually uses. `app` is `None` only in contexts with no AppHandle yet
/// (there currently are none, but this keeps the function testable without one).
fn resolve_rules_dir(app: Option<&tauri::AppHandle>) -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("BULWARK_RULES_DIR") {
        return Ok(PathBuf::from(p));
    }
    if let Some(dir) = find_workspace_rules_dir() {
        return Ok(dir);
    }
    if let Some(app) = app {
        if let Ok(resource_dir) = app.path().resource_dir() {
            let rules = resource_dir.join("rules");
            if rules.is_dir() {
                return Ok(rules);
            }
        }
    }
    Err("couldn't find a 'rules' directory (set BULWARK_RULES_DIR)".to_string())
}

/// Locates the `bulwarkctl` CLI binary this GUI shells out to for the privileged path (see
/// [`scan_privileged`]).
///
/// Resolution order, most-specific first:
/// 1. `BULWARK_CLI_PATH` — explicit override (tests, unusual installs).
/// 2. **Next to the running executable** — this is the one that matters for a GUI-only
///    install. `bulwarkctl` is bundled as a Tauri `externalBin` sidecar, so it lands beside
///    `bulwark-app` in every package format — the desktop `.deb`/`.rpm` *and* the single-file
///    AppImage (which has no `usr/bin` on `PATH` at all). Without this, "Run privileged checks"
///    would fail for exactly the users most likely to install the desktop package alone.
/// 3. Dev-mode workspace walk (`target/{debug,release}/bulwarkctl`).
/// 4. Bare `"bulwarkctl"` on `PATH` — the CLI-package-alongside-GUI case.
fn resolve_cli_binary() -> PathBuf {
    if let Ok(p) = std::env::var("BULWARK_CLI_PATH") {
        return PathBuf::from(p);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sidecar = dir.join("bulwarkctl");
            if sidecar.is_file() {
                return sidecar;
            }
        }
    }
    if let Ok(mut candidate) = std::env::current_dir() {
        for _ in 0..4 {
            for profile in ["debug", "release"] {
                let bin = candidate.join("target").join(profile).join("bulwarkctl");
                if bin.is_file() {
                    return bin;
                }
            }
            if !candidate.pop() {
                break;
            }
        }
    }
    PathBuf::from("bulwarkctl")
}

fn db_path() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("BULWARK_DB_PATH") {
        return Ok(PathBuf::from(p));
    }
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    Ok(PathBuf::from(home).join(".local/share/bulwark/bulwark.db"))
}

#[tauri::command]
async fn scan_start(
    app: tauri::AppHandle,
    on_event: Channel<ScanEvent>,
    needs: Option<Vec<String>>,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let rules_dir = match resolve_rules_dir(Some(&app)) {
            Ok(d) => d,
            Err(e) => {
                let _ = on_event.send(ScanEvent::Error { message: e });
                return;
            }
        };
        let collectors = all_collectors();
        let profile = Profile {
            needs: needs.unwrap_or_default(),
            ..Profile::current_host()
        };
        // This first pass always runs unprivileged — [`scan_privileged`] is the separate,
        // explicit pkexec-elevated path the UI offers when `privileged_collectors_skipped`
        // below is non-empty (architecture doc §4).
        let scan = engine::run_scan(&rules_dir, &collectors, false, &profile);

        for e in &scan.collector_errors {
            let _ = on_event.send(ScanEvent::CollectorError {
                collector: e.collector.clone(),
                message: e.message.clone(),
            });
        }
        if !scan.privileged_collectors_skipped.is_empty() {
            let _ = on_event.send(ScanEvent::PrivilegedSkipped {
                collectors: scan.privileged_collectors_skipped.clone(),
            });
        }
        for finding in &scan.findings {
            let _ = on_event.send(ScanEvent::Finding(finding.clone()));
        }

        if let Ok(db_path) = db_path() {
            if let Ok(mut store) = Store::open(&db_path) {
                // Reconciled, same as the periodic monitoring loop — a manual scan and a
                // background tick finding the same issue must not produce two rows for it.
                let _ = store.persist_and_reconcile(&scan);
            }
        }

        let _ = on_event.send(ScanEvent::Complete {
            total_findings: scan.findings.len(),
            host_fingerprint: scan.host_fingerprint.clone(),
        });
    })
    .await
    .map_err(|e| e.to_string())
}

/// Runs the full (privileged) scan via `pkexec bulwarkctl scan --privileged --json` and
/// returns the parsed result. Deliberately shells out to the already-built, already-tested
/// CLI rather than duplicating collector-invocation logic here — the polkit prompt this
/// triggers is defined by `polkit/com.bulwark.policy` (`auth_admin_keep`, one prompt per
/// session), matching architecture doc §4's GUI privilege model. This replaces the current
/// finding list rather than merging into it — it's a strictly more complete re-scan, not
/// an incremental addition, so there's nothing to de-duplicate against the prior partial run.
#[tauri::command]
async fn scan_privileged(app: tauri::AppHandle) -> Result<ScanRun, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let rules_dir = resolve_rules_dir(Some(&app))?;
        let cli = resolve_cli_binary();
        let output = std::process::Command::new("pkexec")
            .arg(&cli)
            .arg("scan")
            .arg("--privileged")
            .arg("--json")
            .arg("--no-persist")
            .arg("--rules-dir")
            .arg(&rules_dir)
            .output()
            .map_err(|e| format!("failed to launch pkexec: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Exit code 126/127 from pkexec itself means the user cancelled the auth
            // dialog — report that plainly rather than as a generic scan failure.
            if output.status.code() == Some(126) || output.status.code() == Some(127) {
                return Err("Authentication was cancelled or denied.".to_string());
            }
            // bulwarkctl's own exit codes (1/2) mean "ran fine, found something" —
            // only a genuinely empty/unparseable stdout counts as a real failure below.
            if output.stdout.is_empty() {
                return Err(format!("privileged scan failed: {stderr}"));
            }
        }

        serde_json::from_slice::<ScanRun>(&output.stdout)
            .map_err(|e| format!("couldn't parse privileged scan output: {e}"))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Streamed the same way `scan_start` streams findings (Channel, not the global event bus —
/// architecture doc §4 ADR-0003) rather than one `AvScanResult` returned at the end. A ClamAV pass
/// over even the default target set can take minutes; a UI with zero feedback for that whole
/// window reads as hung, not as working.
#[derive(Clone, Serialize)]
#[serde(tag = "event", content = "data", rename_all = "camelCase")]
enum AvScanEvent {
    FileScanned { path: String },
    ThreatFound(bulwark_core::ThreatDetection),
    Complete(AvScanResult),
    Error { message: String },
}

/// Real on-demand virus scan (see `bulwark_core::av_scan` for why this is a separate,
/// explicitly user-triggered command rather than another collector: it's minutes, not
/// milliseconds, and shelling out to ClamAV rather than reimplementing signature detection
/// is the project's own stated design decision, not a shortcut). Uses `scan_streaming`, not
/// `scan`, specifically so the frontend can show live "N files scanned, currently: <path>"
/// progress instead of a spinner with no information for however long the scan takes.
///
/// `paths`, when non-empty, scans exactly those user-chosen files/folders (drag-and-dropped or
/// picked via the native dialog on the Antivirus tab) instead of the fixed default target set —
/// the `HOME`-dependent default lookup only runs when nothing custom was chosen.
#[tauri::command]
async fn run_virus_scan(
    on_event: Channel<AvScanEvent>,
    paths: Option<Vec<String>>,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let targets = match paths {
            Some(p) if !p.is_empty() => p.into_iter().map(PathBuf::from).collect(),
            _ => {
                let home = match std::env::var("HOME") {
                    Ok(h) => h,
                    Err(_) => {
                        let _ = on_event.send(AvScanEvent::Error {
                            message: "HOME not set".to_string(),
                        });
                        return;
                    }
                };
                av_scan::default_scan_targets(std::path::Path::new(&home))
            }
        };
        let result = av_scan::scan_streaming(&targets, |line| {
            let event = match line {
                ClamscanLine::Clean(path) | ClamscanLine::Error(path) => {
                    AvScanEvent::FileScanned { path: path.clone() }
                }
                ClamscanLine::Infected(threat) => AvScanEvent::ThreatFound(threat.clone()),
            };
            let _ = on_event.send(event);
        });
        match result {
            Ok(r) => {
                let _ = on_event.send(AvScanEvent::Complete(r));
            }
            Err(e) => {
                let _ = on_event.send(AvScanEvent::Error {
                    message: e.to_string(),
                });
            }
        }
    })
    .await
    .map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct ClamavInfoResponse {
    /// `Some` when `clamscan -V` succeeded — real engine/database version and build date,
    /// not just a file-modification-time guess (see `av_scan::get_version_info`'s doc
    /// comment for why this is a separate, richer source from the `clamav_status`
    /// collector's `db_age_days`).
    version: Option<ClamavVersionInfo>,
    /// Populated only when `version` is `None` — the distro-appropriate install command, so
    /// the "ClamAV isn't installed" state actually helps instead of assuming `apt`.
    install_command: Option<String>,
}

/// Backs the Antivirus page's status card with real detail (exact ClamAV/database version,
/// or the correct install command for this specific distro) instead of the generic
/// installed/stale signal `BLWK-AV-001`/`002`'s findings alone provide.
#[tauri::command]
async fn clamav_info() -> Result<ClamavInfoResponse, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let version = clamav_version_info();
        let install_command = if version.is_none() {
            Some(clamav_install_command().to_string())
        } else {
            None
        };
        ClamavInfoResponse {
            version,
            install_command,
        }
    })
    .await
    .map_err(|e| e.to_string())
}

/// Establishes a file-integrity baseline for the unprivileged watched paths only — the
/// root-only ones (/etc/shadow, /etc/sudoers) need `sudo bulwarkctl fim baseline --privileged`
/// from the CLI, same asymmetry as `scan_privileged` vs. the regular unprivileged scan, but
/// without the pkexec dance for this one: establishing a baseline is a local write, not a
/// system-state read that benefits from a single elevated session the way a full privileged
/// scan does. Explicitly user-triggered, never automatic — see `fim_establish_baseline`'s
/// own doc comment for why.
#[tauri::command]
async fn fim_baseline() -> Result<usize, String> {
    tauri::async_runtime::spawn_blocking(|| {
        fim_establish_baseline(FIM_UNPRIVILEGED_WATCHED_PATHS).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Lists the loaded rule pack for the Rules view — reuses `engine::load_rules` directly
/// rather than re-parsing YAML in the frontend; rules that failed to load are omitted here
/// (the same load errors already surface via `scan_start`'s `collectorError`/scan flow).
#[tauri::command]
async fn rules_list(app: tauri::AppHandle) -> Result<Vec<RuleSummary>, String> {
    let rules_dir = resolve_rules_dir(Some(&app))?;
    let (rules, _errors) = engine::load_rules(&rules_dir);
    Ok(rules
        .into_iter()
        .map(|r| RuleSummary {
            id: r.rule.id,
            title: r.rule.title,
            category: r.rule.category,
            severity: r.rule.severity,
            collector: r.rule.collector,
            references: r.rule.references,
            explain: r.rule.explain,
            fix: r.rule.fix,
            os: r
                .rule
                .os
                .iter()
                .map(|os| format!("{os:?}").to_lowercase())
                .collect(),
            profiles: r.rule.profiles,
        })
        .collect())
}

#[derive(Serialize)]
struct DashboardSnapshot {
    findings: Vec<Finding>,
    meta: Option<LatestScanMeta>,
}

/// What a freshly-opened window loads instead of starting blank. Regression-motivated: the
/// GUI used to only ever show scan state from the current session's own button clicks, so
/// opening the app after the background monitoring loop had already run (or after closing
/// and reopening following a manual scan) showed "Not scanned yet" with zero findings even
/// though real data existed — caught by actually looking at the running app, not by a test.
#[tauri::command]
async fn dashboard_snapshot() -> Result<DashboardSnapshot, String> {
    let db_path = db_path()?;
    if !db_path.exists() {
        return Ok(DashboardSnapshot {
            findings: Vec::new(),
            meta: None,
        });
    }
    let store = Store::open(&db_path).map_err(|e| e.to_string())?;
    Ok(DashboardSnapshot {
        findings: store.open_findings().map_err(|e| e.to_string())?,
        meta: store.latest_scan_run_meta().map_err(|e| e.to_string())?,
    })
}

/// Total past scan runs — backs a small "N scans recorded" line rather than a full history
/// browser, which is intentionally out of scope for this pass (see AGENTS.md's status notes).
#[tauri::command]
async fn history_count() -> Result<i64, String> {
    let db_path = db_path()?;
    if !db_path.exists() {
        return Ok(0);
    }
    let store = Store::open(&db_path).map_err(|e| e.to_string())?;
    store.count_scan_runs().map_err(|e| e.to_string())
}

/// The full scan-run timeline for the History view — up to 50 most recent runs, newest
/// first. 50 is a plain cap, not a paged browser: at the default 15-minute monitoring
/// interval that's well over 12 hours of ticks, plenty for "did this just start happening
/// or has it been going on for a while," which is what the view is actually for.
#[tauri::command]
async fn history_list() -> Result<Vec<ScanRunSummary>, String> {
    let db_path = db_path()?;
    if !db_path.exists() {
        return Ok(Vec::new());
    }
    let store = Store::open(&db_path).map_err(|e| e.to_string())?;
    store.list_scan_runs(50).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(MonitoringState(Mutex::new(monitoring::initial_inner())))
        .manage(RealtimeAvState(Mutex::new(realtime_av::initial_state())))
        .setup(|app| {
            // Resolves and logs the rule pack location on every launch, dev or packaged.
            // This is the one code path that genuinely differs between `cargo tauri dev`
            // (workspace walk-up) and an installed build (Tauri's resource_dir) — logging
            // it at startup means a real "why can't Bulwark find its rules" report is
            // diagnosable from a log line instead of a guess.
            let handle = app.handle().clone();
            match resolve_rules_dir(Some(&handle)) {
                Ok(dir) => {
                    println!("[bulwark] rules directory resolved: {}", dir.display());
                    monitoring::spawn(handle.clone(), dir.clone());
                    monitoring::spawn_file_watcher(handle.clone(), dir);
                }
                Err(e) => eprintln!("[bulwark] warning: {e} — continuous monitoring disabled"),
            }

            // Resumes real-time AV protection if it was left enabled on a previous run —
            // "persists across restarts" should mean protection actually restarts, not just
            // that the toggle remembers where it was left.
            realtime_av::start_if_enabled(handle);

            if let Err(e) = tray::spawn(app.handle()) {
                eprintln!("[bulwark] warning: couldn't create tray icon: {e}");
            }

            // The ordinary window-manager close button hides the window instead of quitting
            // the process — see tray.rs's module doc for why. Quitting is the tray menu's
            // explicit "Quit" item, or a real process kill/logout, not an accidental click.
            if let Some(window) = app.get_webview_window("main") {
                let window_to_hide = window.clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = window_to_hide.hide();
                    }
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            scan_start,
            scan_privileged,
            rules_list,
            history_count,
            history_list,
            dashboard_snapshot,
            run_virus_scan,
            clamav_info,
            fim_baseline,
            monitoring::monitoring_get_status,
            monitoring::monitoring_set_enabled,
            monitoring::monitoring_set_interval_minutes,
            realtime_av::realtime_av_get_status,
            realtime_av::realtime_av_set_enabled,
            realtime_av::realtime_av_add_folder,
            realtime_av::realtime_av_remove_folder
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
