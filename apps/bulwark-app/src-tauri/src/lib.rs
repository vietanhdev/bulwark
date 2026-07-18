mod ai_security;
mod monitoring;
mod realtime_av;
mod remediation;
mod reveal;
mod ssh_protect;
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::ipc::Channel;
use tauri::Manager;

/// The stop button, as shared state.
///
/// One flag for every user-initiated scan (compliance, agent, antivirus), because the Overview
/// runs them back-to-back from a single button and "Stop" has to mean *stop all of this*, not
/// just the one currently executing. Each scan command clears it before starting and polls it
/// between units of work; `scan_cancel` sets it.
///
/// It's an `AtomicBool` rather than a channel or a `Mutex<bool>` because the poll happens on a
/// blocking worker thread inside a tight loop, and this is exactly the shape that's free there.
#[derive(Clone, Default)]
pub struct ScanControl(Arc<AtomicBool>);

impl ScanControl {
    fn begin(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
    fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    /// A closure the core engines can poll without knowing anything about Tauri.
    fn is_cancelled(&self) -> impl Fn() -> bool {
        let flag = self.0.clone();
        move || flag.load(Ordering::SeqCst)
    }
}

/// Stops whatever scan is running. Idempotent, and safe to call when nothing is running — the
/// flag is cleared by the next scan that starts.
#[tauri::command]
fn scan_cancel(control: tauri::State<ScanControl>) {
    control.cancel();
}

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
        /// The scan was stopped early — its findings are partial and were not persisted.
        cancelled: bool,
    },
    Error {
        message: String,
    },
}

/// Dev-mode heuristic: walk up from the current directory (src-tauri when run via
/// `cargo tauri dev`) looking for the workspace's `rules/` dir.
///
/// Compiled out of shipped builds entirely — both callers gate it on `debug_assertions`,
/// because "whatever `rules/` sits near the launch directory" is a sane rule for a dev loop
/// and an unpredictable one for an installed application.
#[cfg(debug_assertions)]
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

/// The rule pack sitting **next to the running executable**, canonicalized.
///
/// Tauri's `resource_dir()` is not the only layout a real package uses: the Flatpak installs both
/// binaries into `/app/bin` with `rules/` beside them (so the bundled CLI sidecar, which resolves
/// next-to-exe, can find them), and `resource_dir()` there points at a directory that holds no
/// rules at all. Relying on `resource_dir()` alone is what shipped a Flatpak whose GUI started with
/// "couldn't find a 'rules' directory" and silently disabled continuous monitoring.
fn find_exe_sibling_rules_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    let rules = exe.parent()?.join("rules");
    rules.is_dir().then_some(rules)
}

/// Resolution order: explicit env override, then (debug builds only) the workspace walk-up, then
/// the two layouts a real packaged install actually uses — the rule pack bundled as a Tauri
/// resource (`tauri.conf.json`'s `bundle.resources`), and the pack installed beside the executable
/// (Flatpak). A shipped build therefore resolves deterministically, independent of where it was
/// launched from. `app` is `None` only in contexts with no AppHandle yet (there currently are
/// none, but this keeps the function testable without one).
fn resolve_rules_dir(app: Option<&tauri::AppHandle>) -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("BULWARK_RULES_DIR") {
        return Ok(PathBuf::from(p));
    }
    // The workspace walk-up is a *dev* heuristic and is now compiled out of shipped builds,
    // matching what `resolve_privileged_rules_dir` has always done. It walks up from the
    // current directory looking for any `rules/`, which in a released app means the pack
    // depends on where the user happened to launch from. That is not hypothetical: the
    // Flatpak has `--filesystem=host:ro`, so launching it from a checkout silently loaded
    // that checkout's rules instead of the packaged ones — and it masked the fact that the
    // next-to-exe fallback below is what a real install actually depends on.
    #[cfg(debug_assertions)]
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
    if let Some(dir) = find_exe_sibling_rules_dir() {
        return Ok(dir);
    }
    Err("couldn't find a 'rules' directory (set BULWARK_RULES_DIR)".to_string())
}

/// Like [`resolve_rules_dir`] but for the path handed to the **root** `pkexec` scan: it must not be
/// steerable by anything an attacker can set in the GUI's environment. So `BULWARK_RULES_DIR` and
/// the dev workspace walk are honored only under `debug_assertions`; a shipped build resolves the
/// rules only to the bundled Tauri resource dir. This mirrors [`resolve_cli_binary`]'s refusal to
/// trust the environment on the privileged path — the rule engine is declarative and can't execute
/// code, but a root scan should still never read a rules dir an unprivileged actor chose.
fn resolve_privileged_rules_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    #[cfg(debug_assertions)]
    {
        if let Ok(p) = std::env::var("BULWARK_RULES_DIR") {
            return Ok(PathBuf::from(p));
        }
        if let Some(dir) = find_workspace_rules_dir() {
            return Ok(dir);
        }
    }
    if let Ok(resource_dir) = app.path().resource_dir() {
        let rules = resource_dir.join("rules");
        if rules.is_dir() {
            return Ok(rules);
        }
    }
    // Next-to-exe, canonicalized — the Flatpak layout. This is the same trusted location
    // `resolve_cli_binary` pins the root binary to, and for the same reason: it is chosen by the
    // package, not by anything an unprivileged actor can set. No env or CWD influence reaches it.
    if let Some(dir) = find_exe_sibling_rules_dir() {
        return Ok(dir);
    }
    Err("couldn't find the bundled 'rules' directory for the privileged scan".to_string())
}

/// Locates the `bulwarkctl` CLI binary this GUI shells out to for the privileged path (see
/// [`scan_privileged`]).
///
/// This binary is executed **as root** via `pkexec`, so its path must not be influenceable by
/// anything an attacker can set in the GUI process's environment. That rules out, on purpose:
///   * `BULWARK_CLI_PATH` / any env override — a poisoned `~/.profile`, systemd user environment,
///     or tampered `.desktop` `Environment=` would otherwise choose the binary root runs.
///   * the bare-`"bulwarkctl"`-on-`$PATH` fallback — `$PATH` is equally attacker-controlled.
///   * (release builds) the dev workspace `target/` walk — a planted `target/debug/bulwarkctl`
///     under an attacker-chosen CWD would otherwise be run as root.
///
/// The only trusted location is **next to the running executable**, canonicalized: `bulwark`
/// is bundled as a Tauri `externalBin` sidecar, so it lands beside `bulwark-app` in every package
/// format (the desktop `.deb`/`.rpm` and the single-file AppImage alike). The `target/` walk
/// survives *only* under `debug_assertions`, purely so `cargo tauri dev` can find the freshly
/// built CLI; it is compiled out of every shipped build.
fn resolve_cli_binary() -> Result<PathBuf, String> {
    if let Ok(exe) = std::env::current_exe() {
        // Canonicalize the executable's own directory so a symlinked launcher can't point the
        // sidecar lookup at an attacker-controlled directory.
        if let Some(dir) = exe.parent().and_then(|d| std::fs::canonicalize(d).ok()) {
            // `bulwark` is the bundled sidecar (see build.rs for why it is not called `bulwarkctl`
            // or `bulwark-app`); `bulwarkctl` covers an install where the CLI package sits alongside.
            for name in ["bulwark", "bulwarkctl"] {
                let sidecar = dir.join(name);
                if sidecar.is_file() {
                    return Ok(sidecar);
                }
            }
        }
    }

    #[cfg(debug_assertions)]
    if let Ok(mut candidate) = std::env::current_dir() {
        for _ in 0..4 {
            for profile in ["debug", "release"] {
                let bin = candidate.join("target").join(profile).join("bulwarkctl");
                if bin.is_file() {
                    return Ok(bin);
                }
            }
            if !candidate.pop() {
                break;
            }
        }
    }

    Err(
        "couldn't locate the bundled bulwark CLI next to the app — refusing to run an \
         unverified binary as root"
            .to_string(),
    )
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
    control: tauri::State<'_, ScanControl>,
    on_event: Channel<ScanEvent>,
    needs: Option<Vec<String>>,
) -> Result<(), String> {
    let control = control.inner().clone();
    control.begin();

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
        let scan = engine::run_scan_cancellable(
            &rules_dir,
            &collectors,
            false,
            &profile,
            &control.is_cancelled(),
        );

        // A scan that loaded no rules examined nothing, and "0 findings" from it is not a clean bill
        // of health — it is the absence of an opinion. Surfaced as a normal empty result it would be
        // indistinguishable from a healthy host, which is the most dangerous thing a security tool
        // can say; it would also be persisted, and `persist_and_reconcile` closes every open finding
        // a scan didn't re-observe, so an empty rule pack would silently mark the whole dashboard
        // resolved. Report it as the error it is (architecture doc §8: a failure is visible, never a
        // silent drop). Mirrors the same guard in `bulwarkctl scan`.
        if scan.rules_loaded == 0 {
            let _ = on_event.send(ScanEvent::Error {
                message: format!(
                    "Loaded 0 rules from {} — refusing to report a clean result from a scan that \
                     examined nothing.",
                    rules_dir.display()
                ),
            });
            return;
        }

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

        // A stopped scan is *partial*, so it never reaches the database. Persisting it would be
        // actively harmful, not merely incomplete: reconciliation would treat the collectors it
        // never reached as "ran and found nothing" for the rules it did evaluate, and the run
        // would overwrite a complete picture with a half-finished one.
        let mut new_findings = Vec::new();
        if !scan.cancelled {
            if let Ok(db_path) = db_path() {
                if let Ok(mut store) = Store::open(&db_path) {
                    // Reconciled, same as the periodic monitoring loop — a manual scan and a
                    // background tick finding the same issue must not produce two rows for it. The
                    // return value is the set of findings that *newly appeared* this run, which is
                    // exactly what a "new issue" notification should announce.
                    new_findings = store.persist_and_reconcile(&scan).unwrap_or_default();
                }
            }
        }

        // Desktop notification on completion — the user asked to be told when a scan finishes and,
        // especially, when a new issue turns up. A cancelled (partial) run says nothing, since its
        // picture is incomplete. New issues lead the message; a clean finish still confirms the scan
        // ran, so a manual "Scan" click always gets an acknowledgement.
        if !scan.cancelled {
            use tauri_plugin_notification::NotificationExt;
            let (title, body) = if new_findings.is_empty() {
                let body = if scan.findings.is_empty() {
                    "No issues found.".to_string()
                } else {
                    format!("No new issues — {} still open.", scan.findings.len())
                };
                ("Bulwark scan complete".to_string(), body)
            } else {
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
                (title, body)
            };
            let _ = app.notification().builder().title(title).body(body).show();
        }

        let _ = on_event.send(ScanEvent::Complete {
            total_findings: scan.findings.len(),
            host_fingerprint: scan.host_fingerprint.clone(),
            cancelled: scan.cancelled,
        });
    })
    .await
    .map_err(|e| e.to_string())
}

/// Runs the full (privileged) scan via `pkexec bulwarkctl scan --privileged --json` and
/// returns the parsed result. Deliberately shells out to the already-built, already-tested
/// CLI rather than duplicating collector-invocation logic here — the polkit prompt this
/// triggers is defined by `polkit/com.bulwark.policy` (`auth_admin`, one prompt per privileged
/// scan), matching architecture doc §4's GUI privilege model. Both the CLI binary and the rules
/// dir handed to root are resolved without trusting the environment (see `resolve_cli_binary` and
/// `resolve_privileged_rules_dir`). This replaces the current
/// finding list rather than merging into it — it's a strictly more complete re-scan, not
/// an incremental addition, so there's nothing to de-duplicate against the prior partial run.
#[tauri::command]
async fn scan_privileged(app: tauri::AppHandle) -> Result<ScanRun, String> {
    tauri::async_runtime::spawn_blocking(move || {
        // In a Flatpak there is no pkexec inside the sandbox, and reaching the host's would
        // need `--talk-name=org.freedesktop.Flatpak` (a sandbox escape) plus a host-installed
        // bulwarkctl to elevate. Neither exists yet, so say so in words the user can act on
        // rather than letting them hit "failed to launch pkexec: No such file or directory".
        if std::path::Path::new("/.flatpak-info").exists() {
            return Err(
                "Privileged scans aren't available in the Flatpak version, because \
                        the sandbox can't request administrator access. Everything that \
                        doesn't need root still works. For the full system scan, install \
                        Bulwark from the .deb, .rpm or AppImage, or use the bulwarkctl \
                        command-line tool with sudo."
                    .to_string(),
            );
        }
        let rules_dir = resolve_privileged_rules_dir(&app)?;
        let cli = resolve_cli_binary()?;
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
    control: tauri::State<'_, ScanControl>,
    on_event: Channel<AvScanEvent>,
    paths: Option<Vec<String>>,
) -> Result<(), String> {
    let control = control.inner().clone();
    control.begin();

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
        let result = av_scan::scan_streaming_cancellable(
            &targets,
            |line| {
                let event = match line {
                    ClamscanLine::Clean(path) | ClamscanLine::Error(path) => {
                        AvScanEvent::FileScanned { path: path.clone() }
                    }
                    ClamscanLine::Infected(threat) => AvScanEvent::ThreatFound(threat.clone()),
                };
                let _ = on_event.send(event);
            },
            &control.is_cancelled(),
        );
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

/// Who a suppression is attributed to in the audit trail. The desktop app has no `sudo` context,
/// so the logged-in user's name is the honest actor.
fn suppression_actor() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "desktop-user".to_string())
}

/// Accepts the risk a rule reports — the "ignore this rule, with a reason" action the Rules view
/// offers. The rule keeps running every scan; only its presentation changes. The reason is
/// mandatory (enforced in core), which is the whole point: an unexplained suppression is
/// unauditable.
#[tauri::command]
async fn rule_suppress(rule_id: String, reason: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let db_path = db_path()?;
        let mut store = Store::open(&db_path).map_err(|e| e.to_string())?;
        store
            .suppress_rule(&rule_id, &reason, &suppression_actor())
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Withdraws a risk acceptance — the rule's findings count against you again. Also requires a
/// reason, because re-enabling a check is an auditable decision too.
#[tauri::command]
async fn rule_unsuppress(rule_id: String, reason: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let db_path = db_path()?;
        let mut store = Store::open(&db_path).map_err(|e| e.to_string())?;
        store
            .unsuppress_rule(&rule_id, &reason, &suppression_actor())
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// The currently-active suppressions, for the Rules view's "Suppressed" tab.
#[tauri::command]
async fn suppressions_list() -> Result<Vec<bulwark_core::models::Suppression>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let db_path = db_path()?;
        if !db_path.exists() {
            return Ok(Vec::new());
        }
        let mut store = Store::open(&db_path).map_err(|e| e.to_string())?;
        store.list_suppressions().map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// The append-only suppression audit trail (optionally scoped to one rule) — every suppress and
/// un-suppress ever made, so the Rules view can show who accepted what risk, when, and why, even
/// after a suppression has been lifted.
#[tauri::command]
async fn suppression_audit(
    rule_id: Option<String>,
) -> Result<Vec<bulwark_core::models::SuppressionEvent>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let db_path = db_path()?;
        if !db_path.exists() {
            return Ok(Vec::new());
        }
        let mut store = Store::open(&db_path).map_err(|e| e.to_string())?;
        store
            .suppression_audit_log(rule_id.as_deref(), 500)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[derive(Serialize)]
struct DashboardSnapshot {
    /// Every open issue on this host, from *all* scanners — the config rule engine and the
    /// agent-artifact scanner alike — that the user has NOT accepted the risk of. The Overview is
    /// the one place that answers "what's wrong with this machine," so it must not silently omit a
    /// whole scanner's findings.
    findings: Vec<Finding>,
    /// Findings whose rule the user has explicitly suppressed. Kept separate rather than dropped:
    /// the honest summary is "3 to fix, 2 accepted", and the UI shows the second number rather than
    /// pretending the accepted risk isn't there.
    #[serde(rename = "suppressedFindings")]
    suppressed_findings: Vec<Finding>,
    meta: Option<LatestScanMeta>,
    /// Whether an agent-security scan has ever run. Without this the Overview can't tell
    /// "no agent issues" from "the agent scanner never ran" — and claiming a clean bill of
    /// health nobody earned is the one thing this codebase consistently refuses to do.
    agent_scanned: bool,
}

/// Projects an [`AiFinding`] into the common [`Finding`] shape so the Overview can render every
/// scanner's issues in one list without knowing which engine produced them. The agent-specific
/// locality (file, line, which assistant, the masked evidence) is preserved in `context` rather
/// than thrown away — the Agent Security tab reads the richer `AiFinding` directly from its own
/// table, this is purely the aggregate view's flattening.
fn ai_finding_as_finding(
    f: &bulwark_core::AiFinding,
    seen_at: chrono::DateTime<chrono::Utc>,
) -> Finding {
    let mut context = bulwark_core::Fact::new();
    context.insert("file".into(), serde_json::Value::String(f.file.clone()));
    context.insert("tool".into(), serde_json::Value::String(f.tool.clone()));
    context.insert(
        "evidence".into(),
        serde_json::Value::String(f.evidence.clone()),
    );
    if let Some(line) = f.line {
        context.insert("line".into(), serde_json::Value::from(line as u64));
    }
    Finding {
        id: f.id,
        rule_id: f.rule_id.clone(),
        severity: f.severity,
        title: f.title.clone(),
        explanation: f.explanation.clone(),
        fix_hint: f.fix_hint.clone(),
        context,
        first_seen: seen_at,
        last_seen: seen_at,
        status: bulwark_core::FindingStatus::Open,
        // The agent scanner keeps its own run table; a config `scan_runs` id would be a lie, so
        // this carries the nil UUID rather than inventing an association that doesn't exist.
        scan_run_id: uuid::Uuid::nil(),
    }
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
            suppressed_findings: Vec::new(),
            meta: None,
            agent_scanned: false,
        });
    }
    let mut store = Store::open(&db_path).map_err(|e| e.to_string())?;

    let mut findings = store.open_findings().map_err(|e| e.to_string())?;

    // Fold in the latest agent-security scan. Its findings live in their own table (different
    // shape, latest-run-wins rather than reconciled — see store::persist_ai_scan), but the
    // Overview's contract is "all issues", so they're flattened in here.
    let agent = store.latest_ai_scan().map_err(|e| e.to_string())?;
    let agent_scanned = agent.is_some();
    if let Some(snap) = agent {
        findings.extend(
            snap.findings
                .iter()
                .map(|f| ai_finding_as_finding(f, snap.started_at)),
        );
    }

    // Partition off the findings whose rule the user has accepted the risk of. Done here over the
    // combined config+agent set (rather than in `open_findings_split`, which only knows about
    // config findings) so suppression applies uniformly across every scanner — a suppressed
    // BLWK-AI-* rule is honored the same as a suppressed BLWK-KERNEL-* one.
    let suppressed_ids = store.suppressed_rule_ids().map_err(|e| e.to_string())?;
    let (suppressed_findings, findings): (Vec<_>, Vec<_>) = findings
        .into_iter()
        .partition(|f| suppressed_ids.contains(&f.rule_id));

    Ok(DashboardSnapshot {
        findings,
        suppressed_findings,
        meta: store.latest_scan_run_meta().map_err(|e| e.to_string())?,
        agent_scanned,
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
    let mut store = Store::open(&db_path).map_err(|e| e.to_string())?;
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
    let mut store = Store::open(&db_path).map_err(|e| e.to_string())?;
    store.list_scan_runs(50).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // Must be the FIRST plugin registered (plugin requirement). When a second `bulwark-app` is
        // launched — the natural thing a user does when the window is hidden and the tray menu isn't
        // cooperating — this fires in the already-running instance and brings its window back,
        // instead of starting a duplicate. It is the guaranteed escape hatch from "closed to tray".
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            tray::show_main_window(app);
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(ScanControl::default())
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

            // Log where the UI is loaded from, permanently, and shout if it is a dev URL.
            //
            // A packaged build must serve the frontend embedded from `frontendDist`, i.e.
            // `tauri://localhost`. If it instead points at `devUrl` (http://localhost:1420),
            // nothing is listening on a user's machine and the window renders empty — while
            // every other signal stays healthy: it compiles, installs, starts, resolves its
            // rules, completes setup and spawns a WebKit process. That is exactly what the
            // Flatpak and Snap shipped, because Tauri computes `let dev = !custom_protocol`
            // and both built with plain `cargo build`, without that feature.
            //
            // One line makes an otherwise invisible failure obvious in any bug report, and
            // gives the packaging launch tests something to assert on. See
            // scripts/test-gui-packages-docker.sh, which fails on `url = http://`.
            if let Some(w) = app.get_webview_window("main") {
                match w.url() {
                    Ok(url) => {
                        println!("[bulwark] webview url: {url}");
                        if url.scheme() == "http" || url.scheme() == "https" {
                            eprintln!(
                                "[bulwark] ERROR: this build loads the UI from {url} — a DEV \
                                 build. A packaged build must embed the frontend (build with \
                                 --features custom-protocol). The window will be empty."
                            );
                        }
                    }
                    Err(e) => eprintln!("[bulwark] warning: couldn't read the webview url: {e}"),
                }
            } else {
                eprintln!("[bulwark] ERROR: no webview window was created");
            }

            // Resumes real-time AV protection if it was left enabled on a previous run —
            // "persists across restarts" should mean protection actually restarts, not just
            // that the toggle remembers where it was left.
            realtime_av::start_if_enabled(handle.clone());

            // Background AI-artifact auto-scan: one sweep shortly after launch, then periodic,
            // so the AI Security tab shows fresh data without the user clicking Scan first.
            ai_security::spawn(handle);

            // `catch_unwind`, not just the `Result`, because the failure that actually shipped was
            // a *panic*, not an `Err`: libappindicator-sys loads libayatana-appindicator3 with
            // dlopen at first use and panics outright when it is absent, which is the case in a
            // Flatpak runtime that doesn't ship it. That killed the whole app on launch — a
            // missing tray must degrade the tray, never take the window down with it. The
            // single-instance plugin remains the escape hatch if the window is later hidden with
            // no tray to restore it from.
            //
            // The hook is swapped out for the duration of the call. `catch_unwind` catches the
            // unwind, but Rust's default hook has already printed the panic message and a
            // "note: run with RUST_BACKTRACE=1" line to stderr by then — so a user whose runtime
            // simply lacks a tray library sees a full crash report for something that was handled
            // and is not a crash. Silencing it here (and only here, restoring immediately after)
            // leaves the one-line warning below as the whole story.
            let tray_handle = app.handle().clone();
            let previous_hook = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {}));
            let tray_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                tray::spawn(&tray_handle)
            }));
            std::panic::set_hook(previous_hook);
            let tray_available = match tray_result {
                Ok(Ok(())) => true,
                Ok(Err(e)) => {
                    eprintln!("[bulwark] warning: couldn't create tray icon: {e}");
                    false
                }
                Err(_) => {
                    eprintln!(
                        "[bulwark] warning: tray unavailable (no AppIndicator library) — \
                         continuing without a tray icon"
                    );
                    false
                }
            };

            // The ordinary window-manager close button hides the window instead of quitting
            // the process — see tray.rs's module doc for why. Quitting is the tray menu's
            // explicit "Quit" item, or a real process kill/logout, not an accidental click.
            if let Some(window) = app.get_webview_window("main") {
                let window_to_hide = window.clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        // Hide-instead-of-quit is only honest when a tray icon exists to restore
                        // the window from. Without one — a Flatpak runtime with no AppIndicator
                        // library, or any desktop where the tray failed — hiding would make the
                        // app vanish with no visible way back, which is worse than quitting.
                        // So the close button falls back to its ordinary meaning.
                        if tray_available {
                            api.prevent_close();
                            let _ = window_to_hide.hide();
                        }
                    }
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            scan_start,
            scan_cancel,
            scan_privileged,
            rules_list,
            rule_suppress,
            rule_unsuppress,
            suppressions_list,
            suppression_audit,
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
            realtime_av::realtime_av_remove_folder,
            ai_security::ai_scan_start,
            ai_security::ai_scan_snapshot,
            ai_security::ai_redact,
            ai_security::ai_settings_get,
            ai_security::ai_settings_set,
            ssh_protect::ssh_protect_keys,
            remediation::fix_ssh_permissions,
            reveal::open_flagged_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
