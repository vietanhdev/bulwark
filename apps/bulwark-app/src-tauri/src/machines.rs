//! The "Machines" page: other computers monitored over SSH, plus where alerts are sent.
//!
//! Split by what touches the network:
//!   * **Registry and stored results** (list, add, edit, remove, a machine's findings, alert
//!     settings) go straight to `bulwark_core` — `fleet`, `Store`, `notify_config`. Nothing there
//!     leaves the machine.
//!   * **Anything that connects** (check connection, trust a host key, set up key access, scan,
//!     send a test alert) runs the bundled CLI sidecar — `bulwark hosts …` / `bulwark notify …`
//!     with `--json` — so the app and the terminal share one implementation of SSH, host-key
//!     handling, alert delivery and their failure messages. `bulwark-core` stays network-free,
//!     and the GUI process never links an SSH or SMTP client.
//!
//! The scheduler lives here too: every 20 seconds it scans the enabled machines whose interval has
//! elapsed (with backoff for failing ones — decided in `fleet`), at most three at a time, and never
//! the same machine twice at once. Unlike local privileged checks, remote root checks can run
//! unattended, because they go through `sudo -n` on the far side rather than a polkit prompt here.

use bulwark_core::fleet::{self, Alert, NewRemoteHost, RemoteHostPatch, RemoteHostView};
use bulwark_core::notify_config::{self, NotifyConfig, NotifyStatus};
use bulwark_core::{paths, Finding, Store};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

const KEY_ENABLED: &str = "remote_monitoring_enabled";
/// Machines scanned at the same time by the scheduler.
const PARALLEL: usize = 3;
/// How often the scheduler looks for due machines. The intervals themselves are minutes to days.
const TICK: Duration = Duration::from_secs(20);
const EVENT: &str = "machines:changed";

#[derive(Default)]
pub struct MachinesState {
    running: Mutex<HashSet<String>>,
}

fn db() -> Result<PathBuf, String> {
    crate::db_path()
}

fn err(e: impl std::fmt::Display) -> String {
    let s = e.to_string();
    s.strip_prefix("Error: ").unwrap_or(&s).trim().to_string()
}

fn open() -> Result<Store, String> {
    Store::open(&db()?).map_err(err)
}

fn monitoring_enabled(store: &mut Store) -> bool {
    store
        .get_setting(KEY_ENABLED)
        .ok()
        .flatten()
        .is_none_or(|v| v == "true")
}

// ---- the CLI sidecar ----------------------------------------------------------------------------

/// Run the bundled CLI with `--db-path` pinned to the app's database, so both always read and write
/// the same registry. Returns its JSON stdout; a non-zero exit with readable JSON is still a result
/// (a failed connection check is an answer, not an error).
fn run_cli(
    args: &[&str],
    stdin: Option<&str>,
    rules_dir: Option<&Path>,
) -> Result<serde_json::Value, String> {
    let cli = crate::resolve_cli_binary()?;
    let mut cmd = bulwark_core::sandbox::quiet_command(cli);
    cmd.arg("--db-path").arg(db()?);
    if let Some(r) = rules_dir {
        cmd.arg("--rules-dir").arg(r);
    }
    cmd.args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("couldn't start the Bulwark CLI: {e}"))?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(input.as_bytes()).map_err(err)?;
    }
    let out = child.wait_with_output().map_err(err)?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    match serde_json::from_str::<serde_json::Value>(stdout.trim()) {
        Ok(v) => Ok(v),
        Err(_) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let msg = stderr
                .lines()
                .filter(|l| !l.trim().is_empty())
                .collect::<Vec<_>>()
                .join("\n");
            Err(err(if msg.is_empty() {
                format!("the Bulwark CLI exited with {:?}", out.status.code())
            } else {
                msg
            }))
        }
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| e.to_string())?
}

// ---- list / registry ----------------------------------------------------------------------------

#[derive(Serialize)]
pub struct MachineRow {
    #[serde(flatten)]
    view: RemoteHostView,
    scanning: bool,
}

#[derive(Serialize)]
pub struct MachinesOverview {
    /// Scheduled scans on/off for every machine (each can also be paused on its own).
    enabled: bool,
    machines: Vec<MachineRow>,
    /// Whether this build can copy Bulwark to machines that don't have it (not inside a Flatpak).
    can_copy_engine: bool,
}

fn row(state: &MachinesState, view: RemoteHostView) -> MachineRow {
    let scanning = state
        .running
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&view.host.id);
    MachineRow { view, scanning }
}

#[tauri::command]
pub async fn machines_list(
    state: tauri::State<'_, MachinesState>,
) -> Result<MachinesOverview, String> {
    let path = db()?;
    let mut store = Store::open(&path).map_err(err)?;
    let enabled = monitoring_enabled(&mut store);
    drop(store);
    let views = fleet::list_views(&path).map_err(err)?;
    Ok(MachinesOverview {
        enabled,
        machines: views.into_iter().map(|v| row(&state, v)).collect(),
        can_copy_engine: cfg!(target_os = "linux")
            && bulwark_core::sandbox::detect() != bulwark_core::sandbox::Sandbox::Flatpak,
    })
}

/// Registers a machine. `paused` is used by the add-machine flow: the machine is saved (so the
/// connection steps can refer to it) but not scheduled until the user finishes the flow.
#[tauri::command]
pub async fn machine_add(
    app: AppHandle,
    state: tauri::State<'_, MachinesState>,
    input: NewRemoteHost,
    paused: bool,
) -> Result<MachineRow, String> {
    let mut store = open()?;
    let h = store.add_remote_host(&input).map_err(err)?;
    let h = if paused {
        store
            .update_remote_host(
                &h.id,
                &RemoteHostPatch {
                    enabled: Some(false),
                    ..Default::default()
                },
            )
            .map_err(err)?
    } else {
        h
    };
    let _ = app.emit(EVENT, ());
    Ok(row(
        &state,
        fleet::build_view(h, &db()?, chrono::Utc::now()),
    ))
}

#[tauri::command]
pub async fn machine_update(
    app: AppHandle,
    state: tauri::State<'_, MachinesState>,
    id: String,
    patch: RemoteHostPatch,
) -> Result<MachineRow, String> {
    let h = open()?.update_remote_host(&id, &patch).map_err(err)?;
    let _ = app.emit(EVENT, ());
    Ok(row(
        &state,
        fleet::build_view(h, &db()?, chrono::Utc::now()),
    ))
}

#[tauri::command]
pub async fn machine_remove(
    app: AppHandle,
    id: String,
    delete_history: bool,
) -> Result<(), String> {
    let path = db()?;
    Store::open(&path)
        .map_err(err)?
        .delete_remote_host(&id)
        .map_err(err)?;
    if delete_history {
        let hdb = paths::remote_host_db_path(&path, &id);
        if hdb.exists() {
            std::fs::remove_file(&hdb).map_err(err)?;
        }
    }
    let _ = app.emit(EVENT, ());
    Ok(())
}

#[derive(Serialize)]
pub struct MachineFindings {
    active: Vec<Finding>,
    suppressed: Vec<Finding>,
    /// The issue types ignored on this machine, with who ignored them, when and why.
    suppressions: Vec<bulwark_core::models::Suppression>,
    last_scan_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Single findings ignored on this machine (a rule at one place).
    ignores: Vec<bulwark_core::FindingIgnore>,
}

#[tauri::command]
pub async fn machine_findings(id: String) -> Result<MachineFindings, String> {
    let hdb = paths::remote_host_db_path(&db()?, &id);
    if !hdb.exists() {
        return Ok(MachineFindings {
            active: Vec::new(),
            suppressed: Vec::new(),
            suppressions: Vec::new(),
            ignores: Vec::new(),
            last_scan_at: None,
        });
    }
    let mut store = Store::open(&hdb).map_err(err)?;
    let split = store.open_findings_split().map_err(err)?;
    let meta = store.latest_scan_run_meta().map_err(err)?;
    let suppressions = store.list_suppressions().map_err(err)?;
    let ignores = store.list_finding_ignores().map_err(err)?;
    Ok(MachineFindings {
        active: split.active,
        suppressed: split.suppressed,
        suppressions,
        ignores,
        last_scan_at: meta.map(|m| m.started_at),
    })
}

/// Ignore an issue type on one machine — the per-machine counterpart of "ignore this type" on Home.
/// Same model and same guarantees: stored in that machine's own database, a reason is required
/// (enforced in core), the rule keeps running every scan, ignored issues are counted rather than
/// hidden, and every ignore/un-ignore lands in the audit log.
#[tauri::command]
pub async fn machine_suppress(
    app: AppHandle,
    id: String,
    rule_id: String,
    reason: String,
    location: Option<String>,
) -> Result<(), String> {
    let hdb = paths::remote_host_db_path(&db()?, &id);
    let mut store = Store::open(&hdb).map_err(err)?;
    // With a location, only that one finding; without, the whole issue type.
    match location {
        Some(place) => store
            .ignore_finding(&rule_id, &place, &reason, &crate::suppression_actor())
            .map(|_| ()),
        None => store
            .suppress_rule(&rule_id, &reason, &crate::suppression_actor())
            .map(|_| ()),
    }
    .map_err(err)?;
    let _ = app.emit(EVENT, ());
    Ok(())
}

#[tauri::command]
pub async fn machine_unsuppress(
    app: AppHandle,
    id: String,
    rule_id: String,
    reason: String,
    location: Option<String>,
) -> Result<(), String> {
    let hdb = paths::remote_host_db_path(&db()?, &id);
    let mut store = Store::open(&hdb).map_err(err)?;
    match location {
        Some(place) => {
            store.unignore_finding(&rule_id, &place, &reason, &crate::suppression_actor())
        }
        None => store.unsuppress_rule(&rule_id, &reason, &crate::suppression_actor()),
    }
    .map_err(err)?;
    let _ = app.emit(EVENT, ());
    Ok(())
}

#[tauri::command]
pub async fn machines_set_enabled(app: AppHandle, enabled: bool) -> Result<bool, String> {
    open()?
        .set_setting(KEY_ENABLED, if enabled { "true" } else { "false" })
        .map_err(err)?;
    let _ = app.emit(EVENT, ());
    Ok(enabled)
}

// ---- connection -----------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TestArgs {
    /// A registered machine's id, or an address for a machine not saved yet.
    host: String,
    port: Option<u16>,
    identity: Option<String>,
    jump: Option<String>,
    #[serde(default)]
    privileged: bool,
}

/// Step-by-step connection check (`bulwark hosts test --json`).
#[tauri::command]
pub async fn machine_test(args: TestArgs) -> Result<serde_json::Value, String> {
    blocking(move || {
        let mut a: Vec<String> = vec!["hosts".into(), "test".into(), args.host, "--json".into()];
        if let Some(p) = args.port {
            a.extend(["--port".into(), p.to_string()]);
        }
        if let Some(i) = args.identity.filter(|s| !s.trim().is_empty()) {
            a.extend(["--identity".into(), i]);
        }
        if let Some(j) = args.jump.filter(|s| !s.trim().is_empty()) {
            a.extend(["--jump".into(), j]);
        }
        if args.privileged {
            a.push("--privileged".into());
        }
        let refs: Vec<&str> = a.iter().map(String::as_str).collect();
        run_cli(&refs, None, None)
    })
    .await
}

/// Trust the host key with exactly this fingerprint, in Bulwark's own known_hosts.
#[tauri::command]
pub async fn machine_trust(
    app: AppHandle,
    id: String,
    fingerprint: String,
    replace: bool,
) -> Result<serde_json::Value, String> {
    let v = blocking(move || {
        let mut a = vec![
            "hosts",
            "trust",
            &id,
            "--fingerprint",
            &fingerprint,
            "--json",
        ];
        if replace {
            a.push("--replace");
        }
        run_cli(&a, None, None)
    })
    .await?;
    let _ = app.emit(EVENT, ());
    Ok(v)
}

/// Install Bulwark's restricted monitoring key, signing in once with `password` (never stored —
/// it travels to the CLI over stdin and from there to ssh through a 0600 askpass file) or, with no
/// password, with whatever access already works.
#[tauri::command]
pub async fn machine_setup_key(
    app: AppHandle,
    id: String,
    password: Option<String>,
) -> Result<serde_json::Value, String> {
    let v = blocking(move || match password.filter(|p| !p.is_empty()) {
        Some(pw) => run_cli(
            &["hosts", "setup-key", &id, "--password-stdin", "--json"],
            Some(&format!("{pw}\n")),
            None,
        ),
        None => run_cli(&["hosts", "setup-key", &id, "--json"], None, None),
    })
    .await?;
    let _ = app.emit(EVENT, ());
    Ok(v)
}

#[tauri::command]
pub async fn machine_scan_now(app: AppHandle, id: String) -> Result<(), String> {
    let rules = crate::resolve_rules_dir(Some(&app)).ok();
    spawn_scan(app, id, rules);
    Ok(())
}

#[tauri::command]
pub async fn machines_scan_all(app: AppHandle) -> Result<usize, String> {
    let rules = crate::resolve_rules_dir(Some(&app)).ok();
    let hosts = open()?.list_remote_hosts().map_err(err)?;
    let n = hosts.len();
    for h in hosts {
        spawn_scan(app.clone(), h.id, rules.clone());
    }
    Ok(n)
}

// ---- local SSH config, for suggestions --------------------------------------------------------------

#[derive(Serialize, Default)]
pub struct SshSuggestions {
    /// `Host` aliases from ~/.ssh/config (no wildcard patterns).
    aliases: Vec<SshAlias>,
    /// Private keys in ~/.ssh (files with a matching .pub), plus Bulwark's own key if it exists.
    keys: Vec<String>,
    /// Bulwark's dedicated key, when already created.
    bulwark_key: Option<String>,
}

#[derive(Serialize, Default, Clone)]
pub struct SshAlias {
    alias: String,
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    jump: Option<String>,
}

pub(crate) fn parse_ssh_config(text: &str) -> Vec<SshAlias> {
    let mut out: Vec<SshAlias> = Vec::new();
    let mut current: Vec<usize> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = match line.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((k, v)) => (
                k.to_ascii_lowercase(),
                v.trim().trim_start_matches('=').trim(),
            ),
            None => continue,
        };
        match k.as_str() {
            "host" => {
                current.clear();
                for a in v.split_whitespace() {
                    if a.contains(['*', '?', '!']) {
                        continue;
                    }
                    if fleet::validate_spec(a).is_err() {
                        continue;
                    }
                    out.push(SshAlias {
                        alias: a.to_string(),
                        ..Default::default()
                    });
                    current.push(out.len() - 1);
                }
            }
            "match" => current.clear(),
            "hostname" => current
                .iter()
                .for_each(|&i| out[i].hostname = Some(v.into())),
            "user" => current.iter().for_each(|&i| out[i].user = Some(v.into())),
            "port" => current.iter().for_each(|&i| out[i].port = v.parse().ok()),
            "proxyjump" => current.iter().for_each(|&i| out[i].jump = Some(v.into())),
            _ => {}
        }
    }
    out
}

#[tauri::command]
pub async fn ssh_suggestions() -> Result<SshSuggestions, String> {
    let Some(home) = bulwark_core::paths::home_var_os().map(PathBuf::from) else {
        return Ok(SshSuggestions::default());
    };
    let ssh = home.join(".ssh");
    let aliases = std::fs::read_to_string(ssh.join("config"))
        .map(|t| parse_ssh_config(&t))
        .unwrap_or_default();
    let mut keys: Vec<String> = std::fs::read_dir(&ssh)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.extension().is_none_or(|e| e != "pub")
                        && p.with_extension("pub").exists()
                        && p.is_file()
                })
                .map(|p| {
                    format!(
                        "~/.ssh/{}",
                        p.file_name().unwrap_or_default().to_string_lossy()
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    keys.sort();
    let bk = paths::monitoring_key_path(&db()?);
    Ok(SshSuggestions {
        aliases,
        keys,
        bulwark_key: bk.exists().then(|| bk.display().to_string()),
    })
}

// ---- alerts (Telegram / e-mail) ------------------------------------------------------------------

#[tauri::command]
pub async fn notify_status() -> Result<NotifyStatus, String> {
    let path = db()?;
    notify_config::status(&mut Store::open(&path).map_err(err)?, &path).map_err(err)
}

/// Saves the alert settings. Secrets: `None` keeps the stored one, `Some("")` clears it.
#[tauri::command]
pub async fn notify_configure(
    config: NotifyConfig,
    telegram_bot_token: Option<String>,
    smtp_password: Option<String>,
) -> Result<NotifyStatus, String> {
    let path = db()?;
    let mut store = Store::open(&path).map_err(err)?;
    notify_config::save(&mut store, &config).map_err(err)?;
    let sp = notify_config::secrets_path(&path);
    let mut secrets = notify_config::try_load_secrets(&sp).map_err(err)?;
    if let Some(t) = telegram_bot_token {
        secrets.telegram_bot_token = Some(t.trim().to_string()).filter(|s| !s.is_empty());
    }
    if let Some(p) = smtp_password {
        secrets.smtp_password = Some(p).filter(|s| !s.is_empty());
    }
    notify_config::save_secrets(&sp, &secrets).map_err(err)?;
    notify_config::status(&mut store, &path).map_err(err)
}

#[tauri::command]
pub async fn notify_test() -> Result<serde_json::Value, String> {
    blocking(|| run_cli(&["notify", "test", "--json"], None, None)).await
}

#[tauri::command]
pub async fn notify_report() -> Result<serde_json::Value, String> {
    blocking(|| run_cli(&["notify", "report", "--json"], None, None)).await
}

/// Chats that have messaged the bot. With `token`, uses that one (not yet saved).
#[tauri::command]
pub async fn notify_telegram_chats(token: Option<String>) -> Result<serde_json::Value, String> {
    blocking(move || match token.filter(|t| !t.trim().is_empty()) {
        Some(t) => run_cli(
            &["notify", "chats", "--token-stdin", "--json"],
            Some(&format!("{}\n", t.trim())),
            None,
        ),
        None => run_cli(&["notify", "chats", "--json"], None, None),
    })
    .await
}

/// Forward alerts raised by this computer's own monitoring to Telegram/e-mail, if the user set that
/// up. Fire-and-forget on a background thread: delivery must never slow a monitoring tick.
pub fn forward_local_alerts(alerts: Vec<Alert>) {
    if alerts.is_empty() {
        return;
    }
    let Ok(path) = db() else { return };
    let wanted = Store::open(&path)
        .ok()
        .and_then(|mut s| notify_config::load(&mut s).ok())
        .is_some_and(|c| c.any_channel_enabled() && c.include_this_computer);
    if !wanted {
        return;
    }
    std::thread::spawn(move || {
        if let Ok(json) = serde_json::to_string(&alerts) {
            if let Err(e) = run_cli(&["notify", "send", "--json"], Some(&json), None) {
                eprintln!("[bulwark] couldn't send alert: {e}");
            }
        }
    });
}

// ---- scheduler ------------------------------------------------------------------------------------

#[derive(Deserialize)]
struct ScanResult {
    #[serde(default)]
    alerts: Vec<Alert>,
}

fn spawn_scan(app: AppHandle, id: String, rules: Option<PathBuf>) {
    {
        let state = app.state::<MachinesState>();
        let mut running = state.running.lock().unwrap_or_else(|e| e.into_inner());
        if !running.insert(id.clone()) {
            return; // already scanning this machine
        }
    }
    let _ = app.emit(EVENT, ());
    tauri::async_runtime::spawn(async move {
        let sem = app.state::<ScanSlots>().0.clone();
        let _permit = sem.acquire_owned().await;
        let id2 = id.clone();
        let result = tauri::async_runtime::spawn_blocking(move || {
            run_cli(&["hosts", "scan", &id2, "--json"], None, rules.as_deref())
        })
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r);

        match result {
            Ok(v) => {
                let results: Vec<ScanResult> = serde_json::from_value(v).unwrap_or_default();
                for a in results.iter().flat_map(|r| &r.alerts) {
                    let _ = app
                        .notification()
                        .builder()
                        .title(&a.title)
                        .body(a.body.lines().take(4).collect::<Vec<_>>().join("\n"))
                        .show();
                }
            }
            Err(e) => eprintln!("[bulwark] remote scan of {id} failed to run: {e}"),
        }
        app.state::<MachinesState>()
            .running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
        let _ = app.emit(EVENT, ());
        // Remote scans don't touch this machine's findings, but the Home page shows a machines
        // summary, so let every mounted view re-read.
        let _ = app.emit("monitoring:tick", ());
    });
}

pub struct ScanSlots(pub Arc<tokio::sync::Semaphore>);

impl Default for ScanSlots {
    fn default() -> Self {
        ScanSlots(Arc::new(tokio::sync::Semaphore::new(PARALLEL)))
    }
}

pub fn spawn_scheduler(app: AppHandle, rules: Option<PathBuf>) {
    tauri::async_runtime::spawn(async move {
        // Give the window a moment to come up before the first network activity.
        tokio::time::sleep(Duration::from_secs(10)).await;
        loop {
            if let Ok(mut store) = open() {
                maybe_send_daily_report(&mut store);
                if monitoring_enabled(&mut store) {
                    let now = chrono::Utc::now();
                    let due: Vec<String> = store
                        .list_remote_hosts()
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|h| h.is_due(now))
                        .map(|h| h.id)
                        .collect();
                    drop(store);
                    for id in due {
                        spawn_scan(app.clone(), id, rules.clone());
                    }
                }
            }
            tokio::time::sleep(TICK).await;
        }
    });
}

/// Once a day, when the user turned the daily summary on. The timestamp is written *before*
/// sending so a broken channel retries tomorrow rather than every 20 seconds (the failure itself is
/// recorded and shown on the settings page).
fn maybe_send_daily_report(store: &mut Store) {
    let Ok(cfg) = notify_config::load(store) else {
        return;
    };
    if !cfg.daily_report || !cfg.any_channel_enabled() {
        return;
    }
    let now = chrono::Utc::now();
    let last = store
        .get_setting(notify_config::KEY_LAST_REPORT)
        .ok()
        .flatten()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok());
    if last.is_some_and(|t| now.signed_duration_since(t) < chrono::Duration::hours(24)) {
        return;
    }
    let _ = store.set_setting(notify_config::KEY_LAST_REPORT, &now.to_rfc3339());
    std::thread::spawn(|| {
        if let Err(e) = run_cli(&["notify", "report", "--json"], None, None) {
            eprintln!("[bulwark] daily report failed: {e}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_config_aliases_are_suggested_and_patterns_skipped() {
        let cfg = "Host *\n  ServerAliveInterval 30\n\nHost web-1 web1\n  HostName 10.0.0.5\n  User deploy\n  Port 2222\n\nHost db-?\n  User x\nHost inner\n  ProxyJump me@bastion\nHost -oProxyCommand=x\n";
        let a = parse_ssh_config(cfg);
        let names: Vec<&str> = a.iter().map(|x| x.alias.as_str()).collect();
        assert_eq!(names, ["web-1", "web1", "inner"]);
        assert_eq!(a[0].hostname.as_deref(), Some("10.0.0.5"));
        assert_eq!(a[0].user.as_deref(), Some("deploy"));
        assert_eq!(a[0].port, Some(2222));
        assert_eq!(a[2].jump.as_deref(), Some("me@bastion"));
    }

    /// The desktop app's own remote path, end to end against a real OpenSSH server in Docker:
    /// registry writes through `bulwark_core` (as the Machines page does), then connection check,
    /// host-key approval, dedicated-key setup with a one-time password, scan and ignore — each
    /// through `run_cli`, the exact function the scheduler and the page call. The CLI-level twin is
    /// `bulwarkctl/tests/e2e.rs::remote_monitoring_over_real_ssh`; this proves the app's wiring
    /// (argument shapes, `--db-path` pinning, JSON parsing) on top of it.
    #[test]
    #[ignore = "needs Docker and a built CLI; cargo test -p bulwark-app -- --ignored app_remote"]
    fn app_remote_path_against_a_real_sshd() {
        use std::process::Command;
        let docker = |args: &[&str]| {
            std::process::Command::new("docker")
                .args(args)
                .output()
                .unwrap()
        };
        if !docker(&["info"]).status.success() {
            eprintln!("skipping: no Docker");
            return;
        }
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        assert!(docker(&[
            "build",
            "-q",
            "-t",
            "bulwark-e2e-remote-sshd",
            root.join("tests/e2e/remote-sshd").to_str().unwrap()
        ])
        .status
        .success());

        let tmp = tempfile::tempdir().unwrap();
        let keys = tmp.path().join("authorized");
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join("deploy"), "").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(keys.join("deploy"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        let name = format!("bulwark-app-e2e-{}", std::process::id());
        struct Rm(String);
        impl Drop for Rm {
            fn drop(&mut self) {
                let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
            }
        }
        let _rm = Rm(name.clone());
        let mount = format!("{}:/authorized_keys:ro", keys.display());
        assert!(docker(&[
            "run",
            "-d",
            "--name",
            &name,
            "-p",
            "127.0.0.1::22",
            "-v",
            &mount,
            "bulwark-e2e-remote-sshd"
        ])
        .status
        .success());
        let port_out = docker(&["port", &name, "22"]);
        let port: u16 = String::from_utf8_lossy(&port_out.stdout)
            .lines()
            .next()
            .and_then(|l| l.rsplit(':').next())
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        for _ in 0..50 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        // The app resolves its database from the environment, as in production.
        let db = tmp.path().join("state/bulwark.db");
        std::env::set_var("BULWARK_DB_PATH", &db);
        let host = Store::open(&db)
            .unwrap()
            .add_remote_host(&NewRemoteHost {
                name: Some("web-1".into()),
                spec: "deploy@127.0.0.1".into(),
                port: Some(port),
                identity_file: None,
                jump_host: None,
                privileged: false,
                interval_minutes: None,
            })
            .unwrap();

        // Connection check: refused host key, fingerprint offered.
        let r = run_cli(&["hosts", "test", &host.id, "--json"], None, None).unwrap();
        assert_eq!(r["steps"][1]["problem"]["kind"], "host_key_unknown", "{r}");
        let fp = r["host_keys"][0]["fingerprint"]
            .as_str()
            .unwrap()
            .to_string();

        // Approve it, then set up key access with the one-time password (via stdin, as the page does).
        run_cli(
            &["hosts", "trust", &host.id, "--fingerprint", &fp, "--json"],
            None,
            None,
        )
        .unwrap();
        let k = run_cli(
            &["hosts", "setup-key", &host.id, "--password-stdin", "--json"],
            Some("bulwark-e2e-only\n"),
            None,
        )
        .unwrap();
        assert_eq!(k["ok"], true, "{k}");

        // Scan, exactly as the scheduler does (rules dir for the copy-in path).
        let rules = root.join("rules");
        let res = run_cli(
            &["hosts", "scan", &host.id, "--json", "--no-notify"],
            None,
            Some(&rules),
        )
        .unwrap();
        assert_eq!(res[0]["ok"], true, "{res}");
        let views = fleet::list_views(&db).unwrap();
        assert!(
            views[0].counts.high >= 1,
            "password auth is on in the image"
        );
        assert!(views[0].checks_run.unwrap_or(0) > 20);

        // Ignore an issue type from the page's code path (core, per-machine database).
        let hdb = paths::remote_host_db_path(&db, &host.id);
        Store::open(&hdb)
            .unwrap()
            .suppress_rule("BLWK-SSH-001", "test: accepted for this run", "tester")
            .unwrap();
        let after = fleet::list_views(&db).unwrap();
        assert!(after[0].counts.suppressed >= 1);
        std::env::remove_var("BULWARK_DB_PATH");
    }
}
