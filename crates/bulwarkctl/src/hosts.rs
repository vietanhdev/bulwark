//! `bulwarkctl hosts …` — register remote machines and monitor them over SSH.
//!
//! The registry and its rules live in `bulwark_core::fleet` / `Store`; the transport is
//! [`crate::remote`]. This module is the front-door: argument handling, the connection checklist,
//! the scan-and-record loop, and output. The desktop app's "Remote machines" page drives exactly these
//! commands (with `--json`) through its bundled CLI, so the terminal and the GUI cannot drift into
//! two different notions of what a remote scan is.
//!
//! Headless monitoring is one line of cron or a systemd timer:
//!
//! ```text
//! */5 * * * *  bulwarkctl hosts scan --due --quiet
//! ```
//!
//! `--due` scans only the machines whose interval (with backoff for failing ones) has elapsed, so a
//! frequent timer costs nothing between scans.

use crate::remote::{self, RemoteTarget};
use anyhow::{Context, Result};
use bulwark_core::fleet::{
    self, AttemptOutcome, FindingCounts, HostHealth, NewRemoteHost, Problem, RemoteErrorKind,
    RemoteHost, RemoteHostPatch, RemoteHostView,
};
use bulwark_core::models::Severity;
use bulwark_core::{paths, Store};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum HostsAction {
    /// List registered machines with their status and open issues
    List {
        #[arg(long)]
        json: bool,
    },
    /// Register a machine to monitor. Nothing is installed on it; Bulwark connects over your
    /// existing SSH access on each scan.
    Add {
        /// `user@host`, a host name, or a Host alias from ~/.ssh/config
        target: String,
        /// Display name (defaults to the host part of the target)
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        /// Private key to sign in with (default: whatever ssh would use)
        #[arg(long, value_name = "KEYFILE")]
        identity: Option<String>,
        /// Reach the machine through a jump host (ProxyJump), e.g. `me@bastion`
        #[arg(long, value_name = "[USER@]HOST[:PORT]")]
        jump: Option<String>,
        /// Also run the root-only checks, via passwordless `sudo -n` on the machine
        #[arg(long)]
        privileged: bool,
        /// Minutes between scheduled scans (default 60)
        #[arg(long, value_name = "MINUTES")]
        interval: Option<u32>,
        #[arg(long)]
        json: bool,
    },
    /// Change a registered machine's settings
    Set {
        /// Machine name, id, or address
        host: String,
        #[arg(long)]
        name: Option<String>,
        /// New address
        #[arg(long)]
        target: Option<String>,
        #[arg(long, conflicts_with = "no_port")]
        port: Option<u16>,
        /// Go back to ssh's default port
        #[arg(long)]
        no_port: bool,
        #[arg(long, value_name = "KEYFILE", conflicts_with = "no_identity")]
        identity: Option<String>,
        /// Go back to ssh's default key selection
        #[arg(long)]
        no_identity: bool,
        #[arg(long, value_name = "[USER@]HOST[:PORT]", conflicts_with = "no_jump")]
        jump: Option<String>,
        /// Connect directly, without a jump host
        #[arg(long)]
        no_jump: bool,
        /// Run root-only checks (true/false)
        #[arg(long)]
        privileged: Option<bool>,
        /// Include in scheduled scans (true/false); a paused machine can still be scanned on demand
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long, value_name = "MINUTES")]
        interval: Option<u32>,
        /// The machine was renamed or rebuilt on purpose: forget its pinned hostname
        #[arg(long)]
        accept_identity: bool,
        #[arg(long)]
        json: bool,
    },
    /// Unregister a machine and delete its scan history
    Remove {
        host: String,
        /// Keep the machine's findings database on disk
        #[arg(long)]
        keep_history: bool,
        #[arg(long)]
        json: bool,
    },
    /// Check that a machine (registered or not) can be scanned, step by step, with the fix for
    /// whatever fails
    Test {
        /// Machine name/id, or any `user@host` / alias
        host: String,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long, value_name = "KEYFILE")]
        identity: Option<String>,
        #[arg(long, value_name = "[USER@]HOST[:PORT]")]
        jump: Option<String>,
        /// Also check that root checks would work (`sudo -n`)
        #[arg(long)]
        privileged: bool,
        #[arg(long)]
        json: bool,
    },
    /// Show a machine's SSH host key fingerprints, or trust one in Bulwark's own known_hosts
    /// (your ~/.ssh/known_hosts is never modified)
    Trust {
        host: String,
        #[arg(long)]
        port: Option<u16>,
        /// Trust the key with exactly this fingerprint (SHA256:…), after comparing it on the machine
        #[arg(long)]
        fingerprint: Option<String>,
        /// Replace the key Bulwark stored earlier — only after confirming the machine was reinstalled
        #[arg(long, requires = "fingerprint")]
        replace: bool,
        #[arg(long)]
        json: bool,
    },
    /// Create Bulwark's own monitoring key (ed25519, restricted: no forwarding, no terminal) and
    /// install it on a machine, signing in once with your usual SSH access or a password. The
    /// password is used for that one sign-in and never stored.
    SetupKey {
        host: String,
        /// Read a one-time password from stdin (for servers that only accept passwords today)
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        json: bool,
    },
    /// Scan registered machines now and record the results
    Scan {
        /// Machines to scan (name, id or address)
        hosts: Vec<String>,
        /// Every registered machine, including paused ones
        #[arg(long, conflicts_with = "due")]
        all: bool,
        /// Only enabled machines whose interval has elapsed — for cron / systemd timers
        #[arg(long)]
        due: bool,
        /// Print nothing unless something is new or failing (for cron mail)
        #[arg(long)]
        quiet: bool,
        /// Don't send Telegram/e-mail alerts (see `bulwarkctl notify`)
        #[arg(long)]
        no_notify: bool,
        #[arg(long)]
        json: bool,
    },
    /// Ignore an issue type on one machine (it keeps being checked; it's counted, not alerted).
    /// A reason is required and recorded in that machine's audit log.
    Ignore {
        host: String,
        /// Rule ID, e.g. BLWK-NET-005
        rule: String,
        #[arg(long)]
        reason: String,
        /// Only this one finding (its file, `port N on ADDR`, or title), not the whole type
        #[arg(long)]
        place: Option<String>,
    },
    /// Stop ignoring an issue type (or, with --place, one finding) on one machine
    Unignore {
        host: String,
        rule: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        place: Option<String>,
    },
    /// Show a machine's open issues from its last scans
    Show {
        host: String,
        #[arg(long)]
        json: bool,
    },
}

pub fn run(action: HostsAction, db: &Path, rules_dir: Option<PathBuf>) -> Result<i32> {
    match action {
        HostsAction::List { json } => list(db, json),
        HostsAction::Add {
            target,
            name,
            port,
            identity,
            jump,
            privileged,
            interval,
            json,
        } => {
            let mut store = Store::open(db)?;
            let h = store.add_remote_host(&NewRemoteHost {
                name,
                spec: target,
                port,
                identity_file: identity,
                jump_host: jump,
                privileged,
                interval_minutes: interval,
            })?;
            if json {
                print_json(&fleet::build_view(h, db, Utc::now()))?;
            } else {
                println!("Added {} ({}).", h.name, h.spec);
                println!(
                    "Next: `bulwarkctl hosts test {}` to check the connection, then \
                     `bulwarkctl hosts scan {}`.",
                    shell_word(&h.name),
                    shell_word(&h.name)
                );
            }
            Ok(0)
        }
        HostsAction::Set {
            host,
            name,
            target,
            port,
            no_port,
            identity,
            no_identity,
            jump,
            no_jump,
            privileged,
            enabled,
            interval,
            accept_identity,
            json,
        } => {
            let mut store = Store::open(db)?;
            let h = find(&mut store, &host)?;
            let patch = RemoteHostPatch {
                name,
                spec: target,
                port: if no_port { Some(None) } else { port.map(Some) },
                identity_file: if no_identity {
                    Some(None)
                } else {
                    identity.map(Some)
                },
                jump_host: if no_jump { Some(None) } else { jump.map(Some) },
                privileged,
                enabled,
                interval_minutes: interval,
                reset_identity: accept_identity,
            };
            let h = store.update_remote_host(&h.id, &patch)?;
            if json {
                print_json(&fleet::build_view(h, db, Utc::now()))?;
            } else {
                println!("Updated {}.", h.name);
            }
            Ok(0)
        }
        HostsAction::Remove {
            host,
            keep_history,
            json,
        } => {
            let mut store = Store::open(db)?;
            let h = find(&mut store, &host)?;
            store.delete_remote_host(&h.id)?;
            let hdb = paths::remote_host_db_path(db, &h.id);
            let mut deleted = false;
            if !keep_history && hdb.exists() {
                std::fs::remove_file(&hdb)
                    .with_context(|| format!("removing {}", hdb.display()))?;
                deleted = true;
            }
            if json {
                print_json(&serde_json::json!({ "removed": h.id, "history_deleted": deleted }))?;
            } else {
                println!(
                    "Removed {}{}.",
                    h.name,
                    if deleted { " and its history" } else { "" }
                );
            }
            Ok(0)
        }
        HostsAction::Test {
            host,
            port,
            identity,
            jump,
            privileged,
            json,
        } => {
            let report = test(db, &host, port, identity, jump, privileged)?;
            if json {
                print_json(&report)?;
            } else {
                print_test(&report);
            }
            Ok(if report.ok { 0 } else { 3 })
        }
        HostsAction::Trust {
            host,
            port,
            fingerprint,
            replace,
            json,
        } => trust(db, &host, port, fingerprint, replace, json),
        HostsAction::Scan {
            hosts,
            all,
            due,
            quiet,
            no_notify,
            json,
        } => scan(
            db,
            rules_dir,
            ScanSelection {
                keys: hosts,
                all,
                due,
                quiet,
                no_notify,
                json,
            },
        ),
        HostsAction::Show { host, json } => show(db, &host, json),
        HostsAction::Ignore {
            host,
            rule,
            reason,
            place,
        } => {
            let h = find(&mut Store::open(db)?, &host)?;
            let mut store = Store::open(&paths::remote_host_db_path(db, &h.id))?;
            match place {
                Some(p) => {
                    store.ignore_finding(&rule, &p, &reason, &crate::current_actor())?;
                    println!("Ignoring {rule} at {p} on {}.", h.name);
                }
                None => {
                    store.suppress_rule(&rule, &reason, &crate::current_actor())?;
                    println!("Ignoring {rule} on {}.", h.name);
                }
            }
            Ok(0)
        }
        HostsAction::Unignore {
            host,
            rule,
            reason,
            place,
        } => {
            let h = find(&mut Store::open(db)?, &host)?;
            let mut store = Store::open(&paths::remote_host_db_path(db, &h.id))?;
            match place {
                Some(p) => {
                    store.unignore_finding(&rule, &p, &reason, &crate::current_actor())?;
                    println!("No longer ignoring {rule} at {p} on {}.", h.name);
                }
                None => {
                    store.unsuppress_rule(&rule, &reason, &crate::current_actor())?;
                    println!("No longer ignoring {rule} on {}.", h.name);
                }
            }
            Ok(0)
        }
        HostsAction::SetupKey {
            host,
            password_stdin,
            json,
        } => setup_key(db, &host, password_stdin, json),
    }
}

fn find(store: &mut Store, key: &str) -> Result<RemoteHost> {
    store.find_remote_host(key)?.ok_or_else(|| {
        anyhow::anyhow!("no registered machine called \"{key}\" — see `bulwarkctl hosts list`")
    })
}

fn print_json<T: Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

/// Quote a word for display in a suggested command, only when it needs it.
fn shell_word(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_.@:".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

// ---- list / show --------------------------------------------------------------------------------

fn health_label(h: HostHealth) -> &'static str {
    match h {
        HostHealth::New => "not scanned yet",
        HostHealth::NeedsAttention => "needs attention",
        HostHealth::Unsupported => "not supported yet",
        HostHealth::Unreachable => "unreachable",
        HostHealth::Stale => "out of date",
        HostHealth::AtRisk => "at risk",
        HostHealth::Issues => "issues",
        HostHealth::Healthy => "healthy",
    }
}

fn ago(t: Option<DateTime<Utc>>) -> String {
    let Some(t) = t else {
        return "never".into();
    };
    let s = (Utc::now() - t).num_seconds();
    match s {
        s if s < 0 => "just now".into(),
        s if s < 60 => "just now".into(),
        s if s < 3600 => format!("{} min ago", s / 60),
        s if s < 86_400 => format!("{} h ago", s / 3600),
        s => format!("{} d ago", s / 86_400),
    }
}

fn until(t: Option<DateTime<Utc>>) -> String {
    let Some(t) = t else {
        return "paused".into();
    };
    let s = (t - Utc::now()).num_seconds();
    match s {
        s if s <= 0 => "due now".into(),
        s if s < 3600 => format!("in {} min", s / 60 + 1),
        s if s < 86_400 => format!("in {} h", s / 3600),
        s => format!("in {} d", s / 86_400),
    }
}

fn counts_label(c: &FindingCounts) -> String {
    if c.total() == 0 {
        return "-".into();
    }
    let mut parts = Vec::new();
    for (n, l) in [
        (c.critical, "critical"),
        (c.high, "high"),
        (c.medium, "medium"),
        (c.low, "low"),
    ] {
        if n > 0 {
            parts.push(format!("{n} {l}"));
        }
    }
    if parts.is_empty() {
        format!("{} info", c.info)
    } else {
        parts.join(", ")
    }
}

fn list(db: &Path, json: bool) -> Result<i32> {
    let views = fleet::list_views(db)?;
    if json {
        print_json(&views)?;
        return Ok(0);
    }
    if views.is_empty() {
        println!("No machines registered. Add one with `bulwarkctl hosts add user@host`.");
        return Ok(0);
    }
    println!(
        "{:<20} {:<16} {:<26} {:<12} {:<10} TARGET",
        "NAME", "STATUS", "OPEN ISSUES", "LAST SCAN", "NEXT"
    );
    for v in &views {
        println!(
            "{:<20} {:<16} {:<26} {:<12} {:<10} {}",
            truncate(&v.host.name, 20),
            health_label(v.health),
            counts_label(&v.counts),
            ago(v.host.last_success_at),
            until(v.next_due_at),
            match v.host.port {
                Some(p) => format!("{} (port {p})", v.host.spec),
                None => v.host.spec.clone(),
            }
        );
        if let Some(p) = &v.problem {
            println!("    └ {}. {}", p.title, p.hint);
        }
    }
    Ok(0)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}

#[derive(Serialize)]
struct ShowOutput {
    machine: RemoteHostView,
    findings: Vec<bulwark_core::Finding>,
    suppressed: Vec<bulwark_core::Finding>,
}

fn show(db: &Path, key: &str, json: bool) -> Result<i32> {
    let mut store = Store::open(db)?;
    let h = find(&mut store, key)?;
    let hdb = paths::remote_host_db_path(db, &h.id);
    let (active, suppressed) = if hdb.exists() {
        let split = Store::open(&hdb)?.open_findings_split()?;
        (split.active, split.suppressed)
    } else {
        (Vec::new(), Vec::new())
    };
    let view = fleet::build_view(h, db, Utc::now());
    if json {
        print_json(&ShowOutput {
            machine: view,
            findings: active,
            suppressed,
        })?;
        return Ok(0);
    }
    println!(
        "{} — {} (last scan {})",
        view.host.name,
        health_label(view.health),
        ago(view.host.last_success_at)
    );
    if let Some(p) = &view.problem {
        println!("  {}. {}", p.title, p.hint);
    }
    let mut active = active;
    active.sort_by_key(|b| std::cmp::Reverse(b.severity));
    for f in &active {
        println!(
            "  [{:?}] {} ({})",
            f.severity,
            crate::term_safe(&f.title),
            f.rule_id
        );
    }
    if active.is_empty() && view.host.last_success_at.is_some() {
        println!("  No open issues.");
    }
    if !suppressed.is_empty() {
        println!(
            "  ({} ignored issue(s) not listed — `bulwarkctl hosts unignore` to restore)",
            suppressed.len()
        );
    }
    Ok(0)
}

// ---- test ---------------------------------------------------------------------------------------

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Ok,
    Warn,
    Fail,
    Skipped,
}

#[derive(Serialize, Debug)]
pub struct CheckStep {
    pub id: &'static str,
    pub label: &'static str,
    pub status: StepStatus,
    pub detail: String,
    pub problem: Option<Problem>,
}

#[derive(Serialize, Debug)]
pub struct HostKeyView {
    pub key_type: String,
    pub fingerprint: String,
}

#[derive(Serialize, Debug)]
pub struct TestReport {
    pub target: String,
    pub ssh_command: String,
    pub ok: bool,
    pub steps: Vec<CheckStep>,
    /// Offered when the host key isn't trusted yet, so the user can compare and approve one.
    pub host_keys: Vec<HostKeyView>,
    /// How to read the fingerprint on the machine itself, for that comparison.
    pub verify_command: Option<String>,
    /// The offered keys replace a *different* key on record — approving needs `--replace`, and
    /// should only follow a confirmed reinstall.
    pub host_key_changed: bool,
    /// What to call the machine in suggested commands (its name when registered).
    pub host_ref: String,
    pub os: Option<String>,
    pub install_command: Option<String>,
    /// How the connection measures up against good practice, once it works. Flexible on what is
    /// accepted, explicit about what would be better — each item says why and how.
    pub advice: Vec<Advice>,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum AdviceLevel {
    Good,
    Suggest,
    Warn,
}

#[derive(Serialize, Debug)]
pub struct Advice {
    pub id: &'static str,
    pub level: AdviceLevel,
    pub title: String,
    pub detail: String,
    /// A command that applies the recommendation, when there is one.
    pub command: Option<String>,
}

fn advice(
    id: &'static str,
    level: AdviceLevel,
    title: &str,
    detail: &str,
    command: Option<String>,
) -> Advice {
    Advice {
        id,
        level,
        title: title.into(),
        detail: detail.into(),
        command,
    }
}

fn step(
    id: &'static str,
    label: &'static str,
    status: StepStatus,
    detail: impl Into<String>,
) -> CheckStep {
    CheckStep {
        id,
        label,
        status,
        detail: detail.into(),
        problem: None,
    }
}

fn failed(
    id: &'static str,
    label: &'static str,
    kind: RemoteErrorKind,
    ssh: &str,
    detail: String,
) -> CheckStep {
    CheckStep {
        id,
        label,
        status: StepStatus::Fail,
        detail: detail.clone(),
        problem: Some(Problem::new(kind, ssh, Some(detail))),
    }
}

/// Resolve a `hosts` argument to a target: a registered machine if one matches, otherwise an
/// ad-hoc address (unattended, so the check reflects what scheduled scans will experience).
fn target_for(
    db: &Path,
    key: &str,
    port: Option<u16>,
    identity: Option<String>,
    jump: Option<String>,
) -> Result<(RemoteTarget, Option<RemoteHost>)> {
    let kh = paths::known_hosts_path(db);
    let registered = if db.exists() {
        Store::open(db)?.find_remote_host(key)?
    } else {
        None
    };
    if let Some(h) = registered {
        let mut t = RemoteTarget::for_host(&h, &kh);
        if port.is_some() {
            t.port = port;
        }
        if let Some(i) = identity {
            t.identity = Some(PathBuf::from(fleet::expand_tilde(&i)));
        }
        if jump.is_some() {
            t.jump = jump;
        }
        return Ok((t, Some(h)));
    }
    let t = RemoteTarget {
        spec: key.trim().to_string(),
        port,
        identity: identity.map(|i| PathBuf::from(fleet::expand_tilde(&i))),
        ssh_opts: Vec::new(),
        jump: jump.filter(|j| !j.trim().is_empty()),
        unattended: true,
        known_hosts: Some(kh),
    };
    Ok((t, None))
}

pub fn test(
    db: &Path,
    key: &str,
    port: Option<u16>,
    identity: Option<String>,
    jump: Option<String>,
    privileged_flag: bool,
) -> Result<TestReport> {
    let (target, registered) = target_for(db, key, port, identity, jump)?;
    let privileged = privileged_flag || registered.as_ref().is_some_and(|h| h.privileged);
    let ssh = target.ssh_command_line();
    let mut report = TestReport {
        target: target.spec.clone(),
        ssh_command: ssh.clone(),
        ok: false,
        steps: Vec::new(),
        host_keys: Vec::new(),
        verify_command: None,
        host_key_changed: false,
        host_ref: registered
            .as_ref()
            .map(|h| h.name.clone())
            .unwrap_or_else(|| target.spec.clone()),
        os: None,
        install_command: None,
        advice: Vec::new(),
    };
    const ADDR: &str = "Address";
    const CONNECT: &str = "Connect and sign in";
    const ENGINE: &str = "Scanner on the machine";
    const ROOT: &str = "Root checks";

    let skip_rest = |report: &mut TestReport, from: usize| {
        let all = [("connect", CONNECT), ("engine", ENGINE), ("root", ROOT)];
        for (id, label) in &all[from..] {
            report.steps.push(step(
                id,
                label,
                StepStatus::Skipped,
                "Waiting for the step above",
            ));
        }
    };

    // 1. Address and effective SSH settings.
    match remote::resolve_config(&target) {
        Ok(cfg) => {
            let mut d = format!("{}@{} port {}", cfg.user, cfg.hostname, cfg.port);
            if cfg.proxied {
                d.push_str(", through a jump host");
            }
            report.steps.push(step("address", ADDR, StepStatus::Ok, d));
        }
        Err(e) => {
            report.steps.push(failed(
                "address",
                ADDR,
                remote::kind_of(&e),
                &ssh,
                remote::message_of(&e),
            ));
            skip_rest(&mut report, 0);
            return Ok(report);
        }
    }

    // 2. Connect, authenticate, learn about the machine.
    let probe = match remote::probe(&target, privileged) {
        Ok(p) => {
            report.steps.push(step(
                "connect",
                CONNECT,
                StepStatus::Ok,
                if p.os_pretty.is_empty() {
                    format!("Signed in ({})", p.arch)
                } else {
                    format!("Signed in — {} ({})", p.os_pretty, p.arch)
                },
            ));
            p
        }
        Err(e) => {
            let kind = remote::kind_of(&e);
            report.steps.push(failed(
                "connect",
                CONNECT,
                kind,
                &ssh,
                remote::message_of(&e),
            ));
            if matches!(
                kind,
                RemoteErrorKind::HostKeyUnknown | RemoteErrorKind::HostKeyChanged
            ) {
                report.host_key_changed = kind == RemoteErrorKind::HostKeyChanged;
                if let Ok(keys) = remote::fetch_host_keys(&target) {
                    report.verify_command = keys.first().map(|k| {
                        format!(
                            "ssh-keygen -lf /etc/ssh/ssh_host_{}_key.pub",
                            k.key_type.to_lowercase()
                        )
                    });
                    report.host_keys = keys
                        .into_iter()
                        .map(|k| HostKeyView {
                            key_type: k.key_type,
                            fingerprint: k.fingerprint,
                        })
                        .collect();
                }
            }
            skip_rest(&mut report, 1);
            return Ok(report);
        }
    };
    let (os_kind, os_name) = probe.os();
    report.os = Some(os_name.clone());
    if let Some(h) = &registered {
        if let Ok(mut st) = Store::open(db) {
            let _ = st.set_remote_os(&h.id, &os_kind, &os_name);
        }
    }

    // 3. Engine: installed, or copyable.
    let ours = env!("CARGO_PKG_VERSION");
    match (&probe.bin, &probe.version) {
        (Some(bin), Some(v)) if v == ours => report.steps.push(step(
            "engine",
            ENGINE,
            StepStatus::Ok,
            format!("Bulwark {v} is installed ({bin})"),
        )),
        (Some(bin), Some(v)) => report.steps.push(step(
            "engine",
            ENGINE,
            StepStatus::Warn,
            format!(
                "Bulwark {v} is installed ({bin}); this computer has {ours}. Scans use the \
                 machine's own version and checks — update it there to match."
            ),
        )),
        _ => {
            report.install_command = Some(probe.install_hint());
            match remote::push_blocker(&probe) {
                None => report.steps.push(step(
                    "engine",
                    ENGINE,
                    StepStatus::Ok,
                    "Not installed — Bulwark copies itself over for each scan and removes it \
                     afterwards. Installing it there makes scans faster.",
                )),
                Some((kind, why)) => report.steps.push(failed("engine", ENGINE, kind, &ssh, why)),
            }
        }
    }

    // 4. Root checks.
    if probe.is_windows() {
        report.steps.push(step(
            "root",
            ROOT,
            StepStatus::Skipped,
            "Not on Windows yet — settings that need administrator rights are reported as unknown, \
             never as passing",
        ));
    } else if privileged {
        if probe.sudo_ok == Some(true) {
            report.steps.push(step(
                "root",
                ROOT,
                StepStatus::Ok,
                "Passwordless sudo works — root-only checks will run",
            ));
        } else {
            report.steps.push(failed(
                "root",
                ROOT,
                RemoteErrorKind::SudoRequiresPassword,
                &ssh,
                "`sudo -n` needs a password there".into(),
            ));
        }
    } else {
        report.steps.push(step(
            "root",
            ROOT,
            StepStatus::Skipped,
            "Off — checks that need root (e.g. sudoers, shadow) are skipped",
        ));
    }

    report.ok = report.steps.iter().all(|s| s.status != StepStatus::Fail);
    report.advice = connection_advice(
        db,
        &target,
        registered.as_ref(),
        &probe,
        privileged,
        &report,
    );
    Ok(report)
}

/// Good practice for an unattended monitoring connection, checked against what the probe saw. The
/// stance: accept any working setup, say plainly what would make it safer, and make the safer
/// option one command (or one click) away.
fn connection_advice(
    db: &Path,
    target: &RemoteTarget,
    registered: Option<&RemoteHost>,
    probe: &remote::Probe,
    privileged: bool,
    report: &TestReport,
) -> Vec<Advice> {
    use AdviceLevel::*;
    let name = shell_word(&report.host_ref);
    let mut out = vec![advice(
        "host_key",
        Good,
        "Host key verified",
        "Bulwark refuses to connect if the machine's identity key ever changes, so a scan can't be \
         silently redirected to another machine.",
        None,
    )];

    let dedicated = paths::monitoring_key_path(db);
    let uses_dedicated = target
        .identity
        .as_deref()
        .is_some_and(|i| i == dedicated.as_path());
    if uses_dedicated {
        out.push(advice(
            "key",
            Good,
            "Signs in with Bulwark's own restricted key",
            "The key can run the scan but can't forward ports, reach your SSH agent or open a \
             terminal, and you can revoke it on its own by deleting its line from the machine's \
             authorized_keys.",
            None,
        ));
    } else if !probe.is_windows() {
        // Not offered for Windows: `setup-key` can't install keys there yet (see remote::install_key).
        out.push(advice(
            "key",
            Suggest,
            "Use a dedicated key for monitoring",
            "Your own key works. A separate key, restricted to running commands, limits what a \
             stolen copy could do and can be revoked without touching your personal access.",
            registered.map(|_| format!("bulwarkctl hosts setup-key {name}")),
        ));
    }

    if probe.user == "root" {
        out.push(advice(
            "root_login",
            Warn,
            "Signs in as root",
            "Use a regular account instead. If you want root-only checks, turn them on with a sudo \
             rule that allows only the scanner.",
            None,
        ));
    }

    if privileged && probe.sudo_ok == Some(true) {
        if probe.sudo_blanket {
            out.push(advice(
                "sudo",
                Warn,
                "sudo allows every command without a password",
                "Root checks only need the scanner. Narrow the rule so this account can run \
                 nothing else as root without a password.",
                Some(format!(
                    // Exactly the command a root scan runs — never a wildcard: `scan *` would also
                    // allow `scan --ssh x --ssh-opt ProxyCommand=…`, a root shell for anyone who
                    // holds the monitoring key.
                    "echo '{} ALL=(root) NOPASSWD: /usr/bin/bulwarkctl {}' | sudo tee \
                     /etc/sudoers.d/bulwark && sudo chmod 440 /etc/sudoers.d/bulwark",
                    if probe.user.is_empty() {
                        "<user>"
                    } else {
                        &probe.user
                    },
                    remote::SCOPED_SUDO_ARGS
                )),
            ));
        } else {
            out.push(advice(
                "sudo",
                Good,
                "sudo is limited to the scanner",
                "Root checks run without a password, and that is all this account may run as root.",
                None,
            ));
        }
    }

    if probe.bin.is_none() && remote::push_blocker(probe).is_none() {
        out.push(advice(
            "install",
            Suggest,
            "Install Bulwark on the machine",
            "Scans then run a package-managed binary from /usr/bin instead of copying one into \
             /tmp each time — faster, updated with the system, and the only way to limit sudo to \
             just the scanner.",
            Some(probe.install_hint()),
        ));
    }
    out
}

fn print_test(r: &TestReport) {
    print_test_steps(r);
    if !r.advice.is_empty() {
        println!("\n  Connection security:");
        for a in &r.advice {
            let mark = match a.level {
                AdviceLevel::Good => "✓",
                AdviceLevel::Suggest => "→",
                AdviceLevel::Warn => "!",
            };
            println!("    {mark} {}", a.title);
            if a.level != AdviceLevel::Good {
                println!("      {}", a.detail);
                if let Some(c) = &a.command {
                    println!("      $ {c}");
                }
            }
        }
    }
    println!(
        "\n{}",
        if r.ok {
            "Ready to scan."
        } else {
            "Not ready yet — fix the step marked ✗ and run this again."
        }
    );
}

fn print_test_steps(r: &TestReport) {
    println!("Checking {} …\n", r.target);
    for s in &r.steps {
        let mark = match s.status {
            StepStatus::Ok => "✓",
            StepStatus::Warn => "!",
            StepStatus::Fail => "✗",
            StepStatus::Skipped => "·",
        };
        println!("  {mark} {:<24} {}", s.label, crate::term_safe(&s.detail));
        if let Some(p) = &s.problem {
            println!("      {}.", p.title);
            println!("      {}", p.hint);
        }
    }
    if !r.host_keys.is_empty() {
        println!("\n  The machine offers these host keys:");
        for k in &r.host_keys {
            println!("    {:<8} {}", k.key_type, k.fingerprint);
        }
        if let Some(v) = &r.verify_command {
            println!("\n  Compare with the output of `{v}` run on the machine itself, then:");
        }
        if let Some(k) = r.host_keys.first() {
            if r.host_key_changed {
                println!(
                    "  Only if the machine was reinstalled and you confirmed this key with whoever \
                     manages it:"
                );
            }
            println!(
                "    bulwarkctl hosts trust {} --fingerprint {}{}",
                shell_word(&r.host_ref),
                k.fingerprint,
                if r.host_key_changed { " --replace" } else { "" }
            );
        }
    }
    if let Some(cmd) = &r.install_command {
        if r.advice.is_empty() {
            println!("\n  To install Bulwark there: {cmd}");
        }
    }
}

// ---- trust --------------------------------------------------------------------------------------

#[derive(Serialize)]
struct TrustOutput {
    trusted: Option<HostKeyView>,
    host_keys: Vec<HostKeyView>,
    known_hosts: String,
}

fn trust(
    db: &Path,
    key: &str,
    port: Option<u16>,
    fingerprint: Option<String>,
    replace: bool,
    json: bool,
) -> Result<i32> {
    let (target, _) = target_for(db, key, port, None, None)?;
    let kh = paths::known_hosts_path(db);
    match fingerprint {
        Some(fp) => {
            let k = remote::trust(&target, &kh, &fp, replace)?;
            if json {
                print_json(&TrustOutput {
                    trusted: Some(HostKeyView {
                        key_type: k.key_type,
                        fingerprint: k.fingerprint,
                    }),
                    host_keys: Vec::new(),
                    known_hosts: kh.display().to_string(),
                })?;
            } else {
                println!(
                    "Trusted {}'s {} key {} (stored in {}).",
                    target.spec,
                    k.key_type,
                    k.fingerprint,
                    kh.display()
                );
            }
        }
        None => {
            let keys = remote::fetch_host_keys(&target)?;
            let views: Vec<HostKeyView> = keys
                .into_iter()
                .map(|k| HostKeyView {
                    key_type: k.key_type,
                    fingerprint: k.fingerprint,
                })
                .collect();
            if json {
                print_json(&TrustOutput {
                    trusted: None,
                    host_keys: views,
                    known_hosts: kh.display().to_string(),
                })?;
            } else {
                println!("{} offers:", target.spec);
                for k in &views {
                    println!("  {:<8} {}", k.key_type, k.fingerprint);
                }
                println!(
                    "\nCompare one with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` run on \
                     the machine, then re-run with --fingerprint <SHA256:…>."
                );
            }
        }
    }
    Ok(0)
}

// ---- setup-key ----------------------------------------------------------------------------------

#[derive(Serialize)]
struct SetupKeyOutput {
    ok: bool,
    identity_file: String,
    public_key: String,
    machine: RemoteHostView,
}

fn setup_key(db: &Path, key: &str, password_stdin: bool, json: bool) -> Result<i32> {
    let mut store = Store::open(db)?;
    let h = find(&mut store, key)?;
    let password = if password_stdin {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let pw = line.trim_end_matches(['\n', '\r']).to_string();
        if pw.is_empty() {
            anyhow::bail!("no password on stdin");
        }
        Some(pw)
    } else {
        None
    };

    let key_path = paths::monitoring_key_path(db);
    let pub_line = remote::ensure_dedicated_key(&key_path)?;

    // Sign in the way that works today — the user's own key/agent, a terminal prompt, or the
    // one-time password — just once, to install the dedicated key.
    let kh = paths::known_hosts_path(db);
    let mut target = RemoteTarget::for_host(&h, &kh);
    target.unattended = password.is_some() || json;
    if password.is_some() {
        target.identity = None;
    }
    if !json {
        eprintln!("Installing Bulwark's monitoring key on {} …", h.name);
    }
    remote::install_key(&target, &pub_line, password.as_deref()).map_err(|e| {
        if password.is_some() && remote::kind_of(&e) == RemoteErrorKind::AuthFailed {
            anyhow::anyhow!(
                "The machine didn't accept that password (or doesn't allow password sign-in). \
                 Nothing was changed."
            )
        } else {
            e
        }
    })?;

    // Switch the machine over to the new key, then prove it works on its own.
    let key_str = key_path.display().to_string();
    let updated = store.update_remote_host(
        &h.id,
        &RemoteHostPatch {
            identity_file: Some(Some(key_str.clone())),
            ..Default::default()
        },
    )?;
    let verify = remote::probe(&RemoteTarget::for_host(&updated, &kh), false);
    let ok = verify.is_ok();
    if !ok {
        // Leave the machine on the access that worked before rather than on a key that doesn't.
        store.update_remote_host(
            &h.id,
            &RemoteHostPatch {
                identity_file: Some(h.identity_file.clone()),
                ..Default::default()
            },
        )?;
    }
    let machine = fleet::build_view(
        store.find_remote_host(&h.id)?.unwrap_or(updated),
        db,
        Utc::now(),
    );
    if json {
        print_json(&SetupKeyOutput {
            ok,
            identity_file: key_str,
            public_key: pub_line,
            machine,
        })?;
    } else if ok {
        println!(
            "Done. {} now signs in with Bulwark's own restricted key ({key_str}).",
            h.name
        );
        println!("To revoke it later, delete the line ending in \"bulwark-monitoring@…\" from ~/.ssh/authorized_keys on the machine.");
    } else if let Err(e) = verify {
        println!(
            "The key was added, but signing in with it failed ({e:#}). {} keeps using its previous \
             access.",
            h.name
        );
    }
    Ok(if ok { 0 } else { 3 })
}

// ---- scan ---------------------------------------------------------------------------------------

#[derive(Serialize, Debug)]
pub struct NewFindingBrief {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
}

#[derive(Serialize)]
pub struct HostScanResult {
    pub ok: bool,
    /// What, if anything, is worth interrupting someone about (see `fleet::alerts_for_attempt`).
    pub alerts: Vec<fleet::Alert>,
    pub new_findings: Vec<NewFindingBrief>,
    /// Failures in a row *before* this attempt — lets a caller say "back online".
    pub previous_failures: u32,
    pub machine: RemoteHostView,
}

/// Scan one registered machine, persist into its own database, and record the attempt.
pub fn scan_host(
    db: &Path,
    host: &RemoteHost,
    rules_dir: &Path,
    local_binary: &Path,
) -> Result<HostScanResult> {
    let kh = paths::known_hosts_path(db);
    let target = RemoteTarget::for_host(host, &kh);
    let at = Utc::now();
    let mut new_findings = Vec::new();

    let outcome =
        match remote::run_remote_scan(&target, host.privileged, &[], local_binary, rules_dir) {
            Ok(rs) => {
                let (os_kind, os_name) = rs.probe.os();
                if let Ok(mut st) = Store::open(db) {
                    let _ = st.set_remote_os(&host.id, &os_kind, &os_name);
                }
                let hostname = fleet::hostname_of_fingerprint(&rs.scan.host_fingerprint);
                if rs.scan.rules_loaded > 0 && rs.scan.rules_evaluated.is_empty() {
                    // It ran, and nothing could be checked. Recorded as "nothing for this system yet",
                    // never persisted as a clean scan — an empty findings list from a scan that looked
                    // at nothing is the absence of an opinion.
                    AttemptOutcome::Failure {
                        kind: RemoteErrorKind::NothingAssessed,
                        message: format!(
                            "{} check(s) loaded for this system, none could run there yet",
                            rs.scan.rules_loaded
                        ),
                    }
                } else if rs.scan.rules_loaded == 0 {
                    // Same invariant as a local scan: zero rules examined nothing. Never persisted —
                    // reconciliation would mark every open issue on the machine as resolved.
                    AttemptOutcome::Failure {
                        kind: RemoteErrorKind::NoRules,
                        message: "the scan on the machine loaded 0 rules".into(),
                    }
                } else if let Some((expected, hostname)) =
                    fleet::identity_mismatch(host, &rs.scan.host_fingerprint)
                {
                    AttemptOutcome::Failure {
                        kind: RemoteErrorKind::IdentityChanged,
                        message: format!(
                            "{} used to answer as \"{expected}\" and now answers as \"{hostname}\"",
                            host.spec
                        ),
                    }
                } else {
                    // Saving can fail (a locked or damaged per-machine database). That is recorded
                    // as this machine's failed attempt — never allowed to abort the run, which would
                    // leave the attempt unrecorded and the scheduler re-scanning it every tick.
                    let hdb = paths::remote_host_db_path(db, &host.id);
                    let saved = Store::open(&hdb).and_then(|mut store| {
                        let fresh = store.persist_and_reconcile(&rs.scan)?;
                        // Ignored issues and turned-off checks don't alert, here or anywhere.
                        let ignores = store.ignores()?;
                        Ok(fresh
                            .into_iter()
                            .filter(|f| !ignores.covers(f))
                            .collect::<Vec<_>>())
                    });
                    match saved {
                        Ok(fresh) => {
                            new_findings = fresh
                                .into_iter()
                                .map(|f| NewFindingBrief {
                                    rule_id: f.rule_id,
                                    title: f.title,
                                    severity: f.severity,
                                })
                                .collect();
                            AttemptOutcome::Success {
                                hostname,
                                engine: rs.engine.describe(),
                            }
                        }
                        Err(e) => AttemptOutcome::Failure {
                            kind: RemoteErrorKind::LocalStorage,
                            message: format!(
                                "the scan ran but its results couldn't be saved: {e:#}"
                            ),
                        },
                    }
                }
            }
            Err(e) => {
                let kind = remote::kind_of(&e);
                if kind == RemoteErrorKind::UnsupportedOs {
                    if let Ok(mut st) = Store::open(db) {
                        let _ = st.set_remote_os(&host.id, "windows", "Windows");
                    }
                }
                AttemptOutcome::Failure {
                    kind,
                    message: remote::message_of(&e),
                }
            }
        };
    let ok = matches!(outcome, AttemptOutcome::Success { .. });
    let updated = Store::open(db)?.record_remote_attempt(&host.id, at, &outcome)?;
    let briefs: Vec<(Severity, String)> = new_findings
        .iter()
        .map(|f| (f.severity, f.title.clone()))
        .collect();
    let alerts = fleet::alerts_for_attempt(host, &updated, &briefs);
    Ok(HostScanResult {
        ok,
        alerts,
        new_findings,
        previous_failures: host.consecutive_failures,
        machine: fleet::build_view(updated, db, Utc::now()),
    })
}

/// How many machines are scanned at once. Each is mostly waiting on the network.
const PARALLEL_SCANS: usize = 4;

/// What `hosts scan` was asked to do.
struct ScanSelection {
    keys: Vec<String>,
    all: bool,
    due: bool,
    quiet: bool,
    no_notify: bool,
    json: bool,
}

fn scan(db: &Path, rules_dir: Option<PathBuf>, sel: ScanSelection) -> Result<i32> {
    let ScanSelection {
        keys,
        all,
        due,
        quiet,
        no_notify,
        json,
    } = sel;
    let mut store = Store::open(db)?;
    let registered = store.list_remote_hosts()?;
    drop(store);
    let now = Utc::now();
    let targets: Vec<RemoteHost> = if all {
        registered
    } else if due {
        registered.into_iter().filter(|h| h.is_due(now)).collect()
    } else if keys.is_empty() {
        anyhow::bail!("name the machines to scan, or pass --all or --due");
    } else {
        let mut store = Store::open(db)?;
        keys.iter()
            .map(|k| find(&mut store, k))
            .collect::<Result<Vec<_>>>()?
    };

    // Only needed if a machine lacks Bulwark and we copy ourselves there; a missing local pack
    // must not stop machines that have their own.
    let rules_dir = crate::resolve_rules_dir(rules_dir).unwrap_or_default();
    let local_binary = std::env::current_exe().context("cannot locate this bulwarkctl binary")?;

    let mut results: Vec<HostScanResult> = Vec::new();
    let mut run_errors = 0usize;
    for chunk in targets.chunks(PARALLEL_SCANS) {
        let chunk_results: Vec<Result<HostScanResult>> = std::thread::scope(|s| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|h| {
                    if !json && !quiet {
                        eprintln!("Scanning {} …", h.name);
                    }
                    let (rules_dir, local_binary) = (&rules_dir, &local_binary);
                    s.spawn(move || scan_host(db, h, rules_dir, local_binary))
                })
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join()
                        .unwrap_or_else(|_| Err(anyhow::anyhow!("scan thread panicked")))
                })
                .collect()
        });
        // One machine's error (its database, say) is reported and the run goes on: the other
        // machines still get scanned, saved and alerted on.
        for (r, h) in chunk_results.into_iter().zip(chunk) {
            match r {
                Ok(v) => results.push(v),
                Err(e) => {
                    run_errors += 1;
                    eprintln!("error: {}: {e:#}", h.name);
                }
            }
        }
    }

    // Nothing came back at all (the app scans one machine per call): report the error itself, so a
    // caller reading `--json` doesn't mistake an empty list for "nothing to do".
    if results.is_empty() && run_errors > 0 {
        anyhow::bail!("{run_errors} machine(s) couldn't be scanned — see the errors above");
    }

    if !no_notify {
        let alerts: Vec<fleet::Alert> = results.iter().flat_map(|r| r.alerts.clone()).collect();
        if !alerts.is_empty() {
            for r in crate::notify::deliver(db, &alerts) {
                if let Some(e) = r.error {
                    eprintln!("warning: couldn't send the {} alert: {e}", r.channel);
                }
            }
        }
    }

    let any_failed = run_errors > 0 || results.iter().any(|r| !r.ok);
    let worst = results
        .iter()
        .filter(|r| r.ok)
        .filter_map(|r| {
            let c = &r.machine.counts;
            if c.critical > 0 {
                Some(Severity::Critical)
            } else if c.high > 0 {
                Some(Severity::High)
            } else if c.medium > 0 {
                Some(Severity::Medium)
            } else {
                None
            }
        })
        .max();

    if json {
        print_json(&results)?;
    } else {
        for r in &results {
            let m = &r.machine;
            if quiet && r.ok && r.new_findings.is_empty() {
                continue;
            }
            if r.ok {
                println!(
                    "{}: {} — {} open{}",
                    m.host.name,
                    health_label(m.health),
                    m.counts.total(),
                    if r.new_findings.is_empty() {
                        String::new()
                    } else {
                        format!(", {} new", r.new_findings.len())
                    }
                );
                for f in &r.new_findings {
                    println!(
                        "    new: [{:?}] {} ({})",
                        f.severity,
                        crate::term_safe(&f.title),
                        f.rule_id
                    );
                }
            } else if let Some(p) = &m.problem {
                println!("{}: {}.", m.host.name, p.title);
                if let Some(d) = &p.detail {
                    // ssh's own error output, partly written by the far side.
                    println!("    {}", crate::term_safe(d));
                }
                println!("    {}", p.hint);
            }
        }
        if results.is_empty() && !quiet {
            println!(
                "{}",
                if due {
                    "No machines are due for a scan."
                } else {
                    "No machines to scan."
                }
            );
        }
    }
    Ok(if any_failed {
        3
    } else {
        crate::exit_code_for(worst)
    })
}
