use anyhow::Context;
use bulwark_core::{
    all_collectors, engine, fim_baseline_path, fim_establish_baseline, load_decoders,
    load_log_rules, models::Severity, run_log_scan, JournalRange, JournaldSource, LogScanRun,
    LogSource, Profile, Store, SyslogLinesSource, FIM_PRIVILEGED_WATCHED_PATHS,
    FIM_UNPRIVILEGED_WATCHED_PATHS,
};
use clap::{Parser, Subcommand};
use std::io::BufReader;
use std::path::{Path, PathBuf};

mod remote;

#[derive(Parser)]
#[command(
    name = "bulwarkctl",
    version,
    about = "Linux host security scanner — CLI front-door over bulwark-core"
)]
struct Cli {
    /// Directory containing YAML rule files (defaults to auto-detected ./rules)
    #[arg(long, global = true)]
    rules_dir: Option<PathBuf>,

    /// SQLite findings database path (defaults to ~/.local/share/bulwark/bulwark.db)
    #[arg(long, global = true)]
    db_path: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a scan and print findings
    Scan {
        /// Machine-readable JSON output instead of a table
        #[arg(long)]
        json: bool,
        /// Skip persisting this run to the local findings database
        #[arg(long)]
        no_persist: bool,
        /// Also run collectors that need root (e.g. sudoers). Refuses unless actually
        /// running under sudo — see architecture doc §4 ADR-0004: the CLI never self-elevates.
        #[arg(long)]
        privileged: bool,
        /// Comma-separated opt-in need tags (e.g. "server", "developer"). A rule with no
        /// `profiles` tag always runs regardless of this; a rule tagged `profiles: [server]`
        /// only runs when "server" is listed here. Empty by default — see the Profiles
        /// section of the architecture doc.
        #[arg(long, value_delimiter = ',')]
        needs: Vec<String>,
        /// Scan a REMOTE host over SSH instead of this machine. Takes a `[user@]host` spec (or a
        /// `Host` alias from ~/.ssh/config). Prefers a bulwark installed on the remote; otherwise
        /// pushes this binary + rule pack to a temp dir there, runs, and cleans up. Results are
        /// shown here and kept in a per-host history DB, never mixed with this machine's findings.
        #[arg(long, value_name = "[USER@]HOST")]
        ssh: Option<String>,
        /// SSH port for `--ssh` (default: ssh's own default / ~/.ssh/config).
        #[arg(long, requires = "ssh")]
        ssh_port: Option<u16>,
        /// Identity (private key) file for `--ssh`, passed to ssh/scp as `-i`.
        #[arg(long, requires = "ssh", value_name = "KEYFILE")]
        ssh_identity: Option<PathBuf>,
        /// Extra `-o Key=Value` ssh option for `--ssh` (repeatable), e.g.
        /// `--ssh-opt StrictHostKeyChecking=accept-new`.
        #[arg(long = "ssh-opt", requires = "ssh", value_name = "OPT")]
        ssh_opts: Vec<String>,
    },
    /// Inspect the loaded rule pack
    Rules {
        #[command(subcommand)]
        action: ConfigRulesAction,
    },
    /// List past scan runs
    History,
    /// File-integrity baseline management
    Fim {
        #[command(subcommand)]
        action: FimAction,
    },
    /// Analyze system logs for intrusion indicators (SSH brute force, sudo abuse, ...)
    Logs {
        #[command(subcommand)]
        action: LogsAction,
    },
    /// Scan AI coding-assistant artifacts (.claude, CLAUDE.md, MCP configs, transcripts, ...)
    /// for leaked secrets and dangerous agent configuration
    Ai {
        #[command(subcommand)]
        action: AiAction,
    },
    /// Protect SSH private keys (e.g. add a passphrase to every unencrypted key at once)
    Ssh {
        #[command(subcommand)]
        action: SshAction,
    },
    /// Apply safe, reversible autofixes for issues a scan reports (file permissions, sshd
    /// hardening). Dry-run by default — every subcommand previews and touches nothing without
    /// `--apply`.
    Fix {
        #[command(subcommand)]
        action: FixAction,
    },
}

#[derive(Subcommand)]
enum FixAction {
    /// Preview every available autofix for this host without changing anything.
    List,
    /// Tighten permissions in ~/.ssh (dir 700, private keys / config / authorized_keys 600).
    /// User-scoped; needs no privilege. Only ever tightens, never loosens.
    SshPerms {
        /// Actually apply the changes. Without this, only previews.
        #[arg(long)]
        apply: bool,
    },
    /// Tighten permissions on sensitive /etc files (shadow 640, sudoers 440, sshd_config 600, ...).
    /// Needs root when applying — re-run under sudo.
    EtcPerms {
        #[arg(long)]
        apply: bool,
    },
    /// Harden /etc/ssh/sshd_config to clear the SSH rule findings (X11/TCP forwarding off,
    /// MaxAuthTries, ...). Needs root when applying; keeps a backup and validates with `sshd -t`.
    Sshd {
        #[arg(long)]
        apply: bool,
        /// Also apply the two lockout-risky directives (PasswordAuthentication no, PermitRootLogin
        /// no). ONLY do this once you have confirmed key-based login works — it can lock you out of
        /// a password-only host.
        #[arg(long)]
        include_auth: bool,
        /// Operate on this config file instead of /etc/ssh/sshd_config (for testing or a
        /// non-default path). `Include` drop-ins are still resolved relative to /etc/ssh.
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Apply the safe subset in one pass: ~/.ssh perms, /etc perms (if root), and non-lockout sshd
    /// hardening (if root). Never touches the lockout-risky auth directives or key passphrases.
    All {
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum SshAction {
    /// Add ONE passphrase to every unencrypted private key in ~/.ssh, in a single pass. A single
    /// password across the set is far better than leaving plaintext keys on disk. Already-encrypted
    /// keys, and keys whose status can't be read, are left untouched; each modified key is backed
    /// up (0600) first.
    Protect {
        /// Read the passphrase from stdin (for scripting) instead of prompting with no echo.
        #[arg(long)]
        stdin: bool,
        /// Machine-readable JSON output instead of a table
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum AiAction {
    /// Discover and scan AI-assistant artifacts across your workspaces and home directory
    Scan {
        /// Machine-readable JSON output instead of a table
        #[arg(long)]
        json: bool,
        /// Skip persisting this run to the local findings database
        #[arg(long)]
        no_persist: bool,
        /// Extra directory to sweep for workspaces (repeatable). Adds to the built-in common
        /// code roots (~/Workspaces, ~/Projects, ~/src, ...).
        #[arg(long = "root", value_name = "DIR")]
        roots: Vec<PathBuf>,
        /// Directory to exclude from discovery (repeatable)
        #[arg(long = "exclude", value_name = "DIR")]
        excludes: Vec<PathBuf>,
        /// Scan exactly this workspace directory instead of auto-discovering (repeatable).
        /// Suppresses the whole-machine sweep — only the given folders are examined.
        #[arg(long = "target", value_name = "DIR")]
        targets: Vec<PathBuf>,
    },
    /// Remove leaked secrets from AI context files. Dry-run by default — prints what would
    /// change and touches nothing; pass --apply to rewrite the files (a 0600 backup of each is
    /// kept, and file permissions are preserved).
    Redact {
        /// Actually rewrite the files. Without this flag, redact only previews.
        #[arg(long)]
        apply: bool,
        /// Restrict redaction to these workspace directories (repeatable). Defaults to the same
        /// auto-discovered set `ai scan` uses.
        #[arg(long = "target", value_name = "DIR")]
        targets: Vec<PathBuf>,
    },
}

#[derive(Subcommand)]
enum LogsAction {
    /// Decode and correlate a batch of log events, printing any findings
    Scan {
        /// Machine-readable JSON output instead of a table
        #[arg(long)]
        json: bool,
        /// Skip persisting this run to the local findings database
        #[arg(long)]
        no_persist: bool,
        /// Read the current boot's systemd journal (the default when neither --since nor
        /// --from-file is given)
        #[arg(long)]
        boot: bool,
        /// Read the journal at/after a `journalctl --since` spec (e.g. "-1h",
        /// "2026-07-12 00:00:00"). Relative specs start with '-', so pass them with '='
        /// (`--since=-1h`) or quoted.
        #[arg(long, conflicts_with = "from_file", allow_hyphen_values = true)]
        since: Option<String>,
        /// Read a classic syslog-format file (e.g. /var/log/auth.log) instead of journald —
        /// works on non-systemd hosts and for offline analysis
        #[arg(long)]
        from_file: Option<PathBuf>,
        /// Directory of decoder YAML files (defaults to auto-detected ./decoders)
        #[arg(long)]
        decoders_dir: Option<PathBuf>,
        /// Directory of log-rule YAML files (defaults to auto-detected ./log-rules)
        #[arg(long)]
        log_rules_dir: Option<PathBuf>,
    },
    /// Inspect the loaded log-rule pack
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// Inspect the loaded decoder pack
    Decoders {
        #[command(subcommand)]
        action: RulesAction,
    },
}

#[derive(Subcommand)]
enum FimAction {
    /// Record the current state of monitored critical files as the known-good baseline.
    /// Run this explicitly, while you trust the host's current state — never automatic,
    /// since an auto-established baseline recorded after a compromise would just enshrine
    /// the compromised state as "known good."
    Baseline {
        /// Also baseline the root-only files (/etc/shadow, /etc/sudoers). Refuses unless
        /// actually running under sudo, same rule as `scan --privileged`.
        #[arg(long)]
        privileged: bool,
    },
}

#[derive(Subcommand)]
enum RulesAction {
    /// List loaded rules, including any that failed to load
    List,
    /// Validate a rule file or directory without running a scan
    Validate { path: PathBuf },
}

/// Config-scan rule actions. A superset of [`RulesAction`] — suppression is meaningful for config
/// rules (a host state you've decided to accept) but not for log rules or decoders, so those keep
/// the smaller shared enum rather than exposing suppress/unsuppress subcommands that do nothing.
#[derive(Subcommand)]
enum ConfigRulesAction {
    /// List loaded rules, including any that failed to load
    List,
    /// Validate a rule file or directory without running a scan
    Validate { path: PathBuf },
    /// Accept the risk a rule reports, so its findings stop counting against you.
    ///
    /// The rule keeps running on every scan — this only changes how its findings are
    /// presented. Nothing is deleted and no check is turned off, so lifting the
    /// suppression shows you the current truth rather than a stale one.
    Suppress {
        /// Rule to suppress, e.g. BLWK-BANN-001
        rule_id: String,
        /// Why this risk is acceptable. Required — an unexplained suppression is
        /// unauditable, and the person who will need this is future you.
        #[arg(long)]
        reason: String,
    },
    /// Withdraw a risk acceptance and let the rule count against you again
    Unsuppress {
        rule_id: String,
        /// Why the acceptance no longer holds. Required: this is an auditable decision
        /// too, and "why did this alert come back?" is a question someone will ask.
        #[arg(long)]
        reason: String,
    },
    /// Show active suppressions and the append-only audit trail behind them
    Suppressions {
        /// Show the full history (including lifted suppressions), not just what's active
        #[arg(long)]
        audit: bool,
        /// Scope the audit trail to one rule
        #[arg(long)]
        rule_id: Option<String>,
    },
}

/// Standard installed location — `cargo-deb`'s `assets` entry in `Cargo.toml` puts the
/// bundled rule pack here. Caught by actually building and inspecting a real `.deb`: a
/// packaged `bulwarkctl` run from an arbitrary directory (the common case — a real user isn't
/// sitting in the workspace root) has no `rules/` to walk up to, so this fallback isn't
/// optional polish, it's what makes the packaged binary work at all.
const INSTALLED_RULES_DIR: &str = "/usr/share/bulwark/rules";

fn resolve_rules_dir(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    // An explicitly-named directory that isn't there is a typo, not a reason to fall back to the
    // auto-detected pack: silently scanning a *different* rule set than the one asked for is its own
    // kind of lie. Both of these used to be returned unchecked, and a path that didn't exist then
    // produced a scan that loaded zero rules and reported "no findings" — see `run_scan` below.
    if let Some(p) = explicit {
        if !p.is_dir() {
            anyhow::bail!("--rules-dir {} is not a directory", p.display());
        }
        return Ok(p);
    }
    if let Ok(p) = std::env::var("BULWARK_RULES_DIR") {
        let p = PathBuf::from(p);
        if !p.is_dir() {
            anyhow::bail!("BULWARK_RULES_DIR {} is not a directory", p.display());
        }
        return Ok(p);
    }
    // Dev-mode heuristic: running from inside the workspace (cargo run / cargo test).
    let mut candidate = std::env::current_dir()?;
    for _ in 0..4 {
        let rules = candidate.join("rules");
        if rules.is_dir() {
            return Ok(rules);
        }
        if !candidate.pop() {
            break;
        }
    }
    let installed = PathBuf::from(INSTALLED_RULES_DIR);
    if installed.is_dir() {
        return Ok(installed);
    }
    // Last resort: the rule pack shipped beside this executable. The GUI bundles this same binary
    // as the `bulwark` Tauri sidecar and installs the rules into the app's resource directory
    // (`/usr/bin/bulwark` + `/usr/lib/bulwark/rules`), so on a GUI-only install none of the
    // paths above exist. The GUI itself always passes `--rules-dir`, so this changes nothing for
    // it — but the sidecar also lands on `PATH`, and a user who ran it got
    // "couldn't find a 'rules' directory" on a machine that plainly had them.
    //
    // Deliberately the *last* candidate, so it can never shadow an explicit flag, the env var, a
    // workspace checkout, or the packaged `/usr/share` pack: it only speaks up when the answer
    // would otherwise be an error.
    if let Some(dir) = exe_relative_dir("rules") {
        return Ok(dir);
    }
    anyhow::bail!(
        "couldn't find a 'rules' directory — pass --rules-dir explicitly or set BULWARK_RULES_DIR"
    )
}

/// A content directory shipped alongside this executable, for the Tauri-sidecar layout
/// (`<prefix>/bin/bulwark` with its content under `<prefix>/lib/bulwark/<subdir>`). Also
/// accepts `<exe dir>/<subdir>`, which is what the extracted release tarball looks like.
///
/// The `lib/bulwark` segment is the GUI's Tauri resource directory, named after `productName` in
/// `tauri.conf.json`. That name is lowercase `bulwark` — kept in sync with this path — while the
/// app's *display* name stays "Bulwark" via a `desktopTemplate`. If `productName` ever changes,
/// this must follow; a mismatch would only cost the sidecar its standalone fallback (the GUI passes
/// `--rules-dir` explicitly regardless), never correctness of a scan.
fn exe_relative_dir(subdir: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let bin_dir = exe.parent()?;
    let candidates = [
        bin_dir.join(subdir),
        bin_dir.join("../lib/bulwark").join(subdir),
    ];
    candidates
        .into_iter()
        .find(|c| c.is_dir())
        .and_then(|c| c.canonicalize().ok())
}

/// Shared resolution for the log pipeline's content dirs (`decoders`, `log-rules`), following
/// exactly the same precedence as [`resolve_rules_dir`]: explicit flag → env var → walk up from
/// the CWD (dev mode) → installed `/usr/share/bulwark/<subdir>`.
fn resolve_content_dir(
    explicit: Option<PathBuf>,
    env_var: &str,
    subdir: &str,
) -> anyhow::Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    if let Ok(p) = std::env::var(env_var) {
        return Ok(PathBuf::from(p));
    }
    let mut candidate = std::env::current_dir()?;
    for _ in 0..4 {
        let dir = candidate.join(subdir);
        if dir.is_dir() {
            return Ok(dir);
        }
        if !candidate.pop() {
            break;
        }
    }
    let installed = PathBuf::from("/usr/share/bulwark").join(subdir);
    if installed.is_dir() {
        return Ok(installed);
    }
    // Same last-resort as `resolve_rules_dir`: the GUI bundles this binary as a sidecar and ships
    // `decoders`/`log-rules` in its resource dir, where none of the paths above exist.
    if let Some(dir) = exe_relative_dir(subdir) {
        return Ok(dir);
    }
    anyhow::bail!(
        "couldn't find a '{subdir}' directory — pass the corresponding --*-dir flag or set {env_var}"
    )
}

fn resolve_db_path(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    if let Ok(p) = std::env::var("BULWARK_DB_PATH") {
        return Ok(PathBuf::from(p));
    }
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(Path::new(&home).join(".local/share/bulwark/bulwark.db"))
}

/// Who to attribute a suppression to in the audit trail. `SUDO_USER` wins over `USER` so a
/// suppression made under `sudo` is credited to the human who ran it, not to root — the audit log
/// is about accountability, and "root did it" is exactly the answer it exists to improve on.
fn current_actor() -> String {
    std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn exit_code_for(worst: Option<Severity>) -> i32 {
    match worst {
        Some(Severity::Critical) => 2,
        Some(s) if s >= Severity::Medium => 1,
        _ => 0,
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            json,
            no_persist,
            privileged,
            needs,
            ssh,
            ssh_port,
            ssh_identity,
            ssh_opts,
        } => {
            // Remote path: run the same scan over SSH and bring the results home. `--privileged`
            // here refers to the *remote* scan needing root, so we deliberately do NOT gate on local
            // root — the remote invocation uses `sudo -n` on the far side (see remote::run_scan_cmd).
            if let Some(spec) = ssh {
                let worst = run_ssh_scan(
                    remote::RemoteTarget {
                        spec,
                        port: ssh_port,
                        identity: ssh_identity,
                        ssh_opts,
                    },
                    privileged,
                    &needs,
                    json,
                    no_persist,
                    cli.rules_dir,
                )?;
                std::process::exit(exit_code_for(worst));
            }

            if privileged && !engine::is_running_as_root() {
                anyhow::bail!(
                    "--privileged requires root — re-run as: sudo bulwarkctl scan --privileged"
                );
            }
            let rules_dir = resolve_rules_dir(cli.rules_dir)?;
            let collectors = all_collectors();
            let profile = Profile {
                needs,
                ..Profile::current_host()
            };
            let scan = engine::run_scan(&rules_dir, &collectors, privileged, &profile);

            // A scan that loaded no rules examined nothing, and "0 findings" from it is not a clean
            // bill of health — it is the absence of an opinion. Reported as success (exit 0, empty
            // findings list) it is indistinguishable from a genuinely healthy host, which is the
            // single most dangerous thing a security scanner can say. Refuse, before persisting:
            // writing that run to the history would also mark every previously-open finding as
            // resolved, because `persist_and_reconcile` closes anything a scan didn't re-observe.
            //
            // The log scan has always had this guard (`logs scan`, below); the config scan did not,
            // so a rules directory that had been emptied, mispackaged, or simply mistyped produced a
            // confident, silent all-clear. Same invariant, same treatment: a failure must be
            // visible, never a silent drop (architecture doc §8).
            if scan.rules_loaded == 0 {
                anyhow::bail!(
                    "scan loaded 0 rules from {} — refusing to report a clean result from a scan \
                     that examined nothing (check the path, or pass --rules-dir)",
                    rules_dir.display()
                );
            }

            if !no_persist {
                let db_path = resolve_db_path(cli.db_path)?;
                let mut store = Store::open(&db_path)?;
                // Reconciled, matching the GUI's scan_start and the monitoring loop — a
                // manual CLI scan and a background tick finding the same issue must not
                // produce two rows for it. Using plain persist() here was the actual root
                // cause of a real "I see duplicated issues now" bug report: this command
                // kept inserting a fresh row every run against the same shared DB.
                store.persist_and_reconcile(&scan)?;
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&scan)?);
            } else {
                print_scan_table(&scan);
            }

            std::process::exit(exit_code_for(scan.worst_severity()));
        }
        Commands::Rules { action } => match action {
            ConfigRulesAction::List => {
                let rules_dir = resolve_rules_dir(cli.rules_dir)?;
                let (rules, errors) = engine::load_rules(&rules_dir);
                for r in &rules {
                    let os_tag = r
                        .rule
                        .os
                        .iter()
                        .map(|os| format!("{os:?}").to_lowercase())
                        .collect::<Vec<_>>()
                        .join(",");
                    println!(
                        "{:<20} [{:<8}] ({os_tag:<7}) {}",
                        r.rule.id,
                        severity_label(r.rule.severity),
                        r.rule.title
                    );
                }
                if !errors.is_empty() {
                    eprintln!("\n{} rule(s) failed to load:", errors.len());
                    for e in &errors {
                        eprintln!("  {}: {}", e.path, e.message);
                    }
                    std::process::exit(1);
                }
            }
            ConfigRulesAction::Validate { path } => {
                let (rules, mut errors) = engine::load_rules(&path);
                // Schema/condition validity alone isn't enough: a `collector:` field that
                // doesn't match any registered collector name loads without error but then
                // never matches a fact row at scan time, so the rule silently never fires —
                // forever, with nothing in `collector_errors` or `rule_load_errors` to catch
                // it. Cross-checking against the real collector registry here is what turns
                // that into a validate-time failure instead.
                let known_collectors: std::collections::HashSet<&str> = all_collectors()
                    .iter()
                    .map(|c| c.name())
                    .collect::<Vec<_>>()
                    .into_iter()
                    .collect();
                let mut valid_count = rules.len();
                for r in &rules {
                    if !known_collectors.contains(r.rule.collector.as_str()) {
                        valid_count -= 1;
                        errors.push(bulwark_core::models::RuleLoadError {
                            path: r.rule.id.clone(),
                            message: format!(
                                "unknown collector '{}' — not one of: {}",
                                r.rule.collector,
                                {
                                    let mut names: Vec<&str> =
                                        known_collectors.iter().copied().collect();
                                    names.sort_unstable();
                                    names.join(", ")
                                }
                            ),
                        });
                    }
                }
                println!("{valid_count} rule(s) valid");
                if !errors.is_empty() {
                    eprintln!("{} rule(s) invalid:", errors.len());
                    for e in &errors {
                        eprintln!("  {}: {}", e.path, e.message);
                    }
                    std::process::exit(1);
                }
            }
            ConfigRulesAction::Suppress { rule_id, reason } => {
                // Reject a suppression for a rule that doesn't exist — otherwise a typo'd ID
                // becomes a suppression that silently matches nothing, which is indistinguishable
                // from a working one until the day the real rule fires anyway and confuses everyone.
                let rules_dir = resolve_rules_dir(cli.rules_dir)?;
                let (rules, _) = engine::load_rules(&rules_dir);
                if !rules.iter().any(|r| r.rule.id == rule_id) {
                    anyhow::bail!(
                        "no rule '{rule_id}' in the loaded pack — check the id with: bulwarkctl rules list"
                    );
                }
                let db_path = resolve_db_path(cli.db_path)?;
                let mut store = Store::open(&db_path)?;
                let s = store.suppress_rule(&rule_id, &reason, &current_actor())?;
                println!("suppressed {} — {}", s.rule_id, s.reason);
                println!("(the rule still runs every scan; lift it with: bulwarkctl rules unsuppress {rule_id} --reason ...)");
            }
            ConfigRulesAction::Unsuppress { rule_id, reason } => {
                let db_path = resolve_db_path(cli.db_path)?;
                let mut store = Store::open(&db_path)?;
                store.unsuppress_rule(&rule_id, &reason, &current_actor())?;
                println!("unsuppressed {rule_id} — it will count against you again");
            }
            ConfigRulesAction::Suppressions { audit, rule_id } => {
                let db_path = resolve_db_path(cli.db_path)?;
                if !db_path.exists() {
                    println!("no suppressions — nothing recorded yet");
                    return Ok(());
                }
                let mut store = Store::open(&db_path)?;
                if audit {
                    let log = store.suppression_audit_log(rule_id.as_deref(), 500)?;
                    if log.is_empty() {
                        println!("no suppression history recorded");
                    }
                    for e in &log {
                        println!(
                            "{}  {:<12} {:<18} {} — {}",
                            e.at.format("%Y-%m-%d %H:%M"),
                            e.action.as_str(),
                            e.rule_id,
                            e.actor,
                            e.reason
                        );
                    }
                } else {
                    let active = store.list_suppressions()?;
                    if active.is_empty() {
                        println!("no active suppressions");
                    }
                    for s in &active {
                        println!(
                            "{:<18} by {} on {} — {}",
                            s.rule_id,
                            s.created_by,
                            s.created_at.format("%Y-%m-%d"),
                            s.reason
                        );
                    }
                }
            }
        },
        Commands::History => {
            let db_path = resolve_db_path(cli.db_path)?;
            if !db_path.exists() {
                println!("no scans recorded yet at {}", db_path.display());
                return Ok(());
            }
            let mut store = Store::open(&db_path)?;
            println!("{} scan run(s) recorded", store.count_scan_runs()?);
        }
        Commands::Fim { action } => match action {
            FimAction::Baseline { privileged } => {
                if privileged && !engine::is_running_as_root() {
                    anyhow::bail!(
                        "--privileged requires root — re-run as: sudo bulwarkctl fim baseline --privileged"
                    );
                }
                let mut paths: Vec<&str> = FIM_UNPRIVILEGED_WATCHED_PATHS.to_vec();
                if privileged {
                    paths.extend_from_slice(FIM_PRIVILEGED_WATCHED_PATHS);
                }
                let n = fim_establish_baseline(&paths)?;
                println!(
                    "baseline recorded for {n} file(s) at {}",
                    fim_baseline_path().display()
                );
                if !privileged {
                    println!(
                        "note: root-only files ({}) were not included — re-run with sudo and --privileged to cover them too",
                        FIM_PRIVILEGED_WATCHED_PATHS.join(", ")
                    );
                }
            }
        },
        Commands::Logs { action } => run_logs(action, cli.db_path)?,
        Commands::Ai { action } => run_ai(action, cli.db_path)?,
        Commands::Ssh { action } => run_ssh(action)?,
        Commands::Fix { action } => run_fix(action)?,
    }

    Ok(())
}

/// Resolves the user's home directory for AI-artifact discovery.
fn resolve_home() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home))
}

/// Handles the `ssh` subcommand group. Calls the linked `bulwark-core` remediation directly —
/// the CLI is just a front-door over the same in-process function the GUI uses.
/// Drive a remote scan over SSH: run it, print it, persist it to an isolated per-host history DB,
/// and return the worst severity so `main` can pick the process exit code. Kept separate from the
/// local scan path because the persistence target differs — a remote host's findings must never
/// land in this machine's single-host database, where reconciliation would resolve local findings
/// whose rules the remote scan happened to run (the `findings` table has no host column by design).
fn run_ssh_scan(
    target: remote::RemoteTarget,
    privileged: bool,
    needs: &[String],
    json: bool,
    no_persist: bool,
    rules_dir: Option<PathBuf>,
) -> anyhow::Result<Option<Severity>> {
    let rules_dir = resolve_rules_dir(rules_dir)?;
    let local_binary = std::env::current_exe().context("cannot locate this bulwarkctl binary")?;

    let spec = target.spec.clone();
    if !json {
        eprintln!("Scanning {spec} over SSH…");
    }
    let result = remote::run_remote_scan(&target, privileged, needs, &local_binary, &rules_dir)?;
    let scan = result.scan;

    // Same invariant as the local path: a scan that loaded no rules examined nothing, and its empty
    // findings list is the absence of an opinion, not a clean bill of health. Refuse before persisting.
    if scan.rules_loaded == 0 {
        anyhow::bail!(
            "remote scan of {spec} loaded 0 rules — refusing to report a clean result from a scan \
             that examined nothing (is the rule pack present on the remote?)"
        );
    }

    if !no_persist {
        let db_path = remote_db_path(&spec)?;
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let mut store = Store::open(&db_path)?;
        store.persist_and_reconcile(&scan)?;
        if !json {
            eprintln!("History for {spec}: {}", db_path.display());
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&scan)?);
    } else {
        match &result.engine {
            remote::RemoteEngine::Installed(path) => {
                eprintln!("Ran the remote's installed bulwark ({path}).");
            }
            remote::RemoteEngine::Pushed { arch, .. } => {
                eprintln!("Pushed this bulwarkctl ({arch}) to a temp dir and cleaned it up.");
            }
        }
        print_scan_table(&scan);
    }
    Ok(scan.worst_severity())
}

/// Isolated per-remote-host history database, so each scanned host reconciles against its own prior
/// findings and this machine's dashboard stays pristine. The host spec is slugified into a
/// filesystem-safe name (`user@host:port` → `user_at_host_port`).
fn remote_db_path(spec: &str) -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let slug: String = spec
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '.' => c,
            _ => '_',
        })
        .collect();
    let slug = if slug.is_empty() {
        "host".to_string()
    } else {
        slug
    };
    Ok(Path::new(&home)
        .join(".local/share/bulwark/remotes")
        .join(format!("{slug}.db")))
}

fn run_fix(action: FixAction) -> anyhow::Result<()> {
    use bulwark_core::{
        etc_permission_targets, harden_sshd_config, ssh_permission_targets, tighten_permissions,
    };

    let home = std::env::var("HOME").context("HOME not set")?;
    let ssh_dir = PathBuf::from(&home).join(".ssh");
    let backup_dir = PathBuf::from(&home).join(".local/share/bulwark/sshd-config-backups");

    match action {
        FixAction::List => {
            // A pure preview of everything, so a user can see the whole surface at a glance before
            // choosing what to apply. Nothing here writes.
            println!("Available autofixes (preview — nothing changed):\n");

            let ssh_targets = ssh_permission_targets(&ssh_dir);
            let ssh_report = tighten_permissions(&ssh_targets, false);
            println!(
                "• fix ssh-perms   ~/.ssh permissions — {} to tighten",
                ssh_report.changes()
            );
            print_perm_report(&ssh_report, false, "    ");

            let etc_report = tighten_permissions(&etc_permission_targets(), false);
            println!(
                "\n• fix etc-perms   /etc sensitive files — {} to tighten (needs root to apply)",
                etc_report.changes()
            );
            print_perm_report(&etc_report, false, "    ");

            match harden_sshd_config(None, &backup_dir, false, true) {
                Ok(sshd_report) => {
                    println!(
                        "\n• fix sshd        sshd_config hardening — {} directive(s) to set (needs root to apply)",
                        sshd_report.changes.len()
                    );
                    print_sshd_changes(&sshd_report, "    ");
                }
                Err(e) => {
                    println!("\n• fix sshd        sshd_config hardening — unavailable: {e}");
                }
            }

            println!("\nOther fixes (their own commands, need interactive input):");
            println!("    ssh protect     add one passphrase to every unencrypted ~/.ssh key");
            println!("    ai redact       remove leaked secrets from AI-assistant context files");
            println!("\nApply with e.g.:  bulwarkctl fix ssh-perms --apply");
            println!("Or the safe set:  sudo bulwarkctl fix all --apply");
        }

        FixAction::SshPerms { apply } => {
            let targets = ssh_permission_targets(&ssh_dir);
            if targets.is_empty() {
                println!("No ~/.ssh directory found — nothing to fix.");
                return Ok(());
            }
            let report = tighten_permissions(&targets, apply);
            print_perm_report(&report, apply, "");
            report_perm_summary(&report, apply);
        }

        FixAction::EtcPerms { apply } => {
            if apply && !engine::is_running_as_root() {
                anyhow::bail!(
                    "fix etc-perms --apply changes root-owned files — re-run as: \
                     sudo bulwarkctl fix etc-perms --apply"
                );
            }
            let report = tighten_permissions(&etc_permission_targets(), apply);
            print_perm_report(&report, apply, "");
            report_perm_summary(&report, apply);
        }

        FixAction::Sshd {
            apply,
            include_auth,
            config,
        } => {
            // Root is only required to write the real system config; an explicit --config path (used
            // for testing or a user-owned copy) the caller can already write is exempt.
            if apply && config.is_none() && !engine::is_running_as_root() {
                anyhow::bail!(
                    "fix sshd --apply edits /etc/ssh/sshd_config — re-run as: \
                     sudo bulwarkctl fix sshd --apply"
                );
            }
            if include_auth {
                eprintln!(
                    "⚠  --include-auth will set PasswordAuthentication no and PermitRootLogin no.\n\
                     ⚠  Make sure key-based login already works, or you can be locked out.\n"
                );
            }
            let report = harden_sshd_config(config.as_deref(), &backup_dir, apply, include_auth)?;
            print_sshd_report(&report, apply);
        }

        FixAction::All { apply } => {
            let is_root = engine::is_running_as_root();
            println!(
                "Running the safe autofix set{}:\n",
                if apply { " (applying)" } else { " (preview)" }
            );

            // 1. ~/.ssh perms — always available (user-scoped).
            let ssh_targets = ssh_permission_targets(&ssh_dir);
            if ssh_targets.is_empty() {
                println!("[ssh-perms] no ~/.ssh directory — skipped");
            } else {
                let r = tighten_permissions(&ssh_targets, apply);
                println!("[ssh-perms] {} change(s)", r.changes());
                print_perm_report(&r, apply, "    ");
            }

            // 2. /etc perms — only if root when applying.
            if apply && !is_root {
                println!("\n[etc-perms] needs root — skipped (re-run with sudo to include)");
            } else {
                let r = tighten_permissions(&etc_permission_targets(), apply);
                println!("\n[etc-perms] {} change(s)", r.changes());
                print_perm_report(&r, apply, "    ");
            }

            // 3. sshd hardening — non-lockout directives only, root when applying.
            if apply && !is_root {
                println!("\n[sshd] needs root — skipped (re-run with sudo to include)");
            } else {
                match harden_sshd_config(None, &backup_dir, apply, false) {
                    Ok(r) => {
                        println!(
                            "\n[sshd] {} directive(s){}",
                            r.pending_count(),
                            if r.applied { " set" } else { " to set" }
                        );
                        print_sshd_changes(&r, "    ");
                        if let Some(note) = &r.note {
                            println!("    note: {note}");
                        }
                    }
                    Err(e) => println!("\n[sshd] skipped: {e}"),
                }
            }

            if !apply {
                println!(
                    "\nPreview only. Re-run with --apply (and sudo for the root-owned fixes)."
                );
            }
            println!(
                "\nNot included (need a decision or a secret): the lockout-risky sshd auth \
                 directives (fix sshd --include-auth), key passphrases (ssh protect), secret \
                 redaction (ai redact)."
            );
        }
    }
    Ok(())
}

/// Print a permission report's per-file lines. `indent` prefixes each line so `fix list`/`fix all`
/// can nest them under a heading.
fn print_perm_report(report: &bulwark_core::PermReport, apply: bool, indent: &str) {
    use bulwark_core::PermOutcome;
    for r in &report.results {
        let line = match &r.outcome {
            PermOutcome::WouldTighten { from, to } => {
                format!("would chmod {from} → {to}  {} ({})", r.path, r.label)
            }
            PermOutcome::Tightened { from, to } => {
                format!("chmod {from} → {to}  {} ({})", r.path, r.label)
            }
            // In a preview or summary we don't spell out every already-ok/missing row unless it's
            // the only content — keep the signal high.
            _ => continue,
        };
        println!("{indent}{line}");
    }
    let _ = apply;
}

fn report_perm_summary(report: &bulwark_core::PermReport, apply: bool) {
    if report.changes() == 0 {
        println!("All checked permissions are already correct. Nothing to do.");
        return;
    }
    if apply {
        println!(
            "\n{} tightened, {} already ok, {} missing, {} failed.",
            report.tightened, report.already_ok, report.missing, report.failed
        );
        if report.failed > 0 {
            println!("Some changes failed — see the lines above (often: needs root).");
        }
    } else {
        println!(
            "\n{} file(s) would be tightened. Re-run with --apply to make the change.",
            report.would_tighten
        );
    }
}

fn print_sshd_changes(report: &bulwark_core::SshdHardeningReport, indent: &str) {
    use bulwark_core::SshdChangeStatus;
    for c in &report.changes {
        let verb = match c.status {
            SshdChangeStatus::WouldSet => "would set",
            SshdChangeStatus::Set => "set",
            SshdChangeStatus::SkippedLockout => "skipped (lockout risk — use --include-auth)",
        };
        println!(
            "{indent}{verb}: {} {} (was {}) — {}",
            c.keyword, c.desired, c.current, c.why
        );
    }
}

fn print_sshd_report(report: &bulwark_core::SshdHardeningReport, apply: bool) {
    if report.changes.is_empty() {
        println!("sshd_config is already hardened against the SSH rules. Nothing to do.");
        return;
    }
    println!("sshd_config: {}", report.config_path);
    print_sshd_changes(report, "  ");
    if let Some(note) = &report.note {
        println!("note: {note}");
    }
    if report.applied {
        println!("\nApplied. Validate and reload with:  sudo sshd -t && sudo systemctl reload ssh");
        if let Some(b) = &report.backup_path {
            println!("Backup of the original: {b}");
        }
        println!("Undo: restore the backup, or delete the '# BEGIN bulwark-hardening' block.");
    } else if apply {
        println!("\nNothing was applied (only lockout-risky directives were pending — add --include-auth).");
    } else {
        println!("\nPreview only. Re-run with --apply (as root) to make the change.");
    }
}

fn run_ssh(action: SshAction) -> anyhow::Result<()> {
    use bulwark_core::{protect_unencrypted_keys, KeyProtectionOutcome};
    match action {
        SshAction::Protect { stdin, json } => {
            let passphrase = if stdin {
                use std::io::BufRead;
                let mut line = String::new();
                std::io::stdin().lock().read_line(&mut line)?;
                line.trim_end_matches(['\n', '\r']).to_string()
            } else {
                // No-echo prompt, entered twice so a typo doesn't silently lock keys with the
                // wrong passphrase.
                let p1 =
                    rpassword::prompt_password("New passphrase for all unencrypted SSH keys: ")?;
                let p2 = rpassword::prompt_password("Confirm passphrase: ")?;
                if p1 != p2 {
                    anyhow::bail!("passphrases did not match");
                }
                p1
            };
            if passphrase.is_empty() {
                anyhow::bail!(
                    "empty passphrase — an empty passphrase would leave the keys unprotected"
                );
            }

            let home = std::env::var("HOME").context("HOME not set")?;
            let backup_dir = PathBuf::from(home).join(".local/share/bulwark/ssh-key-backups");
            let report = protect_unencrypted_keys(&passphrase, &backup_dir)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Ok(());
            }
            if report.results.is_empty() {
                println!("No SSH private keys found in ~/.ssh.");
                return Ok(());
            }
            for r in &report.results {
                let status = match &r.outcome {
                    KeyProtectionOutcome::Protected => "protected".to_string(),
                    KeyProtectionOutcome::AlreadyEncrypted => "already encrypted".to_string(),
                    KeyProtectionOutcome::Undetermined => "skipped (status unreadable)".to_string(),
                    KeyProtectionOutcome::Failed { reason } => format!("FAILED: {reason}"),
                };
                println!("  {status:<28}  {}", r.path);
            }
            println!(
                "\n{} protected, {} already encrypted, {} undetermined, {} failed.",
                report.protected, report.already_encrypted, report.undetermined, report.failed
            );
            if report.protected > 0 {
                println!("Backups of the originals: {}", backup_dir.display());
                println!(
                    "Tip: 'ssh-add <key>' loads a key into your agent once per session so you \
                     don't retype the passphrase."
                );
            }
        }
    }
    Ok(())
}

/// Handles the `ai` subcommand group. Like `scan`, the `scan` path exits with a
/// severity-derived code so cron/CI can gate on it identically.
fn run_ai(action: AiAction, db_path: Option<PathBuf>) -> anyhow::Result<()> {
    use bulwark_core::{ai_redact_paths, run_ai_scan, AiScanOptions};

    match action {
        AiAction::Scan {
            json,
            no_persist,
            roots,
            excludes,
            targets,
        } => {
            let opts = AiScanOptions {
                home: resolve_home()?,
                configured_roots: roots,
                excluded_roots: excludes,
                explicit_targets: targets,
                max_workspaces: bulwark_core::ai_scan::DEFAULT_MAX_WORKSPACES,
            };
            let report = run_ai_scan(&opts, |_| {});

            if !no_persist {
                let db_path = resolve_db_path(db_path)?;
                let mut store = Store::open(&db_path)?;
                store.persist_ai_scan(&report)?;
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_ai_report(&report);
            }
            std::process::exit(exit_code_for(report.worst_severity()));
        }
        AiAction::Redact { apply, targets } => {
            let opts = AiScanOptions {
                home: resolve_home()?,
                explicit_targets: targets,
                ..AiScanOptions::for_home(resolve_home()?)
            };
            let report = run_ai_scan(&opts, |_| {});
            let files = report.redactable_files();
            if files.is_empty() {
                println!(
                    "No redactable secrets found across {} artifact(s).",
                    report.artifacts_scanned
                );
                return Ok(());
            }

            let backup_dir = resolve_db_path(None)?
                .parent()
                .map(|p| p.join("redaction-backups"))
                .unwrap_or_else(|| PathBuf::from("redaction-backups"));
            let outcome = ai_redact_paths(&files, apply, &backup_dir);
            print_redaction_report(&outcome, apply);
        }
    }
    Ok(())
}

fn print_ai_report(report: &bulwark_core::AiScanReport) {
    println!(
        "Bulwark AI-artifact scan — host {} — {} workspace(s), {} artifact(s) examined",
        report.host_fingerprint,
        report.workspaces_scanned.len(),
        report.artifacts_scanned,
    );
    if report.workspaces_capped {
        println!(
            "⚠ workspace cap reached — some projects weren't scanned. Narrow with --target, or raise the cap."
        );
    }
    if !report.errors.is_empty() {
        println!("⚠ {} artifact(s) could not be read:", report.errors.len());
        for e in &report.errors {
            println!("  {e}");
        }
    }
    println!();
    if report.findings.is_empty() {
        println!("No findings.");
        return;
    }
    for f in &report.findings {
        let loc = match f.line {
            Some(l) => format!("{}:{}", f.file, l),
            None => f.file.clone(),
        };
        println!(
            "[{:<8}] {} — {} ({})",
            severity_label(f.severity),
            f.rule_id,
            f.title,
            f.tool,
        );
        println!("           {loc}");
        println!("           {}", f.explanation.trim());
        if !f.evidence.is_empty() {
            println!("           evidence: {}", f.evidence);
        }
        println!("           fix: {}", f.fix_hint.trim());
        if f.redactable {
            println!("           ↳ redactable: run 'bulwarkctl ai redact --apply'");
        }
    }
    println!("\n{} finding(s) total.", report.findings.len());
}

fn print_redaction_report(report: &bulwark_core::RedactionReport, apply: bool) {
    if report.dry_run {
        println!("Dry run — nothing was changed. Re-run with --apply to redact.\n");
    }
    for entry in &report.entries {
        let verb = if entry.applied {
            "redacted"
        } else {
            "would redact"
        };
        println!(
            "{} {} secret(s) in {}",
            verb, entry.secrets_redacted, entry.path
        );
        if let Some(backup) = &entry.backup_path {
            println!("  backup: {backup}");
        }
    }
    for e in &report.errors {
        println!("⚠ {e}");
    }
    let verb = if apply { "Redacted" } else { "Found" };
    println!(
        "\n{} {} secret(s) across {} file(s).",
        verb,
        report.total_secrets,
        report.entries.len()
    );
}

/// Handles the `logs` subcommand group. Kept as its own function so `main`'s top-level match
/// stays readable; the `scan` path calls `std::process::exit` with a severity-derived code just
/// like `Commands::Scan`, so scripts and cron can gate on it identically.
fn run_logs(action: LogsAction, db_path: Option<PathBuf>) -> anyhow::Result<()> {
    match action {
        LogsAction::Scan {
            json,
            no_persist,
            boot: _,
            since,
            from_file,
            decoders_dir,
            log_rules_dir,
        } => {
            let decoders_dir =
                resolve_content_dir(decoders_dir, "BULWARK_DECODERS_DIR", "decoders")?;
            let rules_dir =
                resolve_content_dir(log_rules_dir, "BULWARK_LOG_RULES_DIR", "log-rules")?;

            let mut source: Box<dyn LogSource> = match from_file {
                Some(path) => {
                    let file = std::fs::File::open(&path)
                        .with_context(|| format!("opening {}", path.display()))?;
                    // syslog headers carry no year. Use the file's last-modified time as the
                    // reference so a rotated log from last year is dated correctly (and a Dec/Jan
                    // boundary is handled per-line by the source), falling back to now for a file
                    // whose mtime can't be read.
                    let reference = file
                        .metadata()
                        .and_then(|m| m.modified())
                        .map(chrono::DateTime::<chrono::Utc>::from)
                        .unwrap_or_else(|_| chrono::Utc::now());
                    Box::new(SyslogLinesSource::new(BufReader::new(file), reference))
                }
                None => {
                    let range = match since {
                        Some(spec) => JournalRange::Since(spec),
                        None => JournalRange::CurrentBoot,
                    };
                    Box::new(JournaldSource::batch(range)?)
                }
            };

            let scan = run_log_scan(&decoders_dir, &rules_dir, source.as_mut());

            if !no_persist {
                let db_path = resolve_db_path(db_path)?;
                let mut store = Store::open(&db_path)?;
                store.persist_log_scan(&scan)?;
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&scan)?);
            } else {
                print_log_scan_table(&scan);
            }
            // A scan that loaded no decoders or no rules never actually analyzed anything — exit
            // with an error so a script gating on the exit code can't mistake it for a clean run
            // (the finding-severity exit code below would otherwise report success).
            if scan.decoders_loaded == 0 || scan.rules_loaded == 0 {
                eprintln!("error: log scan could not run — no decoders and/or rules were loaded");
                std::process::exit(2);
            }
            std::process::exit(exit_code_for(scan.worst_severity()));
        }
        LogsAction::Rules { action } => match action {
            RulesAction::List => {
                let dir = resolve_content_dir(None, "BULWARK_LOG_RULES_DIR", "log-rules")?;
                let (rules, errors) = load_log_rules(&dir);
                for r in &rules {
                    let corr = if r.rule.correlate.is_some() {
                        " [correlated]"
                    } else {
                        ""
                    };
                    println!(
                        "{:<24} [{:<8}] {}{corr}",
                        r.rule.id,
                        severity_label(r.rule.severity),
                        r.rule.title
                    );
                }
                report_load_errors(&errors)?;
            }
            RulesAction::Validate { path } => {
                let (rules, mut errors) = load_log_rules(&path);
                // Cross-check that every rule's `decoder:` names a real decoder — the log analog
                // of the config path's "unknown collector" validate-time guard. A typo there
                // would load cleanly but then silently never match an event.
                if let Ok(decoders_dir) =
                    resolve_content_dir(None, "BULWARK_DECODERS_DIR", "decoders")
                {
                    let (decoders, _) = load_decoders(&decoders_dir);
                    let ids: std::collections::HashSet<&str> =
                        decoders.iter().map(|d| d.id.as_str()).collect();
                    for r in &rules {
                        if let Some(dec) = &r.rule.decoder {
                            if !ids.contains(dec.as_str()) {
                                errors.push(bulwark_core::models::RuleLoadError {
                                    path: r.rule.id.clone(),
                                    message: format!("unknown decoder '{dec}'"),
                                });
                            }
                        }
                    }
                }
                println!(
                    "{} log rule(s) valid",
                    rules.len().saturating_sub(errors.len())
                );
                report_load_errors(&errors)?;
            }
        },
        LogsAction::Decoders { action } => match action {
            RulesAction::List => {
                let dir = resolve_content_dir(None, "BULWARK_DECODERS_DIR", "decoders")?;
                let (decoders, errors) = load_decoders(&dir);
                for d in &decoders {
                    let prog = d.program.as_deref().unwrap_or("(any)");
                    println!("{:<16} program={prog}", d.id);
                }
                report_load_errors(&errors)?;
            }
            RulesAction::Validate { path } => {
                let (decoders, errors) = load_decoders(&path);
                println!("{} decoder(s) valid", decoders.len());
                report_load_errors(&errors)?;
            }
        },
    }
    Ok(())
}

fn report_load_errors(errors: &[bulwark_core::models::RuleLoadError]) -> anyhow::Result<()> {
    if !errors.is_empty() {
        eprintln!("{} item(s) failed to load:", errors.len());
        for e in errors {
            eprintln!("  {}: {}", e.path, e.message);
        }
        std::process::exit(1);
    }
    Ok(())
}

fn print_log_scan_table(scan: &LogScanRun) {
    println!(
        "Bulwark log scan — host {} — {} event(s) read, {} decoded — {} decoder(s), {} rule(s)",
        scan.host_fingerprint,
        scan.events_read,
        scan.events_decoded,
        scan.decoders_loaded,
        scan.rules_loaded,
    );
    for (label, errs) in [
        ("decoder", &scan.decoder_load_errors),
        ("rule", &scan.rule_load_errors),
    ] {
        if !errs.is_empty() {
            println!("⚠ {} {label}(s) failed to load:", errs.len());
            for e in errs {
                println!("  {}: {}", e.path, e.message);
            }
        }
    }
    if !scan.read_errors.is_empty() {
        println!("⚠ {} line(s) could not be read", scan.read_errors.len());
    }
    if !scan.rule_eval_errors.is_empty() {
        println!(
            "⚠ {} rule evaluation error(s):",
            scan.rule_eval_errors.len()
        );
        for e in &scan.rule_eval_errors {
            println!("  {e}");
        }
    }
    // Health warnings make an empty result untrustworthy — surface them prominently so "No findings"
    // is never read as "clean" when the scan couldn't actually analyze the input.
    for w in &scan.warnings {
        println!("⚠ {w}");
    }
    println!();
    if scan.findings.is_empty() {
        if scan.warnings.is_empty() {
            println!("No findings.");
        } else {
            println!("No findings — but see the warnings above: this scan could not reliably analyze the input.");
        }
        return;
    }
    let mut sorted = scan.findings.clone();
    sorted.sort_by_key(|f| std::cmp::Reverse(f.severity));
    for f in &sorted {
        println!(
            "[{:<8}] {} — {}",
            severity_label(f.severity),
            f.rule_id,
            f.title
        );
        println!(
            "           at {} · {} matching event(s)",
            f.observed_at.to_rfc3339(),
            f.match_count
        );
        println!("           {}", f.explanation.trim());
        println!("           fix: {}", f.fix_hint.trim());
    }
    println!("\n{} finding(s) total.", scan.findings.len());
}

fn print_scan_table(scan: &bulwark_core::ScanRun) {
    println!(
        "Bulwark scan — host {} — {} rule(s) loaded",
        scan.host_fingerprint, scan.rules_loaded
    );
    if !scan.rule_load_errors.is_empty() {
        println!("⚠ {} rule(s) failed to load:", scan.rule_load_errors.len());
        for e in &scan.rule_load_errors {
            println!("  {}: {}", e.path, e.message);
        }
    }
    if !scan.collector_errors.is_empty() {
        println!(
            "⚠ {} collector error(s) (partial results):",
            scan.collector_errors.len()
        );
        for e in &scan.collector_errors {
            println!("  {}: {}", e.collector, e.message);
        }
    }
    if !scan.privileged_collectors_skipped.is_empty() {
        println!(
            "⚠ {} check(s) skipped (no privilege) — re-run with 'sudo bulwarkctl scan --privileged': {}",
            scan.privileged_collectors_skipped.len(),
            scan.privileged_collectors_skipped.join(", ")
        );
    }
    println!();
    if scan.findings.is_empty() {
        println!("No findings.");
        return;
    }
    let mut sorted = scan.findings.clone();
    sorted.sort_by_key(|f| std::cmp::Reverse(f.severity));
    for f in &sorted {
        println!(
            "[{:<8}] {} — {}",
            severity_label(f.severity),
            f.rule_id,
            f.title
        );
        println!("           {}", f.explanation);
        println!("           fix: {}", f.fix_hint);
    }
    println!("\n{} finding(s) total.", scan.findings.len());
}
