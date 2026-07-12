use anyhow::Context;
use bulwark_core::{
    all_collectors, engine, fim_baseline_path, fim_establish_baseline, load_decoders,
    load_log_rules, models::Severity, run_log_scan, JournalRange, JournaldSource, LogScanRun,
    LogSource, Profile, Store, SyslogLinesSource, FIM_PRIVILEGED_WATCHED_PATHS,
    FIM_UNPRIVILEGED_WATCHED_PATHS,
};
use chrono::Datelike;
use clap::{Parser, Subcommand};
use std::io::BufReader;
use std::path::{Path, PathBuf};

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
    },
    /// Inspect the loaded rule pack
    Rules {
        #[command(subcommand)]
        action: RulesAction,
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

/// Standard installed location — `cargo-deb`'s `assets` entry in `Cargo.toml` puts the
/// bundled rule pack here. Caught by actually building and inspecting a real `.deb`: a
/// packaged `bulwarkctl` run from an arbitrary directory (the common case — a real user isn't
/// sitting in the workspace root) has no `rules/` to walk up to, so this fallback isn't
/// optional polish, it's what makes the packaged binary work at all.
const INSTALLED_RULES_DIR: &str = "/usr/share/bulwark/rules";

fn resolve_rules_dir(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    if let Ok(p) = std::env::var("BULWARK_RULES_DIR") {
        return Ok(PathBuf::from(p));
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
    anyhow::bail!(
        "couldn't find a 'rules' directory — pass --rules-dir explicitly or set BULWARK_RULES_DIR"
    )
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
        } => {
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
            RulesAction::List => {
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
            RulesAction::Validate { path } => {
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
        },
        Commands::History => {
            let db_path = resolve_db_path(cli.db_path)?;
            if !db_path.exists() {
                println!("no scans recorded yet at {}", db_path.display());
                return Ok(());
            }
            let store = Store::open(&db_path)?;
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
    }

    Ok(())
}

/// Resolves the user's home directory for AI-artifact discovery.
fn resolve_home() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home))
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
                    // syslog headers carry no year; use the current one for a live file.
                    let year = chrono::Utc::now().year();
                    Box::new(SyslogLinesSource::new(BufReader::new(file), year))
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
