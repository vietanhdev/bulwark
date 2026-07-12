use anyhow::Context;
use bulwark_core::{
    all_collectors, engine, fim_baseline_path, fim_establish_baseline, models::Severity, Profile,
    Store, FIM_PRIVILEGED_WATCHED_PATHS, FIM_UNPRIVILEGED_WATCHED_PATHS,
};
use clap::{Parser, Subcommand};
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
    }

    Ok(())
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
