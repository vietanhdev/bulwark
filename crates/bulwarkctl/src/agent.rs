//! `bulwarkctl agent`: give AI coding agents the Bulwark skill, so an agent can run the checks
//! itself — "is this repo safe?" — and asks before fixing anything. The skill and where it goes
//! are `bulwark_core::agent_skill`; this is the front door.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use bulwark_core::agent_skill::{self, Agent, Folder, Outcome, State, AGENTS};
use clap::Subcommand;
use serde::Serialize;

#[derive(Subcommand)]
pub enum AgentAction {
    /// Show which AI coding agents are on this computer and whether each has the Bulwark skill
    List {
        #[command(flatten)]
        target: Target,
        /// Machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
    /// Install the Bulwark skill for the agents found on this computer (or the ones named), so
    /// they can run Bulwark's checks when asked. Writes only <skills folder>/bulwark/SKILL.md.
    Install {
        #[command(flatten)]
        target: Target,
        /// Show what would be written, and write nothing
        #[arg(long)]
        dry_run: bool,
        /// Machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
    /// Remove the Bulwark skill. Only ever removes a skill Bulwark wrote.
    Remove {
        #[command(flatten)]
        target: Target,
        /// Show what would be removed, and remove nothing
        #[arg(long)]
        dry_run: bool,
        /// Machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
}

#[derive(clap::Args)]
pub struct Target {
    /// Only these agents (repeatable): claude-code, codex, copilot, gemini, opencode, cursor.
    /// Default: every agent found on this computer
    #[arg(long = "agent", value_name = "AGENT", value_parser = agent_ids())]
    agents: Vec<String>,
    /// Every supported agent, found or not
    #[arg(long, conflicts_with = "agents")]
    all: bool,
    /// Put the skill in this project instead of your home folder (commit it to share it with
    /// your team). Default: every supported agent
    #[arg(long, value_name = "DIR")]
    project: Option<PathBuf>,
    /// The command agents should run (default: this program's name, e.g. bulwarkctl)
    #[arg(long, value_name = "NAME")]
    command: Option<String>,
}

fn agent_ids() -> clap::builder::PossibleValuesParser {
    clap::builder::PossibleValuesParser::new(AGENTS.iter().map(|a| a.id))
}

/// Everything a run works on: where the skills go, for which agents, for which command.
struct Plan {
    base: PathBuf,
    home: Option<PathBuf>,
    project: bool,
    agents: Vec<&'static Agent>,
    bin: String,
}

impl Plan {
    fn new(t: &Target, home: &Path, install_like: bool) -> anyhow::Result<Plan> {
        let bin = match &t.command {
            Some(c) => c.clone(),
            None => this_command(),
        };
        let (base, project) = match &t.project {
            Some(dir) => {
                if !dir.is_dir() {
                    bail!("{} is not a folder", dir.display());
                }
                (dir.canonicalize()?, true)
            }
            None => (home.to_path_buf(), false),
        };
        let agents: Vec<&'static Agent> = if !t.agents.is_empty() {
            t.agents
                .iter()
                .map(|id| agent_skill::agent(id).expect("validated by clap"))
                .collect()
        } else if t.all || project || !install_like {
            AGENTS.iter().collect()
        } else {
            let found = agent_skill::detect(home);
            if found.is_empty() {
                bail!(
                    "no supported AI coding agent found in your home folder.\n\
                     Name one with --agent ({}), or use --all.",
                    AGENTS.iter().map(|a| a.id).collect::<Vec<_>>().join(", ")
                );
            }
            found
        };
        Ok(Plan {
            base,
            home: Some(home.to_path_buf()),
            project,
            agents,
            bin,
        })
    }

    fn folders(&self) -> Vec<Folder> {
        agent_skill::folders_for(&self.agents)
    }

    fn show(&self, p: &Path) -> String {
        tilde(p, self.home.as_deref())
    }
}

/// This program's own name, which is what an agent will type: `bulwarkctl` for the CLI package,
/// `bulwark` for the copy the desktop app ships.
fn this_command() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "bulwarkctl".into())
}

/// Whether `cmd` would be found by an agent's shell: an absolute path that exists, or a name on
/// PATH.
fn runnable(cmd: &str) -> bool {
    let p = Path::new(cmd);
    if p.is_absolute() {
        return p.is_file();
    }
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let c = dir.join(cmd);
        c.is_file() || (cfg!(windows) && c.with_extension("exe").is_file())
    })
}

fn tilde(p: &Path, home: Option<&Path>) -> String {
    match home.and_then(|h| p.strip_prefix(h).ok()) {
        Some(rest) => format!("~/{}", rest.display()),
        None => p.display().to_string(),
    }
}

#[derive(Serialize)]
struct Change {
    folder: Folder,
    path: PathBuf,
    agents: Vec<&'static str>,
    outcome: Outcome,
    dry_run: bool,
}

/// Runs an `agent` subcommand; returns the exit code.
pub fn run(action: AgentAction, home: &Path) -> anyhow::Result<i32> {
    match action {
        AgentAction::List { target, json } => list(&target, home, json),
        AgentAction::Install {
            target,
            dry_run,
            json,
        } => change(&target, home, dry_run, json, true),
        AgentAction::Remove {
            target,
            dry_run,
            json,
        } => change(&target, home, dry_run, json, false),
    }
}

fn list(t: &Target, home: &Path, json: bool) -> anyhow::Result<i32> {
    let plan = Plan::new(t, home, false)?;
    let found = agent_skill::detect(home);
    if json {
        #[derive(Serialize)]
        struct AgentRow {
            id: &'static str,
            name: &'static str,
            found: bool,
            folder: Folder,
            path: PathBuf,
            #[serde(flatten)]
            state: State,
        }
        let rows: Vec<AgentRow> = plan
            .agents
            .iter()
            .map(|a| {
                let path = agent_skill::skill_path(&plan.base, a.folder);
                AgentRow {
                    id: a.id,
                    name: a.name,
                    found: found.contains(a),
                    folder: a.folder,
                    state: agent_skill::state(&path, &plan.bin),
                    path,
                }
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(0);
    }

    let place = if plan.project {
        format!("in {}", plan.base.display())
    } else {
        "on this computer".to_string()
    };
    println!("AI coding agents {place}\n");
    let mut missing = false;
    for a in &plan.agents {
        let path = agent_skill::skill_path(&plan.base, a.folder);
        let state = agent_skill::state(&path, &plan.bin);
        let here = if plan.project {
            String::new()
        } else if found.contains(a) {
            "found".to_string()
        } else {
            "not found".to_string()
        };
        let skill = match &state {
            State::Missing => {
                if plan.project || found.contains(a) {
                    missing = true;
                }
                "no skill".to_string()
            }
            State::Current => "skill installed".to_string(),
            State::Outdated { version } => {
                missing = true;
                match version {
                    Some(v) => format!("skill from {v}, update available"),
                    None => "skill out of date".to_string(),
                }
            }
            State::Foreign => "another skill named bulwark".to_string(),
            State::Unsafe { reason } => format!("can't use: {reason}"),
        };
        if plan.project {
            println!("  {:<15} {:<26} {}", a.name, skill, plan.show(&path));
        } else {
            println!(
                "  {:<15} {:<10} {:<26} {}",
                a.name,
                here,
                skill,
                plan.show(&path)
            );
        }
    }
    println!();
    if missing {
        let flag = if plan.project {
            format!(" --project {}", plan.base.display())
        } else {
            String::new()
        };
        println!("→ Install it: {} agent install{flag}", plan.bin);
    }
    Ok(0)
}

fn change(
    t: &Target,
    home: &Path,
    dry_run: bool,
    json: bool,
    install: bool,
) -> anyhow::Result<i32> {
    let plan = Plan::new(t, home, install)?;
    let mut changes = Vec::new();
    for folder in plan.folders() {
        let path = agent_skill::skill_path(&plan.base, folder);
        let agents: Vec<&'static str> = plan
            .agents
            .iter()
            .filter(|a| a.folder == folder)
            .map(|a| a.name)
            .collect();
        let outcome = if dry_run {
            preview(&path, &plan.bin, install)
        } else if install {
            agent_skill::install(&path, &plan.bin)
                .with_context(|| format!("writing {}", path.display()))?
        } else {
            agent_skill::remove(&path, &plan.bin)
                .with_context(|| format!("removing {}", path.display()))?
        };
        changes.push(Change {
            folder,
            path,
            agents,
            outcome,
            dry_run,
        });
    }
    let refused = changes
        .iter()
        .any(|c| matches!(c.outcome, Outcome::Skipped(_)));

    if json {
        println!("{}", serde_json::to_string_pretty(&changes)?);
    } else {
        for c in &changes {
            let what = match (&c.outcome, dry_run) {
                (Outcome::Installed, false) => "installed".to_string(),
                (Outcome::Installed, true) => "would install".to_string(),
                (Outcome::Updated, false) => "updated".to_string(),
                (Outcome::Updated, true) => "would update".to_string(),
                (Outcome::AlreadyCurrent, _) => "already installed".to_string(),
                (Outcome::Removed, false) => "removed".to_string(),
                (Outcome::Removed, true) => "would remove".to_string(),
                (Outcome::NotInstalled, _) => "not installed".to_string(),
                (Outcome::Skipped(why), _) => format!("left alone: {why}"),
            };
            println!(
                "{what:<18} {}  ({})",
                plan.show(&c.path),
                c.agents.join(", ")
            );
        }
        if install && !refused {
            if !runnable(&plan.bin) {
                println!(
                    "\n! `{}` isn't on your PATH, so an agent can't run it. Re-run with \
                     --command /full/path/to/{}",
                    plan.bin, plan.bin
                );
            } else if !dry_run {
                println!(
                    "\nAsk your agent: \"Is this repository safe?\" — it runs {} ai scan and asks \
                     before fixing anything.",
                    plan.bin
                );
            }
        }
        if dry_run {
            println!("\nPreview only — nothing was changed.");
        }
    }
    Ok(if refused { 1 } else { 0 })
}

/// What install/remove would do, without doing it.
fn preview(path: &Path, bin: &str, install: bool) -> Outcome {
    match (agent_skill::state(path, bin), install) {
        (State::Unsafe { reason }, _) => Outcome::Skipped(reason),
        (State::Foreign, _) => {
            Outcome::Skipped("a skill named bulwark that Bulwark didn't write".into())
        }
        (State::Missing, true) => Outcome::Installed,
        (State::Outdated { .. }, true) => Outcome::Updated,
        (State::Current, true) => Outcome::AlreadyCurrent,
        (State::Missing, false) => Outcome::NotInstalled,
        (State::Current | State::Outdated { .. }, false) => Outcome::Removed,
    }
}
