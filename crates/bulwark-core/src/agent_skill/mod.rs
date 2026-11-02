//! The Bulwark skill for AI coding agents: a `SKILL.md` that tells an agent how to run Bulwark,
//! read its report, and ask before fixing anything — installed where each agent looks for skills.
//!
//! Every agent here implements the open Agent Skills format (a folder holding `SKILL.md`), and
//! between them they read two folders, per each vendor's own documentation:
//!
//! | Folder                       | Read by                                                |
//! |------------------------------|--------------------------------------------------------|
//! | `~/.claude/skills`           | Claude Code (also OpenCode, Cursor)                    |
//! | `~/.agents/skills`           | Codex, GitHub Copilot, Gemini CLI, OpenCode, Cursor    |
//!
//! and the same two under a project (`.claude/skills`, `.agents/skills`). Codex reads *only*
//! `.agents/skills`, and Claude Code only `.claude/skills`, so both are needed; an agent that reads
//! both sees one skill named `bulwark` in each. Add a folder here only when the agent's own docs
//! name it — a skill written where nothing looks is a feature that silently doesn't exist.
//!
//! Filesystem only, no network. Bulwark writes nothing but `<folder>/bulwark/SKILL.md`, never
//! through a symlink, and never over a `SKILL.md` it didn't write (one without its
//! `generator: bulwark` marker), so installing can't clobber a user's own skill.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// The skill's text, with `{bin}` and `{version}` still to fill in.
const TEMPLATE: &str = include_str!("SKILL.md");

/// The folder name under a skills directory; also the skill's `name`.
pub const SKILL_NAME: &str = "bulwark";

/// The marker a `SKILL.md` carries when Bulwark wrote it.
const MARKER: &str = "generator: bulwark";

/// An agent that can load the skill, and how to tell it is on this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Agent {
    /// Stable id for `--agent` ("claude-code").
    pub id: &'static str,
    pub name: &'static str,
    /// The skills folder this agent reads, relative to the home directory or the project.
    pub folder: Folder,
    /// Config directories under `$HOME` whose presence means the agent is installed.
    #[serde(skip)]
    pub home_markers: &'static [&'static str],
}

/// The two skills folders, relative to a home directory or a project root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Folder {
    /// `.claude/skills`
    Claude,
    /// `.agents/skills`, the cross-agent folder.
    Agents,
}

impl Folder {
    pub fn rel(self) -> &'static str {
        match self {
            Folder::Claude => ".claude/skills",
            Folder::Agents => ".agents/skills",
        }
    }
}

/// Each agent once, with the folder that reaches it. Where an agent reads more than one, the one
/// shared with the most other agents is used, so one install serves as many as possible.
pub const AGENTS: &[Agent] = &[
    Agent {
        id: "claude-code",
        name: "Claude Code",
        folder: Folder::Claude,
        home_markers: &[".claude"],
    },
    Agent {
        id: "codex",
        name: "Codex",
        folder: Folder::Agents,
        home_markers: &[".codex"],
    },
    Agent {
        id: "copilot",
        name: "GitHub Copilot",
        folder: Folder::Agents,
        home_markers: &[".copilot"],
    },
    Agent {
        id: "gemini",
        name: "Gemini CLI",
        folder: Folder::Agents,
        home_markers: &[".gemini"],
    },
    Agent {
        id: "opencode",
        name: "OpenCode",
        folder: Folder::Agents,
        home_markers: &[".config/opencode"],
    },
    Agent {
        id: "cursor",
        name: "Cursor",
        folder: Folder::Agents,
        home_markers: &[".cursor"],
    },
];

pub fn agent(id: &str) -> Option<&'static Agent> {
    AGENTS.iter().find(|a| a.id == id)
}

/// The agents whose config directory exists under `home`.
pub fn detect(home: &Path) -> Vec<&'static Agent> {
    AGENTS
        .iter()
        .filter(|a| a.home_markers.iter().any(|m| home.join(m).is_dir()))
        .collect()
}

/// The skill's text for the command named `bin` ("bulwarkctl", or "bulwark" from the desktop app).
pub fn render(bin: &str) -> String {
    TEMPLATE
        .replace("{bin}", bin)
        .replace("{version}", env!("CARGO_PKG_VERSION"))
}

/// Where the skill goes for `folder` under `base` (a home directory or a project root).
pub fn skill_path(base: &Path, folder: Folder) -> PathBuf {
    base.join(folder.rel()).join(SKILL_NAME).join("SKILL.md")
}

/// What is at a skill location now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum State {
    Missing,
    /// Bulwark's skill, exactly as this version would write it.
    Current,
    /// Bulwark's skill from another version, or with another command name.
    Outdated {
        version: Option<String>,
    },
    /// A `SKILL.md` Bulwark didn't write. Left alone.
    Foreign,
    /// The path (or a folder on the way to it) is a symlink, or not a regular file. Left alone.
    Unsafe {
        reason: String,
    },
}

/// The state of the skill at `path`, compared with what `bin` would produce.
pub fn state(path: &Path, bin: &str) -> State {
    if let Some(reason) = unsafe_component(path) {
        return State::Unsafe { reason };
    }
    match fs::read_to_string(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::Missing,
        Err(e) => State::Unsafe {
            reason: format!("can't read it: {e}"),
        },
        Ok(text) if !is_ours(&text) => State::Foreign,
        Ok(text) if text == render(bin) => State::Current,
        Ok(text) => State::Outdated {
            version: version_of(&text),
        },
    }
}

fn is_ours(text: &str) -> bool {
    frontmatter(text).is_some_and(|f| f.lines().any(|l| l.trim() == MARKER))
}

fn version_of(text: &str) -> Option<String> {
    frontmatter(text)?.lines().find_map(|l| {
        let v = l.trim().strip_prefix("version:")?.trim();
        Some(v.trim_matches('"').to_string())
    })
}

fn frontmatter(text: &str) -> Option<&str> {
    let rest = text.strip_prefix("---\n")?;
    Some(&rest[..rest.find("\n---")?])
}

/// A symlink anywhere from the skills folder down — `.claude`, `skills`, `bulwark` or the file —
/// would let whoever planted it redirect the write, so it is refused rather than followed.
fn unsafe_component(path: &Path) -> Option<String> {
    // The skill file, its `bulwark` folder, `skills`, and the agent folder (`.claude`/`.agents`).
    let mut p = Some(path);
    for _ in 0..4 {
        let here = p?;
        if let Ok(meta) = fs::symlink_metadata(here) {
            if meta.file_type().is_symlink() {
                return Some(format!("{} is a symbolic link", here.display()));
            }
            if here == path && !meta.is_file() {
                return Some(format!("{} is not a regular file", here.display()));
            }
        }
        p = here.parent();
    }
    None
}

/// What [`install`] or [`remove`] did at one location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Installed,
    Updated,
    AlreadyCurrent,
    Removed,
    NotInstalled,
    /// Refused: a foreign or unsafe file is there. The string says why.
    Skipped(String),
}

/// Writes the skill to `path` unless something Bulwark didn't write is there.
pub fn install(path: &Path, bin: &str) -> std::io::Result<Outcome> {
    let outcome = match state(path, bin) {
        State::Current => return Ok(Outcome::AlreadyCurrent),
        State::Foreign => {
            return Ok(Outcome::Skipped(
                "a skill named bulwark is already there, and Bulwark didn't write it".into(),
            ))
        }
        State::Unsafe { reason } => return Ok(Outcome::Skipped(reason)),
        State::Missing => Outcome::Installed,
        State::Outdated { .. } => Outcome::Updated,
    };
    let dir = path.parent().expect("skill path has a folder");
    fs::create_dir_all(dir)?;
    // create_dir_all follows symlinks, so check again now the folders exist.
    if let Some(reason) = unsafe_component(path) {
        return Ok(Outcome::Skipped(reason));
    }
    // Written beside it and renamed over, so an agent never reads half a file.
    let tmp = dir.join(".SKILL.md.bulwark-tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(render(bin).as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(outcome)
}

/// Removes the skill at `path` if Bulwark wrote it, and its `bulwark` folder if that is then empty.
pub fn remove(path: &Path, bin: &str) -> std::io::Result<Outcome> {
    match state(path, bin) {
        State::Missing => Ok(Outcome::NotInstalled),
        State::Foreign => Ok(Outcome::Skipped(
            "this skill named bulwark wasn't written by Bulwark".into(),
        )),
        State::Unsafe { reason } => Ok(Outcome::Skipped(reason)),
        State::Current | State::Outdated { .. } => {
            fs::remove_file(path)?;
            if let Some(dir) = path.parent() {
                let _ = fs::remove_dir(dir); // only succeeds when empty
            }
            Ok(Outcome::Removed)
        }
    }
}

/// The folders to write for `agents`, each once, in a stable order.
pub fn folders_for(agents: &[&Agent]) -> Vec<Folder> {
    let mut f: Vec<Folder> = agents.iter().map(|a| a.folder).collect();
    f.sort();
    f.dedup();
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_skill_is_valid_for_every_agent() {
        let text = render("bulwarkctl");
        let fm = frontmatter(&text).expect("frontmatter");
        // OpenCode: name matches the folder, lowercase-hyphen, 1–64 chars; description 1–1024.
        assert!(fm.lines().any(|l| l == "name: bulwark"));
        let desc = fm
            .lines()
            .find_map(|l| l.strip_prefix("description: "))
            .unwrap();
        assert!((1..=1024).contains(&desc.chars().count()), "{}", desc.len());
        assert!(!text.contains("{bin}") && !text.contains("{version}"));
        assert!(text.contains("`bulwarkctl ai scan --target .`"));
        assert_eq!(
            version_of(&text).as_deref(),
            Some(env!("CARGO_PKG_VERSION"))
        );
        // Valid YAML, with the fields every agent requires.
        let y: serde_yaml::Value = serde_yaml::from_str(fm).unwrap();
        assert_eq!(y["name"].as_str(), Some("bulwark"));
        assert!(y["allowed-tools"].as_sequence().is_some());
    }

    #[test]
    fn nothing_that_changes_the_machine_is_pre_approved() {
        let text = render("bulwarkctl");
        let y: serde_yaml::Value = serde_yaml::from_str(frontmatter(&text).unwrap()).unwrap();
        for tool in y["allowed-tools"].as_sequence().unwrap() {
            let t = tool.as_str().unwrap();
            assert!(!t.contains("apply") && !t.contains("sudo"), "{t}");
            assert!(
                !t.starts_with("Bash(bulwarkctl fix *")
                    && !t.starts_with("Bash(bulwarkctl ai redact *"),
                "{t} would also approve --apply"
            );
        }
    }

    #[test]
    fn install_update_and_remove_round_trip() {
        let home = tempfile::tempdir().unwrap();
        let p = skill_path(home.path(), Folder::Agents);
        assert_eq!(state(&p, "bulwarkctl"), State::Missing);
        assert_eq!(install(&p, "bulwarkctl").unwrap(), Outcome::Installed);
        assert_eq!(state(&p, "bulwarkctl"), State::Current);
        assert_eq!(install(&p, "bulwarkctl").unwrap(), Outcome::AlreadyCurrent);
        // Another command name (the desktop app's `bulwark`) is an update, not a conflict.
        assert!(matches!(state(&p, "bulwark"), State::Outdated { .. }));
        assert_eq!(install(&p, "bulwark").unwrap(), Outcome::Updated);
        assert!(fs::read_to_string(&p).unwrap().contains("`bulwark scan`"));
        assert_eq!(remove(&p, "bulwark").unwrap(), Outcome::Removed);
        assert!(
            !p.parent().unwrap().exists(),
            "the empty bulwark folder goes too"
        );
        assert!(
            home.path().join(".agents/skills").is_dir(),
            "but not the shared folder"
        );
        assert_eq!(remove(&p, "bulwark").unwrap(), Outcome::NotInstalled);
    }

    #[test]
    fn an_older_version_is_outdated() {
        let home = tempfile::tempdir().unwrap();
        let p = skill_path(home.path(), Folder::Claude);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        let old = render("bulwarkctl").replace(env!("CARGO_PKG_VERSION"), "0.0.1");
        fs::write(&p, old).unwrap();
        assert_eq!(
            state(&p, "bulwarkctl"),
            State::Outdated {
                version: Some("0.0.1".into())
            }
        );
        assert_eq!(install(&p, "bulwarkctl").unwrap(), Outcome::Updated);
    }

    #[test]
    fn a_skill_bulwark_did_not_write_is_never_touched() {
        let home = tempfile::tempdir().unwrap();
        let p = skill_path(home.path(), Folder::Claude);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        let mine = "---\nname: bulwark\ndescription: my own notes\n---\nhello\n";
        fs::write(&p, mine).unwrap();
        assert_eq!(state(&p, "bulwarkctl"), State::Foreign);
        assert!(matches!(
            install(&p, "bulwarkctl").unwrap(),
            Outcome::Skipped(_)
        ));
        assert!(matches!(
            remove(&p, "bulwarkctl").unwrap(),
            Outcome::Skipped(_)
        ));
        assert_eq!(fs::read_to_string(&p).unwrap(), mine);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_on_the_way_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        // ~/.agents/skills -> somewhere else: writing would land outside the skills folder.
        fs::create_dir_all(home.path().join(".agents")).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), home.path().join(".agents/skills")).unwrap();
        let p = skill_path(home.path(), Folder::Agents);
        assert!(matches!(state(&p, "bulwarkctl"), State::Unsafe { .. }));
        assert!(matches!(
            install(&p, "bulwarkctl").unwrap(),
            Outcome::Skipped(_)
        ));
        assert!(fs::read_dir(elsewhere.path()).unwrap().next().is_none());
    }

    #[test]
    fn detection_and_folders() {
        let home = tempfile::tempdir().unwrap();
        assert!(detect(home.path()).is_empty());
        fs::create_dir_all(home.path().join(".codex")).unwrap();
        fs::create_dir_all(home.path().join(".config/opencode")).unwrap();
        let found = detect(home.path());
        assert_eq!(
            found.iter().map(|a| a.id).collect::<Vec<_>>(),
            ["codex", "opencode"]
        );
        assert_eq!(folders_for(&found), [Folder::Agents]);
        let all: Vec<&Agent> = AGENTS.iter().collect();
        assert_eq!(folders_for(&all), [Folder::Claude, Folder::Agents]);
    }
}
