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
//!
//! `--project DIR` installs into a repository, and a repository is written by someone else. So
//! the file is first written under a name nobody could have planted (random, created
//! exclusively, never through a link) and only then moved into place; and the command name that
//! goes into the skill's pre-approved commands is accepted only when it is a plain program name
//! or path ([`valid_command`]), because that text decides what an agent may run without asking.

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

/// Whether `cmd` may be written into the skill as the command agents run.
///
/// The name lands in `allowed-tools` lines such as `Bash(<cmd> ai scan *)`, which pre-approve
/// commands. A newline in it adds lines of its own; a `*` turns `Bash(* scan *)` into approval of
/// nearly anything. So it must be a program name, or an absolute path, made only of letters,
/// digits and `. _ - +` — nothing a shell or a pattern gives meaning to, and no spaces.
pub fn valid_command(cmd: &str) -> bool {
    let plain = |part: &str| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && !part.starts_with('-')
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
    };
    if cmd.is_empty() || cmd.len() > 255 {
        return false;
    }
    if !Path::new(cmd).is_absolute() {
        return plain(cmd);
    }
    // An absolute path: `/usr/bin/x`, or `C:\tools\x.exe` on Windows.
    let is_drive = |part: &str| {
        let b = part.as_bytes();
        cfg!(windows) && b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
    };
    let separators: &[char] = if cfg!(windows) { &['/', '\\'] } else { &['/'] };
    let mut parts = cmd.split(separators);
    let first = parts.next().unwrap_or_default();
    (first.is_empty() || is_drive(first)) && parts.all(plain)
}

/// What the message says when [`valid_command`] refuses a name.
pub const COMMAND_RULE: &str =
    "a program name or an absolute path, made only of letters, digits and . _ - +";

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
        Ok(text) if without_record(&text) == render(bin) => State::Current,
        Ok(text) => State::Outdated {
            version: version_of(&text),
        },
    }
}

/// The frontmatter line (under `metadata:`) recording how many folders above the skill's own the
/// install had to make: 1 for `skills`, 2 when the agent's folder (`.claude`, `.agents`) was not
/// there either. Removing the skill takes those folders away again if they are empty, so
/// installing for an agent that is not on the machine and then removing does not leave an empty
/// `~/.claude` behind — which is what makes Claude Code show as "found".
const CREATED_KEY: &str = "  created-folders: ";

fn created_folders(text: &str) -> usize {
    frontmatter(text)
        .and_then(|f| f.lines().find_map(|l| l.strip_prefix(CREATED_KEY)))
        .and_then(|v| v.trim().trim_matches('"').parse::<usize>().ok())
        // Never more than the two folders an install can make, whatever a file claims.
        .map_or(0, |n| n.min(2))
}

fn with_record(text: String, created: usize) -> String {
    if created == 0 {
        return text;
    }
    text.replacen(
        "\n---\n",
        &format!("\n{CREATED_KEY}\"{created}\"\n---\n"),
        1,
    )
}

/// The skill's text without the record line, for comparing with what [`render`] produces.
fn without_record(text: &str) -> String {
    let Some(end) = text.find("\n---\n") else {
        return text.to_string();
    };
    let (head, rest) = text.split_at(end);
    let kept: Vec<&str> = head
        .lines()
        .filter(|l| !l.starts_with(CREATED_KEY))
        .collect();
    format!("{}{rest}", kept.join("\n"))
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
    if !valid_command(bin) {
        return Ok(Outcome::Skipped(format!(
            "the command name is not {COMMAND_RULE}"
        )));
    }
    let (outcome, mut created) = match state(path, bin) {
        State::Current => return Ok(Outcome::AlreadyCurrent),
        State::Foreign => {
            return Ok(Outcome::Skipped(
                "a skill named bulwark is already there, and Bulwark didn't write it".into(),
            ))
        }
        State::Unsafe { reason } => return Ok(Outcome::Skipped(reason)),
        State::Missing => (Outcome::Installed, 0),
        // An update keeps what the first install recorded.
        State::Outdated { .. } => (
            Outcome::Updated,
            fs::read_to_string(path).map_or(0, |t| created_folders(&t)),
        ),
    };
    let dir = path.parent().expect("skill path has a folder");
    // Which of the two folders above the skill's own this install is about to make.
    let absent = |d: Option<&Path>| {
        d.is_some_and(|d| {
            fs::symlink_metadata(d).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        })
    };
    let skills = dir.parent();
    let agent = skills.and_then(Path::parent);
    created = created.max(usize::from(absent(skills)) + usize::from(absent(agent)));
    fs::create_dir_all(dir)?;
    // create_dir_all follows symlinks, so check again now the folders exist.
    if let Some(reason) = unsafe_component(path) {
        return Ok(Outcome::Skipped(reason));
    }
    // Written beside it and renamed over, so an agent never reads half a file. The temporary
    // name is random and the file is created exclusively and never through a link: a fixed name
    // could be planted in a repository as a link, and the skill's text was then written into
    // whatever it pointed at (the user's authorized_keys, say).
    let tmp = dir.join(format!(".SKILL.md.{}.tmp", uuid::Uuid::new_v4().simple()));
    let written = (|| {
        let mut f = create_new_no_follow(&tmp)?;
        f.write_all(with_record(render(bin), created).as_bytes())?;
        f.sync_all()
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    // The last look before the move: the destination must still not be a link, nor anything
    // above it. (A rename replaces a link rather than following it, but a link put there since
    // the first check means someone else is writing here, and that is a reason to stop.)
    if let Some(reason) = unsafe_component(path) {
        let _ = fs::remove_file(&tmp);
        return Ok(Outcome::Skipped(reason));
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(outcome)
}

#[cfg(unix)]
fn create_new_no_follow(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn create_new_no_follow(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Removes the skill at `path` if Bulwark wrote it, its `bulwark` folder if that is then empty,
/// and — when empty — the folders above it that the install itself had to make.
pub fn remove(path: &Path, bin: &str) -> std::io::Result<Outcome> {
    match state(path, bin) {
        State::Missing => Ok(Outcome::NotInstalled),
        State::Foreign => Ok(Outcome::Skipped(
            "this skill named bulwark wasn't written by Bulwark".into(),
        )),
        State::Unsafe { reason } => Ok(Outcome::Skipped(reason)),
        State::Current | State::Outdated { .. } => {
            let created = fs::read_to_string(path).map_or(0, |t| created_folders(&t));
            fs::remove_file(path)?;
            // `remove_dir` only succeeds on an empty folder, so nothing of anyone's is lost.
            let mut dir = path.parent();
            for _ in 0..=created {
                match dir {
                    Some(d) if fs::remove_dir(d).is_ok() => dir = d.parent(),
                    _ => break,
                }
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
        let y = crate::yaml::to_json(fm).unwrap();
        assert_eq!(y["name"].as_str(), Some("bulwark"));
        assert!(y["allowed-tools"].as_array().is_some());
    }

    #[test]
    fn nothing_that_changes_the_machine_is_pre_approved() {
        let text = render("bulwarkctl");
        let y = crate::yaml::to_json(frontmatter(&text).unwrap()).unwrap();
        for tool in y["allowed-tools"].as_array().unwrap() {
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
        // The user already has a skills folder of their own.
        fs::create_dir_all(home.path().join(".agents/skills")).unwrap();
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
            "but not a folder that was there before the install"
        );
        assert_eq!(remove(&p, "bulwark").unwrap(), Outcome::NotInstalled);
    }

    #[test]
    fn folders_the_install_made_are_removed_with_the_skill_when_empty() {
        // Installing for an agent that is not on this machine made ~/.claude, and removing the
        // skill left ~/.claude/skills behind — after which that agent was listed as "found".
        let home = tempfile::tempdir().unwrap();
        for folder in [Folder::Claude, Folder::Agents] {
            let p = skill_path(home.path(), folder);
            assert_eq!(install(&p, "bulwarkctl").unwrap(), Outcome::Installed);
            assert_eq!(
                state(&p, "bulwarkctl"),
                State::Current,
                "the record is not a change"
            );
        }
        assert_eq!(detect(home.path()).len(), 1, "installing made ~/.claude");
        // An update keeps the record of what the first install made.
        let p = skill_path(home.path(), Folder::Claude);
        assert_eq!(install(&p, "bulwark").unwrap(), Outcome::Updated);
        for folder in [Folder::Claude, Folder::Agents] {
            let p = skill_path(home.path(), folder);
            assert_eq!(remove(&p, "bulwark").unwrap(), Outcome::Removed);
        }
        assert!(!home.path().join(".claude").exists());
        assert!(!home.path().join(".agents").exists());
        assert!(
            detect(home.path()).is_empty(),
            "nothing is \"found\" that was not there"
        );

        // The agent's folder was there, its skills folder was not: only `skills` goes.
        fs::create_dir_all(home.path().join(".claude")).unwrap();
        fs::write(home.path().join(".claude/settings.json"), "{}").unwrap();
        assert_eq!(install(&p, "bulwarkctl").unwrap(), Outcome::Installed);
        assert_eq!(remove(&p, "bulwarkctl").unwrap(), Outcome::Removed);
        assert!(!home.path().join(".claude/skills").exists());
        assert!(home.path().join(".claude/settings.json").is_file());

        // Something else moved into a folder the install made: it stays.
        assert_eq!(install(&p, "bulwarkctl").unwrap(), Outcome::Installed);
        fs::create_dir_all(home.path().join(".claude/skills/other")).unwrap();
        assert_eq!(remove(&p, "bulwarkctl").unwrap(), Outcome::Removed);
        assert!(home.path().join(".claude/skills/other").is_dir());

        // A file that claims more than an install can have made is not believed past two levels.
        let deep = home.path().join("a/b/c/.agents/skills/bulwark/SKILL.md");
        fs::create_dir_all(deep.parent().unwrap()).unwrap();
        fs::write(
            &deep,
            with_record(render("bulwarkctl"), 2).replace("\"2\"", "\"9\""),
        )
        .unwrap();
        assert_eq!(remove(&deep, "bulwarkctl").unwrap(), Outcome::Removed);
        assert!(home.path().join("a/b/c").is_dir());
        assert!(!home.path().join("a/b/c/.agents").exists());
    }

    /// A repository contains `.claude/skills/bulwark/.SKILL.md.bulwark-tmp`, a link to a file of
    /// the user's. `agent install --project` wrote the skill's text through it.
    #[cfg(unix)]
    #[test]
    fn a_planted_temporary_file_is_not_written_through() {
        use std::os::unix::fs::symlink;
        let repo = tempfile::tempdir().unwrap();
        let victim_dir = tempfile::tempdir().unwrap();
        let victim = victim_dir.path().join("authorized_keys");
        fs::write(&victim, "ssh-ed25519 AAAA only-copy\n").unwrap();
        let p = skill_path(repo.path(), Folder::Claude);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        // The name the installer used to write to, and a few it might be thought to use.
        for name in [".SKILL.md.bulwark-tmp", ".SKILL.md.tmp", "SKILL.md.tmp"] {
            symlink(&victim, p.parent().unwrap().join(name)).unwrap();
        }

        assert_eq!(install(&p, "bulwarkctl").unwrap(), Outcome::Installed);
        assert_eq!(
            fs::read_to_string(&victim).unwrap(),
            "ssh-ed25519 AAAA only-copy\n",
            "the file the link points at must be byte-for-byte unchanged"
        );
        let meta = fs::symlink_metadata(&p).unwrap();
        assert!(
            meta.is_file(),
            "SKILL.md must be a real file, not the planted link"
        );
        assert_eq!(state(&p, "bulwarkctl"), State::Current);
        // No temporary file of ours is left beside it.
        let ours: Vec<_> = fs::read_dir(p.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp") && !n.ends_with("SKILL.md.tmp"))
            .collect();
        assert!(ours.is_empty(), "{ours:?}");

        // The destination itself planted as a link is refused, as before.
        let repo2 = tempfile::tempdir().unwrap();
        let p2 = skill_path(repo2.path(), Folder::Agents);
        fs::create_dir_all(p2.parent().unwrap()).unwrap();
        symlink(&victim, &p2).unwrap();
        assert!(matches!(
            install(&p2, "bulwarkctl").unwrap(),
            Outcome::Skipped(_)
        ));
        assert_eq!(
            fs::read_to_string(&victim).unwrap(),
            "ssh-ed25519 AAAA only-copy\n"
        );
    }

    #[test]
    fn only_a_plain_command_name_goes_into_the_pre_approved_commands() {
        for good in ["bulwarkctl", "bulwark", "bulwarkctl-0.15", "my_tool.v2"] {
            assert!(valid_command(good), "{good}");
        }
        #[cfg(unix)]
        for good in ["/usr/bin/bulwarkctl", "/opt/bulwark-0.15/bin/bulwark"] {
            assert!(valid_command(good), "{good}");
        }
        for bad in [
            "",
            "*",
            "bulwarkctl\n  - Bash(*)",
            "bulwarkctl ai redact --apply",
            "bulwark ctl",
            "$(id)",
            "`id`",
            "a;b",
            "a|b",
            "a&&b",
            "a)",
            "-rf",
            "./bulwarkctl",
            "../bulwarkctl",
            "bin/bulwarkctl",
            "/usr/bin/../bin/x",
            "/usr/bin/*",
            "/usr/my tools/x",
            "bulwarkctl\u{0}",
            "бульварк",
        ] {
            assert!(!valid_command(bad), "{bad:?} must be refused");
        }
        assert!(!valid_command(&"a".repeat(300)));

        // And the installer itself refuses, whatever its caller checked.
        let home = tempfile::tempdir().unwrap();
        let p = skill_path(home.path(), Folder::Claude);
        for bad in ["*", "bulwarkctl\n  - Bash(*)"] {
            assert!(matches!(install(&p, bad).unwrap(), Outcome::Skipped(_)));
        }
        assert!(!home.path().join(".claude").exists(), "nothing was written");
        // Every pre-approved line of a rendered skill starts with the command and nothing else.
        let text = render("bulwarkctl");
        let y = crate::yaml::to_json(frontmatter(&text).unwrap()).unwrap();
        for tool in y["allowed-tools"].as_array().unwrap() {
            assert!(tool.as_str().unwrap().starts_with("Bash(bulwarkctl "));
        }
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
