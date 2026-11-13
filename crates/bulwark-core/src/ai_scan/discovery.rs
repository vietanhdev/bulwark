//! Finding *what to scan*: the AI coding-assistant artifacts a developer's machine actually
//! holds. Two sources feed the list:
//!
//! 1. **Global tool state** under `$HOME` — `~/.claude/`, `~/.codex/`, `~/.cursor/`,
//!    `~/.gemini/`, `~/.aider.conf.yml`, and friends. Fixed, known locations.
//! 2. **Workspaces** — project directories that contain an AI marker (`.claude/`, `CLAUDE.md`,
//!    `.cursor/`, `.mcp.json`, `AGENTS.md`, …). These are discovered, not hardcoded, because
//!    every developer's project layout is different. We derive them three ways: the projects
//!    Claude Code has recorded under `~/.claude/projects/` (validated back to a real path so a
//!    lossy decode can never invent a root), a shallow sweep of the common code roots
//!    (`~/Workspaces`, `~/Projects`, `~/src`, …), and any roots the user configured explicitly.
//!
//! Everything here takes paths as parameters and touches only the filesystem, so it's testable
//! against a `tempdir` without a real home directory — the same discipline the collectors keep.

use crate::homefs;
use std::path::{Path, PathBuf};

/// Which assistant an artifact belongs to — the label a finding shows so a user knows *which*
/// tool's config to go fix.
pub fn tool_label(tool: Tool) -> &'static str {
    match tool {
        Tool::ClaudeCode => "Claude Code",
        Tool::ClaudeDesktop => "Claude Desktop",
        Tool::Cursor => "Cursor",
        Tool::Copilot => "GitHub Copilot",
        Tool::Codex => "OpenAI Codex",
        Tool::Gemini => "Gemini CLI",
        Tool::Qwen => "Qwen Code",
        Tool::Aider => "Aider",
        Tool::Continue => "Continue",
        Tool::Windsurf => "Windsurf / Devin Desktop",
        Tool::Cline => "Cline / Roo",
        Tool::Kilo => "Kilo Code",
        Tool::AmazonQ => "Amazon Q",
        Tool::Kiro => "Kiro",
        Tool::Zed => "Zed",
        Tool::Goose => "Goose",
        Tool::OpenCode => "OpenCode",
        Tool::Crush => "Crush",
        Tool::Amp => "Amp",
        Tool::Augment => "Augment",
        Tool::JetBrains => "JetBrains Junie / AI Assistant",
        Tool::Warp => "Warp",
        Tool::OpenInterpreter => "Open Interpreter",
        Tool::VsCode => "VS Code / editor",
        Tool::Generic => "AI assistant",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    ClaudeCode,
    ClaudeDesktop,
    Cursor,
    Copilot,
    Codex,
    Gemini,
    Qwen,
    Aider,
    Continue,
    Windsurf,
    Cline,
    Kilo,
    AmazonQ,
    Kiro,
    Zed,
    Goose,
    OpenCode,
    Crush,
    Amp,
    Augment,
    JetBrains,
    Warp,
    OpenInterpreter,
    VsCode,
    Generic,
}

/// What *kind* of artifact a file is, which decides which detectors run over it. A file's kind
/// is how we know to parse it as MCP JSON vs. scan it as free-text instructions vs. treat it as
/// a credential store whose permissions matter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    /// Free-text model instructions (`CLAUDE.md`, `.cursorrules`, `copilot-instructions.md`).
    Instructions,
    /// Agent settings (`.claude/settings.json`, `.vscode/settings.json`, Goose's `config.yaml`).
    Settings,
    /// An MCP server manifest (`.mcp.json`, `~/.cursor/mcp.json`, …) in JSON, YAML or TOML.
    McpConfig,
    /// VS Code tasks (`.vscode/tasks.json`) — auto-run-on-open surface.
    Tasks,
    /// A file whose whole job is to run commands on agent events: `.cursor/hooks.json`,
    /// `.kiro/hooks/*`, `.github/hooks/*.json`, `.clinerules/hooks/*`, a project `crushrc`. Only a
    /// *project*-supplied one is a finding (the CVE-2025-59536 shape); your own are yours.
    Hooks,
    /// A chat/session transcript (`~/.claude/projects/**/*.jsonl`, `.aider.chat.history.md`).
    Transcript,
    /// A credential/token store whose *permissions* are the finding (`~/.claude/.credentials.json`).
    Credential,
    /// A dotenv file (`.env`, `~/.gemini/.env`).
    DotEnv,
    /// Codex `config.toml` — TOML settings with its own sandbox/approval keys.
    CodexConfig,
    /// An agent's persistent memory (`~/.claude/projects/<proj>/memory/*.md`,
    /// `~/.claude/CLAUDE.md`): notes the agent re-reads every session, so a pasted key lives on.
    Memory,
}

/// One discovered thing worth looking at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub path: PathBuf,
    pub tool: Tool,
    pub kind: ArtifactKind,
    /// The workspace this artifact belongs to, if it's project-scoped (used for git/gitignore
    /// leak-surface checks). `None` for global `$HOME` state.
    pub workspace: Option<PathBuf>,
}

/// Common parent directories developers keep code under, swept one or two levels deep for
/// workspaces. Not exhaustive — the configured-roots and Claude-projects sources cover the rest.
pub const COMMON_CODE_ROOTS: &[&str] = &[
    "Workspaces",
    "Projects",
    "projects",
    "src",
    "dev",
    "Developer",
    "code",
    "Code",
    "git",
    "repos",
    "work",
];

/// Folders many projects have whether or not an AI agent is used there. A location inside one is
/// a marker by its full path (`.github/copilot-instructions.md`), never by the folder alone.
const SHARED_DIRS: &[&str] = &[".github", ".vscode"];

/// Locations that are checked when a project is scanned but say nothing about an agent being used
/// in a folder, so they do not make a folder a workspace on their own. Every entry needs a reason.
const NOT_A_MARKER: &[&str] = &[
    // Nearly every project has one; it is checked for exposed keys in projects found another way.
    ".env",
];

/// Markers that exist in very many projects (editor settings). A folder with only these is still
/// checked — `chat.tools.autoApprove` lives there — but it is the first to go when the workspace
/// limit is reached, and the sweep still looks one level below it for agent projects.
const WEAK_MARKERS: &[&str] = &[".vscode/settings.json", ".vscode/tasks.json"];

/// What makes a folder a workspace, derived from [`WORKSPACE_SPECS`] so the two cannot drift: a
/// location that is checked is a location that gets a project found.
struct Markers {
    /// Names directly in the project folder: an agent's own folder (`.claude`) or a file
    /// (`CLAUDE.md`).
    top: std::collections::HashSet<&'static str>,
    /// Full paths inside a shared folder, by that folder's name; the flag is "weak".
    shared: Vec<(&'static str, &'static str, bool)>,
}

/// The marker for one spec location: the first path component, or the whole path inside a shared
/// folder. `None` for the few locations that are deliberately not markers.
fn marker_for(rel: &'static str) -> Option<&'static str> {
    if NOT_A_MARKER.contains(&rel) {
        return None;
    }
    let first = rel.split('/').next().unwrap_or(rel);
    Some(if SHARED_DIRS.contains(&first) {
        rel
    } else {
        first
    })
}

fn markers() -> &'static Markers {
    static MARKERS: std::sync::OnceLock<Markers> = std::sync::OnceLock::new();
    MARKERS.get_or_init(|| {
        let mut top = std::collections::HashSet::new();
        let mut shared: Vec<(&'static str, &'static str, bool)> = Vec::new();
        for Spec(rel, ..) in WORKSPACE_SPECS {
            let Some(marker) = marker_for(rel) else {
                continue;
            };
            match marker.split_once('/') {
                Some((dir, _)) => {
                    if !shared.iter().any(|(_, full, _)| *full == marker) {
                        shared.push((dir, marker, WEAK_MARKERS.contains(&marker)));
                    }
                }
                None => {
                    top.insert(marker);
                }
            }
        }
        Markers { top, shared }
    })
}

/// Directory names never worth descending into during the workspace sweep — dependency and VCS
/// trees that would make discovery slow and could contain thousands of vendored `CLAUDE.md`-like
/// files that aren't the user's own project.
const SWEEP_SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".cache",
    "vendor",
    ".next",
];

/// What one look at a folder found.
#[derive(Default)]
struct Look {
    /// An agent's own marker is here.
    strong: bool,
    /// Only editor-level markers are here.
    weak: bool,
    /// The folders inside it (filled in only when asked for).
    subdirs: Vec<PathBuf>,
}

/// Lists `dir` once and says which markers it holds. One directory listing replaces a `stat` per
/// marker, which matters when a code root holds hundreds of folders. `Err` when the folder cannot
/// be listed.
fn look(dir: &Path, want_subdirs: bool) -> std::io::Result<Look> {
    let table = markers();
    let mut found = Look::default();
    let mut shared_present: Vec<&'static str> = Vec::new();
    for entry in std::fs::read_dir(dir)?.flatten() {
        let name = entry.file_name();
        if let Some(name) = name.to_str() {
            if table.top.contains(name) {
                found.strong = true;
            }
            if let Some(dir) = SHARED_DIRS.iter().find(|d| **d == name) {
                shared_present.push(*dir);
            }
        }
        if want_subdirs {
            // The entry's own type where it is a folder; a link is followed with one `stat`.
            let is_dir = match entry.file_type() {
                Ok(t) if t.is_dir() => true,
                Ok(t) if t.is_symlink() => entry.path().is_dir(),
                _ => false,
            };
            if is_dir {
                found.subdirs.push(entry.path());
            }
        }
    }
    for (shared_dir, full, weak) in &table.shared {
        if found.strong {
            break; // nothing more to learn
        }
        if !shared_present.contains(shared_dir) {
            continue;
        }
        if dir.join(full).exists() {
            if *weak {
                found.weak = true;
            } else {
                found.strong = true;
            }
        }
    }
    Ok(found)
}

fn has_any_marker(dir: &Path) -> bool {
    look(dir, false).is_ok_and(|l| l.strong || l.weak)
}

/// Decodes a `~/.claude/projects/` directory name back to the absolute path it encodes. Claude
/// Code replaces every `/` in the project path with `-` (so `/home/u/proj` → `-home-u-proj`),
/// which is lossy — a real `-` in a path segment is indistinguishable from a separator. Rather
/// than guess, we only ever *validate*: reconstruct the obvious candidate and return it solely
/// if it's a real directory on this machine, so a wrong decode can never inject a phantom root.
fn decode_claude_project_dir(encoded: &str) -> Option<PathBuf> {
    if !encoded.starts_with('-') {
        return None;
    }
    let candidate = PathBuf::from(encoded.replacen('-', "/", 1).replace('-', "/"));
    candidate.is_dir().then_some(candidate)
}

/// How much of a transcript is read to find the folder it was recorded in.
const CWD_READ_BYTES: u64 = 64 * 1024;
/// How many transcripts of one project are tried.
const CWD_FILES_TRIED: usize = 3;
/// How many project folders get this second look in one scan. Each is a folder listing and a
/// read of at most [`CWD_FILES_TRIED`] × [`CWD_READ_BYTES`]; going past the limit is reported.
const MAX_CWD_LOOKUPS: usize = 5000;

/// The way Claude Code turns a project path into a folder name: every character that is not a
/// letter or digit becomes `-`. Applied to both sides before comparing, so an older release that
/// kept a few more characters still matches.
fn claude_project_name(path: &str) -> String {
    path.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// The project folder a `~/.claude/projects/<name>` directory belongs to, read from the `cwd` its
/// transcripts record. This is what finds a project whose path contains a `-`, `.` or `_`, where
/// [`decode_claude_project_dir`] cannot tell a separator from the real character.
///
/// The value is text from a file, so it is trusted only as far as it can be checked: it must be an
/// absolute path, a folder that exists, and one whose name encodes back to this very directory
/// name — a transcript cannot point the scan at an unrelated place.
fn project_dir_from_transcripts(home: &homefs::Root, dir: &Path, name: &str) -> Option<PathBuf> {
    let wanted = claude_project_name(name);
    let transcripts = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .take(CWD_FILES_TRIED);
    for transcript in transcripts {
        let Some(file) = home.try_open(&transcript).ok().flatten() else {
            continue;
        };
        let Some(text) = homefs::read_start(file, CWD_READ_BYTES) else {
            continue;
        };
        for (at, _) in text.match_indices("\"cwd\"") {
            let rest = text[at + 5..].trim_start();
            let Some(rest) = rest.strip_prefix(':') else {
                continue;
            };
            // A JSON string, with its escapes (a Windows path is written with `\\`).
            let mut values = serde_json::Deserializer::from_str(rest).into_iter::<String>();
            let Some(Ok(cwd)) = values.next() else {
                continue;
            };
            let path = PathBuf::from(&cwd);
            if path.is_absolute() && claude_project_name(&cwd) == wanted && path.is_dir() {
                return Some(path);
            }
        }
    }
    None
}

/// The workspaces of one scan, and what finding them ran into.
#[derive(Debug, Default)]
pub struct Workspaces {
    pub roots: Vec<PathBuf>,
    /// More were found than `max_workspaces` allows; `roots` holds the first of them.
    pub capped: bool,
    /// Folders that exist but could not be looked into.
    pub problems: Vec<String>,
    /// For each excluded folder, in the order given: whether it took a workspace out.
    pub exclusions_used: Vec<bool>,
}

/// Whether `path` is `dir` or inside it, comparing the real locations as well as the names given,
/// so a relative path, a link or a trailing slash does not make an exclusion miss.
pub(crate) fn is_under(path: &Path, dir: &Path, dir_real: Option<&Path>) -> bool {
    if path.starts_with(dir) {
        return true;
    }
    let Some(dir_real) = dir_real else {
        return false;
    };
    path.starts_with(dir_real)
        || std::fs::canonicalize(path).is_ok_and(|real| real.starts_with(dir_real))
}

/// Discovers workspace roots from all three sources, de-duplicated. `configured_roots` are
/// user-added directories (each swept like a common root); a workspace at or under an `excluded`
/// folder is dropped even if a marker is present. `max_workspaces` caps the result so a
/// pathological home directory can't make a scan unbounded — the cap being hit is worth surfacing
/// to the user.
pub fn discover_workspaces(
    home: &Path,
    configured_roots: &[PathBuf],
    excluded: &[PathBuf],
    max_workspaces: usize,
) -> Vec<PathBuf> {
    find_workspaces(home, configured_roots, excluded, max_workspaces).roots
}

/// [`discover_workspaces`], also reporting whether the limit cut the list short and which folders
/// could not be listed.
pub fn find_workspaces(
    home: &Path,
    configured_roots: &[PathBuf],
    excluded: &[PathBuf],
    max_workspaces: usize,
) -> Workspaces {
    // Path → "an agent's own marker is here" (false: editor settings only).
    type Seen = std::collections::BTreeMap<PathBuf, bool>;
    fn add(found: &mut Seen, p: PathBuf, strong: bool) {
        *found.entry(p).or_insert(strong) |= strong;
    }
    let mut found = Seen::new();
    let mut problems = Vec::new();

    // Source 1: Claude Code's own record of every project it's opened.
    let projects_dir = home.join(".claude/projects");
    match std::fs::read_dir(&projects_dir) {
        Ok(entries) => {
            let home_root = homefs::Root::new(home);
            let mut lookups = 0usize;
            let mut not_looked_up = 0usize;
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if let Some(path) = decode_claude_project_dir(name) {
                    add(&mut found, path, true);
                } else if lookups < MAX_CWD_LOOKUPS {
                    lookups += 1;
                    if let Some(path) = home_root
                        .as_ref()
                        .and_then(|root| project_dir_from_transcripts(root, &entry.path(), name))
                    {
                        add(&mut found, path, true);
                    }
                } else {
                    not_looked_up += 1;
                }
            }
            if not_looked_up > 0 {
                problems.push(format!(
                    "{}: {not_looked_up} project records beyond the first {MAX_CWD_LOOKUPS} were \
                     not matched to their folders, so those projects' own files may not have been \
                     checked (their transcripts were)",
                    projects_dir.display()
                ));
            }
        }
        Err(e) => problems.extend(unlistable(&projects_dir, &e)),
    }

    // Source 2: a shallow sweep of the common code roots (plus configured roots).
    let sweep_roots: Vec<PathBuf> = COMMON_CODE_ROOTS
        .iter()
        .map(|r| home.join(r))
        .chain(configured_roots.iter().cloned())
        .collect();
    for root in sweep_roots {
        sweep_root(
            &root,
            &mut |p, strong| add(&mut found, p, strong),
            &mut problems,
        );
    }

    // A configured root can itself be a workspace, not just a container of them.
    for root in configured_roots {
        if root.is_dir() && has_any_marker(root) {
            add(&mut found, root.clone(), true);
        }
    }

    let excluded: Vec<(&Path, Option<PathBuf>)> = excluded
        .iter()
        .map(|p| (p.as_path(), std::fs::canonicalize(p).ok()))
        .collect();
    let mut exclusions_used = vec![false; excluded.len()];
    let kept: Vec<(PathBuf, bool)> = found
        .into_iter()
        .filter(|(p, _)| {
            let hit = excluded
                .iter()
                .position(|(ex, real)| is_under(p, ex, real.as_deref()));
            if let Some(i) = hit {
                exclusions_used[i] = true;
            }
            hit.is_none()
        })
        .collect();
    let capped = kept.len() > max_workspaces;
    // Agent projects first, so a home full of folders that only carry editor settings cannot
    // push a real agent project past the limit.
    let mut roots: Vec<PathBuf> = kept
        .iter()
        .filter(|(_, strong)| *strong)
        .chain(kept.iter().filter(|(_, strong)| !*strong))
        .take(max_workspaces)
        .map(|(p, _)| p.clone())
        .collect();
    roots.sort();
    Workspaces {
        roots,
        capped,
        problems,
        exclusions_used,
    }
}

/// The line for a folder that exists but could not be listed. A folder that is simply not there
/// is not a problem.
fn unlistable(dir: &Path, e: &std::io::Error) -> Option<String> {
    use std::io::ErrorKind::{NotADirectory, NotFound};
    (!matches!(e.kind(), NotFound | NotADirectory)).then(|| {
        format!(
            "{}: this folder could not be listed ({e}), so nothing in it was checked",
            dir.display()
        )
    })
}

/// Sweeps one container directory two levels deep for marker-bearing workspaces. Two levels
/// covers both `~/Projects/app` and `~/Projects/org/app` layouts without a full recursive walk.
fn sweep_root(root: &Path, add: &mut dyn FnMut(PathBuf, bool), problems: &mut Vec<String>) {
    let level1 = match look(root, true) {
        Ok(l) => l.subdirs,
        Err(e) => {
            problems.extend(unlistable(root, &e));
            return;
        }
    };
    for p1 in level1 {
        if is_skip_dir(&p1) {
            continue;
        }
        // A folder below a code root that cannot be listed (another account's, a container's
        // data volume) is passed over: only the code roots themselves are reported, or every
        // machine with a root-owned folder in ~/Projects would show a warning on each scan.
        let Ok(here) = look(&p1, true) else {
            continue;
        };
        if here.strong {
            add(p1, true);
            continue; // don't also descend into a directory that's already a workspace
        }
        if here.weak {
            add(p1.clone(), false);
        }
        for p2 in here.subdirs {
            if is_skip_dir(&p2) {
                continue;
            }
            match look(&p2, false) {
                Ok(l) if l.strong => add(p2, true),
                Ok(l) if l.weak => add(p2, false),
                _ => {}
            }
        }
    }
}

/// Inside an agent folder only *dependency and VCS* trees are skipped (an installed plugin can bundle
/// a whole `node_modules`). The wider `SWEEP_SKIP_DIRS` list (`build`, `dist`, `vendor`, …) is for
/// finding workspaces; applied here it would silently drop `.claude/skills/build/SKILL.md`.
const WALK_SKIP_DIRS: &[&str] = &["node_modules", ".git", ".venv", "__pycache__"];

fn is_dependency_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| WALK_SKIP_DIRS.contains(&n))
}

fn is_skip_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| SWEEP_SKIP_DIRS.contains(&n))
        .unwrap_or(false)
}

/// How one artifact location is matched on disk.
#[derive(Debug, Clone, Copy)]
enum Find {
    /// Exactly this file.
    File,
    /// Every file under this directory (recursively, bounded) with one of these extensions; an
    /// empty list means any file (hook *scripts* carry no extension).
    Dir(&'static [&'static str]),
    /// Every file with exactly this name anywhere under this directory (bounded) — for manifests
    /// nested inside installed plugins/extensions (`<plugin>/.mcp.json`).
    Named(&'static str),
    /// Like `Dir`, but only files below one of these folder names — an installed plugin's
    /// `commands/`, `agents/`, `skills/` are what the model loads; its README and CHANGELOG are not.
    DirUnder(&'static [&'static str], &'static [&'static str]),
}

/// One known artifact location, relative to a workspace root or to `$HOME`.
struct Spec(&'static str, Tool, ArtifactKind, Find);

use ArtifactKind::{
    CodexConfig, Credential, DotEnv, Hooks, Instructions, McpConfig, Memory, Settings, Tasks,
    Transcript,
};
use Find::{Dir, DirUnder, File, Named};
use Tool::*;

const MD: &[&str] = &["md"];
const MD_MDC: &[&str] = &["md", "mdc"];
const JSON: &[&str] = &["json"];
const YAML_JSON: &[&str] = &["yaml", "yml", "json"];
const ANY: &[&str] = &[];

/// Project-scoped artifacts, relative to a workspace root. Sources for each agent's layout are its
/// official docs or source tree; a location this table can't vouch for is left out rather than
/// guessed, because a wrong path is silently useless and a wrong *format* produces false findings.
const WORKSPACE_SPECS: &[Spec] = &[
    // ---- Instruction / context files, read by the model every session.
    Spec("CLAUDE.md", ClaudeCode, Instructions, File),
    Spec("CLAUDE.local.md", ClaudeCode, Instructions, File),
    Spec(".claude/CLAUDE.md", ClaudeCode, Instructions, File),
    Spec("AGENTS.md", Generic, Instructions, File),
    Spec("AGENTS.local.md", Generic, Instructions, File),
    Spec("AGENT.md", Generic, Instructions, File),
    Spec("GEMINI.md", Gemini, Instructions, File),
    Spec("QWEN.md", Qwen, Instructions, File),
    Spec("CRUSH.md", Crush, Instructions, File),
    Spec("CRUSH.local.md", Crush, Instructions, File),
    Spec("WARP.md", Warp, Instructions, File),
    Spec("AmazonQ.md", AmazonQ, Instructions, File),
    Spec(".rules", Zed, Instructions, File),
    Spec(".goosehints", Goose, Instructions, File),
    Spec(".cursorrules", Cursor, Instructions, File),
    Spec(".windsurfrules", Windsurf, Instructions, File),
    Spec(".clinerules", Cline, Instructions, File),
    Spec(".roorules", Cline, Instructions, File),
    Spec(".roomodes", Cline, Instructions, File),
    Spec(".augment-guidelines", Augment, Instructions, File),
    Spec(
        ".github/copilot-instructions.md",
        Copilot,
        Instructions,
        File,
    ),
    Spec(".devin/global_rules.md", Windsurf, Instructions, File),
    Spec(".windsurf/global_rules.md", Windsurf, Instructions, File),
    // Rule / command / subagent / skill directories — model-executed instruction surfaces, just as
    // capable of hiding a bidi backdoor or an injected directive as a CLAUDE.md.
    Spec(".cursor/rules", Cursor, Instructions, Dir(&["mdc"])),
    Spec(".cursor/commands", Cursor, Instructions, Dir(MD)),
    Spec(".continue/rules", Continue, Instructions, Dir(MD)),
    Spec(".roo", Cline, Instructions, Dir(MD)),
    Spec(".clinerules", Cline, Instructions, Dir(MD)),
    Spec(".cline/skills", Cline, Instructions, Dir(MD)),
    Spec(".claude/agents", ClaudeCode, Instructions, Dir(MD)),
    Spec(".claude/commands", ClaudeCode, Instructions, Dir(MD)),
    Spec(".claude/skills", ClaudeCode, Instructions, Dir(MD)),
    Spec(".claude/rules", ClaudeCode, Instructions, Dir(MD)),
    Spec(".agents/skills", Generic, Instructions, Dir(MD)),
    Spec(".gemini/commands", Gemini, Instructions, Dir(&["toml"])),
    Spec(".gemini/agents", Gemini, Instructions, Dir(MD)),
    Spec(".gemini/skills", Gemini, Instructions, Dir(MD)),
    Spec(".qwen/rules", Qwen, Instructions, Dir(MD)),
    Spec(".qwen/commands", Qwen, Instructions, Dir(&["md", "toml"])),
    Spec(".qwen/agents", Qwen, Instructions, Dir(MD)),
    Spec(".qwen/skills", Qwen, Instructions, Dir(MD)),
    Spec(".kiro/steering", Kiro, Instructions, Dir(MD)),
    Spec(".kiro/agents", Kiro, Instructions, Dir(MD)),
    Spec(".amazonq/rules", AmazonQ, Instructions, Dir(MD)),
    Spec(".amazonq/prompts", AmazonQ, Instructions, Dir(MD)),
    Spec(".windsurf/rules", Windsurf, Instructions, Dir(MD)),
    Spec(".devin/rules", Windsurf, Instructions, Dir(MD)),
    Spec(".kilo/rules", Kilo, Instructions, Dir(MD)),
    Spec(".kilo/skills", Kilo, Instructions, Dir(MD)),
    Spec(".kilocode/rules", Kilo, Instructions, Dir(MD)),
    Spec(".opencode/agents", OpenCode, Instructions, Dir(MD)),
    Spec(".opencode/agent", OpenCode, Instructions, Dir(MD)),
    Spec(".opencode/commands", OpenCode, Instructions, Dir(MD)),
    Spec(".opencode/command", OpenCode, Instructions, Dir(MD)),
    Spec(".opencode/modes", OpenCode, Instructions, Dir(MD)),
    Spec(".opencode/skills", OpenCode, Instructions, Dir(MD)),
    Spec(".crush/skills", Crush, Instructions, Dir(MD)),
    Spec(".github/instructions", Copilot, Instructions, Dir(MD)),
    Spec(".github/prompts", Copilot, Instructions, Dir(MD)),
    Spec(".github/agents", Copilot, Instructions, Dir(MD)),
    Spec(".github/chatmodes", Copilot, Instructions, Dir(MD)),
    Spec(".junie", JetBrains, Instructions, Dir(MD)),
    Spec(".aiassistant/rules", JetBrains, Instructions, Dir(MD)),
    Spec(".augment/rules", Augment, Instructions, Dir(MD_MDC)),
    // ---- Agent settings.
    Spec(".claude/settings.json", ClaudeCode, Settings, File),
    Spec(".claude/settings.local.json", ClaudeCode, Settings, File),
    Spec(".vscode/settings.json", VsCode, Settings, File),
    Spec(".gemini/settings.json", Gemini, Settings, File),
    Spec(".qwen/settings.json", Qwen, Settings, File),
    Spec(".zed/settings.json", Zed, Settings, File),
    Spec("opencode.json", OpenCode, Settings, File),
    Spec("opencode.jsonc", OpenCode, Settings, File),
    Spec(".opencode/opencode.json", OpenCode, Settings, File),
    Spec(".opencode/opencode.jsonc", OpenCode, Settings, File),
    Spec("kilo.json", Kilo, Settings, File),
    Spec("kilo.jsonc", Kilo, Settings, File),
    Spec(".kilo/kilo.json", Kilo, Settings, File),
    Spec(".kilo/kilo.jsonc", Kilo, Settings, File),
    Spec("crush.json", Crush, Settings, File),
    Spec(".crush.json", Crush, Settings, File),
    Spec(".amp/settings.json", Amp, Settings, File),
    Spec(".amp/settings.jsonc", Amp, Settings, File),
    Spec(".cursor/cli.json", Cursor, Settings, File),
    Spec(".augment/settings.json", Augment, Settings, File),
    Spec(".augment/settings.local.json", Augment, Settings, File),
    Spec(".github/copilot/settings.json", Copilot, Settings, File),
    Spec(
        ".github/copilot/settings.local.json",
        Copilot,
        Settings,
        File,
    ),
    Spec(".devin/config.json", Windsurf, Settings, File),
    Spec(".devin/config.local.json", Windsurf, Settings, File),
    Spec(".amazonq/cli-agents", AmazonQ, Settings, Dir(JSON)),
    Spec(".aider.conf.yml", Aider, Settings, File),
    Spec(".vscode/tasks.json", VsCode, Tasks, File),
    // ---- Hook files: present in a repo, they run its commands on agent events.
    Spec(".cursor/hooks.json", Cursor, Hooks, File),
    Spec(".kiro/hooks", Kiro, Hooks, Dir(&["json", "hook"])),
    Spec(".github/hooks", Copilot, Hooks, Dir(JSON)),
    Spec(".devin/hooks.v1.json", Windsurf, Hooks, File),
    Spec(".clinerules/hooks", Cline, Hooks, Dir(ANY)),
    Spec("crushrc", Crush, Hooks, File),
    Spec(".crushrc", Crush, Hooks, File),
    // ---- MCP manifests.
    Spec(".mcp.json", ClaudeCode, McpConfig, File),
    Spec(".cursor/mcp.json", Cursor, McpConfig, File),
    Spec(".vscode/mcp.json", VsCode, McpConfig, File),
    Spec(".github/mcp.json", Copilot, McpConfig, File),
    Spec(".roo/mcp.json", Cline, McpConfig, File),
    Spec(".amazonq/mcp.json", AmazonQ, McpConfig, File),
    Spec(".kiro/settings/mcp.json", Kiro, McpConfig, File),
    Spec(".continue/mcpServers", Continue, McpConfig, Dir(YAML_JSON)),
    // ---- Dotenv files.
    Spec(".env", Generic, DotEnv, File),
    Spec(".gemini/.env", Gemini, DotEnv, File),
    Spec(".qwen/.env", Qwen, DotEnv, File),
    // ---- Transcripts kept at the repo root.
    Spec(".aider.chat.history.md", Aider, Transcript, File),
    Spec(".aider.llm.history", Aider, Transcript, File),
];

/// Global `$HOME` tool state, relative to `$HOME`.
const GLOBAL_SPECS: &[Spec] = &[
    // ---- Claude Code.
    Spec(".claude/settings.json", ClaudeCode, Settings, File),
    Spec(".claude.json", ClaudeCode, McpConfig, File),
    Spec(".claude/.credentials.json", ClaudeCode, Credential, File),
    Spec(".claude/projects", ClaudeCode, Transcript, Dir(&["jsonl"])),
    Spec(".claude/history.jsonl", ClaudeCode, Transcript, File),
    // Agent memory: per-project memory notes and the global user memory file.
    Spec(".claude/projects", ClaudeCode, Memory, Dir(MD)),
    Spec(".claude/CLAUDE.md", ClaudeCode, Memory, File),
    Spec(".claude/agents", ClaudeCode, Instructions, Dir(MD)),
    Spec(".claude/commands", ClaudeCode, Instructions, Dir(MD)),
    Spec(".claude/skills", ClaudeCode, Instructions, Dir(MD)),
    Spec(".claude/rules", ClaudeCode, Instructions, Dir(MD)),
    // Installed plugins (`cache/<marketplace>/<plugin>/<version>/`) carry their own commands,
    // agents, skills and MCP servers. Only the installed cache — `marketplaces/` is a clone of the
    // whole catalog, most of which the user never enabled.
    Spec(
        ".claude/plugins/cache",
        ClaudeCode,
        Instructions,
        DirUnder(MD, &["commands", "agents", "skills"]),
    ),
    Spec(
        ".claude/plugins/cache",
        ClaudeCode,
        McpConfig,
        Named(".mcp.json"),
    ),
    // ---- Claude Desktop (official Linux beta).
    Spec(
        ".config/Claude/claude_desktop_config.json",
        ClaudeDesktop,
        McpConfig,
        File,
    ),
    // ---- Codex.
    Spec(".codex/config.toml", Codex, CodexConfig, File),
    Spec(".codex/auth.json", Codex, Credential, File),
    Spec(".codex/AGENTS.md", Codex, Instructions, File),
    Spec(".codex/prompts", Codex, Instructions, Dir(MD)),
    Spec(".codex/sessions", Codex, Transcript, Dir(&["jsonl"])),
    Spec(".codex/history.jsonl", Codex, Transcript, File),
    // ---- Cursor (editor + CLI).
    Spec(".cursor/mcp.json", Cursor, McpConfig, File),
    Spec(".cursor/cli-config.json", Cursor, Settings, File),
    // ---- GitHub Copilot (CLI + VS Code user instructions).
    Spec(".copilot/mcp-config.json", Copilot, McpConfig, File),
    Spec(
        ".copilot/copilot-instructions.md",
        Copilot,
        Instructions,
        File,
    ),
    Spec(".copilot/instructions", Copilot, Instructions, Dir(MD)),
    Spec(".copilot/agents", Copilot, Instructions, Dir(MD)),
    Spec(".copilot/skills", Copilot, Instructions, Dir(MD)),
    Spec(".copilot/providers.json", Copilot, Credential, File),
    Spec(
        ".config/github-copilot/hosts.json",
        Copilot,
        Credential,
        File,
    ),
    // ---- Gemini CLI (settings, extensions, chats, credentials).
    Spec(".gemini/settings.json", Gemini, Settings, File),
    Spec(".gemini/GEMINI.md", Gemini, Instructions, File),
    Spec(".gemini/commands", Gemini, Instructions, Dir(&["toml"])),
    Spec(".gemini/agents", Gemini, Instructions, Dir(MD)),
    Spec(".gemini/skills", Gemini, Instructions, Dir(MD)),
    Spec(
        ".gemini/extensions",
        Gemini,
        Instructions,
        Named("GEMINI.md"),
    ),
    Spec(
        ".gemini/extensions",
        Gemini,
        Instructions,
        DirUnder(&["toml"], &["commands"]),
    ),
    Spec(
        ".gemini/extensions",
        Gemini,
        McpConfig,
        Named("gemini-extension.json"),
    ),
    // Chats are `chats/session-*.jsonl`; releases before that wrote `.json`.
    Spec(".gemini/tmp", Gemini, Transcript, Dir(&["jsonl", "json"])),
    Spec(".gemini/.env", Gemini, DotEnv, File),
    Spec(".gemini/oauth_creds.json", Gemini, Credential, File),
    Spec(".gemini/mcp-oauth-tokens.json", Gemini, Credential, File),
    // ---- Qwen Code (a Gemini CLI fork with its own home).
    Spec(".qwen/settings.json", Qwen, Settings, File),
    Spec(".qwen/QWEN.md", Qwen, Instructions, File),
    Spec(".qwen/rules", Qwen, Instructions, Dir(MD)),
    Spec(".qwen/commands", Qwen, Instructions, Dir(&["md", "toml"])),
    Spec(".qwen/agents", Qwen, Instructions, Dir(MD)),
    Spec(".qwen/skills", Qwen, Instructions, Dir(MD)),
    Spec(".qwen/projects", Qwen, Transcript, Dir(&["jsonl"])),
    Spec(".qwen/.env", Qwen, DotEnv, File),
    Spec(".qwen/oauth_creds.json", Qwen, Credential, File),
    // ---- Aider / Continue.
    Spec(".aider.conf.yml", Aider, Settings, File),
    Spec(".continue/config.yaml", Continue, Settings, File),
    Spec(".continue/mcpServers", Continue, McpConfig, Dir(YAML_JSON)),
    Spec(".continue/.env", Continue, DotEnv, File),
    // ---- Windsurf, now Devin Desktop (legacy and current homes).
    Spec(
        ".codeium/windsurf/global_rules.md",
        Windsurf,
        Instructions,
        File,
    ),
    Spec(
        ".codeium/windsurf/mcp_config.json",
        Windsurf,
        McpConfig,
        File,
    ),
    Spec(".devin/global_rules.md", Windsurf, Instructions, File),
    Spec(".devin/rules", Windsurf, Instructions, Dir(MD)),
    Spec(".config/devin/config.json", Windsurf, Settings, File),
    // ---- Amazon Q Developer CLI / Kiro.
    Spec(".aws/amazonq/mcp.json", AmazonQ, McpConfig, File),
    Spec(".aws/amazonq/cli-agents", AmazonQ, Settings, Dir(JSON)),
    Spec(".aws/amazonq/prompts", AmazonQ, Instructions, Dir(MD)),
    Spec(".kiro/settings/mcp.json", Kiro, McpConfig, File),
    Spec(".kiro/steering", Kiro, Instructions, Dir(MD)),
    Spec(".kiro/agents", Kiro, Instructions, Dir(MD)),
    // ---- Cline (current `~/.cline/data` home, plus the legacy Documents copy) / Roo.
    Spec(
        ".cline/data/settings/cline_mcp_settings.json",
        Cline,
        McpConfig,
        File,
    ),
    Spec(".cline/data/tasks", Cline, Transcript, Dir(JSON)),
    Spec(".cline/data/secrets.json", Cline, Credential, File),
    Spec(
        "Documents/Cline/MCP/cline_mcp_settings.json",
        Cline,
        McpConfig,
        File,
    ),
    Spec("Documents/Cline/Rules", Cline, Instructions, Dir(MD)),
    Spec("Documents/Cline/Workflows", Cline, Instructions, Dir(MD)),
    Spec(".roo", Cline, Instructions, Dir(MD)),
    // ---- Zed.
    Spec(".config/zed/settings.json", Zed, Settings, File),
    Spec(".config/zed/AGENTS.md", Zed, Instructions, File),
    // ---- Cross-agent skill folders (Zed, Amp, Crush, Goose all read these).
    Spec(".agents/skills", Generic, Instructions, Dir(MD)),
    Spec(".agents/AGENTS.md", Generic, Instructions, File),
    Spec(".config/agents/skills", Generic, Instructions, Dir(MD)),
    Spec(".config/AGENTS.md", Generic, Instructions, File),
    // ---- Goose.
    Spec(".config/goose/config.yaml", Goose, Settings, File),
    Spec(".config/goose/.goosehints", Goose, Instructions, File),
    Spec(".config/goose/AGENTS.md", Goose, Instructions, File),
    Spec(".config/goose/skills", Goose, Instructions, Dir(MD)),
    Spec(".config/goose/secrets.yaml", Goose, Credential, File),
    // ---- OpenCode / Kilo Code (same config dialect).
    Spec(".config/opencode/opencode.json", OpenCode, Settings, File),
    Spec(".config/opencode/opencode.jsonc", OpenCode, Settings, File),
    Spec(".config/opencode/AGENTS.md", OpenCode, Instructions, File),
    Spec(".config/opencode/agents", OpenCode, Instructions, Dir(MD)),
    Spec(".config/opencode/commands", OpenCode, Instructions, Dir(MD)),
    Spec(".config/opencode/skills", OpenCode, Instructions, Dir(MD)),
    Spec(".config/kilo/kilo.json", Kilo, Settings, File),
    Spec(".config/kilo/kilo.jsonc", Kilo, Settings, File),
    // ---- Crush.
    Spec(".config/crush/crush.json", Crush, Settings, File),
    Spec(".config/crush/CRUSH.md", Crush, Instructions, File),
    Spec(".config/crush/skills", Crush, Instructions, Dir(MD)),
    Spec(".local/share/crush/crush.json", Crush, Credential, File),
    // ---- Amp.
    Spec(".config/amp/settings.json", Amp, Settings, File),
    Spec(".config/amp/settings.jsonc", Amp, Settings, File),
    Spec(".config/amp/AGENTS.md", Amp, Instructions, File),
    Spec(".config/amp/skills", Amp, Instructions, Dir(MD)),
    // ---- Augment / JetBrains Junie.
    Spec(".augment/settings.json", Augment, Settings, File),
    Spec(".augment/rules", Augment, Instructions, Dir(MD_MDC)),
    Spec(".junie/AGENTS.md", JetBrains, Instructions, File),
    // ---- Open Interpreter (legacy Python release) profiles.
    Spec(
        ".config/open-interpreter/profiles",
        OpenInterpreter,
        Settings,
        Dir(&["yaml", "yml"]),
    ),
];

/// VS Code-family editors keep user settings, a user-level `mcp.json`, and extension storage under
/// `~/.config/<product>/User/`. Every fork is a separate home with its own copy of the settings
/// that matter (chat auto-approve, Workspace Trust) — a YOLO flag set in Cursor's user settings is
/// invisible to a scan that only reads VS Code's.
const VSCODE_FAMILY: &[&str] = &[
    "Code",
    "Code - Insiders",
    "Code - OSS",
    "VSCodium",
    "Cursor",
    "Windsurf",
    "Kiro",
];

/// VS Code extensions that keep MCP manifests and task transcripts in `globalStorage`.
const EXTENSION_STORAGE: &[(&str, Tool, &str)] = &[
    (
        "saoudrizwan.claude-dev",
        Cline,
        "settings/cline_mcp_settings.json",
    ),
    (
        "rooveterinaryinc.roo-cline",
        Cline,
        "settings/mcp_settings.json",
    ),
    ("kilocode.kilo-code", Kilo, "settings/mcp_settings.json"),
];

/// What discovery found in one place, and what it could not look at.
#[derive(Debug, Default)]
pub struct Found {
    pub artifacts: Vec<Artifact>,
    /// Things that exist but could not be examined: a folder that cannot be listed, a link that
    /// leaves the project. Reported by the scan, never dropped.
    pub problems: Vec<String>,
}

impl Found {
    fn problem(&mut self, text: String) {
        if !self.problems.contains(&text) {
            self.problems.push(text);
        }
    }
}

/// Whether a spec location can be examined.
enum Reach {
    /// Nothing is there.
    Absent,
    /// It exists, and everything it resolves to is inside the folder being checked.
    Inside(std::fs::Metadata),
    /// It exists but must not be read; already recorded as a problem.
    Blocked,
}

/// Looks at `base/rel` without trusting any link on the way. A project's files are written by
/// whoever wrote the project: a tracked `.claude/commands -> ../../../Documents` would otherwise
/// pull the user's own documents into the scan (and from there into redaction). The same rule as
/// [`homefs`]: a link is followed only while what it resolves to stays inside `base`.
fn reach(out: &mut Found, base: &Path, base_real: &Path, rel: &Path) -> Reach {
    use std::io::ErrorKind::{NotADirectory, NotFound, PermissionDenied};
    let path = base.join(rel);
    let direct = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if matches!(e.kind(), NotFound | NotADirectory) => return Reach::Absent,
        Err(e) => {
            // A folder on the way could not be entered. Name that folder, once, instead of every
            // location under it.
            let mut blocked = base.to_path_buf();
            for part in rel.iter() {
                let next = blocked.join(part);
                if std::fs::symlink_metadata(&next).is_err_and(|e| e.kind() == PermissionDenied) {
                    break;
                }
                blocked = next;
            }
            out.problem(format!(
                "{}: this folder could not be opened ({e}), so nothing in it was checked",
                blocked.display()
            ));
            return Reach::Blocked;
        }
    };
    // One component and not a link: nothing to resolve.
    let plain = rel.iter().count() == 1 && !direct.file_type().is_symlink();
    if !plain {
        match std::fs::canonicalize(&path) {
            Ok(real) if real.starts_with(base_real) => {}
            Ok(_) => {
                out.problem(format!(
                    "{}: not checked, because it is a link to a place outside {}",
                    first_link(base, rel).display(),
                    base.display()
                ));
                return Reach::Blocked;
            }
            Err(e) if e.kind() == PermissionDenied => {
                out.problem(format!("{}: could not be opened ({e})", path.display()));
                return Reach::Blocked;
            }
            // A link that leads nowhere: there is nothing an agent could read either.
            Err(_) => return Reach::Absent,
        }
    }
    match std::fs::metadata(&path) {
        Ok(meta) => Reach::Inside(meta),
        Err(_) => Reach::Absent,
    }
}

/// The first component of `base/rel` that is a symbolic link (for the message), else the path.
fn first_link(base: &Path, rel: &Path) -> PathBuf {
    let mut cur = base.to_path_buf();
    for part in rel.iter() {
        cur.push(part);
        if std::fs::symlink_metadata(&cur).is_ok_and(|m| m.file_type().is_symlink()) {
            return cur;
        }
    }
    cur
}

/// Adds the file at `base/rel` if it is there. A pipe or device in a file's place is added too:
/// the scan's own open refuses it without waiting on it, and says so, where leaving it out here
/// would be a silent gap.
fn add_file(
    out: &mut Found,
    base: &Path,
    base_real: &Path,
    rel: &Path,
    tool: Tool,
    kind: ArtifactKind,
    ws: Option<&Path>,
) {
    if let Reach::Inside(meta) = reach(out, base, base_real, rel) {
        if !meta.is_dir() {
            out.artifacts.push(Artifact {
                path: base.join(rel),
                tool,
                kind,
                workspace: ws.map(Path::to_path_buf),
            });
        }
    }
}

/// Adds every file under the folder `base/rel` accepted by `want`.
#[allow(clippy::too_many_arguments)]
fn add_dir(
    out: &mut Found,
    base: &Path,
    base_real: &Path,
    rel: &Path,
    want: impl Fn(&Path) -> bool,
    tool: Tool,
    kind: ArtifactKind,
    ws: Option<&Path>,
) {
    if let Reach::Inside(meta) = reach(out, base, base_real, rel) {
        if meta.is_dir() {
            collect_dir(out, &base.join(rel), want, tool, kind, ws);
        }
    }
}

fn apply_specs(out: &mut Found, base: &Path, specs: &[Spec], ws: Option<&Path>) {
    // A folder that cannot be resolved is not there to check.
    let Ok(base_real) = std::fs::canonicalize(base) else {
        return;
    };
    for Spec(rel, tool, kind, find) in specs {
        let rel = Path::new(rel);
        let path = base.join(rel);
        match find {
            File => add_file(out, base, &base_real, rel, *tool, *kind, ws),
            Dir(exts) => add_dir(
                out,
                base,
                &base_real,
                rel,
                |p| has_ext(p, exts),
                *tool,
                *kind,
                ws,
            ),
            DirUnder(exts, parents) => add_dir(
                out,
                base,
                &base_real,
                rel,
                |p| {
                    has_ext(p, exts)
                        && p.strip_prefix(&path).is_ok_and(|rel| {
                            rel.components().any(|c| {
                                c.as_os_str().to_str().is_some_and(|c| parents.contains(&c))
                            })
                        })
                },
                *tool,
                *kind,
                ws,
            ),
            Named(name) => add_dir(
                out,
                base,
                &base_real,
                rel,
                |p| p.file_name().and_then(|n| n.to_str()) == Some(name),
                *tool,
                *kind,
                ws,
            ),
        }
    }
}

fn has_ext(path: &Path, exts: &[&str]) -> bool {
    exts.is_empty()
        || path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| exts.contains(&e))
}

/// The project-scoped artifacts to examine inside one workspace `ws`. Every entry is gated on
/// existence, so a project using only Cursor contributes only Cursor artifacts.
pub fn workspace_artifacts(ws: &Path) -> Vec<Artifact> {
    find_in_workspace(ws).artifacts
}

/// [`workspace_artifacts`], with what could not be looked at.
pub fn find_in_workspace(ws: &Path) -> Found {
    let mut out = Found::default();
    apply_specs(&mut out, ws, WORKSPACE_SPECS, Some(ws));
    out
}

/// The global `$HOME` tool state to examine, independent of any workspace.
pub fn global_artifacts(home: &Path) -> Vec<Artifact> {
    find_in_home(home).artifacts
}

/// [`global_artifacts`], with what could not be looked at.
pub fn find_in_home(home: &Path) -> Found {
    let mut out = Found::default();
    apply_specs(&mut out, home, GLOBAL_SPECS, None);
    let Ok(home_real) = std::fs::canonicalize(home) else {
        return out;
    };
    for product in VSCODE_FAMILY {
        let user = Path::new(".config").join(product).join("User");
        let file = |out: &mut Found, rel: PathBuf, tool, kind| {
            add_file(out, home, &home_real, &rel, tool, kind, None)
        };
        file(&mut out, user.join("settings.json"), VsCode, Settings);
        file(&mut out, user.join("mcp.json"), VsCode, McpConfig);
        // Profiles carry their own settings.json — a YOLO flag can live in a non-default profile.
        let profiles = user.join("profiles");
        if let Reach::Inside(meta) = reach(&mut out, home, &home_real, &profiles) {
            if meta.is_dir() {
                if let Ok(entries) = std::fs::read_dir(home.join(&profiles)) {
                    for p in entries.flatten() {
                        let profile = profiles.join(p.file_name());
                        file(&mut out, profile.join("settings.json"), VsCode, Settings);
                        file(&mut out, profile.join("mcp.json"), VsCode, McpConfig);
                    }
                }
            }
        }
        for (ext, tool, mcp) in EXTENSION_STORAGE {
            let store = user.join("globalStorage").join(ext);
            file(&mut out, store.join(mcp), *tool, McpConfig);
            add_dir(
                &mut out,
                home,
                &home_real,
                &store.join("tasks"),
                |p| has_ext(p, JSON),
                *tool,
                Transcript,
                None,
            );
        }
    }
    out
}

/// Adds every regular file under `dir` accepted by `want` as an artifact. Recursion is bounded to
/// a sane depth so a transcript directory tree (`~/.claude/projects/<proj>/*.jsonl`,
/// `~/.codex/sessions/YYYY/MM/DD/*.jsonl`) is fully covered without an unbounded walk, and
/// dependency/VCS trees are skipped — an installed plugin can bundle a whole `node_modules`.
///
/// A folder that cannot be listed is recorded as a problem: a `chmod 000` agent folder used to
/// vanish from the scan without a word.
fn collect_dir(
    out: &mut Found,
    dir: &Path,
    want: impl Fn(&Path) -> bool,
    tool: Tool,
    kind: ArtifactKind,
    ws: Option<&Path>,
) {
    fn walk(
        out: &mut Found,
        dir: &Path,
        want: &dyn Fn(&Path) -> bool,
        tool: Tool,
        kind: ArtifactKind,
        ws: Option<&Path>,
        depth: usize,
    ) {
        if depth > 6 {
            return;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                if let Some(line) = unlistable(dir, &e) {
                    out.problem(line);
                }
                return;
            }
        };
        for entry in entries.flatten() {
            // Use the dirent's own type (does not traverse the link) and skip symlinks entirely:
            // a symlink planted in a scanned tree could otherwise redirect the walk out of scope
            // (into /etc or another user's home) and pull those files into the scan — and, worse,
            // into the redaction path. Redaction refuses symlinks too, but not descending onto
            // them here is the first and cheaper line of defense (and avoids symlink-loop walks).
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if file_type.is_dir() {
                if !is_dependency_dir(&path) {
                    walk(out, &path, want, tool, kind, ws, depth + 1);
                }
            } else if !want(&path) {
                // Not a file this location is about.
            } else if file_type.is_file() {
                out.artifacts.push(Artifact {
                    path,
                    tool,
                    kind,
                    workspace: ws.map(Path::to_path_buf),
                });
            } else {
                // A pipe, socket or device with an agent file's name. Opening one can wait for
                // ever (a pipe nobody writes to), so it never becomes something to read.
                out.problem(format!(
                    "{}: not checked, because it is not a regular file (a pipe, socket or device)",
                    path.display()
                ));
            }
        }
    }
    walk(out, dir, &want, tool, kind, ws, 0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn touch(path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, "x").unwrap();
    }

    #[test]
    fn sweep_finds_a_marker_bearing_workspace() {
        let home = tempfile::tempdir().unwrap();
        let proj = home.path().join("Projects/myapp");
        touch(&proj.join("CLAUDE.md"));

        let ws = discover_workspaces(home.path(), &[], &[], 100);
        assert!(
            ws.contains(&proj),
            "a project with CLAUDE.md must be discovered"
        );
    }

    #[test]
    fn sweep_finds_a_nested_org_layout() {
        let home = tempfile::tempdir().unwrap();
        let proj = home.path().join("src/acme/service");
        touch(&proj.join(".mcp.json"));

        let ws = discover_workspaces(home.path(), &[], &[], 100);
        assert!(
            ws.contains(&proj),
            "a two-level org/app layout must be discovered"
        );
    }

    #[test]
    fn sweep_skips_node_modules() {
        let home = tempfile::tempdir().unwrap();
        let vendored = home.path().join("Projects/app/node_modules/dep");
        touch(&vendored.join("CLAUDE.md"));
        // The app itself is also a workspace via a real marker.
        touch(&home.path().join("Projects/app/AGENTS.md"));

        let ws = discover_workspaces(home.path(), &[], &[], 100);
        assert!(ws.contains(&home.path().join("Projects/app")));
        assert!(
            !ws.iter()
                .any(|p| p.to_string_lossy().contains("node_modules")),
            "vendored markers inside node_modules must not become workspaces"
        );
    }

    #[test]
    fn excluded_roots_are_dropped() {
        let home = tempfile::tempdir().unwrap();
        let proj = home.path().join("Projects/secret");
        touch(&proj.join("CLAUDE.md"));

        let ws = discover_workspaces(home.path(), &[], std::slice::from_ref(&proj), 100);
        assert!(
            !ws.contains(&proj),
            "an explicitly excluded root must not be scanned"
        );
    }

    #[test]
    fn configured_root_that_is_itself_a_workspace_is_found() {
        let home = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        touch(&elsewhere.path().join("CLAUDE.md"));

        let ws = discover_workspaces(home.path(), &[elsewhere.path().to_path_buf()], &[], 100);
        assert!(ws.contains(&elsewhere.path().to_path_buf()));
    }

    #[cfg(unix)]
    #[test]
    fn claude_projects_decode_only_yields_real_dirs() {
        let home = tempfile::tempdir().unwrap();
        // A real project directory the encoded name points back to.
        let real = home.path().join("stuff/app");
        fs::create_dir_all(&real).unwrap();
        let encoded = real.to_string_lossy().replace('/', "-");
        touch(
            &home
                .path()
                .join(format!(".claude/projects/{encoded}/session.jsonl")),
        );
        // An encoded name whose decoded path does not exist must be ignored.
        touch(
            &home
                .path()
                .join(".claude/projects/-nonexistent-ghost-path/s.jsonl"),
        );

        let ws = discover_workspaces(home.path(), &[], &[], 100);
        assert!(ws.contains(&real));
        assert!(!ws.iter().any(|p| p.to_string_lossy().contains("ghost")));
    }

    #[test]
    fn workspace_artifacts_only_includes_present_files() {
        let ws = tempfile::tempdir().unwrap();
        touch(&ws.path().join("CLAUDE.md"));
        touch(&ws.path().join(".claude/settings.json"));
        touch(&ws.path().join(".mcp.json"));
        touch(&ws.path().join(".cursor/rules/style.mdc"));

        let arts = workspace_artifacts(ws.path());
        assert!(arts
            .iter()
            .any(|a| a.path.ends_with("CLAUDE.md") && a.kind == ArtifactKind::Instructions));
        assert!(arts
            .iter()
            .any(|a| a.path.ends_with(".mcp.json") && a.kind == ArtifactKind::McpConfig));
        assert!(arts.iter().any(|a| a.path.ends_with("style.mdc")));
        // A file that doesn't exist must not appear.
        assert!(!arts.iter().any(|a| a.path.ends_with(".cursorrules")));
    }

    #[test]
    fn workspace_artifacts_scans_agents_commands_and_nested_skills() {
        // Subagents, slash commands, and skills are model-executed instruction surfaces — a bidi
        // backdoor in any of them must be reachable by the scanner.
        let ws = tempfile::tempdir().unwrap();
        touch(&ws.path().join(".claude/agents/reviewer.md"));
        touch(&ws.path().join(".claude/commands/deploy.md"));
        touch(&ws.path().join(".claude/skills/my-skill/SKILL.md")); // nested

        let arts = workspace_artifacts(ws.path());
        for name in ["reviewer.md", "deploy.md", "SKILL.md"] {
            assert!(
                arts.iter()
                    .any(|a| a.path.ends_with(name) && a.kind == ArtifactKind::Instructions),
                "{name} must be discovered as an instruction surface"
            );
        }
    }

    #[test]
    fn global_artifacts_walks_the_transcript_tree() {
        let home = tempfile::tempdir().unwrap();
        touch(
            &home
                .path()
                .join(".claude/projects/-home-u-app/session-1.jsonl"),
        );
        touch(
            &home
                .path()
                .join(".codex/sessions/2026/07/12/rollout-x.jsonl"),
        );
        touch(&home.path().join(".claude/.credentials.json"));

        let arts = global_artifacts(home.path());
        assert!(arts
            .iter()
            .any(|a| a.path.ends_with("session-1.jsonl") && a.kind == ArtifactKind::Transcript));
        assert!(arts.iter().any(|a| a.path.ends_with("rollout-x.jsonl")));
        assert!(arts.iter().any(|a| a.kind == ArtifactKind::Credential));
    }

    #[test]
    fn every_supported_agent_contributes_its_project_artifacts() {
        let ws = tempfile::tempdir().unwrap();
        let cases: &[(&str, Tool, ArtifactKind)] = &[
            (".zed/settings.json", Tool::Zed, ArtifactKind::Settings),
            (".rules", Tool::Zed, ArtifactKind::Instructions),
            (".goosehints", Tool::Goose, ArtifactKind::Instructions),
            ("opencode.json", Tool::OpenCode, ArtifactKind::Settings),
            (
                ".opencode/agents/review.md",
                Tool::OpenCode,
                ArtifactKind::Instructions,
            ),
            ("kilo.jsonc", Tool::Kilo, ArtifactKind::Settings),
            ("crush.json", Tool::Crush, ArtifactKind::Settings),
            ("crushrc", Tool::Crush, ArtifactKind::Hooks),
            ("CRUSH.md", Tool::Crush, ArtifactKind::Instructions),
            (".amp/settings.json", Tool::Amp, ArtifactKind::Settings),
            (".qwen/settings.json", Tool::Qwen, ArtifactKind::Settings),
            ("QWEN.md", Tool::Qwen, ArtifactKind::Instructions),
            (
                ".gemini/settings.json",
                Tool::Gemini,
                ArtifactKind::Settings,
            ),
            (
                ".gemini/commands/fix.toml",
                Tool::Gemini,
                ArtifactKind::Instructions,
            ),
            (
                ".kiro/steering/product.md",
                Tool::Kiro,
                ArtifactKind::Instructions,
            ),
            (
                ".kiro/hooks/lint.kiro.hook",
                Tool::Kiro,
                ArtifactKind::Hooks,
            ),
            (
                ".kiro/settings/mcp.json",
                Tool::Kiro,
                ArtifactKind::McpConfig,
            ),
            (
                ".amazonq/rules/style.md",
                Tool::AmazonQ,
                ArtifactKind::Instructions,
            ),
            (
                ".amazonq/cli-agents/dev.json",
                Tool::AmazonQ,
                ArtifactKind::Settings,
            ),
            (".cursor/hooks.json", Tool::Cursor, ArtifactKind::Hooks),
            (".cursor/cli.json", Tool::Cursor, ArtifactKind::Settings),
            (
                ".github/hooks/guard.json",
                Tool::Copilot,
                ArtifactKind::Hooks,
            ),
            (
                ".github/instructions/ts.instructions.md",
                Tool::Copilot,
                ArtifactKind::Instructions,
            ),
            (".github/mcp.json", Tool::Copilot, ArtifactKind::McpConfig),
            (
                ".clinerules/hooks/TaskStart",
                Tool::Cline,
                ArtifactKind::Hooks,
            ),
            (".devin/hooks.v1.json", Tool::Windsurf, ArtifactKind::Hooks),
            (
                ".windsurf/rules/r.md",
                Tool::Windsurf,
                ArtifactKind::Instructions,
            ),
            (
                ".continue/mcpServers/db.yaml",
                Tool::Continue,
                ArtifactKind::McpConfig,
            ),
            (
                ".augment/settings.json",
                Tool::Augment,
                ArtifactKind::Settings,
            ),
            (
                ".junie/guidelines.md",
                Tool::JetBrains,
                ArtifactKind::Instructions,
            ),
            (
                ".aiassistant/rules/r.md",
                Tool::JetBrains,
                ArtifactKind::Instructions,
            ),
            (
                ".agents/skills/s/SKILL.md",
                Tool::Generic,
                ArtifactKind::Instructions,
            ),
            ("WARP.md", Tool::Warp, ArtifactKind::Instructions),
        ];
        for (rel, _, _) in cases {
            touch(&ws.path().join(rel));
        }
        let arts = workspace_artifacts(ws.path());
        for (rel, tool, kind) in cases {
            assert!(
                arts.iter()
                    .any(|a| a.path == ws.path().join(rel) && a.tool == *tool && a.kind == *kind),
                "{rel} must be discovered as {tool:?}/{kind:?}"
            );
        }
    }

    #[test]
    fn a_new_agent_marker_makes_a_workspace() {
        let home = tempfile::tempdir().unwrap();
        for (proj, marker) in [
            ("a", ".kiro"),
            ("b", "opencode.json"),
            ("c", ".goosehints"),
            ("d", "QWEN.md"),
        ] {
            touch(
                &home
                    .path()
                    .join("Projects")
                    .join(proj)
                    .join(marker)
                    .join("x"),
            );
        }
        let ws = discover_workspaces(home.path(), &[], &[], 100);
        for proj in ["a", "b", "c", "d"] {
            assert!(
                ws.contains(&home.path().join("Projects").join(proj)),
                "{proj}"
            );
        }
    }

    #[test]
    fn global_state_of_other_agents_and_editor_forks_is_found() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        let cases: &[(&str, ArtifactKind)] = &[
            (".config/zed/settings.json", ArtifactKind::Settings),
            (".config/goose/config.yaml", ArtifactKind::Settings),
            (".config/opencode/opencode.jsonc", ArtifactKind::Settings),
            (".config/crush/crush.json", ArtifactKind::Settings),
            (".config/amp/settings.json", ArtifactKind::Settings),
            (".qwen/projects/p/chats/s.jsonl", ArtifactKind::Transcript),
            (".qwen/oauth_creds.json", ArtifactKind::Credential),
            (".gemini/tmp/abc/chats/session-1.jsonl", ArtifactKind::Transcript),
            (".gemini/extensions/ext/gemini-extension.json", ArtifactKind::McpConfig),
            (".claude/plugins/cache/mk/plug/1.0.0/.mcp.json", ArtifactKind::McpConfig),
            (".claude/plugins/cache/mk/plug/1.0.0/commands/go.md", ArtifactKind::Instructions),
            (".claude/history.jsonl", ArtifactKind::Transcript),
            (".config/Claude/claude_desktop_config.json", ArtifactKind::McpConfig),
            (".cursor/cli-config.json", ArtifactKind::Settings),
            (".kiro/settings/mcp.json", ArtifactKind::McpConfig),
            (".cline/data/settings/cline_mcp_settings.json", ArtifactKind::McpConfig),
            (".cline/data/tasks/1/api_conversation_history.json", ArtifactKind::Transcript),
            (".codeium/windsurf/mcp_config.json", ArtifactKind::McpConfig),
            (".copilot/providers.json", ArtifactKind::Credential),
            (".config/Cursor/User/settings.json", ArtifactKind::Settings),
            (".config/VSCodium/User/mcp.json", ArtifactKind::McpConfig),
            (".config/Code/User/profiles/p1/settings.json", ArtifactKind::Settings),
            (
                ".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
                ArtifactKind::McpConfig,
            ),
            (
                ".config/Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks/t/ui_messages.json",
                ArtifactKind::Transcript,
            ),
        ];
        for (rel, _) in cases {
            touch(&h.join(rel));
        }
        let arts = global_artifacts(h);
        for (rel, kind) in cases {
            assert!(
                arts.iter()
                    .any(|a| a.path == h.join(rel) && a.kind == *kind),
                "{rel} must be discovered as {kind:?}"
            );
        }
    }

    #[test]
    fn plugin_dependency_trees_are_not_walked() {
        let home = tempfile::tempdir().unwrap();
        touch(
            &home
                .path()
                .join(".claude/plugins/cache/mk/p/1/node_modules/dep/README.md"),
        );
        let arts = global_artifacts(home.path());
        assert!(!arts
            .iter()
            .any(|a| a.path.to_string_lossy().contains("node_modules")));
    }

    #[test]
    fn agent_folders_named_like_build_dirs_are_still_walked() {
        let ws = tempfile::tempdir().unwrap();
        touch(&ws.path().join(".claude/skills/build/SKILL.md"));
        touch(&ws.path().join(".cursor/rules/dist/x.mdc"));
        let arts = workspace_artifacts(ws.path());
        assert!(arts.iter().any(|a| a.path.ends_with("build/SKILL.md")));
        assert!(arts.iter().any(|a| a.path.ends_with("dist/x.mdc")));
    }

    #[test]
    fn only_a_plugins_loaded_folders_are_instructions() {
        let home = tempfile::tempdir().unwrap();
        let plug = home.path().join(".claude/plugins/cache/mk/p/1.0.0");
        touch(&plug.join("README.md"));
        touch(&plug.join("skills/s/SKILL.md"));
        let arts = global_artifacts(home.path());
        assert!(arts.iter().any(|a| a.path.ends_with("skills/s/SKILL.md")));
        assert!(!arts.iter().any(|a| a.path.ends_with("1.0.0/README.md")));
    }

    // ---- Projects that discovery used to miss.

    /// The transcript line Claude Code writes, with the folder the session ran in.
    fn transcript_line(cwd: &Path) -> String {
        serde_json::json!({
            "parentUuid": null, "type": "user", "cwd": cwd, "sessionId": "s",
            "message": {"role": "user", "content": "hi"}
        })
        .to_string()
            + "\n"
    }

    #[cfg(unix)]
    #[test]
    fn a_project_whose_path_has_a_dash_is_found_from_its_transcripts() {
        // `-home-u-stuff-my-app` decodes to /home/u/stuff/my/app, which is not there. The real
        // folder is recorded in the transcripts.
        let home = tempfile::tempdir().unwrap();
        let home_path = home.path().canonicalize().unwrap();
        let real = home_path.join("stuff/my-app.v2_final");
        fs::create_dir_all(&real).unwrap();
        let encoded = claude_project_name(&real.to_string_lossy());
        let dir = home_path.join(".claude/projects").join(&encoded);
        // The first line of a transcript is often something else.
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("a.jsonl"),
            format!(
                "{{\"type\":\"summary\",\"summary\":\"x\"}}\n{}",
                transcript_line(&real)
            ),
        )
        .unwrap();

        let ws = discover_workspaces(&home_path, &[], &[], 100);
        assert_eq!(ws, std::slice::from_ref(&real));
    }

    #[cfg(unix)]
    #[test]
    fn a_recorded_folder_is_believed_only_as_far_as_it_can_be_checked() {
        let home = tempfile::tempdir().unwrap();
        let home_path = home.path().canonicalize().unwrap();
        let elsewhere = home_path.join("Documents");
        fs::create_dir_all(&elsewhere).unwrap();
        let gone = home_path.join("was/my-app");
        let projects = home_path.join(".claude/projects");
        let record = |name: &str, body: String| {
            fs::create_dir_all(projects.join(name)).unwrap();
            fs::write(projects.join(name).join("s.jsonl"), body).unwrap();
        };
        // The transcript names a folder that exists, but not the one this record is for: a
        // transcript is text, and must not be able to point the scan somewhere else.
        record(
            &claude_project_name(&gone.to_string_lossy()),
            transcript_line(&elsewhere),
        );
        // The right folder, which no longer exists.
        record("-x-gone-app", transcript_line(Path::new("/x/gone-app")));
        // Not a path at all, a relative path, a number, and text cut off mid-string.
        record("-x-rel", "{\"cwd\":\"x/rel\"}\n".to_string());
        record("-x-num", "{\"cwd\":42}\n{\"cwd\":\n".to_string());
        record("-x-cut", "{\"cwd\":\"/x/cu".to_string());
        // A pipe where a transcript should be is not waited on.
        fs::create_dir_all(projects.join("-x-pipe")).unwrap();
        let fifo =
            std::ffi::CString::new(projects.join("-x-pipe/s.jsonl").to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path and a plain mode.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        let started = std::time::Instant::now();
        let ws = discover_workspaces(&home_path, &[], &[], 100);
        assert!(ws.is_empty(), "{ws:?}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn every_checked_location_makes_its_folder_a_workspace() {
        // The marker list used to be kept by hand next to the location table, and had drifted:
        // `.vscode/settings.json`, `.vscode/tasks.json`, `.github/chatmodes`, `.github/copilot`,
        // `.cline` and `.crush` were checked when a project was found some other way, and never
        // got a project found. Markers are derived from the table now; this fails if a location
        // is ever added without one (or without a reason in NOT_A_MARKER).
        for (i, Spec(rel, _, _, find)) in WORKSPACE_SPECS.iter().enumerate() {
            let home = tempfile::tempdir().unwrap();
            let proj = home.path().join(format!("Projects/p{i}"));
            match find {
                File => touch(&proj.join(rel)),
                _ => touch(&proj.join(rel).join("inner/x.md")),
            }
            let found = discover_workspaces(home.path(), &[], &[], 100).contains(&proj);
            assert_eq!(
                found,
                !NOT_A_MARKER.contains(rel),
                "{rel}: a project holding only this must{} be discovered",
                if NOT_A_MARKER.contains(rel) {
                    " not"
                } else {
                    ""
                }
            );
        }
        // The shared folders themselves say nothing.
        let home = tempfile::tempdir().unwrap();
        touch(&home.path().join("Projects/ci/.github/workflows/ci.yml"));
        touch(&home.path().join("Projects/ed/.vscode/launch.json"));
        assert!(discover_workspaces(home.path(), &[], &[], 100).is_empty());
    }

    #[test]
    fn editor_only_projects_do_not_crowd_out_or_shadow_agent_projects() {
        let home = tempfile::tempdir().unwrap();
        // Many folders with nothing but editor settings, named to sort first.
        for i in 0..8 {
            touch(
                &home
                    .path()
                    .join(format!("Projects/aa{i}/.vscode/settings.json")),
            );
        }
        touch(&home.path().join("Projects/zz-agent/CLAUDE.md"));
        // An editor-settings folder that contains agent projects one level down.
        touch(&home.path().join("Projects/mono/.vscode/settings.json"));
        touch(&home.path().join("Projects/mono/svc/AGENTS.md"));

        let all = find_workspaces(home.path(), &[], &[], 100);
        assert_eq!(all.roots.len(), 11);
        assert!(!all.capped);
        assert!(all.roots.contains(&home.path().join("Projects/mono")));
        assert!(all.roots.contains(&home.path().join("Projects/mono/svc")));

        // With room for three, the two agent projects are in, whatever their names sort as.
        let few = find_workspaces(home.path(), &[], &[], 3);
        assert!(few.capped);
        assert_eq!(few.roots.len(), 3);
        assert!(few.roots.contains(&home.path().join("Projects/zz-agent")));
        assert!(few.roots.contains(&home.path().join("Projects/mono/svc")));
    }

    #[test]
    fn exclusions_cover_parents_and_other_spellings() {
        let home = tempfile::tempdir().unwrap();
        touch(&home.path().join("Projects/org/a/CLAUDE.md"));
        touch(&home.path().join("Projects/org/b/CLAUDE.md"));
        touch(&home.path().join("Projects/keep/CLAUDE.md"));
        let keep = home.path().join("Projects/keep");
        // A parent of the projects, written with a `..` in it.
        let roundabout = home.path().join("Projects/keep/../org");
        let found = find_workspaces(
            home.path(),
            &[],
            &[roundabout, home.path().join("nope")],
            100,
        );
        assert_eq!(found.roots, [keep]);
        assert_eq!(found.exclusions_used, [true, false]);
    }

    #[cfg(unix)]
    #[test]
    fn links_are_followed_only_while_they_stay_inside() {
        use std::os::unix::fs::symlink;
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        touch(&outside.path().join("claude/commands/x.md"));
        touch(&outside.path().join("notes.md"));
        // Dotfiles kept in one folder of the home and linked into place: followed.
        touch(&home.path().join("dotfiles/claude/commands/mine.md"));
        symlink(
            home.path().join("dotfiles/claude"),
            home.path().join(".claude"),
        )
        .unwrap();
        // An agent folder that lives outside the home, and a single file that does: not followed.
        symlink(outside.path().join("claude"), home.path().join(".gemini")).unwrap();
        fs::create_dir_all(home.path().join(".codex")).unwrap();
        symlink(
            outside.path().join("notes.md"),
            home.path().join(".codex/AGENTS.md"),
        )
        .unwrap();
        // A link that leads nowhere is like a file that is not there.
        symlink(home.path().join("missing"), home.path().join(".qwen")).unwrap();

        let found = find_in_home(home.path());
        let paths: Vec<&Path> = found.artifacts.iter().map(|a| a.path.as_path()).collect();
        assert_eq!(paths, [home.path().join(".claude/commands/mine.md")]);
        assert_eq!(found.problems.len(), 2, "{:?}", found.problems);
        assert!(found
            .problems
            .iter()
            .any(|p| p.starts_with(&home.path().join(".gemini").display().to_string())));
        assert!(found
            .problems
            .iter()
            .any(|p| p.contains(".codex/AGENTS.md")));
        assert!(found.problems.iter().all(|p| p.contains("outside")));
    }
}
