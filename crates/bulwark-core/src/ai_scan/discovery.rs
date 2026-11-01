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

use std::collections::BTreeSet;
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

/// The marker files/dirs whose presence makes a directory a "workspace" worth scanning. Kept in
/// sync with the artifacts `workspace_artifacts` will then look for.
const WORKSPACE_MARKERS: &[&str] = &[
    ".claude",
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    "AGENT.md",
    "GEMINI.md",
    "QWEN.md",
    "CRUSH.md",
    "WARP.md",
    "AmazonQ.md",
    ".agents",
    ".cursor",
    ".cursorrules",
    ".mcp.json",
    ".windsurf",
    ".windsurfrules",
    ".devin",
    ".continue",
    ".clinerules",
    ".roo",
    ".roorules",
    ".roomodes",
    ".kilo",
    ".kilocode",
    "kilo.json",
    "kilo.jsonc",
    ".aider.conf.yml",
    ".aider.chat.history.md",
    ".gemini",
    ".qwen",
    ".kiro",
    ".amazonq",
    ".zed",
    ".rules",
    ".goosehints",
    ".opencode",
    "opencode.json",
    "opencode.jsonc",
    "crush.json",
    ".crush.json",
    "crushrc",
    ".crushrc",
    ".amp",
    ".augment",
    ".augment-guidelines",
    ".junie",
    ".aiassistant",
    ".github/copilot-instructions.md",
    ".github/instructions",
    ".github/agents",
    ".github/prompts",
    ".github/hooks",
    ".github/mcp.json",
    ".vscode/mcp.json",
];

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

fn has_any_marker(dir: &Path) -> bool {
    WORKSPACE_MARKERS.iter().any(|m| dir.join(m).exists())
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

/// Discovers workspace roots from all three sources, de-duplicated. `configured_roots` are
/// user-added directories (each swept like a common root); `excluded` roots are dropped from the
/// result even if a marker is present. `max_workspaces` caps the result so a pathological home
/// directory can't make a scan unbounded — the cap being hit is worth surfacing to the user.
pub fn discover_workspaces(
    home: &Path,
    configured_roots: &[PathBuf],
    excluded: &[PathBuf],
    max_workspaces: usize,
) -> Vec<PathBuf> {
    let mut found: BTreeSet<PathBuf> = BTreeSet::new();

    // Source 1: Claude Code's own record of every project it's opened.
    let projects_dir = home.join(".claude/projects");
    if let Ok(entries) = std::fs::read_dir(&projects_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Some(path) = decode_claude_project_dir(name) {
                    found.insert(path);
                }
            }
        }
    }

    // Source 2: a shallow sweep of the common code roots (plus configured roots).
    let sweep_roots: Vec<PathBuf> = COMMON_CODE_ROOTS
        .iter()
        .map(|r| home.join(r))
        .chain(configured_roots.iter().cloned())
        .collect();
    for root in sweep_roots {
        sweep_root(&root, &mut found);
    }

    // A configured root can itself be a workspace, not just a container of them.
    for root in configured_roots {
        if root.is_dir() && has_any_marker(root) {
            found.insert(root.clone());
        }
    }

    let excluded: BTreeSet<&Path> = excluded.iter().map(|p| p.as_path()).collect();
    found
        .into_iter()
        .filter(|p| !excluded.contains(p.as_path()))
        .take(max_workspaces)
        .collect()
}

/// Sweeps one container directory two levels deep for marker-bearing workspaces. Two levels
/// covers both `~/Projects/app` and `~/Projects/org/app` layouts without a full recursive walk.
fn sweep_root(root: &Path, found: &mut BTreeSet<PathBuf>) {
    let Ok(level1) = std::fs::read_dir(root) else {
        return;
    };
    for e1 in level1.flatten() {
        let p1 = e1.path();
        if !p1.is_dir() || is_skip_dir(&p1) {
            continue;
        }
        if has_any_marker(&p1) {
            found.insert(p1.clone());
            continue; // don't also descend into a directory that's already a workspace
        }
        if let Ok(level2) = std::fs::read_dir(&p1) {
            for e2 in level2.flatten() {
                let p2 = e2.path();
                if p2.is_dir() && !is_skip_dir(&p2) && has_any_marker(&p2) {
                    found.insert(p2);
                }
            }
        }
    }
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
}

/// One known artifact location, relative to a workspace root or to `$HOME`.
struct Spec(&'static str, Tool, ArtifactKind, Find);

use ArtifactKind::{
    CodexConfig, Credential, DotEnv, Hooks, Instructions, McpConfig, Memory, Settings, Tasks,
    Transcript,
};
use Find::{Dir, File, Named};
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
    Spec(".claude/plugins/cache", ClaudeCode, Instructions, Dir(MD)),
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
    Spec(".gemini/extensions", Gemini, Instructions, Dir(MD)),
    Spec(
        ".gemini/extensions",
        Gemini,
        McpConfig,
        Named("gemini-extension.json"),
    ),
    Spec(".gemini/tmp", Gemini, Transcript, Dir(&["jsonl"])),
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

fn push_if_exists(
    out: &mut Vec<Artifact>,
    path: PathBuf,
    tool: Tool,
    kind: ArtifactKind,
    ws: Option<&Path>,
) {
    if path.is_file() {
        out.push(Artifact {
            path,
            tool,
            kind,
            workspace: ws.map(Path::to_path_buf),
        });
    }
}

fn apply_specs(out: &mut Vec<Artifact>, base: &Path, specs: &[Spec], ws: Option<&Path>) {
    for Spec(rel, tool, kind, find) in specs {
        let path = base.join(rel);
        match find {
            File => push_if_exists(out, path, *tool, *kind, ws),
            Dir(exts) => collect_dir(out, &path, |p| has_ext(p, exts), *tool, *kind, ws),
            Named(name) => collect_dir(
                out,
                &path,
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
    let mut out = Vec::new();
    apply_specs(&mut out, ws, WORKSPACE_SPECS, Some(ws));
    out
}

/// The global `$HOME` tool state to examine, independent of any workspace.
pub fn global_artifacts(home: &Path) -> Vec<Artifact> {
    let mut out = Vec::new();
    apply_specs(&mut out, home, GLOBAL_SPECS, None);
    for product in VSCODE_FAMILY {
        let user = home.join(".config").join(product).join("User");
        push_if_exists(&mut out, user.join("settings.json"), VsCode, Settings, None);
        push_if_exists(&mut out, user.join("mcp.json"), VsCode, McpConfig, None);
        // Profiles carry their own settings.json — a YOLO flag can live in a non-default profile.
        if let Ok(profiles) = std::fs::read_dir(user.join("profiles")) {
            for p in profiles.flatten() {
                push_if_exists(
                    &mut out,
                    p.path().join("settings.json"),
                    VsCode,
                    Settings,
                    None,
                );
                push_if_exists(&mut out, p.path().join("mcp.json"), VsCode, McpConfig, None);
            }
        }
        for (ext, tool, mcp) in EXTENSION_STORAGE {
            let store = user.join("globalStorage").join(ext);
            push_if_exists(&mut out, store.join(mcp), *tool, McpConfig, None);
            collect_dir(
                &mut out,
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

/// Adds every file under `dir` accepted by `want` as an artifact. Recursion is bounded to a sane
/// depth so a transcript directory tree (`~/.claude/projects/<proj>/*.jsonl`,
/// `~/.codex/sessions/YYYY/MM/DD/*.jsonl`) is fully covered without an unbounded walk, and
/// dependency/VCS trees are skipped — an installed plugin can bundle a whole `node_modules`.
fn collect_dir(
    out: &mut Vec<Artifact>,
    dir: &Path,
    want: impl Fn(&Path) -> bool,
    tool: Tool,
    kind: ArtifactKind,
    ws: Option<&Path>,
) {
    fn walk(
        out: &mut Vec<Artifact>,
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
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
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
                if !is_skip_dir(&path) {
                    walk(out, &path, want, tool, kind, ws, depth + 1);
                }
            } else if want(&path) {
                out.push(Artifact {
                    path,
                    tool,
                    kind,
                    workspace: ws.map(Path::to_path_buf),
                });
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
}
