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
        Tool::Cursor => "Cursor",
        Tool::Copilot => "GitHub Copilot",
        Tool::Codex => "OpenAI Codex",
        Tool::Gemini => "Gemini CLI",
        Tool::Aider => "Aider",
        Tool::Continue => "Continue",
        Tool::Windsurf => "Windsurf",
        Tool::Cline => "Cline / Roo",
        Tool::AmazonQ => "Amazon Q",
        Tool::VsCode => "VS Code / editor",
        Tool::Generic => "AI assistant",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    ClaudeCode,
    Cursor,
    Copilot,
    Codex,
    Gemini,
    Aider,
    Continue,
    Windsurf,
    Cline,
    AmazonQ,
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
    /// Agent settings JSON (`.claude/settings.json`, `.vscode/settings.json`).
    Settings,
    /// An MCP server manifest (`.mcp.json`, `~/.cursor/mcp.json`, …).
    McpConfig,
    /// VS Code tasks (`.vscode/tasks.json`) — auto-run-on-open surface.
    Tasks,
    /// A chat/session transcript (`~/.claude/projects/**/*.jsonl`, `.aider.chat.history.md`).
    Transcript,
    /// A credential/token store whose *permissions* are the finding (`~/.claude/.credentials.json`).
    Credential,
    /// A dotenv file (`.env`, `~/.gemini/.env`).
    DotEnv,
    /// Codex `config.toml` — TOML settings with its own sandbox/approval keys.
    CodexConfig,
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
    "AGENTS.md",
    "GEMINI.md",
    ".cursor",
    ".cursorrules",
    ".mcp.json",
    ".windsurfrules",
    ".continue",
    ".clinerules",
    ".roo",
    ".aider.conf.yml",
    ".aider.chat.history.md",
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

fn push_if_exists(
    out: &mut Vec<Artifact>,
    path: PathBuf,
    tool: Tool,
    kind: ArtifactKind,
    ws: Option<&Path>,
) {
    if path.exists() {
        out.push(Artifact {
            path,
            tool,
            kind,
            workspace: ws.map(Path::to_path_buf),
        });
    }
}

/// The project-scoped artifacts to examine inside one workspace `ws`. Every entry is gated on
/// existence, so a project using only Cursor contributes only Cursor artifacts.
pub fn workspace_artifacts(ws: &Path) -> Vec<Artifact> {
    use ArtifactKind::*;
    use Tool::*;
    let mut out = Vec::new();

    // Instruction / context files.
    push_if_exists(
        &mut out,
        ws.join("CLAUDE.md"),
        ClaudeCode,
        Instructions,
        Some(ws),
    );
    push_if_exists(
        &mut out,
        ws.join("AGENTS.md"),
        Generic,
        Instructions,
        Some(ws),
    );
    push_if_exists(
        &mut out,
        ws.join("GEMINI.md"),
        Gemini,
        Instructions,
        Some(ws),
    );
    push_if_exists(
        &mut out,
        ws.join(".cursorrules"),
        Cursor,
        Instructions,
        Some(ws),
    );
    push_if_exists(
        &mut out,
        ws.join(".windsurfrules"),
        Windsurf,
        Instructions,
        Some(ws),
    );
    push_if_exists(
        &mut out,
        ws.join(".clinerules"),
        Cline,
        Instructions,
        Some(ws),
    );
    push_if_exists(
        &mut out,
        ws.join(".github/copilot-instructions.md"),
        Copilot,
        Instructions,
        Some(ws),
    );
    collect_dir(
        &mut out,
        &ws.join(".cursor/rules"),
        "mdc",
        Cursor,
        Instructions,
        Some(ws),
    );
    collect_dir(
        &mut out,
        &ws.join(".continue/rules"),
        "md",
        Continue,
        Instructions,
        Some(ws),
    );
    collect_dir(
        &mut out,
        &ws.join(".roo/rules"),
        "md",
        Cline,
        Instructions,
        Some(ws),
    );

    // Agent settings.
    push_if_exists(
        &mut out,
        ws.join(".claude/settings.json"),
        ClaudeCode,
        Settings,
        Some(ws),
    );
    push_if_exists(
        &mut out,
        ws.join(".claude/settings.local.json"),
        ClaudeCode,
        Settings,
        Some(ws),
    );
    push_if_exists(
        &mut out,
        ws.join(".vscode/settings.json"),
        VsCode,
        Settings,
        Some(ws),
    );
    push_if_exists(
        &mut out,
        ws.join(".vscode/tasks.json"),
        VsCode,
        Tasks,
        Some(ws),
    );

    // MCP manifests.
    push_if_exists(
        &mut out,
        ws.join(".mcp.json"),
        ClaudeCode,
        McpConfig,
        Some(ws),
    );
    push_if_exists(
        &mut out,
        ws.join(".cursor/mcp.json"),
        Cursor,
        McpConfig,
        Some(ws),
    );
    push_if_exists(
        &mut out,
        ws.join(".vscode/mcp.json"),
        VsCode,
        McpConfig,
        Some(ws),
    );
    push_if_exists(
        &mut out,
        ws.join(".roo/mcp.json"),
        Cline,
        McpConfig,
        Some(ws),
    );
    push_if_exists(
        &mut out,
        ws.join(".amazonq/mcp.json"),
        AmazonQ,
        McpConfig,
        Some(ws),
    );

    // Dotenv + tool config.
    push_if_exists(&mut out, ws.join(".env"), Generic, DotEnv, Some(ws));
    push_if_exists(&mut out, ws.join(".gemini/.env"), Gemini, DotEnv, Some(ws));
    push_if_exists(
        &mut out,
        ws.join(".aider.conf.yml"),
        Aider,
        Settings,
        Some(ws),
    );

    // Transcripts kept at the repo root.
    push_if_exists(
        &mut out,
        ws.join(".aider.chat.history.md"),
        Aider,
        Transcript,
        Some(ws),
    );
    push_if_exists(
        &mut out,
        ws.join(".aider.llm.history"),
        Aider,
        Transcript,
        Some(ws),
    );

    out
}

/// The global `$HOME` tool state to examine, independent of any workspace.
pub fn global_artifacts(home: &Path) -> Vec<Artifact> {
    use ArtifactKind::*;
    use Tool::*;
    let mut out = Vec::new();

    // Claude Code.
    push_if_exists(
        &mut out,
        home.join(".claude/settings.json"),
        ClaudeCode,
        Settings,
        None,
    );
    push_if_exists(
        &mut out,
        home.join(".claude.json"),
        ClaudeCode,
        McpConfig,
        None,
    );
    push_if_exists(
        &mut out,
        home.join(".claude/.credentials.json"),
        ClaudeCode,
        Credential,
        None,
    );
    collect_dir(
        &mut out,
        &home.join(".claude/projects"),
        "jsonl",
        ClaudeCode,
        Transcript,
        None,
    );

    // Codex.
    push_if_exists(
        &mut out,
        home.join(".codex/config.toml"),
        Codex,
        CodexConfig,
        None,
    );
    push_if_exists(
        &mut out,
        home.join(".codex/auth.json"),
        Codex,
        Credential,
        None,
    );
    push_if_exists(
        &mut out,
        home.join(".codex/AGENTS.md"),
        Codex,
        Instructions,
        None,
    );
    collect_dir(
        &mut out,
        &home.join(".codex/sessions"),
        "jsonl",
        Codex,
        Transcript,
        None,
    );

    // Cursor / Copilot / Gemini / Aider / Windsurf / Amazon Q globals.
    push_if_exists(
        &mut out,
        home.join(".cursor/mcp.json"),
        Cursor,
        McpConfig,
        None,
    );
    push_if_exists(
        &mut out,
        home.join(".copilot/mcp-config.json"),
        Copilot,
        McpConfig,
        None,
    );
    push_if_exists(
        &mut out,
        home.join(".config/github-copilot/hosts.json"),
        Copilot,
        Credential,
        None,
    );
    push_if_exists(
        &mut out,
        home.join(".gemini/settings.json"),
        Gemini,
        Settings,
        None,
    );
    push_if_exists(
        &mut out,
        home.join(".gemini/GEMINI.md"),
        Gemini,
        Instructions,
        None,
    );
    push_if_exists(&mut out, home.join(".gemini/.env"), Gemini, DotEnv, None);
    push_if_exists(
        &mut out,
        home.join(".gemini/mcp-oauth-tokens.json"),
        Gemini,
        Credential,
        None,
    );
    push_if_exists(
        &mut out,
        home.join(".aider.conf.yml"),
        Aider,
        Settings,
        None,
    );
    push_if_exists(
        &mut out,
        home.join(".continue/config.yaml"),
        Continue,
        Settings,
        None,
    );
    push_if_exists(
        &mut out,
        home.join(".continue/.env"),
        Continue,
        DotEnv,
        None,
    );
    push_if_exists(
        &mut out,
        home.join(".codeium/windsurf/global_rules.md"),
        Windsurf,
        Instructions,
        None,
    );
    push_if_exists(
        &mut out,
        home.join(".aws/amazonq/mcp.json"),
        AmazonQ,
        McpConfig,
        None,
    );

    out
}

/// Adds every file directly (or, for transcript trees, recursively) under `dir` with extension
/// `ext` as an artifact. Recursion is bounded to a sane depth so a transcript directory tree
/// (`~/.claude/projects/<proj>/*.jsonl`, `~/.codex/sessions/YYYY/MM/DD/*.jsonl`) is fully
/// covered without an unbounded walk.
fn collect_dir(
    out: &mut Vec<Artifact>,
    dir: &Path,
    ext: &str,
    tool: Tool,
    kind: ArtifactKind,
    ws: Option<&Path>,
) {
    fn walk(
        out: &mut Vec<Artifact>,
        dir: &Path,
        ext: &str,
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
            let path = entry.path();
            if path.is_dir() {
                walk(out, &path, ext, tool, kind, ws, depth + 1);
            } else if path.extension().and_then(|e| e.to_str()) == Some(ext) {
                out.push(Artifact {
                    path,
                    tool,
                    kind,
                    workspace: ws.map(Path::to_path_buf),
                });
            }
        }
    }
    walk(out, dir, ext, tool, kind, ws, 0);
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
}
