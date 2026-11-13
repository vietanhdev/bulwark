//! What git would say about a file — is it ignored, is it tracked — worked out by **reading**,
//! never by running git.
//!
//! The scan used to ask `git check-ignore` inside every project it found. Git reads the
//! repository's own `.git/config` before it does anything, and that file can name programs for git
//! to run (`core.fsmonitor` is one of many), so unpacking an archive into `~/Projects` and running
//! a scan executed a command the archive chose. A scanner that reads files must not start a
//! program whose behaviour the scanned folder configures, so nothing here executes anything:
//!
//! * **Ignored** is decided from the ignore files themselves, with the `ignore` crate's
//!   implementation of gitignore patterns (negation, `**`, anchoring, folder-only patterns): every
//!   `.gitignore` from the project root down to the file's folder, then `.git/info/exclude`, then
//!   the user's own global ignore file. The repository's `.git/config` is never read, so a
//!   `core.excludesFile` set *there* is not honoured.
//! * **Tracked** is decided from `.git/index`, the list of files git has staged or committed. The
//!   reader accepts only what it fully understands (index versions 2–4, SHA-1 or SHA-256 object
//!   ids, no split or sparse index, at most [`MAX_INDEX_BYTES`]); anything else is
//!   [`Tracked::Unknown`], which callers must treat as "cannot tell", never as "not tracked".
//!
//! Every file is opened through [`homefs`], so an ignore file or index that is a pipe, or a link
//! out of the project, is skipped instead of followed.

use crate::homefs;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::Match;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// The most that is read from one ignore file. Real ones are a few kilobytes.
const MAX_IGNORE_BYTES: u64 = 1024 * 1024;

/// The largest index that is read. The Linux kernel's is about 9 MB; a repository beyond this is
/// reported as [`Tracked::Unknown`].
pub(super) const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;

/// Whether git tracks a file (it is in the index: staged or committed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Tracked {
    Yes,
    No,
    /// The index could not be read or is in a form this reader does not handle.
    Unknown,
}

/// Git's view of the projects in one scan. Built empty; each repository is read the first time a
/// file in it is asked about, so a scan that finds no key pays nothing.
pub(super) struct GitView {
    home: PathBuf,
    /// Lines of the user's own global ignore file.
    global: OnceLock<Vec<String>>,
    repos: Mutex<HashMap<PathBuf, Option<Arc<Repo>>>>,
}

impl GitView {
    pub(super) fn new(home: &Path) -> GitView {
        GitView {
            home: home.to_path_buf(),
            global: OnceLock::new(),
            repos: Mutex::new(HashMap::new()),
        }
    }

    /// The repository whose root is `workspace`, or `None` when that folder has no `.git`.
    pub(super) fn repo(&self, workspace: &Path) -> Option<Arc<Repo>> {
        let mut repos = self.repos.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(known) = repos.get(workspace) {
            return known.clone();
        }
        let repo = std::fs::symlink_metadata(workspace.join(".git"))
            .is_ok()
            .then(|| Repo::open(workspace, self.global_lines()))
            .flatten()
            .map(Arc::new);
        repos.insert(workspace.to_path_buf(), repo.clone());
        repo
    }

    fn global_lines(&self) -> &[String] {
        self.global.get_or_init(|| global_ignore_lines(&self.home))
    }
}

/// One project that is a git repository.
pub(super) struct Repo {
    workspace: PathBuf,
    root: homefs::Root,
    /// `.git` is a plain folder inside the project. When it is a file (a linked worktree or a
    /// submodule) the index and `info/exclude` live somewhere the project chooses, and are not
    /// followed.
    plain_git_dir: bool,
    rules: Mutex<Rules>,
    index: OnceLock<Option<Vec<u8>>>,
}

struct Rules {
    /// One matcher per folder that has been looked at; `None` when it has no usable `.gitignore`.
    per_dir: HashMap<PathBuf, Option<Gitignore>>,
    /// `.git/info/exclude`, then the user's global file: lower priority than any `.gitignore`.
    shared: Vec<Gitignore>,
}

impl Repo {
    fn open(workspace: &Path, global: &[String]) -> Option<Repo> {
        let root = homefs::Root::new(workspace)?;
        let plain_git_dir =
            std::fs::symlink_metadata(workspace.join(".git")).is_ok_and(|m| m.file_type().is_dir());
        let mut shared = Vec::new();
        if plain_git_dir {
            if let Some(text) = read_text(&root, &workspace.join(".git/info/exclude")) {
                shared.extend(matcher(workspace, text.lines()));
            }
        }
        shared.extend(matcher(workspace, global.iter().map(String::as_str)));
        Some(Repo {
            workspace: workspace.to_path_buf(),
            root,
            plain_git_dir,
            rules: Mutex::new(Rules {
                per_dir: HashMap::new(),
                shared,
            }),
            index: OnceLock::new(),
        })
    }

    /// Whether an ignore rule covers `path` (a file somewhere under this project).
    ///
    /// Git's own order: a file inside an ignored folder is ignored whatever else matches, and
    /// otherwise the last matching pattern of the nearest `.gitignore` decides.
    pub(super) fn ignored(&self, path: &Path) -> bool {
        let Ok(rel) = path.strip_prefix(&self.workspace) else {
            return false;
        };
        let parts: Vec<&std::ffi::OsStr> = rel.iter().collect();
        let mut rules = self.rules.lock().unwrap_or_else(|e| e.into_inner());
        for depth in 1..=parts.len() {
            let sub: PathBuf = parts[..depth].iter().collect();
            let is_dir = depth < parts.len();
            // Re-included, or nothing matched: look at the next level down.
            if self.decision(&mut rules, &sub, is_dir) == Some(true) {
                return true;
            }
        }
        false
    }

    /// What the rules say about `sub` itself (not its parents): ignored, re-included, or nothing.
    fn decision(&self, rules: &mut Rules, sub: &Path, is_dir: bool) -> Option<bool> {
        let mut dir = sub.parent();
        while let Some(d) = dir {
            let abs = self.workspace.join(d);
            let gi = rules.per_dir.entry(d.to_path_buf()).or_insert_with(|| {
                read_text(&self.root, &abs.join(".gitignore"))
                    .and_then(|text| matcher(&abs, text.lines()))
            });
            if let (Some(gi), Ok(below)) = (gi.as_ref(), sub.strip_prefix(d)) {
                match gi.matched(below, is_dir) {
                    Match::Ignore(_) => return Some(true),
                    Match::Whitelist(_) => return Some(false),
                    Match::None => {}
                }
            }
            dir = d.parent();
        }
        for gi in &rules.shared {
            match gi.matched(sub, is_dir) {
                Match::Ignore(_) => return Some(true),
                Match::Whitelist(_) => return Some(false),
                Match::None => {}
            }
        }
        None
    }

    /// Whether git tracks `path`.
    pub(super) fn tracked(&self, path: &Path) -> Tracked {
        let Ok(rel) = path.strip_prefix(&self.workspace) else {
            return Tracked::Unknown;
        };
        if !self.plain_git_dir {
            return Tracked::Unknown;
        }
        let index = self.index.get_or_init(|| {
            match self.root.try_open(&self.workspace.join(".git/index")) {
                // No index yet (a fresh `git init`): nothing is tracked. An empty one stands for
                // that below.
                Ok(None) => Some(Vec::new()),
                Ok(Some(file)) => read_index_bytes(file),
                Err(_) => None,
            }
        });
        match index {
            None => Tracked::Unknown,
            Some(bytes) if bytes.is_empty() => Tracked::No,
            Some(bytes) => match index_lists(bytes, &index_name(rel)) {
                Some(true) => Tracked::Yes,
                Some(false) => Tracked::No,
                None => Tracked::Unknown,
            },
        }
    }
}

/// The path the way the index spells it: `/` between folders, raw bytes.
fn index_name(rel: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, part) in rel.iter().enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            out.extend_from_slice(part.as_bytes());
        }
        #[cfg(not(unix))]
        out.extend_from_slice(part.to_string_lossy().as_bytes());
    }
    out
}

fn read_text(root: &homefs::Root, path: &Path) -> Option<String> {
    let file = root.try_open(path).ok().flatten()?;
    homefs::read_start(file, MAX_IGNORE_BYTES)
}

/// A matcher for ignore lines that apply from `dir` down. `None` when no line is a usable pattern.
fn matcher<'a>(dir: &Path, lines: impl Iterator<Item = &'a str>) -> Option<Gitignore> {
    let mut builder = GitignoreBuilder::new(dir);
    for line in lines {
        // A pattern git cannot parse is skipped by git too.
        let _ = builder.add_line(None, line.trim_end_matches('\r'));
    }
    builder.build().ok().filter(|g| !g.is_empty())
}

/// The user's own global ignore file: the one `core.excludesFile` names in their git config, else
/// git's default `~/.config/git/ignore`. Read from the home folder only.
fn global_ignore_lines(home: &Path) -> Vec<String> {
    let configured = [".gitconfig", ".config/git/config"].iter().find_map(|rel| {
        let text = homefs::read_in_home(home, &home.join(rel), MAX_IGNORE_BYTES).found()?;
        excludes_file_setting(&text, home)
    });
    let path = configured.unwrap_or_else(|| home.join(".config/git/ignore"));
    homefs::read_in_home(home, &path, MAX_IGNORE_BYTES)
        .found()
        .map(|text| text.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// `core.excludesFile` from a git config file's text, with a leading `~/` resolved.
fn excludes_file_setting(config: &str, home: &Path) -> Option<PathBuf> {
    let mut in_core = false;
    let mut value = None;
    for line in config.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_core = line
                .trim_start_matches('[')
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("core]");
            continue;
        }
        if !in_core || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some((key, v)) = line.split_once('=') {
            if key.trim().eq_ignore_ascii_case("excludesfile") {
                value = Some(v.trim().trim_matches('"').to_string());
            }
        }
    }
    let value = value.filter(|v| !v.is_empty())?;
    match value.strip_prefix("~/") {
        Some(rest) => Some(home.join(rest)),
        None => Some(PathBuf::from(&value)).filter(|p| p.is_absolute()),
    }
}

fn read_index_bytes(file: std::fs::File) -> Option<Vec<u8>> {
    use std::io::Read;
    let len = file.metadata().ok()?.len();
    if len > MAX_INDEX_BYTES {
        return None;
    }
    let mut bytes = Vec::with_capacity(usize::try_from(len).ok()?);
    file.take(MAX_INDEX_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    // An index that exists but is empty is not something git writes: cannot tell.
    (!bytes.is_empty() && bytes.len() as u64 <= MAX_INDEX_BYTES).then_some(bytes)
}

/// Whether the index in `data` lists `name`. `None` when the index is not in a form this reader
/// fully understands.
///
/// The format is git's `Documentation/gitformat-index.txt`: a 12-byte header (`DIRC`, version,
/// entry count), the entries sorted by name, optional extensions, and a trailing checksum. The
/// object-id length (20 bytes for SHA-1, 32 for SHA-256) is not recorded in the file, so both are
/// tried; a wrong guess cannot pass the checks below, because every entry has to carry a valid
/// file mode, the names have to be in order, and the walk has to end exactly at the checksum.
pub(super) fn index_lists(data: &[u8], name: &[u8]) -> Option<bool> {
    [20usize, 32]
        .into_iter()
        .find_map(|id_len| index_lists_with(data, name, id_len))
}

fn index_lists_with(data: &[u8], name: &[u8], id_len: usize) -> Option<bool> {
    let be32 = |at: usize| -> Option<u32> {
        Some(u32::from_be_bytes(data.get(at..at + 4)?.try_into().ok()?))
    };
    let be16 = |at: usize| -> Option<u16> {
        Some(u16::from_be_bytes(data.get(at..at + 2)?.try_into().ok()?))
    };
    if data.get(..4)? != b"DIRC" {
        return None;
    }
    let version = be32(4)?;
    if !(2..=4).contains(&version) {
        return None;
    }
    let count = be32(8)? as usize;
    // Everything before the trailing checksum.
    let end = data.len().checked_sub(id_len)?;
    let mut pos = 12usize;
    let mut found = false;
    let mut previous: Vec<u8> = Vec::new();
    for _ in 0..count {
        let start = pos;
        // 40 bytes of file times, sizes and ids; the object id; 2 bytes of flags.
        let flags_at = start + 40 + id_len;
        if flags_at + 2 > end {
            return None;
        }
        let mode = be32(start + 24)?;
        // A regular file, an executable, a link, a submodule, or a sparse folder.
        if !matches!(mode, 0o100644 | 0o100755 | 0o120000 | 0o160000 | 0o040000) {
            return None;
        }
        let flags = be16(flags_at)?;
        pos = flags_at + 2;
        if flags & 0x4000 != 0 {
            // Extended flags exist from version 3 on.
            if version < 3 || pos + 2 > end {
                return None;
            }
            pos += 2;
        }
        let current: Vec<u8> = if version == 4 {
            // The name is stored as "drop N bytes from the previous name, then append this".
            let (drop, used) = varint(data.get(pos..end)?)?;
            pos += used;
            let rest = data.get(pos..end)?;
            let nul = rest.iter().position(|b| *b == 0)?;
            let keep = previous.len().checked_sub(drop)?;
            let mut full = previous[..keep].to_vec();
            full.extend_from_slice(&rest[..nul]);
            pos += nul + 1;
            full
        } else {
            let short = usize::from(flags & 0x0FFF);
            let len = if short < 0x0FFF {
                short
            } else {
                data.get(pos..end)?.iter().position(|b| *b == 0)?
            };
            let bytes = data.get(pos..pos + len)?;
            // Entries are padded with 1 to 8 NUL bytes to a multiple of eight.
            let padded = (pos + len - start + 8) & !7;
            let padding = data.get(pos + len..start + padded)?;
            if start + padded > end || bytes.contains(&0) || padding.iter().any(|b| *b != 0) {
                return None;
            }
            pos = start + padded;
            bytes.to_vec()
        };
        // Names are never empty and are stored in order (the same name can repeat during a merge).
        if current.is_empty() || current < previous {
            return None;
        }
        found |= current == name;
        previous = current;
    }
    // Extensions: a 4-byte name and a 4-byte length each.
    while pos < end {
        let sig = data.get(pos..pos + 4)?;
        let size = be32(pos + 4)? as usize;
        // A split index keeps most entries in another file; a sparse index lists whole folders
        // instead of their files. Either way this list is not the whole answer.
        if sig == b"link" || sig == b"sdir" {
            return None;
        }
        pos = pos.checked_add(8)?.checked_add(size)?;
    }
    (pos == end).then_some(found)
}

/// Git's variable-length integer (the "offset" encoding used for version-4 names): the value and
/// how many bytes it took.
fn varint(data: &[u8]) -> Option<(usize, usize)> {
    let mut used = 0usize;
    let mut byte = *data.get(used)?;
    used += 1;
    let mut value = usize::from(byte & 0x7F);
    while byte & 0x80 != 0 {
        byte = *data.get(used)?;
        used += 1;
        value = value
            .checked_add(1)?
            .checked_mul(128)?
            .checked_add(usize::from(byte & 0x7F))?;
    }
    Some((value, used))
}

#[cfg(test)]
/// A version 2 or 3 index holding `names` (sorted by the caller), with `id_len`-byte ids.
pub(super) fn index_v2(
    version: u32,
    id_len: usize,
    names: &[&str],
    extension: Option<&[u8; 4]>,
) -> Vec<u8> {
    let mut out = b"DIRC".to_vec();
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(names.len() as u32).to_be_bytes());
    for name in names {
        let start = out.len();
        out.extend_from_slice(&[0u8; 24]); // times, device, inode
        out.extend_from_slice(&0o100644u32.to_be_bytes());
        out.extend_from_slice(&[0u8; 12]); // uid, gid, size
        out.extend_from_slice(&vec![0xAB; id_len]);
        out.extend_from_slice(&(name.len().min(0xFFF) as u16).to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        let padded = (out.len() - start + 8) & !7;
        out.resize(start + padded, 0);
    }
    if let Some(sig) = extension {
        out.extend_from_slice(sig);
        out.extend_from_slice(&4u32.to_be_bytes());
        out.extend_from_slice(&[1, 2, 3, 4]);
    }
    out.extend_from_slice(&vec![0xCD; id_len]); // the checksum; not verified
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(path: &Path, text: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    /// A repository folder with these ignore lines at its root and an empty `.git`.
    fn repo_with(lines: &str) -> (tempfile::TempDir, Arc<Repo>) {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".git")).unwrap();
        write(&dir.path().join(".gitignore"), lines);
        let view = GitView::new(dir.path());
        let repo = view.repo(dir.path()).expect("a folder with .git");
        (dir, repo)
    }

    #[test]
    fn ignore_rules_follow_gits_semantics() {
        let (dir, repo) = repo_with(
            "*.env\n.claude/\n.aider*\n/build\n# a comment\n\n!keep.env\ndocs/**/draft.md\nnotes/*.md\n",
        );
        let p = |rel: &str| dir.path().join(rel);
        assert!(repo.ignored(&p("prod.env")));
        assert!(repo.ignored(&p("deep/down/prod.env")));
        assert!(
            !repo.ignored(&p("keep.env")),
            "a later ! pattern re-includes"
        );
        assert!(repo.ignored(&p(".claude/settings.local.json")));
        assert!(repo.ignored(&p(".claude/commands/x.md")));
        assert!(repo.ignored(&p(".aider.chat.history.md")));
        assert!(repo.ignored(&p("build")), "/build is anchored to the root");
        assert!(!repo.ignored(&p("src/build")), "and does not match deeper");
        assert!(repo.ignored(&p("docs/a/b/draft.md")));
        assert!(repo.ignored(&p("notes/a.md")));
        assert!(
            !repo.ignored(&p("notes/sub/a.md")),
            "* does not cross a folder"
        );
        assert!(!repo.ignored(&p("CLAUDE.md")));
        assert!(!repo.ignored(&p(".mcp.json")));
    }

    #[test]
    fn a_file_under_an_ignored_folder_cannot_be_re_included() {
        // Git's documented rule, and the one a hostile repository would otherwise lean on the
        // other way round: `!` cannot reach into a folder that is itself ignored.
        let (dir, repo) = repo_with(".cursor/\n!.cursor/rules/keep.mdc\n");
        assert!(repo.ignored(&dir.path().join(".cursor/rules/keep.mdc")));
    }

    #[test]
    fn nested_ignore_files_and_info_exclude_are_read() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        write(&ws.join(".git/info/exclude"), "local-only.md\n");
        write(&ws.join(".gitignore"), "*.log\n");
        write(&ws.join(".claude/.gitignore"), "scratch/\n!important.log\n");
        let view = GitView::new(ws);
        let repo = view.repo(ws).unwrap();
        assert!(repo.ignored(&ws.join("local-only.md")));
        assert!(repo.ignored(&ws.join(".claude/scratch/n.md")));
        assert!(repo.ignored(&ws.join(".claude/x.log")));
        assert!(
            !repo.ignored(&ws.join(".claude/important.log")),
            "the nearer .gitignore wins over the root one"
        );
        assert!(!repo.ignored(&ws.join(".claude/commands/n.md")));
    }

    #[test]
    fn the_users_global_ignore_file_counts_and_the_repositorys_config_does_not() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("Projects/app");
        fs::create_dir_all(ws.join(".git")).unwrap();
        // The repository's own config names an excludes file: not honoured, never read.
        write(
            &ws.join(".git/config"),
            "[core]\n\texcludesFile = /dev/zero\n\tfsmonitor = touch /should-not-run\n",
        );
        write(&home.path().join(".config/git/ignore"), ".env\n");
        let view = GitView::new(home.path());
        assert!(view.repo(&ws).unwrap().ignored(&ws.join(".env")));
        assert!(!view.repo(&ws).unwrap().ignored(&ws.join("CLAUDE.md")));

        // A `core.excludesFile` in the user's own config replaces the default location.
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("Projects/app");
        fs::create_dir_all(ws.join(".git")).unwrap();
        write(
            &home.path().join(".gitconfig"),
            "[user]\n\tname = x\n[Core]\n\tExcludesFile = ~/.my-ignores\n",
        );
        write(&home.path().join(".my-ignores"), "secrets.md\n");
        write(&home.path().join(".config/git/ignore"), ".env\n");
        let view = GitView::new(home.path());
        let repo = view.repo(&ws).unwrap();
        assert!(repo.ignored(&ws.join("secrets.md")));
        assert!(!repo.ignored(&ws.join(".env")));
    }

    #[test]
    fn a_folder_without_git_is_not_a_repository() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join(".gitignore"), "*\n");
        assert!(GitView::new(dir.path()).repo(dir.path()).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn an_ignore_file_that_is_a_pipe_or_a_link_out_is_skipped_without_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let ws = dir.path();
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::create_dir_all(ws.join("sub")).unwrap();
        write(&outside.path().join("rules"), "*\n");
        std::os::unix::fs::symlink(outside.path().join("rules"), ws.join(".gitignore")).unwrap();
        let fifo = std::ffi::CString::new(ws.join("sub/.gitignore").to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path and a plain mode.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();
        let repo = GitView::new(ws).repo(ws).unwrap();
        assert!(!repo.ignored(&ws.join("sub/notes.md")));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    // ---- The index reader.

    /// A version 4 index: names are stored as a difference from the one before.
    fn index_v4(names: &[&str]) -> Vec<u8> {
        let mut out = b"DIRC".to_vec();
        out.extend_from_slice(&4u32.to_be_bytes());
        out.extend_from_slice(&(names.len() as u32).to_be_bytes());
        let mut previous = String::new();
        for name in names {
            out.extend_from_slice(&[0u8; 24]);
            out.extend_from_slice(&0o100644u32.to_be_bytes());
            out.extend_from_slice(&[0u8; 12]);
            out.extend_from_slice(&[0xAB; 20]);
            out.extend_from_slice(&(name.len() as u16).to_be_bytes());
            let common = previous
                .bytes()
                .zip(name.bytes())
                .take_while(|(a, b)| a == b)
                .count();
            let drop = previous.len() - common;
            assert!(drop < 128, "the test encoder only writes one-byte lengths");
            out.push(drop as u8);
            out.extend_from_slice(&name.as_bytes()[common..]);
            out.push(0);
            previous = name.to_string();
        }
        out.extend_from_slice(&[0xCD; 20]);
        out
    }

    #[test]
    fn the_index_reader_finds_tracked_names_in_every_supported_form() {
        let names = [".claude/settings.json", ".env", ".mcp.json", "src/main.rs"];
        for (label, index) in [
            ("v2 sha1", index_v2(2, 20, &names, None)),
            ("v3 sha1", index_v2(3, 20, &names, None)),
            ("v2 sha256", index_v2(2, 32, &names, None)),
            (
                "v2 with a cache-tree extension",
                index_v2(2, 20, &names, Some(b"TREE")),
            ),
            ("v4", index_v4(&names)),
        ] {
            assert_eq!(index_lists(&index, b".env"), Some(true), "{label}");
            assert_eq!(index_lists(&index, b".mcp.json"), Some(true), "{label}");
            assert_eq!(index_lists(&index, b"src/main.rs"), Some(true), "{label}");
            assert_eq!(index_lists(&index, b".envx"), Some(false), "{label}");
            assert_eq!(index_lists(&index, b"src"), Some(false), "{label}");
        }
        // No entries at all.
        assert_eq!(
            index_lists(&index_v2(2, 20, &[], None), b".env"),
            Some(false)
        );
    }

    #[test]
    fn the_index_reader_says_unknown_rather_than_guess() {
        let names = [".env", "a"];
        let good = index_v2(2, 20, &names, None);
        // A split index or a sparse index does not list everything.
        assert_eq!(
            index_lists(&index_v2(2, 20, &names, Some(b"link")), b".env"),
            None
        );
        assert_eq!(
            index_lists(&index_v2(3, 20, &names, Some(b"sdir")), b".env"),
            None
        );
        // Not an index, a future version, cut short, or with bytes changed.
        assert_eq!(index_lists(b"", b".env"), None);
        assert_eq!(
            index_lists(b"not an index at all, just text", b".env"),
            None
        );
        let mut future = good.clone();
        future[7] = 5;
        assert_eq!(index_lists(&future, b".env"), None);
        for cut in [1, 11, 13, 40, good.len() - 21, good.len() - 1] {
            assert_eq!(index_lists(&good[..cut], b".env"), None, "cut at {cut}");
        }
        let mut bad_mode = good.clone();
        bad_mode[12 + 24..12 + 28].copy_from_slice(&0o777u32.to_be_bytes());
        assert_eq!(index_lists(&bad_mode, b".env"), None);
        // Names out of order: not something git writes.
        assert_eq!(index_lists(&index_v2(2, 20, &["b", "a"], None), b"a"), None);
        // An entry count far larger than the file.
        let mut lying = good.clone();
        lying[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(index_lists(&lying, b".env"), None);
        // Random bytes after a valid header never panic.
        let mut noise = b"DIRC\0\0\0\x02\0\0\0\x03".to_vec();
        noise.extend((0..4096u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8));
        let _ = index_lists(&noise, b".env");
    }

    #[test]
    fn tracked_is_read_from_the_projects_own_index() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        fs::create_dir_all(ws.join(".git")).unwrap();
        let view = GitView::new(ws);
        // No index yet: nothing is tracked.
        assert_eq!(
            view.repo(ws).unwrap().tracked(&ws.join(".env")),
            Tracked::No
        );

        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::write(
            ws.join(".git/index"),
            index_v2(2, 20, &[".claude/settings.json", ".env"], None),
        )
        .unwrap();
        let repo = GitView::new(ws).repo(ws).unwrap();
        assert_eq!(repo.tracked(&ws.join(".env")), Tracked::Yes);
        assert_eq!(
            repo.tracked(&ws.join(".claude/settings.json")),
            Tracked::Yes
        );
        assert_eq!(repo.tracked(&ws.join("CLAUDE.md")), Tracked::No);

        // `.git` is a file (a linked worktree): the index is elsewhere and is not followed.
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        fs::write(
            ws.join(".git"),
            "gitdir: /somewhere/else/.git/worktrees/x\n",
        )
        .unwrap();
        fs::write(ws.join(".gitignore"), "local.md\n").unwrap();
        let repo = GitView::new(ws).repo(ws).unwrap();
        assert_eq!(repo.tracked(&ws.join("local.md")), Tracked::Unknown);
        assert!(
            repo.ignored(&ws.join("local.md")),
            "its .gitignore files still apply"
        );

        // An unreadable form of index.
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::write(ws.join(".git/index"), b"garbage").unwrap();
        assert_eq!(
            GitView::new(ws).repo(ws).unwrap().tracked(&ws.join(".env")),
            Tracked::Unknown
        );
    }

    /// The reader against indexes written by the real `git`, in each form git can produce. Skipped
    /// where git is not installed; the hand-built indexes above cover the format without it.
    #[test]
    fn the_index_reader_agrees_with_real_git() {
        let git = |dir: &Path, args: &[&str]| -> bool {
            crate::sandbox::quiet_command("git")
                .arg("-C")
                .arg(dir)
                .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
                .args(args)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        };
        let probe = tempfile::tempdir().unwrap();
        if !git(probe.path(), &["init", "-q", "."]) {
            eprintln!("git not installed; skipping");
            return;
        }
        // (how to make the repository, what to do after adding, expected answer for a tracked file)
        let forms: &[(&[&str], &[&str], Tracked)] = &[
            (&["init", "-q", "."], &[], Tracked::Yes),
            (
                &["init", "-q", "."],
                &["update-index", "--index-version", "4"],
                Tracked::Yes,
            ),
            (
                &["init", "-q", "--object-format=sha256", "."],
                &[],
                Tracked::Yes,
            ),
            (
                &["init", "-q", "."],
                &["update-index", "--split-index"],
                Tracked::Unknown,
            ),
        ];
        for (init, after, expected) in forms {
            let dir = tempfile::tempdir().unwrap();
            let ws = dir.path();
            if !git(ws, init) {
                continue; // an older git without this option
            }
            write(&ws.join(".gitignore"), ".claude/\n.env\n");
            write(&ws.join(".claude/settings.json"), "{}");
            write(&ws.join(".claude/settings.local.json"), "{}");
            write(&ws.join(".env"), "A=1\n");
            write(&ws.join("src/a b/ünï.rs"), "fn main() {}\n");
            for i in 0..40 {
                write(&ws.join(format!("src/gen/file_{i:02}.txt")), "x\n");
            }
            assert!(git(
                ws,
                &["add", "-f", ".claude/settings.json", ".gitignore", "src"]
            ));
            if !after.is_empty() && !git(ws, after) {
                continue;
            }
            let repo = GitView::new(ws).repo(ws).unwrap();
            let label = format!("{init:?} {after:?}");
            assert_eq!(
                repo.tracked(&ws.join(".claude/settings.json")),
                *expected,
                "{label}"
            );
            assert_eq!(
                repo.tracked(&ws.join("src/a b/ünï.rs")),
                *expected,
                "{label}"
            );
            if *expected == Tracked::Yes {
                assert_eq!(repo.tracked(&ws.join(".env")), Tracked::No, "{label}");
                assert_eq!(
                    repo.tracked(&ws.join(".claude/settings.local.json")),
                    Tracked::No,
                    "{label}"
                );
            }
            assert!(repo.ignored(&ws.join(".claude/settings.json")), "{label}");
            assert!(repo.ignored(&ws.join(".env")), "{label}");
        }
    }
}
