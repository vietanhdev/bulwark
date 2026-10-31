//! Python interpreter startup hooks. Python's `site` module executes every line that starts with
//! `import` in each `*.pth` file of a site-packages directory, and imports `sitecustomize` /
//! `usercustomize` if present — at the start of *every* Python process, before any user code.
//! That is how the October 2026 LiteLLM 1.107.0 release ran its credential stealer without ever
//! being imported, so hooks that execute code are worth surfacing.
//!
//! Two collectors live here:
//!   * `python_startup_hooks` — one row per hook that executes code (or whose content couldn't be
//!     read, in which case `executes_code` is omitted and the rule reports a collector error).
//!   * `supply_chain_iocs` — one row per known supply-chain indicator actually present on disk.

use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct PythonStartupHooksCollector;
pub struct SupplyChainIocsCollector;

/// `.pth` files shipped by widely used, legitimate tooling that do execute an import line.
const BENIGN_PTH_NAMES: &[&str] = &[
    "distutils-precedence.pth",
    "_virtualenv.pth",
    "easy-install.pth",
    "a1_coverage.pth",
    "coverage.pth",
    "pytest-cov.pth",
    "pywin32.pth",
    // coloredlogs installs itself into the root logger when $COLOREDLOGS_AUTO_INSTALL is set.
    "coloredlogs.pth",
];

/// True for a `.pth` produced by a well-known legitimate mechanism (setuptools editable installs,
/// namespace packages, virtualenv, coverage).
pub fn is_known_benign_pth(name: &str) -> bool {
    BENIGN_PTH_NAMES.contains(&name)
        || name.starts_with("__editable__")
        || name.ends_with("-nspkg.pth")
}

/// Number of lines `site` would execute: those starting with `import` followed by whitespace.
pub fn executable_pth_lines(text: &str) -> usize {
    text.lines()
        .filter(|l| {
            l.strip_prefix("import")
                .is_some_and(|rest| rest.starts_with(' ') || rest.starts_with('\t'))
        })
        .count()
}

/// Names the LiteLLM 1.107.0 payload dropped into site-packages.
const LITELLM_PAYLOAD_PTH: &str = "cook.pth";

fn python_lib_dirs(prefix: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(prefix.join("lib")) else {
        return vec![];
    };
    entries
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("python3"))
        .map(|e| e.path())
        .collect()
}

/// `prefix/lib/python3*/{site,dist}-packages` that exist.
fn site_dirs_under(prefix: &Path) -> Vec<PathBuf> {
    python_lib_dirs(prefix)
        .into_iter()
        .flat_map(|lib| [lib.join("site-packages"), lib.join("dist-packages")])
        .filter(|d| d.is_dir())
        .collect()
}

fn children(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|it| it.flatten().map(|e| e.path()).collect())
        .unwrap_or_default()
}

/// Every site-packages directory worth checking: system, user, conda/pyenv/pipx/uv environments,
/// and project virtualenvs (any `pyvenv.cfg` up to four levels below a home directory).
pub(crate) fn site_package_dirs() -> Vec<PathBuf> {
    let mut prefixes: Vec<PathBuf> = vec![PathBuf::from("/usr"), PathBuf::from("/usr/local")];
    for home in super::user_homes() {
        prefixes.push(home.join(".local"));
        for conda in ["miniconda3", "anaconda3", "miniforge3", "mambaforge"] {
            let base = home.join(conda);
            prefixes.push(base.clone());
            prefixes.extend(children(&base.join("envs")));
        }
        for managed in [
            ".pyenv/versions",
            ".virtualenvs",
            ".local/share/virtualenvs",
            ".local/share/uv/tools",
            ".local/share/pipx/venvs",
            ".local/pipx/venvs",
        ] {
            prefixes.extend(children(&home.join(managed)));
        }
        let walker = walkdir::WalkDir::new(&home)
            .max_depth(4)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                e.depth() == 0
                    || !(name == "node_modules"
                        || name == ".git"
                        || name == ".cache"
                        || name == ".local"
                        || name.starts_with("miniconda")
                        || name.starts_with("anaconda"))
            });
        for entry in walker.flatten() {
            if entry.file_type().is_file() && entry.file_name() == "pyvenv.cfg" {
                if let Some(venv) = entry.path().parent() {
                    prefixes.push(venv.to_path_buf());
                }
            }
        }
    }
    // Canonicalize so a symlinked alias (conda's `lib/python3.1` -> `python3.10`) is one directory.
    let mut dirs: Vec<PathBuf> = prefixes
        .iter()
        .flat_map(|p| site_dirs_under(p))
        .map(|d| d.canonicalize().unwrap_or(d))
        .collect();
    dirs.sort();
    dirs.dedup();
    dirs
}

fn hook_rows(site: &Path) -> Vec<Fact> {
    let mut rows = Vec::new();
    let Ok(entries) = std::fs::read_dir(site) else {
        return rows;
    };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let hook_type = if name.ends_with(".pth") {
            "pth"
        } else if name == "sitecustomize.py" {
            "sitecustomize"
        } else if name == "usercustomize.py" {
            "usercustomize"
        } else {
            continue;
        };
        let mut fact = Fact::new();
        fact.insert(
            "path".into(),
            Value::String(entry.path().display().to_string()),
        );
        fact.insert("hook_type".into(), Value::String(hook_type.into()));
        fact.insert(
            "known_benign".into(),
            Value::Bool(hook_type == "pth" && is_known_benign_pth(&name)),
        );
        fact.insert(
            "malicious_name".into(),
            Value::Bool(name == LITELLM_PAYLOAD_PTH),
        );
        if hook_type == "pth" {
            // Unreadable: leave `executes_code` out so the rule reports it as undetermined.
            if let Ok(text) = super::read_capped(&entry.path()) {
                if executable_pth_lines(&text) == 0 {
                    // A path-only .pth just extends sys.path; not a code-execution hook.
                    continue;
                }
                fact.insert("executes_code".into(), Value::Bool(true));
            }
        } else {
            fact.insert("executes_code".into(), Value::Bool(true));
        }
        rows.push(fact);
    }
    rows
}

impl Collector for PythonStartupHooksCollector {
    fn name(&self) -> &'static str {
        "python_startup_hooks"
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        Ok(site_package_dirs()
            .iter()
            .flat_map(|d| hook_rows(d))
            .collect())
    }
}

fn ioc_row(indicator: &str, path: &Path) -> Fact {
    let mut fact = Fact::new();
    fact.insert("indicator".into(), Value::String(indicator.into()));
    fact.insert("path".into(), Value::String(path.display().to_string()));
    fact
}

/// LiteLLM 1.107.0 indicators in a temp directory: the backdoor's lock file and the stealer's
/// "already ran" markers.
pub fn temp_dir_iocs(tmp: &Path) -> Vec<Fact> {
    let mut rows = Vec::new();
    let lock = tmp.join("remote_code_loader.lock");
    if std::fs::symlink_metadata(&lock).is_ok() {
        rows.push(ioc_row("litellm_loader_lock", &lock));
    }
    if let Ok(entries) = std::fs::read_dir(tmp) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(".pc_once_") {
                rows.push(ioc_row("litellm_exfil_marker", &entry.path()));
            }
        }
    }
    rows
}

impl Collector for SupplyChainIocsCollector {
    fn name(&self) -> &'static str {
        "supply_chain_iocs"
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let mut rows = temp_dir_iocs(Path::new("/tmp"));
        rows.extend(temp_dir_iocs(Path::new("/var/tmp")));
        for site in site_package_dirs() {
            let pth = site.join(LITELLM_PAYLOAD_PTH);
            if std::fs::symlink_metadata(&pth).is_ok() {
                rows.push(ioc_row("litellm_cook_pth", &pth));
            }
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn only_import_lines_execute() {
        assert_eq!(
            executable_pth_lines("/opt/lib\nimport os; os.system('x')\n"),
            1
        );
        assert_eq!(executable_pth_lines("importlib_path\n/opt/x\n"), 0);
        assert_eq!(executable_pth_lines("import\tsys\n"), 1);
    }

    #[test]
    fn benign_names_cover_editable_and_namespace_installs() {
        assert!(is_known_benign_pth("distutils-precedence.pth"));
        assert!(is_known_benign_pth("__editable__.mypkg-1.0.pth"));
        assert!(is_known_benign_pth("google_api-1.2-py3.12-nspkg.pth"));
        assert!(!is_known_benign_pth("cook.pth"));
    }

    #[test]
    fn hook_rows_flag_code_hooks_and_skip_path_only_pth() {
        let site = tempfile::tempdir().unwrap();
        fs::write(site.path().join("paths.pth"), "/opt/extra\n").unwrap();
        fs::write(site.path().join("evil.pth"), "import os\n").unwrap();
        fs::write(site.path().join("sitecustomize.py"), "print('hi')\n").unwrap();
        let rows = hook_rows(site.path());
        assert_eq!(rows.len(), 2, "{rows:?}");
        let evil = rows
            .iter()
            .find(|r| r["path"].as_str().unwrap().ends_with("evil.pth"))
            .unwrap();
        assert_eq!(
            evil.get("executes_code"),
            Some(&Value::Bool(true)),
            "{evil:?}"
        );
        assert_eq!(
            evil.get("known_benign"),
            Some(&Value::Bool(false)),
            "{evil:?}"
        );
        assert_eq!(
            evil.get("malicious_name"),
            Some(&Value::Bool(false)),
            "{evil:?}"
        );
    }

    /// The LiteLLM payload is recognised by name alone. Its content is deliberately NOT the real
    /// payload shape: Windows Defender quarantines a `cook.pth` that imports `cook`, which made this
    /// test fail with "file contains a virus" (os error 225) and would alarm any developer's AV.
    /// A read blocked that way leaves `executes_code` undetermined, never false.
    #[test]
    fn litellm_payload_name_is_flagged_without_reading_it() {
        let site = tempfile::tempdir().unwrap();
        fs::write(site.path().join("cook.pth"), "import os\n").unwrap();
        let rows = hook_rows(site.path());
        let cook = rows
            .iter()
            .find(|r| r["path"].as_str().unwrap().ends_with("cook.pth"))
            .unwrap();
        assert_eq!(
            cook.get("malicious_name"),
            Some(&Value::Bool(true)),
            "{cook:?}"
        );
        assert_ne!(
            cook.get("executes_code"),
            Some(&Value::Bool(false)),
            "{cook:?}"
        );
    }

    #[test]
    fn temp_dir_iocs_find_lock_and_markers() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(temp_dir_iocs(tmp.path()).is_empty());
        fs::write(tmp.path().join("remote_code_loader.lock"), "").unwrap();
        fs::write(tmp.path().join(".pc_once_abc"), "").unwrap();
        let mut kinds: Vec<String> = temp_dir_iocs(tmp.path())
            .iter()
            .map(|r| r["indicator"].as_str().unwrap().to_string())
            .collect();
        kinds.sort();
        assert_eq!(kinds, ["litellm_exfil_marker", "litellm_loader_lock"]);
    }
}
