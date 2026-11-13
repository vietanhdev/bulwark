use super::Collector;
use crate::homefs::HomeFile;
use crate::models::Fact;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct ShellHistoryConfigCollector;

/// True if a single rc-file line configures the shell to stop recording history. The local signal
/// for MITRE ATT&CK T1070.003 (Clear Command History). The old version matched five exact whole-line
/// strings, which missed essentially every real-world form; this handles the ways people (and
/// attackers) actually write it:
///   * `HISTFILE=/dev/null` or `HISTFILE=` — history is written nowhere.
///   * `HISTSIZE=0` / `HISTFILESIZE=0`, including both on one `export` line.
///   * `unset HISTFILE` (with or without additional vars).
///   * `set +o history` — disables recording outright.
///
/// It tolerates leading indentation, a trailing `# comment`, `export`, quotes, and
/// `;`-separated statements.
fn line_suppresses_history(line: &str) -> bool {
    let line = line.split('#').next().unwrap_or("").trim();
    if line.is_empty() {
        return false;
    }
    if line.contains("set +o history") {
        return true;
    }
    for stmt in line.split([';', '&']) {
        let stmt = stmt.trim();
        let stmt = stmt.strip_prefix("export ").unwrap_or(stmt).trim();
        if let Some(rest) = stmt.strip_prefix("unset ") {
            if rest.split_whitespace().any(|v| v == "HISTFILE") {
                return true;
            }
            continue;
        }
        for tok in stmt.split_whitespace() {
            if let Some((var, val)) = tok.split_once('=') {
                let val = val.trim_matches(['"', '\'']);
                match var {
                    "HISTFILE" if val.is_empty() || val == "/dev/null" => return true,
                    "HISTSIZE" | "HISTFILESIZE" if val == "0" => return true,
                    _ => {}
                }
            }
        }
    }
    false
}

pub fn detect_history_suppression(rc_text: &str) -> Fact {
    let mut fact = Fact::new();
    let suppressed = rc_text.lines().any(line_suppresses_history);
    fact.insert("history_suppressed".to_string(), Value::Bool(suppressed));
    fact
}

/// System-wide rc files: a suppression planted here hits every user.
const SYSTEM_RC_FILES: &[&str] = &["/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc"];

/// Per-user rc files, relative to a home folder.
const HOME_RC_FILES: &[&str] = &[
    ".bashrc",
    ".zshrc",
    ".zshenv",
    ".profile",
    ".bash_profile",
    ".bash_login",
];

/// One row saying whether any rc file suppresses history, plus one row for each file that could
/// not be read or was only partly read. `homes` are the home folders the scan covers: `$HOME`,
/// and under sudo or pkexec the invoking user's too (where a "hide my tracks" line would be).
///
/// Home files are opened through [`crate::homefs`]: their owner controls them, and a named pipe
/// put in place of `~/.bashrc` used to hold the scan, a root scan included, forever.
fn collect_from(system: &[PathBuf], homes: &[PathBuf]) -> Vec<Fact> {
    let mut combined = String::new();
    let mut unread = Vec::new();
    let mut take = |path: &Path, read: HomeFile<super::CappedText>, refused: &str| match read {
        HomeFile::Found(read) => {
            if read.truncated {
                unread.push(super::unread_row(path, super::TOO_LARGE));
            }
            combined.push_str(&read.text);
            combined.push('\n');
        }
        HomeFile::Missing => {}
        HomeFile::Refused => unread.push(super::unread_row(path, refused)),
    };
    for path in system {
        take(path, super::read_system(path), super::refused_reason(path));
    }
    for home in homes {
        for rc in HOME_RC_FILES {
            let path = home.join(rc);
            take(&path, super::read_home(home, &path), crate::homefs::REFUSED);
        }
    }
    let mut rows = vec![detect_history_suppression(&combined)];
    rows.append(&mut unread);
    rows
}

impl Collector for ShellHistoryConfigCollector {
    fn name(&self) -> &'static str {
        "shell_history_config"
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let system: Vec<PathBuf> = SYSTEM_RC_FILES.iter().map(PathBuf::from).collect();
        Ok(collect_from(&system, &super::user_homes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_histsize_zero() {
        let fact = detect_history_suppression("export PATH=$PATH:/foo\nexport HISTSIZE=0\n");
        assert_eq!(fact.get("history_suppressed").unwrap(), &Value::Bool(true));
    }

    #[test]
    fn detects_the_real_world_suppression_forms() {
        // Every one of these used to slip past the exact-match check.
        for rc in [
            "  HISTFILE=/dev/null\n",             // indented, /dev/null
            "export HISTSIZE=0 HISTFILESIZE=0\n", // two on one export line
            "set +o history\n",                   // disables recording outright
            "unset HISTFILE HISTSIZE\n",          // unset with extra vars
            "HISTFILE=   # cover my tracks\n",    // empty + inline comment
            "HISTSIZE=0\n",                       // no `export`
        ] {
            assert_eq!(
                detect_history_suppression(rc)
                    .get("history_suppressed")
                    .unwrap(),
                &Value::Bool(true),
                "should flag: {rc:?}"
            );
        }
    }

    #[test]
    fn ordinary_rc_file_is_not_flagged() {
        let fact = detect_history_suppression(
            "alias ll='ls -la'\nexport HISTSIZE=1000\nexport HISTFILE=$HOME/.bash_history\nHISTFILESIZE=2000\n",
        );
        assert_eq!(fact.get("history_suppressed").unwrap(), &Value::Bool(false));
    }

    #[cfg(unix)]
    #[test]
    fn a_pipe_in_place_of_an_rc_file_is_reported_and_never_waited_on() {
        let home = tempfile::tempdir().unwrap();
        let etc = tempfile::tempdir().unwrap();
        for name in [".bashrc", ".zshrc", ".profile"] {
            let c = std::ffi::CString::new(home.path().join(name).to_str().unwrap()).unwrap();
            // SAFETY: a valid NUL-terminated path and a plain mode.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        }
        std::fs::write(home.path().join(".bash_profile"), "unset HISTFILE\n").unwrap();
        let system_fifo = etc.path().join("profile");
        let c = std::ffi::CString::new(system_fifo.to_str().unwrap()).unwrap();
        // SAFETY: as above.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

        let (tx, rx) = std::sync::mpsc::channel();
        let (system, homes) = (vec![system_fifo.clone()], vec![home.path().to_path_buf()]);
        std::thread::spawn(move || {
            let _ = tx.send(collect_from(&system, &homes));
        });
        let rows = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("a pipe named ~/.bashrc must not block the scan");
        // What could be read is still judged.
        assert_eq!(rows[0]["history_suppressed"], Value::Bool(true));
        let unread: Vec<&str> = rows
            .iter()
            .filter(|r| r.contains_key(crate::homefs::COULD_NOT_READ))
            .filter_map(|r| r["path"].as_str())
            .collect();
        assert_eq!(unread.len(), 4, "{unread:?}");
        assert!(unread.contains(&home.path().join(".bashrc").to_str().unwrap()));
        assert!(unread.contains(&system_fifo.to_str().unwrap()));
        // Those rows carry no verdict, so the rule over them is not counted as passed.
        assert!(rows[1..]
            .iter()
            .all(|r| !r.contains_key("history_suppressed")));
    }

    #[cfg(unix)]
    #[test]
    fn an_rc_file_linked_out_of_the_home_folder_is_not_read() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("rc"), "HISTSIZE=0\n").unwrap();
        std::os::unix::fs::symlink(outside.path().join("rc"), home.path().join(".bashrc")).unwrap();
        std::fs::write(home.path().join(".zshrc"), "alias ll='ls -la'\n").unwrap();
        let rows = collect_from(&[], &[home.path().to_path_buf()]);
        assert_eq!(rows[0]["history_suppressed"], Value::Bool(false));
        assert_eq!(
            rows.len(),
            2,
            "the link is reported as not checked: {rows:?}"
        );
    }
}
