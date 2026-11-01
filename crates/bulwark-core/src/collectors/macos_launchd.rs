//! macOS's persistence analog to `systemd::SystemdUnitsCollector`: every LaunchAgent and
//! LaunchDaemon plist (`~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`)
//! is something macOS starts on every login or boot — the same primitive `BLWK-PERSIST-001/002`
//! watch for on Linux.
//!
//! One fact per plist: its label, scope, the program it runs, and `recognized` — false when the job
//! has the *shape* persistence malware uses rather than the shape installed software uses. That is
//! deliberately not "anything that isn't Apple's": a developer's Mac carries dozens of legitimate
//! third-party agents (updaters, Docker, Tailscale, Homebrew services), and a high-severity finding
//! for each would train the user to ignore the rule. What it flags instead:
//!
//! * a program in a temp or shared-writable directory (`/tmp`, `/var/tmp`, `/Users/Shared`), or
//!   anywhere under a hidden directory (`~/.something/…`) — where droppers put payloads;
//! * an interpreter running inline code (`sh -c …`, `python -c …`, `osascript -e …`), or a job
//!   that runs `curl`/`wget` itself — fetch-and-execute at login;
//! * a plist that is readable but malformed, so what it runs can't be determined.
//!
//! Two things that are *not* findings, both learned on a real Mac: a plist that is a dangling
//! symlink (an uninstaller removed its target; launchd can't run it, so it isn't persistence), and a
//! root-only (`0600 root`) daemon plist read by an unprivileged scan. The latter is recorded with
//! `readable = false` instead of being flagged — "couldn't look" is not "looks malicious" — and is
//! covered once root checks are turned on.
//!
//! `/System/Library` is not read: it is on the sealed, signed system volume and can't be modified
//! without disabling SIP, which is a different finding entirely.
//!
//! Plists are read with `plutil -convert json` (it handles binary plists, which most installers
//! write), so this collector only ever runs on macOS. Verified against a real Mac; the
//! classification itself is pure and unit-tested on every OS.

use super::Collector;
use crate::models::{Fact, OperatingSystem};
use std::path::{Path, PathBuf};

const MACOS_ONLY: &[OperatingSystem] = &[OperatingSystem::Macos];

pub struct LaunchdPersistenceCollector;

fn launch_dirs() -> Vec<(PathBuf, &'static str)> {
    let mut dirs = vec![
        (PathBuf::from("/Library/LaunchAgents"), "system-agent"),
        (PathBuf::from("/Library/LaunchDaemons"), "system-daemon"),
    ];
    if let Some(home) = crate::paths::home_var_os() {
        dirs.insert(
            0,
            (
                PathBuf::from(home).join("Library/LaunchAgents"),
                "user-agent",
            ),
        );
    }
    dirs
}

impl Collector for LaunchdPersistenceCollector {
    fn name(&self) -> &'static str {
        "launchd_persistence"
    }

    fn supported_os(&self) -> &'static [OperatingSystem] {
        MACOS_ONLY
    }

    fn is_applicable(&self) -> bool {
        cfg!(target_os = "macos") && launch_dirs().iter().any(|(d, _)| d.is_dir())
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let mut facts = Vec::new();
        for (dir, scope) in launch_dirs() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            let mut paths: Vec<PathBuf> = entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "plist"))
                .collect();
            paths.sort();
            for path in paths {
                // `exists()` follows symlinks: false for a link whose target is gone.
                if !path.exists() {
                    continue;
                }
                facts.push(fact_for(&path, scope));
            }
        }
        Ok(facts)
    }
}

/// What a plist says it runs.
struct Job {
    label: String,
    program: String,
    args: Vec<String>,
}

enum Plist {
    Job(Job),
    /// Parsed fine, but declares no `Program`/`ProgramArguments`, so launchd has nothing to run.
    /// Uninstallers leave these behind (some write an empty `{}`); not persistence.
    NothingToRun(String),
    /// Couldn't be parsed at all.
    Malformed,
}

fn read_plist(path: &Path) -> Plist {
    let Ok(out) = crate::sandbox::quiet_command("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-", "--"])
        .arg(path)
        .output()
    else {
        return Plist::Malformed;
    };
    if !out.status.success() {
        return Plist::Malformed;
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else {
        return Plist::Malformed;
    };
    parse_job(&v, path)
}

fn parse_job(v: &serde_json::Value, path: &Path) -> Plist {
    let args: Vec<String> = v
        .get("ProgramArguments")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let label = v
        .get("Label")
        .and_then(|l| l.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| stem(path));
    let Some(program) = v
        .get("Program")
        .and_then(|p| p.as_str())
        .map(str::to_string)
        .or_else(|| args.first().cloned())
    else {
        return Plist::NothingToRun(label);
    };
    Plist::Job(Job {
        label,
        program,
        args,
    })
}

fn stem(path: &Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn fact_for(path: &Path, scope: &str) -> Fact {
    let mut f = Fact::new();
    f.insert("path".into(), path.display().to_string().into());
    f.insert("scope".into(), scope.into());
    let permission_denied = std::fs::File::open(path)
        .err()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied);
    if permission_denied {
        f.insert("label".into(), stem(path).into());
        f.insert("program".into(), "".into());
        f.insert("readable".into(), false.into());
        f.insert("recognized".into(), true.into());
        f.insert(
            "reason".into(),
            "readable by root only; covered when root checks are on".into(),
        );
        return f;
    }
    f.insert("readable".into(), true.into());
    match read_plist(path) {
        Plist::NothingToRun(label) => {
            f.insert("label".into(), label.into());
            f.insert("program".into(), "".into());
            f.insert("recognized".into(), true.into());
            f.insert("reason".into(), "declares nothing to run".into());
        }
        Plist::Job(job) => {
            let reason = suspicious_reason(&job.program, &job.args);
            f.insert("label".into(), job.label.into());
            f.insert("program".into(), job.program.into());
            f.insert("recognized".into(), reason.is_none().into());
            f.insert("reason".into(), reason.unwrap_or_default().into());
        }
        Plist::Malformed => {
            f.insert("label".into(), stem(path).into());
            f.insert("program".into(), "".into());
            f.insert("recognized".into(), false.into());
            f.insert(
                "reason".into(),
                "its plist is malformed, so what it runs can't be determined".into(),
            );
        }
    }
    f
}

/// Why a launch job looks like persistence malware rather than installed software, or `None`.
pub(crate) fn suspicious_reason(program: &str, args: &[String]) -> Option<String> {
    let lower = program.to_ascii_lowercase();
    for dir in [
        "/tmp/",
        "/private/tmp/",
        "/var/tmp/",
        "/private/var/tmp/",
        "/users/shared/",
    ] {
        if lower.starts_with(dir) {
            return Some(format!(
                "it runs a program from {dir}, a world-writable directory"
            ));
        }
    }
    if Path::new(program).components().any(|c| {
        c.as_os_str().to_string_lossy().starts_with('.')
            && c.as_os_str() != "."
            && c.as_os_str() != ".."
    }) {
        return Some("it runs a program from a hidden directory".into());
    }
    let base = Path::new(program)
        .file_name()
        .map(|b| b.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let interpreter = matches!(
        base.as_str(),
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "osascript" | "perl" | "ruby" | "node"
    ) || base.starts_with("python");
    if interpreter && args.iter().skip(1).any(|a| a == "-c" || a == "-e") {
        return Some(format!("it runs inline code through {base}"));
    }
    if matches!(base.as_str(), "curl" | "wget")
        || args.iter().any(|a| {
            a.contains("curl ") || a.contains("wget ") || a.contains("| sh") || a.contains("|sh")
        })
    {
        return Some("it downloads something every time it starts".into());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn only_declares_macos_support() {
        assert_eq!(
            LaunchdPersistenceCollector.supported_os(),
            &[OperatingSystem::Macos]
        );
    }

    #[test]
    fn never_applicable_off_macos() {
        if !cfg!(target_os = "macos") {
            assert!(!LaunchdPersistenceCollector.is_applicable());
        }
    }

    #[test]
    fn an_empty_plist_declares_nothing_to_run() {
        // Some uninstallers leave an empty `{}` behind.
        let p = Path::new("/Library/LaunchAgents/com.example.updater.agent.plist");
        assert!(matches!(
            parse_job(&serde_json::json!({}), p),
            Plist::NothingToRun(l) if l == "com.example.updater.agent"
        ));
        let job = serde_json::json!({"Label": "x", "ProgramArguments": ["/bin/sh", "-c", "id"]});
        assert!(matches!(parse_job(&job, p), Plist::Job(j) if j.program == "/bin/sh"));
    }

    #[test]
    fn ordinary_installed_software_is_not_flagged() {
        // The point of the rule's design: a developer's Mac full of legitimate agents stays quiet.
        for (program, a) in [
            (
                "/Applications/Docker.app/Contents/MacOS/com.docker.vmnetd",
                vec![],
            ),
            (
                "/opt/homebrew/opt/postgresql@16/bin/postgres",
                vec!["postgres", "-D", "/opt/homebrew/var/postgresql@16"],
            ),
            (
                "/Library/Application Support/Example/Updater.app/Contents/MacOS/Updater",
                vec!["Updater", "--wake"],
            ),
            (
                "/usr/bin/python3",
                vec!["python3", "/Users/me/tools/backup.py"],
            ),
            ("/bin/sh", vec!["sh", "/usr/local/bin/sync.sh"]),
        ] {
            assert_eq!(suspicious_reason(program, &args(&a)), None, "{program}");
        }
    }

    #[test]
    fn persistence_shapes_are_flagged() {
        for (program, a) in [
            ("/tmp/.x/updater", vec![]),
            ("/Users/Shared/agent", vec![]),
            ("/Users/me/.local/share/.cache/helper", vec![]),
            ("/bin/bash", vec!["bash", "-c", "echo hi"]),
            (
                "/usr/bin/osascript",
                vec!["osascript", "-e", "do shell script \"x\""],
            ),
            ("/usr/bin/python3", vec!["python3", "-c", "import os"]),
            ("/usr/bin/curl", vec!["curl", "-s", "https://example.com/x"]),
            (
                "/bin/zsh",
                vec!["zsh", "/Users/me/run.sh", "curl https://x | sh"],
            ),
        ] {
            assert!(
                suspicious_reason(program, &args(&a)).is_some(),
                "{program} {a:?}"
            );
        }
    }
}
