//! `bulwarkctl` is one file: copy it anywhere and it scans, with no rules folder beside it.
//!
//! The rule pack, the log rules and the log decoders are compiled in by `build.rs`. These tests run
//! a *copy* of the real binary from an empty directory, with every pack environment variable
//! cleared, so nothing on disk can be found by accident — the only pack it can use is the one it
//! carries. Before the built-in pack, exactly this situation (a binary outside the workspace and
//! the package layout) failed with "couldn't find a 'rules' directory".

use std::path::{Path, PathBuf};
use std::process::Command;

/// A copy of the built binary in its own empty directory, run from that directory.
struct Lonely {
    dir: tempfile::TempDir,
    exe: PathBuf,
}

impl Lonely {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir
            .path()
            .join(format!("bulwarkctl{}", std::env::consts::EXE_SUFFIX));
        std::fs::copy(env!("CARGO_BIN_EXE_bulwarkctl"), &exe).unwrap();
        Lonely { dir, exe }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(&self.exe);
        c.current_dir(self.dir.path())
            .env_remove("BULWARK_RULES_DIR")
            .env_remove("BULWARK_LOG_RULES_DIR")
            .env_remove("BULWARK_DECODERS_DIR")
            // Never touch the developer's real database or custom rules.
            .arg("--db-path")
            .arg(self.dir.path().join("bulwark.db"))
            .arg("--no-custom-rules");
        c
    }
}

fn rule_files(pack: &str) -> usize {
    fn walk(p: &Path) -> usize {
        std::fs::read_dir(p)
            .unwrap()
            .flatten()
            .map(|e| {
                let path = e.path();
                if path.is_dir() {
                    walk(&path)
                } else {
                    usize::from(matches!(
                        path.extension().and_then(|x| x.to_str()),
                        Some("yaml" | "yml")
                    ))
                }
            })
            .sum()
    }
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(pack),
    )
}

#[test]
fn a_copied_binary_lists_every_shipped_rule_from_its_built_in_pack() {
    let bin = Lonely::new();
    let out = bin.cmd().args(["rules", "list"]).output().unwrap();
    assert!(
        out.status.success(),
        "rules list failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let listed = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.trim_start().starts_with("BLWK-"))
        .count();
    assert_eq!(
        listed,
        rule_files("rules"),
        "every rule file in the repository must be built into the binary"
    );
}

#[test]
fn a_copied_binary_scans_with_its_built_in_pack() {
    let bin = Lonely::new();
    let out = bin
        .cmd()
        .args(["scan", "--json", "--no-persist", "--no-notify"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("couldn't find"),
        "the built-in pack wasn't used: {stderr}"
    );
    let scan: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("scan must print JSON ({e}); stderr: {stderr}"));
    assert!(scan["rules_loaded"].as_u64().unwrap() > 0, "{stderr}");
    assert_eq!(
        scan["rule_load_errors"].as_array().unwrap().len(),
        0,
        "the built-in pack must load cleanly: {}",
        scan["rule_load_errors"]
    );
}

#[test]
fn a_copied_binary_runs_the_log_pipeline_from_its_built_in_packs() {
    let bin = Lonely::new();
    let log = bin.dir.path().join("auth.log");
    let mut lines = String::new();
    for i in 0..10 {
        lines.push_str(&format!(
            "Jan 10 10:00:{i:02} host sshd[100{i}]: Failed password for root from 203.0.113.9 port 4{i}000 ssh2\n"
        ));
    }
    std::fs::write(&log, lines).unwrap();

    let out = bin
        .cmd()
        .args(["logs", "scan", "--json", "--no-persist", "--from-file"])
        .arg(&log)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let scan: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("logs scan must print JSON ({e}); stderr: {stderr}"));
    assert!(scan["decoders_loaded"].as_u64().unwrap() > 0, "{stderr}");
    assert!(scan["rules_loaded"].as_u64().unwrap() > 0, "{stderr}");
    assert!(
        !scan["findings"].as_array().unwrap().is_empty(),
        "ten failed root logins from one address in ten seconds must be reported: {scan}"
    );
}

#[test]
fn an_explicit_rules_folder_still_wins_over_the_built_in_pack() {
    let bin = Lonely::new();
    let mine = bin.dir.path().join("my-rules");
    std::fs::create_dir(&mine).unwrap();
    std::fs::write(
        mine.join("x.yaml"),
        "id: MY-001\ntitle: t\ncategory: c\nseverity: low\ncollector: sshd_config\n\
         condition: x11_forwarding == \"yes\"\nexplain: e\nfix: f\nos: [linux, macos, windows]\n",
    )
    .unwrap();
    let out = bin
        .cmd()
        .args(["rules", "list", "--rules-dir"])
        .arg(&mine)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("MY-001") && !stdout.contains("BLWK-"),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
