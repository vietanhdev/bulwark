//! Root reached through `sudo` never opens a database another account can write to.
//!
//! The decision itself is unit-tested in `src/db_guard.rs`. This drives the real binary, as root,
//! against a home folder owned by someone else, which is the case the guard exists for. It needs
//! root to stage that, so it runs in the container CI jobs and reports itself skipped elsewhere.
#![cfg(unix)]

use std::os::unix::fs::MetadataExt;
use std::process::Command;

fn bulwarkctl(home: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_bulwarkctl"));
    c.arg("history")
        .env("HOME", home)
        .env_remove("BULWARK_DB_PATH")
        .env_remove("XDG_DATA_HOME")
        .env_remove("SUDO_USER")
        .env_remove("PKEXEC_UID");
    c
}

#[test]
fn sudo_refuses_a_database_in_another_accounts_home() {
    let home = tempfile::tempdir().unwrap();
    if std::fs::metadata(home.path()).unwrap().uid() != 0 {
        eprintln!("skipped: staging another account's home folder needs root");
        return;
    }
    std::os::unix::fs::chown(home.path(), Some(65534), Some(65534)).unwrap();

    let out = bulwarkctl(home.path())
        .env("SUDO_USER", "nobody")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "must refuse; stderr: {stderr}");
    assert!(stderr.contains("refusing to use"), "{stderr}");
    assert!(
        !home.path().join(".local").exists(),
        "nothing may be created in that folder before the refusal"
    );

    // A real root login chose its own files: no sudo, no refusal.
    let out = bulwarkctl(home.path()).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
